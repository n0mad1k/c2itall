"""Lab records: one WireGuard gateway, its members and the shared networks per provider.

A lab is a named record under deployments/lab/ that every lab deployment
reads and updates: which VM is the gateway (hub), which members joined with
which lab address, which provider networks exist, and where the lab's
secrets live. Members stay ordinary deployments; the record only ties them
together so teardown can unwind them in order.
"""

import ipaddress
import json
import os
import re
import shutil
import time
from pathlib import Path

from .controller_io import ROOT, secure_directory
from .ssh_utils import generate_ssh_key
from .state_store import StateStore

LAB_ROOT = ROOT / 'deployments' / 'lab'
NAME = re.compile(r'[a-z0-9][a-z0-9-]{0,19}')
# RFC 2544 space: clear of LUDUS ranges (10/8), Docker (172.17+), AWS default
# VPCs (172.31/16) and VirtualBox host-only networks (192.168.56/24).
SPACE = ipaddress.ip_network('198.18.0.0/16')
OVERLAY = ipaddress.ip_network('198.18.0.0/24')
HUB_IP = '198.18.0.1'
OPERATOR_IP = '198.18.0.2'
FIRST_MEMBER = 10
FIRST_BLOCK = ipaddress.ip_network('198.18.16.0/20')
WG_PORT = 51820


def _validate(state):
    name = state.get('name')
    if (not isinstance(name, str) or not NAME.fullmatch(name)
            or state.get('deployment_id') != 'lab-' + name):
        raise ValueError('Invalid lab record')
    return state


_STORE = StateStore(validate=_validate, planned_ids=lambda state: {}, label='lab')


def create(name, blocked_cidrs=()):
    """Persist a new lab record and its shared SSH key."""
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError('Lab name must match [a-z0-9][a-z0-9-]{0,19}')
    key = Path.home() / '.ssh' / ('c2deploy_lab-' + name)
    record = {
        'deployment_id': 'lab-' + name, 'name': name,
        'ssh_key_path': str(key) + '.pub', 'ssh_private_key_path': str(key),
        'ssh_key_generated': True,
        'cidr': str(OVERLAY), 'cidrs': [str(SPACE)], 'range_cidrs': [],
        'blocked_cidrs': [str(ipaddress.ip_network(cidr, strict=False)) for cidr in blocked_cidrs],
        'gateway': None, 'members': {}, 'networks': {}, 'blocks': {}, 'passwords': {},
    }
    lab = _STORE.prepare(record, LAB_ROOT)
    if not generate_ssh_key('lab-' + name):
        raise RuntimeError('Could not generate the lab SSH key')
    with secure_directory(secret_dir(lab), create=True):
        pass
    return lab


def load(name):
    return _STORE.load('lab-' + str(name), LAB_ROOT)


def save(lab):
    _STORE.save(lab, LAB_ROOT)


def list_labs():
    return [state['name'] for state in _STORE.list(LAB_ROOT)]


def secret_dir(lab):
    return LAB_ROOT / lab['name']


def write_secret(lab, filename, data):
    """Store lab-only credentials as owner-readable JSON beside the record."""
    with secure_directory(secret_dir(lab), create=True) as directory:
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600,
                     dir_fd=directory)
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2)
    return secret_dir(lab) / filename


def read_secret(lab, filename):
    path = secret_dir(lab) / filename
    return json.loads(path.read_text()) if path.is_file() else None


def journal(lab, entry):
    """Append one audit line; an implant entry must say which Falcon exception it used."""
    if entry.get('action') == 'implant' and not str(entry.get('falcon_exception') or '').strip():
        raise ValueError('An implant entry must record the Falcon exception used, or "none"')
    with secure_directory(secret_dir(lab), create=True) as directory:
        fd = os.open('journal.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600,
                     dir_fd=directory)
        with os.fdopen(fd, 'a') as stream:
            stream.write(json.dumps({'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                                     **entry}) + '\n')


def next_block(lab, provider):
    """The /20 a native provider's lab subnet is carved from; allocated once."""
    if provider in lab['blocks']:
        return lab['blocks'][provider]
    used = {ipaddress.ip_network(block) for block in lab['blocks'].values()}
    block = FIRST_BLOCK
    while block in used:
        block = ipaddress.ip_network((int(block.network_address) + block.num_addresses, 20))
        if not block.subnet_of(SPACE):
            raise ValueError('No lab address block left for ' + provider)
    lab['blocks'][provider] = str(block)
    save(lab)
    return str(block)


def ensure_network(lab, driver, config):
    """Create or reuse the provider's shared lab network; None for overlay-only providers."""
    if 'lab_network' not in driver.capabilities:
        return None
    network = lab['networks'].get(driver.provider)
    if network and network.get('status') == 'ready':
        return network
    block = next_block(lab, driver.provider)
    lab['networks'][driver.provider] = {'status': 'creating', 'cidr': block}
    save(lab)
    network = dict(driver.lab_network(lab, config), status='ready', cidr=block)
    lab['networks'][driver.provider] = network
    save(lab)
    return network


def _next_lab_ip(lab):
    used = {member['lab_ip'] for member in lab['members'].values()}
    for host in OVERLAY.hosts():
        if int(host) - int(OVERLAY.network_address) >= FIRST_MEMBER and str(host) not in used:
            return str(host)
    raise ValueError('Lab overlay has no free address')


def placement(lab, driver, deployment_id, profile, operator_ip):
    """The ProvisionRequest.lab dict for one VM; records the member before any resource exists."""
    native = 'lab_network' in driver.capabilities
    network = lab['networks'].get(driver.provider) if native else None
    if native and not (network and network.get('status') == 'ready'):
        raise ValueError(driver.provider + ' lab network is not ready')
    common = {'name': lab['name'], 'cidrs': list(lab['cidrs']),
              'range_cidrs': list(lab['range_cidrs']), 'network': network}
    if profile.lab_role == 'gateway':
        current = lab.get('gateway')
        if current and current['deployment_id'] != deployment_id and current.get('status') == 'ready':
            raise ValueError('Lab {0} already has gateway {1}'.format(lab['name'], current['deployment_id']))
        lab['gateway'] = {'deployment_id': deployment_id, 'provider': driver.provider,
                          'lab_ip': HUB_IP, 'ssh_user': driver.ssh_user, 'port': WG_PORT,
                          'status': 'planned'}
        save(lab)
        return dict(common, role='gateway', lab_ip=HUB_IP, public_ip=True, ssh_source=operator_ip,
                    ssh_proxy=None, egress_via_hub=False)
    gateway = lab.get('gateway')
    if not gateway or gateway.get('status') != 'ready':
        raise ValueError('Lab ' + lab['name'] + ' has no ready gateway; deploy it first')
    if native and gateway['provider'] != driver.provider:
        # ponytail: v1 bootstraps a private member through a gateway in the same
        # network; cloud-init spoke configs would lift this ceiling.
        raise ValueError('A private {0} member needs the lab gateway on {0}'.format(driver.provider))
    member = lab['members'].get(deployment_id) or {'lab_ip': _next_lab_ip(lab)}
    member.update(provider=driver.provider, workload=profile.workload, status='planned',
                  egress_via_hub=not native)
    lab['members'][deployment_id] = member
    save(lab)
    # The controller reaches local hosts itself; everything else goes through the gateway.
    direct = driver.private_addresses
    proxy = None if direct else {'user': gateway['ssh_user'], 'host': gateway['public_ip'],
                                 'key': lab['ssh_private_key_path'],
                                 'known_hosts': str(secret_dir(lab) / 'gateway-known-hosts')}
    return dict(common, role='member', lab_ip=member['lab_ip'], public_ip=not native,
                ssh_source=operator_ip if direct else gateway['public_ip'] + '/32',
                ssh_proxy=proxy, egress_via_hub=not native)


def register(lab, deployment_id, ssh_host, public_ip=None):
    """Record where a provisioned gateway or member is reached."""
    gateway = lab.get('gateway')
    if gateway and gateway['deployment_id'] == deployment_id:
        gateway.update(public_ip=public_ip or ssh_host, ssh_host=ssh_host, status='ready')
    else:
        lab['members'][deployment_id].update(ssh_host=ssh_host, status='ready')
    save(lab)


def unregister(lab, deployment_id):
    gateway = lab.get('gateway')
    if gateway and gateway['deployment_id'] == deployment_id:
        lab['gateway'] = None
    else:
        lab['members'].pop(deployment_id, None)
    save(lab)


def gateway_target(lab):
    """How the controller reaches the gateway itself."""
    gateway = lab['gateway']
    return {'user': gateway['ssh_user'], 'host': gateway['public_ip'],
            'key': lab['ssh_private_key_path'],
            'known_hosts': str(secret_dir(lab) / 'gateway-known-hosts')}


def service_variables(lab, deployment_id):
    """The `lab` variable every lab play receives."""
    gateway = lab.get('gateway') or {}
    member = lab['members'].get(deployment_id)
    return {
        'name': lab['name'], 'cidr': lab['cidr'], 'cidrs': list(lab['cidrs']),
        'range_cidrs': list(lab['range_cidrs']), 'blocked_cidrs': list(lab['blocked_cidrs']),
        'secret_dir': str(secret_dir(lab)),
        'hub': {'lab_ip': HUB_IP, 'operator_ip': OPERATOR_IP, 'port': WG_PORT,
                'public_ip': gateway.get('public_ip'), 'ssh_user': gateway.get('ssh_user')},
        'member': dict(member, deployment_id=deployment_id) if member else None,
        'members': {name: dict(entry) for name, entry in lab['members'].items()},
    }


def member_adapter(lab, deployment_id):
    """The adapter and reconstructed config of one ready member or the gateway."""
    from .provider_registry import load_infrastructure_state, workload_route
    state = load_infrastructure_state(deployment_id)
    if state is None:
        raise ValueError('No recovery state for ' + deployment_id)
    gateway = lab.get('gateway') or {}
    entry = (gateway if gateway.get('deployment_id') == deployment_id
             else lab['members'].get(deployment_id))
    if not entry or entry.get('status') != 'ready':
        raise ValueError(deployment_id + ' is not a ready part of lab ' + lab['name'])
    adapter = workload_route(state)
    config = dict(state, lab=lab['name'], ssh_host=entry['ssh_host'],
                  ssh_user=adapter.driver.ssh_user, ssh_key=state['ssh_private_key_path'])
    if adapter.profile.address_key:
        config[adapter.profile.address_key] = (
            entry['public_ip'] if entry is gateway else entry['lab_ip'])
    return adapter, config


def run_member_playbook(name, deployment_id, playbook, variables, log_suffix, timeout):
    """Run an extra play (repo-relative path) on a ready member with its lab variables."""
    lab = load(name)
    adapter, config = member_adapter(lab, deployment_id)
    address = config['ssh_host']
    inventory = address + ','
    if adapter.profile.inventory_group:
        inventory = '[' + adapter.profile.inventory_group + ']\n' + address + ' ansible_host=' + address + '\n'
    merged = dict(variables, lab=service_variables(lab, deployment_id))
    return adapter._run_playbook(config, str(ROOT / playbook), inventory, merged, log_suffix, timeout)


def member_command(name, deployment_id, argv, timeout=120):
    """Run one command on a ready member through its usual SSH path; return the CompletedProcess."""
    lab = load(name)
    adapter, config = member_adapter(lab, deployment_id)
    known_hosts = adapter._export_ssh_known_hosts(config)
    command = adapter.driver.ssh_argv(config, config['ssh_host'], known_hosts) + list(argv)
    return adapter.driver.run_command(command, timeout=timeout, check=False)


def set_range(lab, deployment_id, cidr):
    """Record the LUDUS range behind a member; refresh() pushes the routes to everyone."""
    cidr = str(ipaddress.ip_network(cidr, strict=True))
    if cidr not in lab['range_cidrs']:
        lab['range_cidrs'].append(cidr)
    routes = lab['members'][deployment_id].setdefault('hub_routes', [])
    if cidr not in routes:
        routes.append(cidr)
    save(lab)


def refresh(name):
    """Re-run the gateway play and every member's spoke join so new routes reach all of them."""
    lab = load(name)
    adapter, config = member_adapter(lab, lab['gateway']['deployment_id'])
    if not adapter._run_service_playbook(config):
        return False
    for deployment_id, entry in lab['members'].items():
        if entry.get('status') != 'ready':
            continue
        adapter, config = member_adapter(lab, deployment_id)
        placement = dict(config[adapter.driver.prefix + 'lab'],
                         hub_routes=list(entry.get('hub_routes') or []),
                         range_cidrs=list(lab['range_cidrs']))
        if not adapter._run_spoke_playbook(config, lab, placement):
            return False
    return True


def teardown(name):
    """Members first, then the gateway, then every shared network; stop at the first failure."""
    from .cleanup_engine import cleanup_ssh_keys_for_deployment
    from .provider_registry import load_infrastructure_state, provider_driver, workload_route
    lab = load(name)
    order = list(reversed(list(lab['members'])))
    if lab.get('gateway'):
        order.append(lab['gateway']['deployment_id'])
    for deployment_id in order:
        state = load_infrastructure_state(deployment_id)
        if state is None:
            print('No recovery state for ' + deployment_id + '; treating it as gone')
            lab = load(name)
            unregister(lab, deployment_id)
            continue
        adapter = workload_route(state)
        if adapter is None or not adapter.cleanup(state):
            return False
        lab = load(name)
    for provider, network in list(lab['networks'].items()):
        if not provider_driver(provider).delete_lab_network(lab, network):
            return False
        del lab['networks'][provider]
        save(lab)
    cleanup_ssh_keys_for_deployment('lab-' + name)
    shutil.rmtree(secret_dir(lab), ignore_errors=True)
    _STORE.retire(lab, LAB_ROOT)
    return True
