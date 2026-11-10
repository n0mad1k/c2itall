"""Infrastructure-only Azure lifecycle, using CLI session auth and Ansible."""

import contextlib
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

from . import controller_io
from .controller_io import ROOT, interruption_handlers, secure_directory
from .controller_io import regular_file as _regular_file
from .ssh_utils import ipv4, ssh_options
from .state_store import StateStore
STATE_DIR = ROOT / 'deployments' / 'azure'
CONFIG_KEYS = frozenset({
    'provider', 'deployment_id', 'deployment_type', 'infrastructure_deployment',
    'provider_workload',
    'azure_subscription_id', 'azure_location', 'azure_vm_size',
    'azure_resource_group', 'azure_os_disk_gb', 'operator_ip', 'ssh_key_path',
    'ssh_private_key_path', 'ssh_key_generated', 'azure_inbound_rules',
    'azure_image', 'azure_edge', 'azure_lab', 'ssh_proxy',
})
_SUBNET_ID = (r'/subscriptions/[0-9a-f-]{36}/resourceGroups/[A-Za-z0-9_-]{1,90}/providers/'
              r'Microsoft\.Network/virtualNetworks/[A-Za-z0-9_-]{1,80}/subnets/[A-Za-z0-9_-]{1,80}')
# Front Door reaches origins from this service tag and stamps this header.
EDGE_SOURCE = 'AzureFrontDoor.Backend'
EDGE_HEADER = 'X-Azure-FDID'
EDGE_FORWARDING = ('HttpsOnly', 'HttpOnly', 'MatchRequest')
_HOSTNAME = r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*'
DEFAULT_IMAGE = {'publisher': 'Canonical', 'offer': 'ubuntu-24_04-lts',
                 'sku': 'server', 'version': 'latest', 'plan': False}
UNSUPPORTED_FLAGS = frozenset({'c2_only', 'deploy_c2', 'c2_framework', 'attack_box_deployment',
    'redirector_only', 'tracker_deployment', 'phishing_deployment', 'chat_deployment',
    'payload_deployment', 'payload_server_deployment', 'webrunner_deployment'})
_AUTH_VALID_UNTIL = {}
_AUTH_CERTIFICATE_DIRECTORY = None
_AUTH_CERTIFICATE_PATH = None
_AUTOMATION_KEYS = (
    'AZURE_CLIENT_ID', 'AZURE_CLIENT_CERTIFICATE',
    'AZURE_TENANT_ID', 'AZURE_SUBSCRIPTION_ID',
)
_AZURE_INFISICAL_FOLDER = 'homelab'


def supports_infrastructure(config):
    return (config.get('infrastructure_deployment') is True and
            config.get('deployment_type') == 'infrastructure' and
            not any(config.get(key) for key in UNSUPPORTED_FLAGS))


@contextlib.contextmanager
def lifecycle_lock(config):
    """Serialize both deployment identity and its subscription/resource-group target."""
    target = f"{config['azure_subscription_id']}/{config['azure_resource_group']}"
    with _STORE.lock(config['deployment_id'], target, config.get('azure_state_dir') or STATE_DIR):
        yield


def azure_environment():
    """Only controller/runtime settings; never inherit provider credentials."""
    allowed = {'PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'LC_CTYPE',
               'TMPDIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE',
               'AZURE_CONFIG_DIR', 'SYSTEMROOT'}
    env = {k: v for k, v in os.environ.items() if k in allowed}
    env['AZURE_CORE_COLLECT_TELEMETRY'] = 'false'
    return env


def _credential_environment():
    allowed = {'PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'LC_CTYPE',
               'TMPDIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE',
               'INFISICAL_URL', 'SYSTEMROOT'}
    return {key: value for key, value in os.environ.items() if key in allowed}


def _infisical_credential(key):
    helper = Path.home() / '.local' / 'bin' / 'creds'
    try:
        result = subprocess.run(
            [str(helper), 'get', key, _AZURE_INFISICAL_FOLDER],
            env=_credential_environment(), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError('Infisical Azure credential lookup failed') from exc
    value = result.stdout.strip()
    if result.returncode or not value:
        raise RuntimeError(f'Infisical Azure credential is unavailable: {key}')
    return value


def azure_automation_credentials(subscription_id=None):
    """Load one complete Azure automation credential without exposing it."""
    from_environment = {key: os.environ.get(key, '') for key in _AUTOMATION_KEYS}
    if any(from_environment.values()):
        if not all(from_environment.values()):
            raise RuntimeError('Azure automation environment is incomplete')
        values = from_environment
    else:
        values = {key: _infisical_credential(key) for key in _AUTOMATION_KEYS}
    try:
        values['AZURE_CLIENT_ID'] = str(uuid.UUID(values['AZURE_CLIENT_ID']))
        values['AZURE_TENANT_ID'] = str(uuid.UUID(values['AZURE_TENANT_ID']))
        values['AZURE_SUBSCRIPTION_ID'] = str(uuid.UUID(values['AZURE_SUBSCRIPTION_ID']))
    except ValueError as exc:
        raise RuntimeError('Azure automation identity contains an invalid UUID') from exc
    certificate = values['AZURE_CLIENT_CERTIFICATE']
    if (not re.search(r'-----BEGIN [^-]*PRIVATE KEY-----', certificate)
            or 'BEGIN CERTIFICATE' not in certificate):
        raise RuntimeError('Azure automation certificate is invalid')
    if subscription_id is not None:
        requested = str(uuid.UUID(subscription_id))
        if values['AZURE_SUBSCRIPTION_ID'] != requested:
            raise RuntimeError('Infisical Azure subscription does not match the requested subscription')
    return values


def authentication_error(error):
    detail = str(error).lower()
    return any(marker in detail for marker in (
        "please run 'az login'", 'az login', 'aadsts', 'authentication failed',
        'credential', 'token has expired', 'no subscriptions found',
        'service-principal.pem', 'filenotfounderror',
    ))


def _clear_azure_auth_certificate():
    global _AUTH_CERTIFICATE_DIRECTORY, _AUTH_CERTIFICATE_PATH
    if _AUTH_CERTIFICATE_DIRECTORY is not None:
        _AUTH_CERTIFICATE_DIRECTORY.cleanup()
    _AUTH_CERTIFICATE_DIRECTORY = None
    _AUTH_CERTIFICATE_PATH = None


def _materialize_azure_auth_certificate(certificate_text):
    global _AUTH_CERTIFICATE_DIRECTORY, _AUTH_CERTIFICATE_PATH
    if (_AUTH_CERTIFICATE_PATH is not None and _AUTH_CERTIFICATE_PATH.exists()
            and _AUTH_CERTIFICATE_PATH.read_text() == certificate_text):
        return _AUTH_CERTIFICATE_PATH
    _clear_azure_auth_certificate()
    _AUTH_CERTIFICATE_DIRECTORY = tempfile.TemporaryDirectory(
        prefix='c2itall-azure-login-')
    _AUTH_CERTIFICATE_PATH = (
        Path(_AUTH_CERTIFICATE_DIRECTORY.name) / 'service-principal.pem')
    _AUTH_CERTIFICATE_PATH.write_text(certificate_text)
    _AUTH_CERTIFICATE_PATH.chmod(0o600)
    return _AUTH_CERTIFICATE_PATH


def ensure_azure_auth(subscription_id=None, force=False):
    """Retain a valid CLI session, using Infisical service-principal auth as fallback."""
    requested = str(uuid.UUID(subscription_id)) if subscription_id is not None else None
    cache_key = requested or 'default'
    now = time.monotonic()
    if not force and _AUTH_VALID_UNTIL.get(cache_key, 0) > now:
        return requested
    if not force:
        command = ['az', 'account', 'get-access-token', '--only-show-errors',
                   '--output', 'none']
        if requested:
            command.extend(['--subscription', requested])
        try:
            run_command(command, timeout=30)
            _AUTH_VALID_UNTIL[cache_key] = now + 300
            return requested
        except RuntimeError:
            pass
    credentials = azure_automation_credentials(requested)
    certificate = _materialize_azure_auth_certificate(
        credentials['AZURE_CLIENT_CERTIFICATE'])
    run_command([
        'az', 'login', '--service-principal',
        '--username', credentials['AZURE_CLIENT_ID'],
        '--tenant', credentials['AZURE_TENANT_ID'],
        '--subscription', credentials['AZURE_SUBSCRIPTION_ID'],
        '--skip-subscription-discovery', '--certificate', str(certificate),
        '--only-show-errors', '--output', 'none',
    ], timeout=60)
    _AUTH_VALID_UNTIL[credentials['AZURE_SUBSCRIPTION_ID']] = time.monotonic() + 300
    _AUTH_VALID_UNTIL['default'] = time.monotonic() + 300
    return credentials['AZURE_SUBSCRIPTION_ID']


def run_command(argv, timeout=60, deadline=None, check=True):
    """Run a bounded az/ansible command with only the controller's Azure environment."""
    return controller_io.run_command(argv, timeout=timeout, deadline=deadline, check=check,
                                     env=azure_environment(), label='Azure')


def run_az(args, subscription_id, deadline=None, timeout=60):
    command = ['az', *args, '--subscription', subscription_id,
               '--only-show-errors', '--output', 'json']
    try:
        result = run_command(command, timeout=timeout, deadline=deadline)
    except RuntimeError as exc:
        if not authentication_error(exc):
            raise
        ensure_azure_auth(subscription_id, force=True)
        result = run_command(command, timeout=timeout, deadline=deadline)
    return json.loads(result.stdout) if result.stdout.strip() else None


def check_connection(subscription_id=None):
    """Verify CLI authentication and a real, read-only ARM request."""
    command = ['az', 'account', 'show', '--only-show-errors', '--output', 'json']
    if subscription_id is not None:
        command.extend(['--subscription', str(uuid.UUID(subscription_id))])
    try:
        account = json.loads(run_command(command).stdout)
    except RuntimeError as exc:
        if not authentication_error(exc):
            raise
        selected = ensure_azure_auth(subscription_id, force=True)
        if subscription_id is None and selected is not None:
            command.extend(['--subscription', selected])
        account = json.loads(run_command(command).stdout)
    selected = str(uuid.UUID(account['id']))
    if account.get('state') != 'Enabled':
        raise ValueError('Azure subscription is not enabled')
    if subscription_id is not None and selected != str(uuid.UUID(subscription_id)):
        raise ValueError('Azure CLI returned a different subscription')
    count = run_az(['group', 'list', '--query', 'length(@)'], selected)
    if type(count) is not int or count < 0:
        raise ValueError('Azure returned an invalid resource-group response')
    return {'subscription_id': selected, 'resource_group_count': count}


def validate_config(config, require_key=True):
    if not supports_infrastructure(config):
        raise ValueError('Azure supports only the infrastructure workload')
    result = {k: v for k, v in config.items() if k in CONFIG_KEYS}
    if result.get('provider') != 'azure' or result.get('infrastructure_deployment') is not True:
        raise ValueError('Azure supports infrastructure deployments only')
    if result.get('deployment_type') != 'infrastructure':
        raise ValueError('Azure deployment_type must be infrastructure')
    workload = result.get('provider_workload', 'infrastructure')
    if not isinstance(workload, str) or not re.fullmatch(r'[a-z][a-z0-9_]{1,39}', workload):
        raise ValueError('Invalid Azure provider_workload')
    result['provider_workload'] = workload
    deployment_id = result.get('deployment_id', '')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', deployment_id):
        raise ValueError('Invalid Azure deployment ID')
    result['azure_subscription_id'] = str(uuid.UUID(result['azure_subscription_id']))
    for key, pattern in [('azure_location', r'[a-z][a-z0-9]{1,39}'),
                         ('azure_vm_size', r'Standard_[A-Za-z0-9_]+')]:
        if not re.fullmatch(pattern, result.get(key, '')):
            raise ValueError(f'Invalid {key}')
    disk_size = result.get('azure_os_disk_gb', 32)
    if type(disk_size) is not int or not 32 <= disk_size <= 2048:
        raise ValueError('azure_os_disk_gb must be an integer from 32 through 2048')
    result['azure_os_disk_gb'] = disk_size
    result.setdefault('azure_resource_group', f'c2itall-{deployment_id}')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,89}', result['azure_resource_group']):
        raise ValueError('Invalid Azure resource group')
    network = ipaddress.ip_network(result['operator_ip'] if '/' in result['operator_ip']
                                   else result['operator_ip'] + '/32', strict=True)
    if network.version != 4 or network.prefixlen != 32 or not network.network_address.is_global:
        raise ValueError('operator_ip must be a public IPv4 /32')
    result['operator_ip'] = str(network)
    inbound = result.get('azure_inbound_rules', [])
    if not isinstance(inbound, list) or len(inbound) > 16:
        raise ValueError('azure_inbound_rules must be a list of at most 16 rules')
    normalized_rules = []
    seen_rules = set()
    for rule in inbound:
        if not isinstance(rule, dict) or set(rule) != {'name', 'protocol', 'port', 'source'}:
            raise ValueError('Invalid Azure inbound rule shape')
        name = rule['name']
        protocol = str(rule['protocol']).title()
        try:
            port = int(rule['port'])
        except (TypeError, ValueError):
            raise ValueError('Invalid Azure inbound rule port')
        source = rule['source']
        if source not in ('*', EDGE_SOURCE):
            try:
                network = ipaddress.ip_network(
                    source if '/' in str(source) else str(source) + '/32', strict=True)
            except ValueError:
                raise ValueError('Invalid Azure inbound rule')
            if (network.version != 4 or network.prefixlen != 32
                    or not network.network_address.is_global):
                raise ValueError('Invalid Azure inbound rule')
            source = str(network)
        if (not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
                or protocol not in ('Tcp', 'Udp') or not 1 <= port <= 65535
                or port == 22):
            raise ValueError('Invalid Azure inbound rule')
        identity = (protocol, port, source)
        if identity in seen_rules:
            raise ValueError('Duplicate Azure inbound rule')
        seen_rules.add(identity)
        normalized_rules.append({'name': name, 'protocol': protocol,
                                 'port': str(port), 'source': source})
    result['azure_inbound_rules'] = normalized_rules
    edge = result.get('azure_edge')
    if edge is not None:
        if (not isinstance(edge, dict) or set(edge) != {'host_header', 'forwarding', 'name'}
                or not re.fullmatch(_HOSTNAME, str(edge['host_header']))
                or edge['forwarding'] not in EDGE_FORWARDING
                or not re.fullmatch(r'[a-z][a-z0-9-]{0,45}', str(edge['name']))):
            raise ValueError('Invalid Azure edge request')
        result['azure_edge'] = {key: str(edge[key]) for key in ('host_header', 'forwarding', 'name')}
    lab = result.get('azure_lab')
    if lab is not None:
        if (edge is not None or not isinstance(lab, dict)
                or not {'name', 'role', 'lab_ip', 'public_ip', 'cidrs', 'network'} <= set(lab)
                or type(lab['public_ip']) is not bool or lab['role'] not in ('gateway', 'member')
                or not re.fullmatch(_SUBNET_ID, str((lab['network'] or {}).get('subnet_id', '')))):
            raise ValueError('Invalid Azure lab placement')
        ipv4(lab['lab_ip'], private_ok=True)
        for cidr in lab['cidrs']:
            ipaddress.ip_network(cidr)
    proxy = result.get('ssh_proxy')
    if proxy is not None and (not isinstance(proxy, dict)
                              or set(proxy) != {'user', 'host', 'key', 'known_hosts'}):
        raise ValueError('Invalid ssh_proxy')
    image = result.get('azure_image')
    if image is not None:
        fields = ('publisher', 'offer', 'sku', 'version')
        if (not isinstance(image, dict) or set(image) - {*fields, 'plan'}
                or any(not isinstance(image.get(key), str)
                       or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', image[key])
                       for key in fields)
                or type(image.get('plan', False)) is not bool):
            raise ValueError('Invalid Azure image reference')
        result['azure_image'] = {**{key: image[key] for key in fields},
                                 'plan': bool(image.get('plan', False))}
    public = Path(result['ssh_key_path']).expanduser().absolute()
    private = Path(result.get('ssh_private_key_path', str(public).removesuffix('.pub'))).expanduser().absolute()
    if public == private:
        raise ValueError('ssh_key_path must point to a .pub public key')
    result.update(ssh_key_path=str(public), ssh_private_key_path=str(private))
    if not isinstance(result.get('ssh_key_generated', False), bool):
        raise ValueError('ssh_key_generated must be a boolean')
    result.setdefault('ssh_key_generated', False)
    if result['ssh_key_generated']:
        expected = Path.home() / '.ssh' / f'c2deploy_{deployment_id}'
        if private != expected or public != Path(str(expected) + '.pub'):
            raise ValueError('Generated SSH key paths do not belong to this deployment')
        if private.is_symlink() or public.is_symlink():
            raise ValueError('Generated SSH key paths must not be symlinks')
    if require_key:
        key = public.read_text().strip()
        if not re.fullmatch(r'(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+(?: [^\r\n]+)?', key):
            raise ValueError('Invalid SSH public key')
    return result


validate_azure_config = validate_config


def resource_ids(config):
    prefix = (f"/subscriptions/{config['azure_subscription_id']}/resourceGroups/"
              f"{config['azure_resource_group']}/providers/")
    name = f"c2itall-{config['deployment_id']}"
    kinds = [
        ('vnet', 'Microsoft.Network/virtualNetworks', 'vnet'),
        ('nsg', 'Microsoft.Network/networkSecurityGroups', 'nsg'),
        ('public_ip', 'Microsoft.Network/publicIPAddresses', 'ip'),
        ('nic', 'Microsoft.Network/networkInterfaces', 'nic'),
        ('vm', 'Microsoft.Compute/virtualMachines', 'vm'),
        ('os_disk', 'Microsoft.Compute/disks', 'osdisk')]
    if config.get('azure_edge'):
        kinds.append(('edge', 'Microsoft.Cdn/profiles', 'edge'))
    lab = config.get('azure_lab')
    if lab:
        # The VNet is the lab's; a private member has no public address.
        kinds = [item for item in kinds
                 if item[0] != 'vnet' and (item[0] != 'public_ip' or lab['public_ip'])]
    return {key: prefix + kind + '/' + name + '-' + suffix for key, kind, suffix in kinds}


_STORE = StateStore(validate=lambda state: validate_config(state, require_key=False),
                    planned_ids=resource_ids, label='Azure')


def _state_path(deployment_id, state_dir=None):
    return _STORE.path(deployment_id, state_dir or STATE_DIR)


def save_state(state, state_dir=None):
    _STORE.save(state, state_dir or STATE_DIR)


def load_state(deployment_id, state_dir=None):
    return _STORE.load(deployment_id, state_dir or STATE_DIR)


def list_states(state_dir=None):
    return _STORE.list(state_dir or STATE_DIR)


def prepare_state(config):
    validated = validate_config(config, require_key=False)
    directory = config.get('azure_state_dir')
    with lifecycle_lock(dict(validated, azure_state_dir=directory)):
        return _STORE.prepare(validated, directory or STATE_DIR)


def prepare_ssh_key(config):
    """Keep the existing key helper behind an isolated, bounded child process."""
    normalized = validate_config(config, require_key=False)
    with lifecycle_lock(dict(normalized, azure_state_dir=config.get('azure_state_dir'))):
        state = prepare_state(config)
        if not state['ssh_key_generated']:
            return state['ssh_private_key_path']
        with secure_directory(Path(state['ssh_private_key_path']).parent, create=True):
            pass
        code = ('import sys; from utils.ssh_utils import generate_ssh_key; '
                'sys.exit(0 if generate_ssh_key(sys.argv[1]) else 1)')
        run_command([sys.executable, '-c', code, state['deployment_id']],
                    timeout=60, deadline=config.get('azure_deadline'))
        return state['ssh_private_key_path']


def ownership_tags(state):
    return {'c2itall-deployment': state['deployment_id'], 'c2itall-owner': state['ownership_marker']}


def validate_ownership(state, group, resources):
    expected_group = f"/subscriptions/{state['azure_subscription_id']}/resourceGroups/{state['azure_resource_group']}"
    tags = ownership_tags(state)
    if not group or group.get('id', '').lower() != expected_group.lower() or any((group.get('tags') or {}).get(k) != v for k, v in tags.items()):
        raise ValueError('Refusing foreign resource group or subscription')
    expected = {v.lower() for v in state['planned_resource_ids'].values()}
    edge = (state['planned_resource_ids'].get('edge') or '').lower()
    for resource in resources:
        rid = resource.get('id', '').lower()
        if edge and rid.startswith(edge + '/'):
            # Endpoints, origin groups and routes live under the owned profile.
            continue
        if rid not in expected:
            raise ValueError(f'Refusing unexpected resource: {rid}')
        # The managed disk created implicitly by Compute may not inherit VM tags.
        disk = rid == state['planned_resource_ids']['os_disk'].lower()
        owner = (resource.get('managedBy') or '').lower()
        owned_disk = disk and owner == state['planned_resource_ids']['vm'].lower()
        # Deletion can detach the disk before it removes it. Retain prior proof,
        # including its immutable disk uniqueId, so a same-name replacement fails.
        proof = state.get('verified_disk', {})
        if disk and not owner and state.get('deletion_started') and proof:
            owned_disk = (proof.get('id', '').lower() == rid and
                          bool(proof.get('uniqueId')) and
                          proof['uniqueId'] == resource.get('uniqueId'))
        if not owned_disk and any((resource.get('tags') or {}).get(k) != v for k, v in tags.items()):
            raise ValueError(f'Refusing unowned resource: {rid}')


def render_template(config):
    from jinja2 import Environment, FileSystemLoader, StrictUndefined
    normalized = validate_config(config)
    image = normalized.get('azure_image') or DEFAULT_IMAGE
    lab = normalized.get('azure_lab')
    context = dict(normalized, azure_edge=normalized.get('azure_edge'), azure_lab=lab,
                   azure_public_ip=not lab or lab['public_ip'],
                   names={k: v.rsplit('/', 1)[1] for k, v in resource_ids(normalized).items()},
                   ssh_public_key=Path(normalized['ssh_key_path']).read_text().strip(),
                   image_reference={k: image[k] for k in ('publisher', 'offer', 'sku', 'version')},
                   image_plan=({'name': image['sku'], 'product': image['offer'],
                                'publisher': image['publisher']} if image['plan'] else None),
                   tags=ownership_tags(config) if config.get('ownership_marker') else
                   {'c2itall-deployment': normalized['deployment_id'], 'c2itall-owner': 'validation-only'})
    env = Environment(loader=FileSystemLoader(ROOT / 'providers/Azure/templates'), undefined=StrictUndefined)
    return json.loads(env.get_template('infrastructure.json.j2').render(**context))


def _resources(state, deadline):
    sub = state['azure_subscription_id']
    resources = run_az(['resource', 'list', '--resource-group', state['azure_resource_group']], sub, deadline)
    for resource in resources:
        if resource.get('id', '').lower() == state['planned_resource_ids']['os_disk'].lower():
            disk = run_az(['disk', 'show', '--ids', resource['id']], sub, deadline)
            resource.update(disk)
    return resources


def _group(state, deadline):
    args = ['--name', state['azure_resource_group']]
    sub = state['azure_subscription_id']
    if not run_az(['group', 'exists', *args], sub, deadline):
        return None
    try:
        return run_az(['group', 'show', *args], sub, deadline)
    except RuntimeError:
        # Deletion may complete between the existence check and detail request.
        if not run_az(['group', 'exists', *args], sub, deadline):
            return None
        raise


def _wait_deployment(state, deadline, cancel=False):
    sub = state['azure_subscription_id']
    args = ['--resource-group', state['azure_resource_group'], '--name', state['deployment_id']]
    deployments = run_az(['deployment', 'group', 'list', '--resource-group', state['azure_resource_group']], sub, deadline)
    current = next((d for d in deployments if d['name'] == state['deployment_id']), None)
    if not current:
        if cancel:
            return
        raise RuntimeError('ARM deployment missing after submission')
    terminal = {'Succeeded', 'Failed', 'Canceled'}
    if cancel and current['properties']['provisioningState'] not in terminal:
        run_az(['deployment', 'group', 'cancel', *args], sub, deadline)
    while True:
        current = run_az(['deployment', 'group', 'show', *args], sub, deadline)
        status = current['properties']['provisioningState']
        if status in terminal:
            if not cancel and status != 'Succeeded':
                raise RuntimeError(f'ARM deployment ended with {status}: {current["properties"].get("error")}')
            return current
        if time.monotonic() >= deadline:
            raise TimeoutError('ARM deployment deadline exceeded')
        time.sleep(min(5, max(0, deadline - time.monotonic())))


def _wait_for_ssh(state, deadline):
    """Return only after the provisioned VM accepts the deployment key."""
    try:
        address = ipv4(vm_address(state), private_ok=bool(state.get('azure_lab')))
    except ValueError as exc:
        raise RuntimeError('ARM deployment returned an invalid address') from exc
    private_key = Path(state['ssh_private_key_path'])
    if (not private_key.is_file() or private_key.is_symlink()
            or private_key.stat().st_uid != os.getuid()):
        raise RuntimeError('Azure SSH private key is unavailable')
    with tempfile.TemporaryDirectory(prefix='c2itall-azure-ssh-') as temporary:
        known_hosts = Path(temporary) / 'known_hosts'
        command = ['ssh', *ssh_options(known_hosts, private_key, state.get('ssh_proxy')),
                   'azureuser@' + str(address), 'true']
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError('Azure SSH readiness deadline exceeded')
            try:
                result = run_command(command, timeout=15, deadline=deadline,
                                     check=False)
            except subprocess.TimeoutExpired:
                result = None
            if result is not None and result.returncode == 0:
                return
            time.sleep(min(5, max(0, deadline - time.monotonic())))


def vm_address(state):
    """Where the controller reaches the VM: its public address, or the private one inside a lab."""
    outputs = state.get('outputs') or {}
    return (outputs.get('public_ip') or outputs.get('private_ip') or {}).get('value', '')


def _lab_identity(lab, subscription_id, group):
    return {'azure_subscription_id': subscription_id, 'azure_resource_group': group,
            'deployment_id': 'lab-' + lab['name'], 'ownership_marker': lab['ownership_marker']}


def create_lab_network(lab, config):
    """The lab's shared VNet with NAT egress and flow logs; re-runnable until it exists."""
    from jinja2 import Environment, FileSystemLoader, StrictUndefined
    sub = str(uuid.UUID(config['azure_subscription_id']))
    location = config.get('azure_location', 'eastus')
    identity = _lab_identity(lab, sub, 'c2itall-lab-' + lab['name'])
    group = identity['azure_resource_group']
    deadline = time.monotonic() + 1200
    with lifecycle_lock(dict(identity, azure_state_dir=config.get('azure_state_dir'))):
        tags = ownership_tags(identity)
        existing = _group(identity, deadline)
        if existing:
            if any((existing.get('tags') or {}).get(k) != v for k, v in tags.items()):
                raise ValueError('Refusing foreign resource group ' + group)
        else:
            run_az(['group', 'create', '--name', group, '--location', location, '--tags',
                    *(k + '=' + v for k, v in tags.items())], sub, deadline)
        block = ipaddress.ip_network(lab['blocks']['azure'])
        storage = ('c2lab' + re.sub(r'[^a-z0-9]', '', lab['name'])
                   + hashlib.sha256((sub + lab['name']).encode()).hexdigest()[:8])[:24]
        env = Environment(loader=FileSystemLoader(ROOT / 'providers/Azure/templates'),
                          undefined=StrictUndefined)
        template = env.get_template('lab_network.json.j2').render(
            name=identity['deployment_id'], location=location, tags=tags, cidr=str(block),
            subnet_cidr=str(next(block.subnets(new_prefix=24))), storage_account=storage)
        with tempfile.TemporaryDirectory(prefix='c2itall-azure-lab-') as temporary:
            path = Path(temporary) / 'lab_network.json'
            path.write_text(json.dumps(json.loads(template)))
            path.chmod(0o600)
            run_az(['deployment', 'group', 'create', '--resource-group', group,
                    '--name', identity['deployment_id'], '--template-file', str(path),
                    '--mode', 'Incremental', '--no-wait'], sub, deadline)
            outputs = _wait_deployment(identity, deadline)['properties']['outputs']
        network = {key: outputs[key]['value']
                   for key in ('vnet_id', 'subnet_id', 'nat_ip', 'storage_account_id')}
        flow = identity['deployment_id'] + '-flow'
        run_az(['network', 'watcher', 'configure', '--locations', location, '--enabled', 'true',
                '--resource-group', 'NetworkWatcherRG'], sub, deadline, timeout=120)
        run_az(['network', 'watcher', 'flow-log', 'create', '--location', location,
                '--resource-group', group, '--name', flow, '--vnet', network['vnet_id'],
                '--storage-account', network['storage_account_id'], '--enabled', 'true',
                '--retention', '7'], sub, deadline, timeout=300)
        return dict(network, subscription_id=sub, resource_group=group, location=location,
                    flow_log=flow, storage_account=storage)


def delete_lab_network(lab, network):
    """Remove the flow log and the lab's resource group once no NIC uses the subnet."""
    sub = str(uuid.UUID(network['subscription_id']))
    identity = _lab_identity(lab, sub, network['resource_group'])
    deadline = time.monotonic() + 900
    with lifecycle_lock(identity):
        group = _group(identity, deadline)
        if group is None:
            return True
        tags = ownership_tags(identity)
        if any((group.get('tags') or {}).get(k) != v for k, v in tags.items()):
            raise ValueError('Refusing foreign resource group ' + network['resource_group'])
        if run_az(['network', 'vnet', 'subnet', 'show', '--ids', network['subnet_id'],
                   '--query', 'ipConfigurations'], sub, deadline):
            raise RuntimeError('Lab subnet still has network interfaces; tear down the members first')
        if run_az(['network', 'watcher', 'flow-log', 'list', '--location', network['location'],
                   '--query', "[?name=='" + network['flow_log'] + "'].name"], sub, deadline):
            run_az(['network', 'watcher', 'flow-log', 'delete', '--location', network['location'],
                    '--name', network['flow_log']], sub, deadline, timeout=300)
        run_az(['group', 'delete', '--name', network['resource_group'], '--yes', '--no-wait'],
               sub, deadline)
        while _group(identity, deadline) is not None:
            if time.monotonic() >= deadline:
                raise TimeoutError('Lab resource group deletion deadline exceeded')
            time.sleep(min(5, max(0, deadline - time.monotonic())))
        return True


def health_azure(config):
    """Read owned VM provisioning/power state without starting or modifying it."""
    state = load_state(config['deployment_id'], config.get('azure_state_dir'))
    for key in ('azure_subscription_id', 'azure_resource_group', 'ownership_marker'):
        if key in config and config[key] != state[key]:
            raise ValueError('Health-check identity does not match saved state')
    deadline = min(config.get('azure_deadline', float('inf')), time.monotonic() + 60)
    group = _group(state, deadline)
    if group is None:
        return {'healthy': False, 'detail': 'Resource group is absent'}
    resources = _resources(state, deadline)
    validate_ownership(state, group, resources)
    vm_id = state['planned_resource_ids']['vm']
    if not any(resource.get('id', '').lower() == vm_id.lower() for resource in resources):
        return {'healthy': False, 'detail': 'VM is absent'}
    view = run_az(['vm', 'get-instance-view', '--ids', vm_id,
                   '--query', '{id:id,statuses:instanceView.statuses}'],
                  state['azure_subscription_id'], deadline)
    if view.get('id', '').lower() != vm_id.lower():
        raise ValueError('Health response does not match the owned VM')
    statuses = {item.get('code', '').lower() for item in (view.get('statuses') or [])}
    powers = {value.split('/', 1)[1] for value in statuses if value.startswith('powerstate/')}
    provisions = {value.split('/', 1)[1] for value in statuses if value.startswith('provisioningstate/')}
    power = next(iter(powers)) if len(powers) == 1 else 'unknown'
    provisioning = next(iter(provisions)) if len(provisions) == 1 else 'unknown'
    return {'healthy': power == 'running' and provisioning == 'succeeded',
            'power_state': power, 'provisioning_state': provisioning,
            'detail': f'VM {power}; provisioning {provisioning}'}


def deploy_azure(config):
    try:
        normalized = validate_config(config, require_key=False)
        with lifecycle_lock(dict(normalized, azure_state_dir=config.get('azure_state_dir'))):
            return _deploy_azure_locked(config)
    except (Exception, KeyboardInterrupt) as exc:
        logging.error('Azure deployment unavailable: %s', exc)
        return False


def _deploy_azure_locked(config):
    """Persist intent, submit through shared Ansible execution, then observe ARM."""
    from utils.deployment_engine import execute_playbook
    state = None
    directory = config.get('azure_state_dir')
    deadline = config.get('azure_deadline', time.monotonic() + 1800)
    try:
        with interruption_handlers():
            validate_config(config)
            state = prepare_state(config)
            group = _group(state, deadline)
            if group:
                validate_ownership(state, group, _resources(state, deadline))
            state['status'] = 'provisioning'
            save_state(state, directory)
            runtime = dict(state, azure_deadline=deadline, azure_state_dir=directory)
            # Repeat the ownership check while holding both locks immediately
            # before the playbook can create/update the group.
            group = _group(state, deadline)
            if group:
                validate_ownership(state, group, _resources(state, deadline))
            if not execute_playbook(str(ROOT / 'providers/Azure/infrastructure.yml'), runtime):
                raise RuntimeError('Azure infrastructure playbook failed')
            deployment = _wait_deployment(state, deadline)
            resources = _resources(state, deadline)
            validate_ownership(state, _group(state, deadline), resources)
            state.update(status='waiting_for_ssh',
                         actual_resource_ids=[r['id'] for r in resources],
                         outputs=deployment['properties'].get('outputs', {}))
            save_state(state, directory)
            _wait_for_ssh(state, deadline)
            state['status'] = 'ready'
            save_state(state, directory)
            return True
    except (Exception, KeyboardInterrupt) as exc:
        logging.error('Azure deployment failed: %s', exc)
        if state:
            state.update(status='failed', error=str(exc))
            save_state(state, directory)
        return False


def cleanup_azure(config):
    try:
        state = load_state(config['deployment_id'], config.get('azure_state_dir'))
        with lifecycle_lock(dict(state, azure_state_dir=config.get('azure_state_dir'))):
            return _cleanup_azure_locked(config)
    except (Exception, KeyboardInterrupt) as exc:
        logging.error('Azure cleanup unavailable; state retained: %s', exc)
        return False


def _cleanup_azure_locked(config):
    """Recover from durable intent; fail closed before any cloud deletion."""
    from utils.deployment_engine import execute_playbook
    directory = config.get('azure_state_dir')
    deadline = config.get('azure_cleanup_deadline')
    state = None
    try:
        with interruption_handlers():
            state = load_state(config['deployment_id'], directory)
            if deadline is None:
                # A Front Door profile takes minutes longer to delete than a VM.
                deadline = time.monotonic() + (1800 if state.get('azure_edge') else 600)
            for key in ('azure_subscription_id', 'azure_resource_group', 'ownership_marker'):
                if key in config and config[key] != state[key]:
                    raise ValueError(f'Cleanup {key} does not match saved state')
            group = _group(state, deadline)
            if group:
                validate_ownership(state, group, _resources(state, deadline))
                # No deletion while ARM could still be creating resources.
                _wait_deployment(state, deadline, cancel=True)
                resources = _resources(state, deadline)
                validate_ownership(state, _group(state, deadline), resources)
                for resource in resources:
                    if resource['id'].lower() == state['planned_resource_ids']['os_disk'].lower():
                        state['verified_disk'] = {'id': resource['id'], 'uniqueId': resource.get('uniqueId')}
                state['deletion_started'] = True
                state['status'] = 'deleting'
                save_state(state, directory)
                runtime = dict(state, azure_deadline=deadline, azure_state_dir=directory)
                if not execute_playbook(str(ROOT / 'providers/Azure/cleanup.yml'), runtime):
                    raise RuntimeError('Azure cleanup playbook failed')
                while _group(state, deadline) is not None:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Resource group deletion deadline exceeded')
                    time.sleep(min(5, max(0, deadline - time.monotonic())))
            # Recheck exact key ownership; never use legacy prefix/glob cleanup.
            validate_config(state, require_key=False)
            _STORE.retire(state, directory or STATE_DIR)
            return True
    except (Exception, KeyboardInterrupt) as exc:
        logging.error('Azure cleanup failed; retaining state and resource IDs: %s', exc)
        if state:
            state.update(status='cleanup_failed', error=str(exc))
            save_state(state, directory)
        return False


def gather_azure_config():
    return {
        'azure_subscription_id': input('Azure subscription ID: ').strip(),
        'azure_location': input('Azure location [eastus]: ').strip() or 'eastus',
        'azure_vm_size': input('Azure VM size [Standard_D2as_v4]: ').strip() or 'Standard_D2as_v4',
        'operator_ip': input('Operator public IPv4 (SSH /32): ').strip(),
    }
