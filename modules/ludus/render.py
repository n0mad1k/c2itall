"""Pure-Python LUDUS range rendering: merge identities, weaknesses and lab context
into the range config LUDUS consumes. No ansible or utils.lab imports here so it
stays independently unit-testable.
"""

import copy
import ipaddress
from pathlib import Path

import yaml

MODULE_DIR = Path(__file__).resolve().parent
BUILTIN_GROUPS = frozenset({'Backup Operators', 'Protected Users', 'Domain Admins'})
WEAKNESS_ROLES = frozenset({'lab_ad_seed', 'lab_host'})


def load_identities(path=None):
    """Load and validate identities.yml: unique sams, known group/weakness references."""
    data = yaml.safe_load(Path(path or MODULE_DIR / 'identities.yml').read_text())
    sams = [user['sam'] for user in data['users']]
    if len(sams) != len(set(sams)):
        raise ValueError('identities.yml has duplicate sAMAccountNames')
    known_sams = set(sams)
    known_groups = set(data.get('groups') or {}) | BUILTIN_GROUPS
    for user in data['users']:
        unknown = set(user.get('groups') or ()) - known_groups
        if unknown:
            raise ValueError('Unknown group(s) for ' + user['sam'] + ': ' + ', '.join(sorted(unknown)))
    for entry in data.get('protect') or ():
        if entry != 'domain_admin' and entry not in known_sams:
            raise ValueError('protect references an unknown user: ' + str(entry))
    for key, weakness in (data.get('weaknesses') or {}).items():
        if weakness.get('role') not in WEAKNESS_ROLES:
            raise ValueError(key + ' names an unknown weakness role: ' + str(weakness.get('role')))
        user = weakness.get('user')
        if user is not None and user not in known_sams:
            raise ValueError(key + ' references an unknown user: ' + str(user))
    for shares in (data.get('shares') or {}).values():
        for share in shares:
            if share.get('group') and share['group'] not in known_groups:
                raise ValueError('share ' + share['name'] + ' references an unknown group: ' + share['group'])
    return data


def reserved_ranges(cidrs):
    """Second octet of every 10.x.x.x/x CIDR: the range numbers already in use."""
    reserved = set()
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        octets = str(network.network_address).split('.')
        if octets[0] == '10':
            reserved.add(int(octets[1]))
    return sorted(reserved)


def _member_ip(lab_vars, workload):
    for entry in (lab_vars.get('members') or {}).values():
        if entry.get('workload') == workload:
            return entry.get('lab_ip')
    return None


def render_range(name, lab_vars, identities, passwords, weaknesses, falcon, implant=None):
    """Build the full LUDUS range config dict for 'corp' or 'mini'."""
    base = yaml.safe_load((MODULE_DIR / 'ranges' / (name + '.yml')).read_text())
    vms = copy.deepcopy(base['ludus'])
    has_falcon = bool(falcon and falcon.get('installer'))
    implant_vm = None
    for vm in vms:
        roles = vm.get('roles') or []
        if not has_falcon:
            roles = [role for role in roles if role != 'lab_falcon']
        vm['roles'] = roles
    if implant:
        for vm in vms:
            if vm['vm_name'] == implant['vm']:
                vm['roles'] = list(vm.get('roles') or []) + ['lab_implant']
                vm['role_vars'] = dict(vm.get('role_vars') or {}, **implant['role_vars'])
                implant_vm = vm['vm_name']
                break
        else:
            raise ValueError('Implant target VM not found in range ' + name + ': ' + implant['vm'])

    hostnames = [vm['hostname'] for vm in vms]
    if any(len(hostname) > 15 for hostname in hostnames):
        raise ValueError('VM hostnames must be 15 characters or fewer')
    by_vlan = {}
    for vm in vms:
        by_vlan.setdefault(vm['vlan'], []).append(vm['ip_last_octet'])
    for vlan, octets in by_vlan.items():
        if len(octets) != len(set(octets)):
            raise ValueError('Duplicate ip_last_octet in VLAN ' + str(vlan))
    primary_dcs = [vm for vm in vms if (vm.get('domain') or {}).get('role') == 'primary-dc']
    if len(primary_dcs) != 1:
        raise ValueError('Exactly one VM must be domain.role: primary-dc')

    defaults = dict(
        snapshot_with_RAM=False, stale_hours=0,
        ad_domain_functional_level='Win2016', ad_forest_functional_level='Win2016',
        ad_domain_admin=passwords['ad_domain_admin'], ad_domain_admin_password=passwords['ad_domain_admin_password'],
        ad_domain_user=passwords['ad_domain_user'], ad_domain_user_password=passwords['ad_domain_user_password'],
        ad_domain_safe_mode_password=passwords['ad_domain_safe_mode_password'],
        timezone='Etc/UTC', enable_dynamic_wallpaper=False,
    )
    if any(defaults.get(key) is None for key in defaults):
        raise ValueError('Every range default must be set')
    sentinels = {'__ad_domain_user__': 'ad_domain_user',
                 '__ad_domain_user_password__': 'ad_domain_user_password'}
    for vm in vms:
        windows = vm.get('windows') or {}
        for key, value in windows.items():
            if isinstance(value, str) and value in sentinels:
                windows[key] = defaults[sentinels[value]]

    network = dict(base.get('network') or {})
    network['always_blocked_networks'] = list(lab_vars.get('blocked_cidrs') or ())

    lab_cidrs = list(lab_vars.get('cidrs') or ())
    router = dict(base.get('router') or {})
    commands = list(router.get('iptables_commands') or [])
    for cidr in lab_cidrs:
        commands.append('iptables -I FORWARD -s ' + cidr + ' -j ACCEPT')
        commands.append('iptables -I FORWARD -d ' + cidr + ' -j ACCEPT')
    router['iptables_commands'] = commands
    if not all(any(cidr in command for command in commands) for cidr in lab_cidrs):
        raise ValueError('router.iptables_commands must admit every lab CIDR')

    global_role_vars = {
        'identities': identities, 'weaknesses': sorted(weaknesses or ()),
        'user_passwords': dict(passwords.get('users') or {}),
        'domain_admin_user': defaults['ad_domain_admin'],
        'domain_user': defaults['ad_domain_user'],
        'domain_user_password': defaults['ad_domain_user_password'],
        'datasets_url': lab_vars.get('datasets_url'),
        'c2_ip': _member_ip(lab_vars, 'c2'),
        'exfil_ip': _member_ip(lab_vars, 'exfil_receiver'),
        'payload_ip': _member_ip(lab_vars, 'payload_server'),
        'falcon_cid': (falcon or {}).get('cid'),
    }

    roles_with_falcon = [vm['vm_name'] for vm in vms if 'lab_falcon' in (vm.get('roles') or ())]
    if has_falcon and not roles_with_falcon:
        raise ValueError('Falcon installer given but no VM carries the lab_falcon role')
    if not has_falcon and roles_with_falcon:
        raise ValueError('lab_falcon must be stripped from every VM without an installer')
    implant_vms = [vm['vm_name'] for vm in vms if 'lab_implant' in (vm.get('roles') or ())]
    if implant and implant_vms != [implant_vm]:
        raise ValueError('lab_implant must land on exactly the chosen VM')
    if not implant and implant_vms:
        raise ValueError('lab_implant must not be present without an implant request')

    return {'ludus': vms, 'global_role_vars': global_role_vars, 'defaults': defaults,
            'network': network, 'router': router}


def dump(range_dict):
    return yaml.safe_dump(range_dict, sort_keys=False, default_flow_style=False)
