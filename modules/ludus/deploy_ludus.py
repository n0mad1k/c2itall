#!/usr/bin/env python3
"""LUDUS host: installs LUDUS on a nested-virtualization host and builds the lab's AD range."""

import os
import secrets
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import lab as lab_mod
from utils.common import COLORS, clear_screen, confirm_action, generate_deployment_id, print_banner, wait_for_input
from utils.provider_utils import apply_provider_profile, gather_provider_config, select_provider

from render import dump, load_identities, render_range

RANGE_TIMEOUT = 6 * 3600


def _generate_password():
    # token_urlsafe mixes case and digits already; the suffix guarantees every
    # AD complexity category regardless of what randomness produced.
    return secrets.token_urlsafe(12) + 'Aa1!'


def _ensure_passwords(lab, identities):
    data = lab_mod.read_secret(lab, 'identities.json')
    if data is None:
        data = {
            'ad_domain_admin': 'rangeadmin', 'ad_domain_admin_password': _generate_password(),
            'ad_domain_user': 'ranguser', 'ad_domain_user_password': _generate_password(),
            'ad_domain_safe_mode_password': _generate_password(),
            'users': {user['sam']: _generate_password() for user in identities['users']},
        }
        lab_mod.write_secret(lab, 'identities.json', data)
    return data


def _ludus_member(lab):
    for deployment_id, entry in lab['members'].items():
        if entry.get('workload') == 'ludus_host' and entry.get('status') == 'ready':
            return deployment_id, entry
    return None, None


def _choose_weaknesses(identities):
    keys = sorted(identities['weaknesses'])
    print(f"\n{COLORS['WHITE']}Available weaknesses (comma-separated numbers, blank for none):{COLORS['RESET']}")
    for i, key in enumerate(keys, 1):
        print(f"  {i}. {key} - {identities['weaknesses'][key]['description']}")
    choice = input('Selection: ').strip()
    if not choice:
        return []
    chosen = []
    for part in choice.split(','):
        part = part.strip()
        if part.isdigit() and 1 <= int(part) <= len(keys):
            chosen.append(keys[int(part) - 1])
    return chosen


def gather_ludus_parameters(lab_name):
    """Collect the inputs for the lab's LUDUS host."""
    config = {'deployment_id': generate_deployment_id(), 'lab': lab_name}
    print(f"Deployment ID: {COLORS['CYAN']}{config['deployment_id']}{COLORS['RESET']}")
    provider = select_provider('ludus_host')
    if not provider:
        return None
    provider_config = gather_provider_config(provider, 'ludus_host')
    if not provider_config:
        return None
    config.update(provider_config)
    config.update(provider=provider, provider_workload='ludus_host',
                  deployment_type='ludus_host', ludus_name='ludus-' + config['deployment_id'])
    apply_provider_profile(config, 'instance_size', 'nested')
    config['ssh_key_path'] = lab_mod.load(lab_name)['ssh_key_path']

    lab_range = ''
    while lab_range not in ('corp', 'mini'):
        lab_range = input('Range size (corp|mini): ').strip().lower()
    config['lab_range'] = lab_range
    ram_override = input(f"Minimum host RAM in GB [blank for the {lab_range} default]: ").strip()
    if ram_override:
        config['ludus_min_ram_gb'] = int(ram_override)

    identities = load_identities()
    weaknesses = _choose_weaknesses(identities)
    config['ludus_weaknesses'] = weaknesses

    falcon_cid = input('CrowdStrike Falcon CID [blank to skip]: ').strip()
    falcon_installer = ''
    if falcon_cid:
        falcon_installer = input('Path to the Falcon Windows sensor installer: ').strip()
    config['falcon_cid'] = falcon_cid or None
    config['falcon_installer_path'] = falcon_installer or None
    return config


def execute_ludus_deployment(config):
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"Deployment ID: {config['deployment_id']}")
    print(f"Lab: {config['lab']}")
    print(f"Provider: {config['provider']}")
    print(f"Range: {config['lab_range']}")
    print(f"Weaknesses: {', '.join(config['ludus_weaknesses']) or 'none'}")
    print(f"Falcon: {'yes, CID set' if config['falcon_cid'] else 'no'}")
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with LUDUS host deployment?{COLORS['RESET']}", default=False):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return False
    from utils.deployment_engine import deploy_infrastructure
    success = deploy_infrastructure(config)
    if not success:
        print(f"\n{COLORS['RED']}LUDUS host deployment failed.{COLORS['RESET']}")
        return False
    lab = lab_mod.load(config['lab'])
    lab_mod.write_secret(lab, 'ludus.json', {
        'lab_range': config['lab_range'], 'weaknesses': config['ludus_weaknesses'],
        'falcon_cid': config['falcon_cid'], 'falcon_installer_path': config['falcon_installer_path'],
        'range_number': route_range(config['lab'], config['deployment_id']),
    })
    print(f"\n{COLORS['GREEN']}LUDUS host deployed at {config['ludus_host_ip']} inside lab {config['lab']}.{COLORS['RESET']}")
    return True


def route_range(lab_name, deployment_id):
    """Read the range number LUDUS assigned and push 10.<N>.0.0/16 to the hub and every member."""
    result = lab_mod.member_command(lab_name, deployment_id, [
        'sudo', '-n', 'sh', '-c', '. /root/.ludus-lab.env && echo "$LAB_RANGE_NUMBER"'])
    number = int(result.stdout.strip())
    lab_mod.set_range(lab_mod.load(lab_name), deployment_id, '10.{0}.0.0/16'.format(number))
    if not lab_mod.refresh(lab_name):
        print(f"{COLORS['YELLOW']}Range route not pushed to every member yet; rerun the lab refresh{COLORS['RESET']}")
    return number


def _render_for(lab_name, implant=None):
    """Build the range dict and YAML text for the lab's current settings."""
    lab = lab_mod.load(lab_name)
    deployment_id, entry = _ludus_member(lab)
    if not deployment_id:
        print(f"{COLORS['RED']}No ready LUDUS host in lab {lab_name}{COLORS['RESET']}")
        return None, None, None
    settings = lab_mod.read_secret(lab, 'ludus.json') or {}
    identities = load_identities()
    passwords = _ensure_passwords(lab, identities)
    falcon = None
    if settings.get('falcon_cid'):
        falcon = {'cid': settings['falcon_cid'], 'installer': bool(settings.get('falcon_installer_path'))}
    lab_vars = lab_mod.service_variables(lab, deployment_id)
    lab_vars['datasets_url'] = 'http://' + entry['lab_ip'] + ':8000'
    range_dict = render_range(settings.get('lab_range', 'mini'), lab_vars, identities, passwords,
                              settings.get('weaknesses') or [], falcon, implant)
    return deployment_id, range_dict, lab_name


def run_range_action(lab_name, action, implant=None, extra_variables=None):
    deployment_id, range_dict, _ = _render_for(lab_name, implant)
    if not deployment_id:
        return False
    variables = {'ludus_action': action, 'range_config_content': dump(range_dict)}
    variables.update(extra_variables or {})
    return lab_mod.run_member_playbook(lab_name, deployment_id, 'modules/ludus/range.yml',
                                       variables, 'ludus-range-' + action, RANGE_TIMEOUT)


def stage_implant(lab_name):
    vm = input('Target VM (WS01 for full-chain, else technique-isolated): ').strip()
    if not vm:
        return False
    user = input('Domain user to run the implant as: ').strip()
    url = input('Payload URL: ').strip()
    sha256 = input('Payload sha256: ').strip()
    note = ''
    while not note:
        note = input('Falcon exception note (mandatory; "none" if not applicable): ').strip()
    if not (vm and user and url and sha256):
        print(f"{COLORS['RED']}Every implant field is required{COLORS['RESET']}")
        return False
    mode = 'full-chain' if vm == 'WS01' else 'technique-isolated'
    implant = {'vm': vm, 'role_vars': {'lab_implant_user': user, 'lab_implant_payload_url': url,
                                       'lab_implant_sha256': sha256, 'lab_implant_mode': mode}}
    success = run_range_action(lab_name, 'roles', implant=implant,
                               extra_variables={'ludus_limit': vm, 'ludus_only_roles': 'lab_implant'})
    lab = lab_mod.load(lab_name)
    lab_mod.journal(lab, {'action': 'implant', 'mode': mode, 'vm': vm, 'user': user,
                          'sha256': sha256, 'falcon_exception': note})
    return success


def ludus_menu():
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}LUDUS MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}=========={COLORS['RESET']}")
        print('1) Deploy a LUDUS host into a lab')
        print('2) Range: set config and deploy')
        print('3) Range: status')
        print('4) Range: logs')
        print('5) Range: snapshot baseline')
        print('6) Range: revert baseline')
        print('7) Range: rm (destroy VMs, keep the range)')
        print('8) Stage an implant')
        print('9) Verify the range')
        print('99) Return to Main Menu')
        choice = input('\nSelect an option: ').strip()
        if choice == '1':
            name = input('Lab name [lab]: ').strip() or 'lab'
            try:
                lab_mod.load(name)
            except FileNotFoundError:
                print(f"{COLORS['RED']}No lab named {name}; deploy its gateway first{COLORS['RESET']}")
                wait_for_input()
                continue
            config = gather_ludus_parameters(name)
            if config:
                execute_ludus_deployment(config)
            wait_for_input()
        elif choice in ('2', '3', '4', '5', '6', '7', '9'):
            name = input('Lab name [lab]: ').strip() or 'lab'
            action = {'2': 'deploy', '3': 'status', '4': 'logs', '5': 'snapshot',
                      '6': 'revert', '7': 'rm', '9': 'roles'}[choice]
            extra = {'ludus_only_roles': 'lab_verify'} if choice == '9' else None
            run_range_action(name, action, extra_variables=extra)
            wait_for_input()
        elif choice == '8':
            name = input('Lab name [lab]: ').strip() or 'lab'
            stage_implant(name)
            wait_for_input()
        elif choice == '99':
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()


if __name__ == '__main__':
    ludus_menu()
