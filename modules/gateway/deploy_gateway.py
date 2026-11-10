#!/usr/bin/env python3
"""Lab gateway: the WireGuard hub and logged egress every lab member joins."""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils import lab as lab_mod
from utils.common import (
    COLORS, clear_screen, confirm_action, generate_deployment_id, get_public_ip,
    print_banner, wait_for_input,
)
from utils.provider_utils import gather_provider_config, select_provider


def gather_gateway_parameters(lab_name):
    """Collect the inputs for the gateway VM of one lab."""
    config = {'deployment_id': generate_deployment_id(), 'lab': lab_name}
    print(f"Deployment ID: {COLORS['CYAN']}{config['deployment_id']}{COLORS['RESET']}")
    provider = select_provider('lab_gateway')
    if not provider:
        return None
    provider_config = gather_provider_config(provider, 'lab_gateway')
    if not provider_config:
        return None
    config.update(provider_config)
    config.update(provider=provider, provider_workload='lab_gateway',
                  deployment_type='lab_gateway',
                  lab_gateway_name='gw-' + config['deployment_id'])
    if not config.get('operator_ip'):
        suggested = get_public_ip()
        config['operator_ip'] = input(
            f"Your IPv4 for SSH and WireGuard [detected: {suggested}]: ").strip() or suggested
    config['ssh_key_path'] = lab_mod.load(lab_name)['ssh_key_path']
    return config


def execute_gateway_deployment(config):
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"Deployment ID: {config['deployment_id']}")
    print(f"Lab: {config['lab']}")
    print(f"Provider: {config['provider']}")
    print(f"Operator: {config['operator_ip']} (SSH and WireGuard peer)")
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with gateway deployment?{COLORS['RESET']}", default=False):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return False
    from utils.deployment_engine import deploy_infrastructure
    success = deploy_infrastructure(config)
    if success:
        lab = lab_mod.load(config['lab'])
        print(f"\n{COLORS['GREEN']}Lab gateway deployed.{COLORS['RESET']}")
        print(f"Hub: {lab['gateway']['public_ip']}:{lab['gateway']['port']} (lab address {lab['gateway']['lab_ip']})")
        print(f"Operator WireGuard config: {lab_mod.secret_dir(lab) / 'operator.conf'}")
        print('Bring it up with: sudo wg-quick up ' + str(lab_mod.secret_dir(lab) / 'operator.conf'))
    else:
        print(f"\n{COLORS['RED']}Lab gateway deployment failed.{COLORS['RESET']}")
    return success


def ensure_lab(name=None):
    """Return an existing lab by name, or create it after asking for the blocked networks."""
    name = name or input('Lab name [lab]: ').strip() or 'lab'
    try:
        return lab_mod.load(name)
    except FileNotFoundError:
        pass
    blocked = input('Networks the lab must never reach (comma-separated CIDRs, blank for none): ').strip()
    return lab_mod.create(name, [cidr.strip() for cidr in blocked.split(',') if cidr.strip()])


def gateway_menu():
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}LAB GATEWAY MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}================{COLORS['RESET']}")
        print("1) Deploy the lab gateway (WireGuard hub, logged NAT egress)")
        print("99) Return to Main Menu")
        choice = input("\nSelect an option: ").strip()
        if choice == '1':
            lab = ensure_lab()
            config = gather_gateway_parameters(lab['name'])
            if config:
                execute_gateway_deployment(config)
            wait_for_input()
        elif choice == '99':
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()


if __name__ == '__main__':
    gateway_menu()
