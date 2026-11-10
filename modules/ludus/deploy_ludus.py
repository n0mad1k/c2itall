#!/usr/bin/env python3
"""LUDUS host: installs LUDUS on a nested-virtualization host and builds the lab's AD range."""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils import lab as lab_mod
from utils.common import COLORS, clear_screen, confirm_action, generate_deployment_id, print_banner, wait_for_input
from utils.provider_utils import gather_provider_config, prepare_module_ssh_key, select_provider


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
    ready, _ = prepare_module_ssh_key(config, config['deployment_id'])
    if not ready:
        print(f"{COLORS['RED']}Failed to prepare the SSH key{COLORS['RESET']}")
        return None
    return config


def execute_ludus_deployment(config):
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"Deployment ID: {config['deployment_id']}")
    print(f"Lab: {config['lab']}")
    print(f"Provider: {config['provider']}")
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with LUDUS host deployment?{COLORS['RESET']}", default=False):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return False
    from utils.deployment_engine import deploy_infrastructure
    success = deploy_infrastructure(config)
    if success:
        print(f"\n{COLORS['GREEN']}LUDUS host deployed at {config['ludus_host_ip']} inside lab {config['lab']}.{COLORS['RESET']}")
    else:
        print(f"\n{COLORS['RED']}LUDUS host deployment failed.{COLORS['RESET']}")
    return success


def ludus_menu():
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}LUDUS MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}=========={COLORS['RESET']}")
        print("1) Deploy a LUDUS host into a lab")
        print("99) Return to Main Menu")
        choice = input("\nSelect an option: ").strip()
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
        elif choice == '99':
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()


if __name__ == '__main__':
    ludus_menu()
