#!/usr/bin/env python3
"""Standalone email tracking pixel server."""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils.common import (
    COLORS, clear_screen, confirm_action, generate_deployment_id, get_public_ip,
    print_banner, wait_for_input,
)
from utils.provider_utils import gather_provider_config, prepare_module_ssh_key, select_provider


def gather_tracker_parameters():
    """Collect the inputs for a standalone tracker deployment."""
    clear_screen()
    print_banner()
    print(f"{COLORS['WHITE']}EMAIL TRACKER SETUP{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}==================={COLORS['RESET']}")
    config = {'deployment_id': generate_deployment_id()}
    print(f"Deployment ID: {COLORS['CYAN']}{config['deployment_id']}{COLORS['RESET']}")
    provider = select_provider('tracker')
    if not provider:
        return None
    provider_config = gather_provider_config(provider, 'tracker')
    if not provider_config:
        return None
    config.update(provider_config)
    config.update(provider=provider, provider_workload='tracker',
                  deployment_type='email_tracker',
                  tracker_name='t-' + config['deployment_id'])
    domain = input("Domain for the tracker [required]: ").strip()
    if not domain:
        print(f"{COLORS['RED']}A domain is required{COLORS['RESET']}")
        return None
    config['domain'] = domain
    config['tracker_subdomain'] = input("Tracker subdomain [default: track]: ").strip() or 'track'
    default_email = f"admin@{domain}"
    config['letsencrypt_email'] = input(
        f"Email for Let's Encrypt [default: {default_email}]: ").strip() or default_email
    suggested_ip = get_public_ip()
    prompt = (f"Your public IP for the dashboard [detected: {suggested_ip}]: " if suggested_ip
              else "Your public IP for the dashboard: ")
    config['operator_ip'] = input(prompt).strip() or suggested_ip
    config['zero_logs'] = confirm_action("Disable nginx access logs (zero logs)?", default=True)
    ready, _ = prepare_module_ssh_key(config, config['deployment_id'])
    if not ready:
        print(f"{COLORS['RED']}Failed to generate SSH key{COLORS['RESET']}")
        return None
    config['ssh_after_deploy'] = confirm_action("SSH into instance after deployment?", default=False)
    return config


def execute_tracker_deployment(config):
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"Deployment ID: {config['deployment_id']}")
    print(f"Provider: {config['provider']}")
    print(f"Tracker host: {config['tracker_subdomain']}.{config['domain']}")
    print(f"Dashboard allowed from: {config['operator_ip']}")
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with tracker deployment?{COLORS['RESET']}", default=False):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return False
    from utils.deployment_engine import deploy_infrastructure
    success = deploy_infrastructure(config)
    if success:
        print(f"\n{COLORS['GREEN']}Email tracker deployed.{COLORS['RESET']}")
        if config.get('ssh_after_deploy'):
            from utils.ssh_utils import ssh_to_instance
            ssh_to_instance(config)
    else:
        print(f"\n{COLORS['RED']}Email tracker deployment failed.{COLORS['RESET']}")
    return success


def tracker_menu():
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}EMAIL TRACKER MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}=================={COLORS['RESET']}")
        print("1) Deploy Email Tracker (public pixel, operator-only dashboard)")
        print("99) Return to Main Menu")
        choice = input("\nSelect an option: ").strip()
        if choice == '1':
            config = gather_tracker_parameters()
            if config:
                execute_tracker_deployment(config)
            wait_for_input()
        elif choice == '99':
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()


if __name__ == '__main__':
    tracker_menu()
