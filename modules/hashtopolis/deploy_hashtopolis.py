#!/usr/bin/env python3
"""Hashtopolis cracking coordinator."""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils.common import (
    COLORS, clear_screen, confirm_action, generate_deployment_id, get_public_ip,
    print_banner, wait_for_input,
)
from utils.provider_utils import gather_provider_config, prepare_module_ssh_key, select_provider


def gather_hashtopolis_parameters():
    """Collect the inputs for a Hashtopolis deployment."""
    clear_screen()
    print_banner()
    print(f"{COLORS['WHITE']}HASHTOPOLIS SETUP{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}================={COLORS['RESET']}")
    config = {'deployment_id': generate_deployment_id()}
    print(f"Deployment ID: {COLORS['CYAN']}{config['deployment_id']}{COLORS['RESET']}")
    provider = select_provider('hashtopolis')
    if not provider:
        return None
    provider_config = gather_provider_config(provider, 'hashtopolis')
    if not provider_config:
        return None
    config.update(provider_config)
    config.update(provider=provider, provider_workload='hashtopolis',
                  deployment_type='hashtopolis',
                  hashtopolis_name='h-' + config['deployment_id'])
    suggested_ip = get_public_ip()
    prompt = (f"Your public IP for the UI and SSH [detected: {suggested_ip}]: " if suggested_ip
              else "Your public IP for the UI and SSH: ")
    config['operator_ip'] = input(prompt).strip() or suggested_ip
    sources = input("Cracking agent public IPs, comma separated [none]: ").strip()
    config['hashtopolis_agent_sources'] = [item.strip() for item in sources.split(',') if item.strip()]
    config['hashtopolis_admin_user'] = input("Admin user [admin]: ").strip() or 'admin'
    domain = input("Public domain for a Let's Encrypt certificate [none, self-signed]: ").strip()
    config['domain'] = domain
    if domain:
        default_email = f"admin@{domain}"
        config['letsencrypt_email'] = input(
            f"Email for Let's Encrypt [default: {default_email}]: ").strip() or default_email
    ready, _ = prepare_module_ssh_key(config, config['deployment_id'])
    if not ready:
        print(f"{COLORS['RED']}Failed to generate SSH key{COLORS['RESET']}")
        return None
    config['ssh_after_deploy'] = confirm_action("SSH into instance after deployment?", default=False)
    return config


def execute_hashtopolis_deployment(config):
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"Deployment ID: {config['deployment_id']}")
    print(f"Provider: {config['provider']}")
    print(f"UI/SSH allowed from: {config['operator_ip']}")
    print(f"Agents allowed: {', '.join(config['hashtopolis_agent_sources']) or 'none'}")
    certificate = "Let's Encrypt for " + config['domain'] if config.get('domain') else 'self-signed'
    print(f"Certificate: {certificate}")
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with Hashtopolis deployment?{COLORS['RESET']}", default=False):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return False
    from utils.deployment_engine import deploy_infrastructure
    success = deploy_infrastructure(config)
    if success:
        print(f"\n{COLORS['GREEN']}Hashtopolis deployed.{COLORS['RESET']}")
        if config.get('ssh_after_deploy'):
            from utils.ssh_utils import ssh_to_instance
            ssh_to_instance(config)
    else:
        print(f"\n{COLORS['RED']}Hashtopolis deployment failed.{COLORS['RESET']}")
    return success


def hashtopolis_menu():
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}HASHTOPOLIS MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}================{COLORS['RESET']}")
        print("1) Deploy Hashtopolis Server (operator + agent allowlist)")
        print("99) Return to Main Menu")
        choice = input("\nSelect an option: ").strip()
        if choice == '1':
            config = gather_hashtopolis_parameters()
            if config:
                execute_hashtopolis_deployment(config)
            wait_for_input()
        elif choice == '99':
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()


if __name__ == '__main__':
    hashtopolis_menu()
