#!/usr/bin/env python3
"""Team logging server: RedELK infrastructure without any onboarding."""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils.common import (
    COLORS, clear_screen, confirm_action, generate_deployment_id, get_public_ip,
    print_banner, wait_for_input,
)
from utils.provider_utils import gather_provider_config, prepare_module_ssh_key, select_provider


def gather_logging_parameters():
    """Collect the inputs for a RedELK server deployment."""
    clear_screen()
    print_banner()
    print(f"{COLORS['WHITE']}LOGGING SERVER SETUP (RedELK){COLORS['RESET']}")
    print(f"{COLORS['WHITE']}============================={COLORS['RESET']}")
    print("The ELK server is installed and locked to you. Redirectors and C2 servers are")
    print("onboarded by hand later with the packages left on the host.")
    config = {'deployment_id': generate_deployment_id()}
    print(f"\nDeployment ID: {COLORS['CYAN']}{config['deployment_id']}{COLORS['RESET']}")
    provider = select_provider('logging_server')
    if not provider:
        return None
    provider_config = gather_provider_config(provider, 'logging_server')
    if not provider_config:
        return None
    config.update(provider_config)
    config.update(provider=provider, provider_workload='logging_server',
                  deployment_type='logging_server',
                  logging_server_name='log-' + config['deployment_id'])
    suggested_ip = get_public_ip()
    prompt = (f"Your public IP for Kibana and SSH [detected: {suggested_ip}]: " if suggested_ip
              else "Your public IP for Kibana and SSH: ")
    config['operator_ip'] = input(prompt).strip() or suggested_ip
    sources = input("Hosts allowed to ship logs on 5044, comma separated [none yet]: ").strip()
    config['logging_ingest_sources'] = [item.strip() for item in sources.split(',') if item.strip()]
    config['logging_cert_name'] = input(
        "Name on the ELK certificate [logs.internal]: ").strip() or 'logs.internal'
    config['redelk_ref'] = input("RedELK git ref [master]: ").strip() or 'master'
    print(f"\n{COLORS['YELLOW']}RedELK needs 8 GB of memory; keep the provider's default VM size or larger.{COLORS['RESET']}")
    ready, _ = prepare_module_ssh_key(config, config['deployment_id'])
    if not ready:
        print(f"{COLORS['RED']}Failed to generate SSH key{COLORS['RESET']}")
        return None
    config['ssh_after_deploy'] = confirm_action("SSH into instance after deployment?", default=False)
    return config


def execute_logging_deployment(config):
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"Deployment ID: {config['deployment_id']}")
    print(f"Provider: {config['provider']}")
    print(f"Kibana/SSH allowed from: {config['operator_ip']}")
    print(f"Log shippers allowed: {', '.join(config['logging_ingest_sources']) or 'none yet'}")
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with logging server deployment?{COLORS['RESET']}", default=False):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return False
    from utils.deployment_engine import deploy_infrastructure
    success = deploy_infrastructure(config)
    if success:
        print(f"\n{COLORS['GREEN']}Logging server deployed.{COLORS['RESET']}")
        if config.get('ssh_after_deploy'):
            from utils.ssh_utils import ssh_to_instance
            ssh_to_instance(config)
    else:
        print(f"\n{COLORS['RED']}Logging server deployment failed.{COLORS['RESET']}")
    return success


def logging_menu():
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}LOGGING SERVER MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}==================={COLORS['RESET']}")
        print("1) Deploy RedELK Server (infrastructure only, operator-locked)")
        print("99) Return to Main Menu")
        choice = input("\nSelect an option: ").strip()
        if choice == '1':
            config = gather_logging_parameters()
            if config:
                execute_logging_deployment(config)
            wait_for_input()
        elif choice == '99':
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()


if __name__ == '__main__':
    logging_menu()
