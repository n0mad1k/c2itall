#!/usr/bin/env python3
"""
C2 infrastructure deployment module
"""

import os
import sys
import logging

# Add the project root to the path so we can import utils
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils.common import (
    COLORS, clear_screen, print_banner, generate_deployment_id, 
    setup_logging, get_public_ip, confirm_action, wait_for_input,
    archive_old_logs
)
from utils.provider_utils import (
    select_provider, gather_provider_config, prepare_module_ssh_key,
)
from utils.naming_utils import get_deployment_name_with_options
from utils.workloads import load_profile

def gather_c2_parameters():
    """Collect parameters specific to C2 deployments"""
    clear_screen()
    print_banner()
    print(f"{COLORS['WHITE']}C2 INFRASTRUCTURE SETUP{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}========================{COLORS['RESET']}")
    
    config = {}
    
    # Generate deployment ID
    config['deployment_id'] = generate_deployment_id()
    print(f"Deployment ID: {COLORS['CYAN']}{config['deployment_id']}{COLORS['RESET']}")
    
    # Provider selection
    provider = select_provider('c2', legacy_fallback=True)
    if not provider:
        return None
    config['provider'] = provider
    # Every C2 route provisions one C2 host; redirectors come from their module.
    config['c2_only'] = True
    
    # Get provider-specific configuration
    provider_config = gather_provider_config(provider, 'c2', legacy_fallback=True)
    if not provider_config:
        return None
    config.update(provider_config)
    config['provider_workload'] = 'c2'
    
    # C2-specific configuration
    print(f"\n{COLORS['BLUE']}C2 Configuration{COLORS['RESET']}")
    
    # Domain configuration
    domain = input(f"Domain for C2 infrastructure [required]: ")
    if not domain:
        print(f"{COLORS['RED']}A domain is required for C2 deployments{COLORS['RESET']}")
        return None
    config['domain'] = domain
    
    # Subdomain configuration
    config['c2_subdomain'] = input("C2 server subdomain [default: mail]: ") or "mail"
    
    # Instance naming options
    config['redirector_name'] = get_deployment_name_with_options(
        deployment_type='redirector',
        deployment_id=config['deployment_id'],
        prefix='r-'
    )
    
    config['c2_name'] = get_deployment_name_with_options(
        deployment_type='c2',
        deployment_id=config['deployment_id'],
        prefix='s-'
    )
    
    # C2 Framework selection: the module profile owns the catalog
    frameworks = list(load_profile('c2').frameworks.items())
    print(f"\n{COLORS['BLUE']}C2 Framework Selection:{COLORS['RESET']}")
    for i, (_, framework) in enumerate(frameworks, 1):
        print(f"{i}) {framework['label']}")

    framework_choice = input("Select C2 framework [default: 1]: ").strip() or "1"
    selected = int(framework_choice) - 1 if framework_choice.isdigit() else -1
    config['c2_framework'] = frameworks[selected if 0 <= selected < len(frameworks) else 0][0]
    
    # Email for Let's Encrypt
    default_email = f"admin@{config['domain']}"
    config['letsencrypt_email'] = input(f"Email for Let's Encrypt [default: {default_email}]: ") or default_email
    
    # Get operator IP for security
    suggested_ip = get_public_ip()
    if suggested_ip:
        operator_ip = input(f"Your public IP for secure access [detected: {suggested_ip}]: ") or suggested_ip
    else:
        operator_ip = input("Your public IP for secure access: ")
    config['operator_ip'] = operator_ip
    
    # SSH key generation
    key_ready, _ = prepare_module_ssh_key(config, config['deployment_id'])
    if not key_ready:
        print(f"{COLORS['RED']}Failed to generate SSH key{COLORS['RESET']}")
        return None
    
    # SMTP Configuration for email services
    print(f"\n{COLORS['BLUE']}SMTP Configuration{COLORS['RESET']}")
    config['smtp_auth_user'] = input("SMTP authentication username [default: admin]: ") or "admin"
    
    import secrets
    import string
    def generate_random_password(length=16):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password
    
    default_password = generate_random_password()
    smtp_password = input(f"SMTP authentication password [default: random generated]: ")
    config['smtp_auth_pass'] = smtp_password if smtp_password else default_password
    
    print(f"{COLORS['GREEN']}SMTP Credentials:{COLORS['RESET']}")
    print(f"  Username: {config['smtp_auth_user']}")
    print(f"  Password: {config['smtp_auth_pass']}")
    print(f"{COLORS['YELLOW']}Note: These credentials will be saved in the deployment info file{COLORS['RESET']}")
    
    # Security Configuration
    print(f"\n{COLORS['BLUE']}Security Configuration{COLORS['RESET']}")
    zero_logs_choice = input("Enable zero-logs configuration? (y/n) [default: y]: ").lower()
    config['zero_logs'] = zero_logs_choice != 'n'  # Default to True unless explicitly 'n'
    
    # Post-deployment options
    config['ssh_after_deploy'] = confirm_action("SSH into instance after deployment?", default=True)
    
    return config

def c2_menu():
    """Display the C2 submenu and handle user selection"""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}C2 INFRASTRUCTURE MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}======================={COLORS['RESET']}")
        frameworks = list(load_profile('c2').frameworks.items())
        print(f"1) C2 Server Only {COLORS['GREEN']}*QUICK*{COLORS['RESET']} {COLORS['GRAY']}(Basic setup){COLORS['RESET']}")
        for i, (_, framework) in enumerate(frameworks, 2):
            print(f"{i}) {framework['label']} C2 Server")
        print(f"99) Return to Main Menu")
        
        choice = input(f"\nSelect an option: ").strip()
        
        if choice == "1":
            deploy_c2_only()
        elif choice.isdigit() and 2 <= int(choice) < len(frameworks) + 2:
            deploy_framework_c2(frameworks[int(choice) - 2][0])
        elif choice == "99":
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()

def deploy_c2_only():
    """Deploy C2 server only"""
    config = gather_c2_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'c2_only'
    
    print(f"\n{COLORS['GREEN']}Deploying C2 server only...{COLORS['RESET']}")
    execute_c2_deployment(config)

def deploy_framework_c2(framework):
    """Deploy a C2 server running one framework from the module profile"""
    config = gather_c2_parameters()
    if not config:
        return
    
    config['c2_framework'] = framework
    config['deployment_type'] = framework + '_c2'
    
    label = load_profile('c2').frameworks[framework]['label']
    print(f"\n{COLORS['GREEN']}Deploying {label} C2 server...{COLORS['RESET']}")
    execute_c2_deployment(config)

def execute_c2_deployment(config):
    """Execute C2 infrastructure deployment"""
    clear_screen()
    print_banner()
    print(f"\n{COLORS['GREEN']}Starting C2 deployment...{COLORS['RESET']}")
    
    # Archive old logs before starting new deployment
    print(f"Archiving old logs...")
    archive_old_logs(max_logs_to_keep=5)  # Keep last 5 deployments
    
    # Set up logging
    log_file = setup_logging(config['deployment_id'], "c2_deployment")
    
    # Display configuration summary
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"Deployment Type: {config['deployment_type']}")
    print(f"Deployment ID: {config['deployment_id']}")
    print(f"Provider: {config['provider']}")
    print(f"Domain: {config['domain']}")
    print(f"C2 Framework: {config['c2_framework']}")
    
    # Confirm deployment
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with C2 deployment?{COLORS['RESET']}", default=False):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return
    
    # Execute the actual deployment using the deployment engine
    from utils.deployment_engine import deploy_infrastructure
    success = deploy_infrastructure(config)
    
    if success:
        print(f"\n{COLORS['GREEN']}C2 infrastructure deployed successfully!{COLORS['RESET']}")
        
        if config.get('ssh_after_deploy'):
            from utils.ssh_utils import ssh_to_instance
            ssh_to_instance(config)
    else:
        print(f"\n{COLORS['RED']}C2 infrastructure deployment failed.{COLORS['RESET']}")
    
    wait_for_input()

if __name__ == "__main__":
    c2_menu()
