#!/usr/bin/env python3
"""
Redirector infrastructure deployment module
"""

import os
import sys
import logging

# Add the project root to the path so we can import utils
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils.common import (
    COLORS, clear_screen, print_banner, generate_deployment_id, 
    setup_logging, get_public_ip, confirm_action, wait_for_input
)
from utils.provider_utils import (
    select_provider, gather_provider_config, prepare_module_ssh_key,
)

def gather_redirector_parameters():
    """Collect parameters specific to redirector deployments"""
    clear_screen()
    print_banner()
    print(f"{COLORS['WHITE']}REDIRECTOR INFRASTRUCTURE SETUP{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}================================{COLORS['RESET']}")
    
    config = {}
    
    # Generate deployment ID
    config['deployment_id'] = generate_deployment_id()
    print(f"Deployment ID: {COLORS['CYAN']}{config['deployment_id']}{COLORS['RESET']}")
    
    # Provider selection
    provider = select_provider('redirector', legacy_fallback=True)
    if not provider:
        return None
    config['provider'] = provider
    
    # Get provider-specific configuration
    provider_config = gather_provider_config(
        provider, 'redirector', legacy_fallback=True)
    if not provider_config:
        return None
    config.update(provider_config)
    config['provider_workload'] = 'redirector'
    
    # Redirector-specific configuration
    print(f"\n{COLORS['BLUE']}Redirector Configuration{COLORS['RESET']}")
    
    # Domain configuration
    domain = input(f"Domain for redirector [required]: ")
    if not domain:
        print(f"{COLORS['RED']}A domain is required for redirector deployments{COLORS['RESET']}")
        return None
    config['domain'] = domain
    
    # Subdomain configuration
    config['redirector_subdomain'] = input("Redirector subdomain [default: cdn]: ") or "cdn"
    
    # Backend configuration
    backend_type = input("Backend type (c2/phishing/payload) [default: c2]: ") or "c2"
    config['backend_type'] = backend_type
    
    if backend_type in ['c2', 'phishing']:
        backend_ip = input(f"Backend {backend_type} server IP [required]: ")
        if not backend_ip:
            print(f"{COLORS['RED']}Backend server IP is required{COLORS['RESET']}")
            return None
        config['backend_ip'] = backend_ip
    
    # Every redirector is the nginx HTTPS proxy the provider plays configure.
    config['redirector_type'] = 'https'
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
    
    # Post-deployment options
    config['ssh_after_deploy'] = confirm_action("SSH into instance after deployment?", default=True)
    
    return config

def redirector_menu():
    """Display the redirector submenu and handle user selection"""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}REDIRECTOR INFRASTRUCTURE MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}==============================={COLORS['RESET']}")
        print(f"1) C2 Redirector {COLORS['GREEN']}*COMMON*{COLORS['RESET']} {COLORS['GRAY']}(C2 traffic redirection){COLORS['RESET']}")
        print(f"2) HTTPS Redirector {COLORS['GRAY']}(Web traffic redirection){COLORS['RESET']}")
        print(f"3) Payload Redirector {COLORS['GRAY']}(Payload delivery redirection){COLORS['RESET']}")
        print(f"4) Phishing Redirector {COLORS['GRAY']}(Phishing traffic redirection){COLORS['RESET']}")
        print(f"99) Return to Main Menu")
        
        choice = input(f"\nSelect an option: ")
        
        if choice == "1":
            deploy_c2_redirector()
        elif choice == "2":
            deploy_https_redirector()
        elif choice == "3":
            deploy_payload_redirector()
        elif choice == "4":
            deploy_phishing_redirector()
        elif choice == "99":
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()

def deploy_https_redirector():
    """Deploy HTTPS redirector"""
    config = gather_redirector_parameters()
    if not config:
        return
    
    config['redirector_type'] = 'https'
    config['deployment_type'] = 'https_redirector'
    
    print(f"\n{COLORS['GREEN']}Deploying HTTPS redirector...{COLORS['RESET']}")
    execute_redirector_deployment(config)

def deploy_payload_redirector():
    """Deploy payload redirector"""
    config = gather_redirector_parameters()
    if not config:
        return
    
    config['backend_type'] = 'payload'
    config['deployment_type'] = 'payload_redirector'
    
    print(f"\n{COLORS['GREEN']}Deploying payload redirector...{COLORS['RESET']}")
    execute_redirector_deployment(config)

def deploy_phishing_redirector():
    """Deploy phishing redirector"""
    config = gather_redirector_parameters()
    if not config:
        return
    
    config['backend_type'] = 'phishing'
    config['deployment_type'] = 'phishing_redirector'
    
    print(f"\n{COLORS['GREEN']}Deploying phishing redirector...{COLORS['RESET']}")
    execute_redirector_deployment(config)

def deploy_c2_redirector():
    """Deploy C2 redirector"""
    config = gather_redirector_parameters()
    if not config:
        return
    
    config['backend_type'] = 'c2'
    config['deployment_type'] = 'c2_redirector'
    
    print(f"\n{COLORS['GREEN']}Deploying C2 redirector...{COLORS['RESET']}")
    execute_redirector_deployment(config)

def execute_redirector_deployment(config):
    """Execute redirector infrastructure deployment"""
    clear_screen()
    print_banner()
    print(f"\n{COLORS['GREEN']}Starting redirector deployment...{COLORS['RESET']}")
    
    # Display configuration summary
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"Deployment Type: {config['deployment_type']}")
    print(f"Deployment ID: {config['deployment_id']}")
    print(f"Provider: {config['provider']}")
    print(f"Domain: {config['domain']}")
    print(f"Redirector Type: {config['redirector_type']}")
    print(f"Backend Type: {config.get('backend_type', 'N/A')}")
    
    # Confirm deployment
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with redirector deployment?{COLORS['RESET']}", default=False):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return
    
    # Set deployment flags for redirector-only deployment
    config['redirector_only'] = True
    config['c2_only'] = False
    
    # Execute the actual deployment using the deployment engine
    from utils.deployment_engine import deploy_infrastructure
    success = deploy_infrastructure(config)
    
    if success:
        print(f"\n{COLORS['GREEN']}Redirector infrastructure deployed successfully!{COLORS['RESET']}")
        
        if config.get('ssh_after_deploy'):
            from utils.ssh_utils import ssh_to_instance
            ssh_to_instance(config)
    else:
        print(f"\n{COLORS['RED']}Redirector infrastructure deployment failed.{COLORS['RESET']}")
    
    wait_for_input()

if __name__ == "__main__":
    redirector_menu()
