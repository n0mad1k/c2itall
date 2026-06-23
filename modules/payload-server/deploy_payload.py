#!/usr/bin/env python3
"""
Payload server infrastructure deployment module
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
from utils.provider_utils import select_provider, gather_provider_config
from utils.ssh_utils import generate_ssh_key

def gather_payload_parameters():
    """Collect parameters specific to payload server deployments"""
    clear_screen()
    print_banner()
    print(f"{COLORS['WHITE']}PAYLOAD SERVER SETUP{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}===================={COLORS['RESET']}")
    
    config = {}
    
    # Generate deployment ID
    config['deployment_id'] = generate_deployment_id()
    print(f"Deployment ID: {COLORS['CYAN']}{config['deployment_id']}{COLORS['RESET']}")
    
    # Provider selection
    provider = select_provider()
    if not provider:
        return None
    config['provider'] = provider
    
    # Get provider-specific configuration
    provider_config = gather_provider_config(provider)
    if not provider_config:
        return None
    config.update(provider_config)
    
    # Payload-specific configuration
    print(f"\n{COLORS['BLUE']}Payload Server Configuration{COLORS['RESET']}")
    
    # Domain configuration
    domain = input(f"Domain for payload server [required]: ")
    if not domain:
        print(f"{COLORS['RED']}A domain is required for payload server deployments{COLORS['RESET']}")
        return None
    config['domain'] = domain
    
    # Subdomain configuration
    config['payload_subdomain'] = input("Payload server subdomain [default: cdn]: ") or "cdn"
    
    # Payload types
    print(f"\n{COLORS['BLUE']}Payload Types to Host:{COLORS['RESET']}")
    config['host_executables'] = confirm_action("Host Windows executables?", default=True)
    config['host_scripts'] = confirm_action("Host PowerShell/Python scripts?", default=True)
    config['host_documents'] = confirm_action("Host weaponized documents?", default=False)
    config['host_mobile'] = confirm_action("Host mobile payloads (APK/IPA)?", default=False)
    
    # Security options
    print(f"\n{COLORS['BLUE']}Security Options:{COLORS['RESET']}")
    config['enable_basic_auth'] = confirm_action("Enable basic authentication?", default=True)
    config['enable_ip_filtering'] = confirm_action("Enable IP filtering?", default=True)
    config['enable_user_agent_filtering'] = confirm_action("Enable User-Agent filtering?", default=True)
    config['enable_rate_limiting'] = confirm_action("Enable rate limiting?", default=True)
    
    # Payload generation
    config['auto_generate_payloads'] = confirm_action("Auto-generate common payloads?", default=False)
    
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
    ssh_key_path = generate_ssh_key(config['deployment_id'])
    if not ssh_key_path:
        print(f"{COLORS['RED']}Failed to generate SSH key{COLORS['RESET']}")
        return None
    config['ssh_key_path'] = f"{ssh_key_path}.pub"
    
    # Post-deployment options
    config['ssh_after_deploy'] = confirm_action("SSH into instance after deployment?", default=True)
    
    return config

def payload_menu():
    """Display the payload server submenu and handle user selection"""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}PAYLOAD SERVER MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}==================={COLORS['RESET']}")
        print(f"1) Basic Payload Server {COLORS['GREEN']}*SIMPLE*{COLORS['RESET']} {COLORS['GRAY']}(Quick setup){COLORS['RESET']}")
        print(f"2) Multi-Format Payload Server {COLORS['GRAY']}(Supports multiple payload types){COLORS['RESET']}")
        print(f"3) Document Payload Server {COLORS['GRAY']}(Specialized for document payloads){COLORS['RESET']}")
        print(f"4) Mobile Payload Server {COLORS['GRAY']}(Mobile-focused payloads){COLORS['RESET']}")
        print(f"5) Secure Payload Server {COLORS['GRAY']}(Auth + filtering){COLORS['RESET']}")
        print(f"6) Payload Server with Redirector {COLORS['GRAY']}(With traffic redirection){COLORS['RESET']}")
        print(f"99) Return to Main Menu")
        
        choice = input(f"\nSelect an option: ")
        
        if choice == "1":
            deploy_basic_payload_server()
        elif choice == "2":
            deploy_multi_format_payload_server()
        elif choice == "3":
            deploy_document_payload_server()
        elif choice == "4":
            deploy_mobile_payload_server()
        elif choice == "5":
            deploy_secure_payload_server()
        elif choice == "6":
            deploy_payload_server_with_redirector()
        elif choice == "99":
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()

def deploy_basic_payload_server():
    """Deploy basic payload server"""
    config = gather_payload_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'basic_payload_server'
    config['enable_basic_auth'] = False
    config['enable_ip_filtering'] = False
    config['enable_user_agent_filtering'] = False
    
    print(f"\n{COLORS['GREEN']}Deploying basic payload server...{COLORS['RESET']}")
    execute_payload_deployment(config)

def deploy_payload_server_with_redirector():
    """Deploy payload server with redirector"""
    config = gather_payload_parameters()
    if not config:
        return
    
    # Additional redirector configuration
    config['redirector_subdomain'] = input("Redirector subdomain [default: dl]: ") or "dl"
    
    config['deployment_type'] = 'payload_server_with_redirector'
    config['deploy_redirector'] = True
    
    print(f"\n{COLORS['GREEN']}Deploying payload server with redirector...{COLORS['RESET']}")
    execute_payload_deployment(config)

def deploy_secure_payload_server():
    """Deploy secure payload server with authentication and filtering"""
    config = gather_payload_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'secure_payload_server'
    config['enable_basic_auth'] = True
    config['enable_ip_filtering'] = True
    config['enable_user_agent_filtering'] = True
    config['enable_rate_limiting'] = True
    
    # Additional security configuration
    config['auth_username'] = input("Basic auth username [default: admin]: ") or "admin"
    config['auth_password'] = input("Basic auth password [default: random]: ") or None
    
    print(f"\n{COLORS['GREEN']}Deploying secure payload server...{COLORS['RESET']}")
    execute_payload_deployment(config)

def deploy_mobile_payload_server():
    """Deploy mobile payload server"""
    config = gather_payload_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'mobile_payload_server'
    config['host_mobile'] = True
    config['host_executables'] = False
    config['host_scripts'] = False
    config['host_documents'] = False
    
    print(f"\n{COLORS['GREEN']}Deploying mobile payload server...{COLORS['RESET']}")
    execute_payload_deployment(config)

def deploy_document_payload_server():
    """Deploy document payload server"""
    config = gather_payload_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'document_payload_server'
    config['host_documents'] = True
    config['host_executables'] = False
    config['host_scripts'] = False
    config['host_mobile'] = False
    
    print(f"\n{COLORS['GREEN']}Deploying document payload server...{COLORS['RESET']}")
    execute_payload_deployment(config)

def deploy_multi_format_payload_server():
    """Deploy multi-format payload server"""
    config = gather_payload_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'multi_format_payload_server'
    config['host_executables'] = True
    config['host_scripts'] = True
    config['host_documents'] = True
    config['host_mobile'] = True
    
    print(f"\n{COLORS['GREEN']}Deploying multi-format payload server...{COLORS['RESET']}")
    execute_payload_deployment(config)

def execute_payload_deployment(config):
    """Execute payload server infrastructure deployment"""
    clear_screen()
    print_banner()
    print(f"\n{COLORS['GREEN']}Starting payload server deployment...{COLORS['RESET']}")
    
    # Set up logging
    log_file = setup_logging(config['deployment_id'], "payload_deployment")
    
    # Display configuration summary
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"Deployment Type: {config['deployment_type']}")
    print(f"Deployment ID: {config['deployment_id']}")
    print(f"Provider: {config['provider']}")
    print(f"Domain: {config['domain']}")
    print(f"Host Executables: {config.get('host_executables', False)}")
    print(f"Host Scripts: {config.get('host_scripts', False)}")
    print(f"Host Documents: {config.get('host_documents', False)}")
    print(f"Host Mobile: {config.get('host_mobile', False)}")
    
    # Confirm deployment
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with payload server deployment?{COLORS['RESET']}", default=False):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return
    
    # Execute the actual deployment
    success = execute_ansible_deployment(config)
    
    if success:
        print(f"\n{COLORS['GREEN']}Payload server infrastructure deployed successfully!{COLORS['RESET']}")
        
        if config.get('ssh_after_deploy'):
            from utils.ssh_utils import ssh_to_instance
            ssh_to_instance(config)
    else:
        print(f"\n{COLORS['RED']}Payload server infrastructure deployment failed.{COLORS['RESET']}")
    
    wait_for_input()

def execute_ansible_deployment(config):
    """Execute the Ansible deployment based on configuration"""
    import subprocess
    
    deployment_type = config.get('deployment_type')
    provider = config.get('provider')
    
    print(f"\n{COLORS['BLUE']}Executing {deployment_type} deployment on {provider}...{COLORS['RESET']}")
    
    # Use the payload server playbooks
    playbook_map = {
        'basic_payload_server': 'payload_server.yml',
        'payload_server_with_redirector': 'payload_server.yml',
        'secure_payload_server': 'payload_server.yml',
        'mobile_payload_server': 'payload_server.yml',
        'document_payload_server': 'payload_server.yml',
        'multi_format_payload_server': 'payload_server.yml'
    }
    
    playbook = playbook_map.get(deployment_type)
    if not playbook:
        print(f"{COLORS['RED']}Unknown deployment type: {deployment_type}{COLORS['RESET']}")
        return False
    
    # Change to the module directory and execute the playbook
    module_dir = os.path.dirname(__file__)
    playbook_path = os.path.join(module_dir, playbook)
    
    if not os.path.exists(playbook_path):
        print(f"{COLORS['YELLOW']}Playbook not found: {playbook_path}{COLORS['RESET']}")
        print(f"{COLORS['YELLOW']}This would normally execute the {playbook} playbook{COLORS['RESET']}")
        return True  # Simulate success for now
    
    try:
        # Build the ansible-playbook command
        cmd = [
            'ansible-playbook',
            playbook_path,
            '-e', f'deployment_id={config["deployment_id"]}',
            '-e', f'provider={config["provider"]}',
            '-e', f'domain={config["domain"]}',
            '-e', f'deployment_type={deployment_type}'
        ]
        
        # Add payload-specific variables
        for key in ['host_executables', 'host_scripts', 'host_documents', 'host_mobile']:
            if key in config:
                cmd.extend(['-e', f'{key}={str(config[key]).lower()}'])
        
        # Add security options
        for key in ['enable_basic_auth', 'enable_ip_filtering', 'enable_user_agent_filtering', 'enable_rate_limiting']:
            if key in config:
                cmd.extend(['-e', f'{key}={str(config[key]).lower()}'])
        
        # Add provider-specific variables
        if provider == 'aws':
            if config.get('aws_access_key'):
                cmd.extend(['-e', f'aws_access_key={config["aws_access_key"]}'])
            if config.get('aws_secret_key'):
                cmd.extend(['-e', f'aws_secret_key={config["aws_secret_key"]}'])
            if config.get('aws_region'):
                cmd.extend(['-e', f'aws_region={config["aws_region"]}'])
        
        # Execute the playbook
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"{COLORS['GREEN']}Ansible playbook executed successfully{COLORS['RESET']}")
            return True
        else:
            print(f"{COLORS['RED']}Ansible playbook failed:{COLORS['RESET']}")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"{COLORS['RED']}Error executing playbook: {e}{COLORS['RESET']}")
        return False

if __name__ == "__main__":
    payload_menu()
