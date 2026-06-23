#!/usr/bin/env python3
"""
Phishing infrastructure deployment module
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
from utils.provider_utils import select_provider, gather_provider_config
from utils.ssh_utils import generate_ssh_key
from utils.naming_utils import get_deployment_name_with_options

def gather_phishing_parameters():
    """Collect parameters specific to phishing deployments"""
    clear_screen()
    print_banner()
    print(f"{COLORS['WHITE']}PHISHING INFRASTRUCTURE SETUP{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}=============================={COLORS['RESET']}")
    
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
    
    # Phishing-specific configuration
    print(f"\n{COLORS['BLUE']}Phishing Configuration{COLORS['RESET']}")
    
    # Domain configuration
    phishing_domain = input(f"Phishing domain (aged domain recommended) [required]: ")
    if not phishing_domain:
        print(f"{COLORS['RED']}A domain is required for phishing deployments{COLORS['RESET']}")
        return None
    
    # Set all domain variables for compatibility
    config['phishing_domain'] = phishing_domain
    config['primary_domain'] = phishing_domain  # For compatibility with existing playbooks
    config['domain'] = phishing_domain  # For compatibility
    
    # Subdomain configuration
    config['mta_hostname'] = input(f"MTA hostname [default: mail.{phishing_domain}]: ") or f"mail.{phishing_domain}"
    config['phishing_hostname'] = input(f"Phishing hostname [default: portal.{phishing_domain}]: ") or f"portal.{phishing_domain}"
    
    # Instance naming
    print(f"\n{COLORS['BLUE']}Instance Naming{COLORS['RESET']}")
    
    # MTA Front naming
    config['mta_name'] = get_deployment_name_with_options(
        deployment_type='phishing',
        component_type='MTA Front Server',
        default_suffix='mta'
    )
    
    # GoPhish server naming  
    config['gophish_name'] = get_deployment_name_with_options(
        deployment_type='phishing',
        component_type='GoPhish Server', 
        default_suffix='gophish'
    )
    
    # Phishing redirector naming
    config['phishing_redirector_name'] = get_deployment_name_with_options(
        deployment_type='phishing',
        component_type='Phishing Redirector',
        default_suffix='redirector'
    )
    
    # Phishing webserver naming
    config['phishing_webserver_name'] = get_deployment_name_with_options(
        deployment_type='phishing', 
        component_type='Phishing Webserver',
        default_suffix='webserver'
    )
    
    # MTA Authentication
    config['smtp_auth_user'] = input("SMTP auth username [default: admin]: ") or "admin"
    config['smtp_auth_pass'] = input("SMTP auth password [default: random]: ") or None
    
    # GoPhish configuration
    config['gophish_admin_port'] = input("GoPhish admin port [default: 8090]: ") or "8090"
    
    # Campaign configuration
    config['campaign_name'] = input("Campaign name [default: test-campaign]: ") or "test-campaign"
    config['sender_name'] = input("Sender display name [default: IT Support]: ") or "IT Support"
    config['sender_email'] = f"noreply@{config['phishing_domain']}"
    
    # Template selection
    print(f"\n{COLORS['BLUE']}Email Template Selection:{COLORS['RESET']}")
    print(f"1) Office 365 Login")
    print(f"2) Password Expiration")
    print(f"3) Security Alert")
    print(f"4) File Share Notification")
    print(f"5) Custom Template")
    
    template_choice = input("Select template [default: 1]: ") or "1"
    templates = {
        "1": "office365_login",
        "2": "password_expiry", 
        "3": "security_alert",
        "4": "file_share",
        "5": "custom"
    }
    config['email_template'] = templates.get(template_choice, "office365_login")
    
    # If custom template, get details
    if config['email_template'] == 'custom':
        config['custom_template_name'] = input("Custom template name: ")
        config['custom_subject'] = input("Email subject line: ")
        config['custom_sender'] = input("Sender email/name: ")
    
    # Security settings
    print(f"\n{COLORS['BLUE']}Security Settings:{COLORS['RESET']}")
    config['enable_credential_harvesting'] = confirm_action("Enable credential harvesting?", default=True)
    config['enable_attachment_tracking'] = confirm_action("Enable attachment tracking?", default=True)
    config['enable_link_tracking'] = confirm_action("Enable link click tracking?", default=True)
    
    # Email for Let's Encrypt
    default_email = f"admin@{config['phishing_domain']}"
    config['letsencrypt_email'] = input(f"Email for Let's Encrypt [default: {default_email}]: ") or default_email
    
    # Get operator IP for security
    suggested_ip = get_public_ip()
    if suggested_ip:
        operator_ip = input(f"Your public IP for admin access [detected: {suggested_ip}]: ") or suggested_ip
    else:
        operator_ip = input("Your public IP for admin access: ")
    config['operator_ip'] = operator_ip
    
    # SSH key generation
    ssh_key_path = generate_ssh_key(config['deployment_id'])
    if not ssh_key_path:
        print(f"{COLORS['RED']}Failed to generate SSH key{COLORS['RESET']}")
        return None
    config['ssh_key_path'] = f"{ssh_key_path}.pub"
    
    # Post-deployment options
    config['ssh_after_deploy'] = confirm_action("SSH into instance after deployment?", default=True)
    config['open_admin_panel'] = confirm_action("Open GoPhish admin panel after deployment?", default=True)
    
    return config

def phishing_menu():
    """Display the phishing submenu and handle user selection"""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}PHISHING INFRASTRUCTURE MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}============================{COLORS['RESET']}")
        print(f"1) Basic Phishing Setup {COLORS['GREEN']}*RECOMMENDED*{COLORS['RESET']} {COLORS['GRAY']}(MTA + GoPhish){COLORS['RESET']}")
        print(f"2) GoPhish Server Only {COLORS['GRAY']}(Campaign management only){COLORS['RESET']}")
        print(f"3) Phishing Web Server Only {COLORS['GRAY']}(Landing pages only){COLORS['RESET']}")
        print(f"4) MTA Front Server Only {COLORS['GRAY']}(Email sending only){COLORS['RESET']}")
        print(f"5) Advanced Phishing Setup {COLORS['GRAY']}(MTA + GoPhish + Redirector){COLORS['RESET']}")
        print(f"6) Phishing Redirector Only {COLORS['GRAY']}(Traffic redirection only){COLORS['RESET']}")
        print(f"7) Ephemeral MTA Setup {COLORS['GRAY']}(Temporary email infrastructure){COLORS['RESET']}")
        print(f"8) Full Phishing Infrastructure {COLORS['GRAY']}(Complete multi-tier setup){COLORS['RESET']}")
        print(f"9) FedRAMP Compliant Phishing {COLORS['GRAY']}(Compliance-focused setup){COLORS['RESET']}")
        print(f"99) Return to Main Menu")
        
        choice = input(f"\nSelect an option: ")
        
        if choice == "1":
            deploy_basic_phishing()
        elif choice == "2":
            deploy_gophish_only()
        elif choice == "3":
            deploy_phishing_webserver_only()
        elif choice == "4":
            deploy_mta_front_only()
        elif choice == "5":
            deploy_advanced_phishing()
        elif choice == "6":
            deploy_phishing_redirector_only()
        elif choice == "7":
            deploy_ephemeral_mta()
        elif choice == "8":
            deploy_full_phishing()
        elif choice == "9":
            deploy_fedramp_phishing()
        elif choice == "99":
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()

def deploy_gophish_only():
    """Deploy GoPhish server only"""
    config = gather_phishing_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'gophish_only'
    config['deploy_gophish'] = True
    
    print(f"\n{COLORS['GREEN']}Deploying GoPhish server only...{COLORS['RESET']}")
    execute_phishing_deployment(config)

def deploy_mta_front_only():
    """Deploy MTA front server only"""
    config = gather_phishing_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'mta_front_only'
    config['deploy_mta_front'] = True
    
    print(f"\n{COLORS['GREEN']}Deploying MTA front server only...{COLORS['RESET']}")
    execute_phishing_deployment(config)

def deploy_phishing_webserver_only():
    """Deploy phishing web server only"""
    config = gather_phishing_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'phishing_webserver_only'
    config['deploy_phishing_webserver'] = True
    
    print(f"\n{COLORS['GREEN']}Deploying phishing web server only...{COLORS['RESET']}")
    execute_phishing_deployment(config)

def deploy_phishing_redirector_only():
    """Deploy phishing redirector only"""
    config = gather_phishing_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'phishing_redirector_only'
    config['deploy_phishing_redirector'] = True
    
    print(f"\n{COLORS['GREEN']}Deploying phishing redirector only...{COLORS['RESET']}")
    execute_phishing_deployment(config)

def deploy_basic_phishing():
    """Deploy basic phishing setup (MTA + GoPhish)"""
    config = gather_phishing_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'basic_phishing'
    config['deploy_mta_front'] = True
    config['deploy_gophish'] = True
    
    print(f"\n{COLORS['GREEN']}Deploying basic phishing infrastructure...{COLORS['RESET']}")
    execute_phishing_deployment(config)

def deploy_advanced_phishing():
    """Deploy advanced phishing setup (MTA + GoPhish + Redirector)"""
    config = gather_phishing_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'advanced_phishing'
    config['deploy_mta_front'] = True
    config['deploy_gophish'] = True
    config['deploy_phishing_redirector'] = True
    
    print(f"\n{COLORS['GREEN']}Deploying advanced phishing infrastructure...{COLORS['RESET']}")
    execute_phishing_deployment(config)

def deploy_full_phishing():
    """Deploy full phishing infrastructure"""
    config = gather_phishing_parameters()
    if not config:
        return
    
    config['deployment_type'] = 'full_phishing'
    config['deploy_mta_front'] = True
    config['deploy_gophish'] = True
    config['deploy_phishing_redirector'] = True
    config['deploy_phishing_webserver'] = True
    config['deploy_tracker'] = True
    
    print(f"\n{COLORS['GREEN']}Deploying full phishing infrastructure...{COLORS['RESET']}")
    execute_phishing_deployment(config)

def deploy_fedramp_phishing():
    """Deploy FedRAMP compliant phishing infrastructure"""
    config = gather_phishing_parameters()
    if not config:
        return
    
    # FedRAMP specific configuration
    clear_screen()
    print_banner()
    print(f"{COLORS['WHITE']}FEDRAMP COMPLIANCE CONFIGURATION{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}==================================={COLORS['RESET']}")
    
    # Compliance requirements
    print(f"\n{COLORS['BLUE']}FedRAMP Compliance Requirements:{COLORS['RESET']}")
    print(f"• Immediate disclosure of phishing attempts")
    print(f"• Comprehensive audit logging")
    print(f"• Compliance notification requirements")
    print(f"• Mandatory log retention")
    
    # Immediate disclosure (required for FedRAMP)
    config['immediate_disclosure'] = True
    print(f"\n{COLORS['YELLOW']}Immediate disclosure is REQUIRED for FedRAMP compliance{COLORS['RESET']}")
    
    # Authorization reference for documentation
    auth_reference = input(f"Authorization reference/ticket number [optional]: ") or "Pre-authorized FedRAMP exercise"
    config['authorization_reference'] = auth_reference
    
    # Log retention period
    retention_days = input(f"Log retention period in days [default: 90]: ") or "90"
    try:
        config['log_retention_days'] = int(retention_days)
    except ValueError:
        config['log_retention_days'] = 90
    
    # Audit logging level
    print(f"\n{COLORS['BLUE']}Audit Logging Level:{COLORS['RESET']}")
    print(f"1) Basic (Login attempts, email sends)")
    print(f"2) Detailed (+ IP addresses, user agents)")
    print(f"3) Comprehensive (+ full request logs)")
    
    log_level = input(f"Select logging level [default: 3]: ") or "3"
    log_levels = {"1": "basic", "2": "detailed", "3": "comprehensive"}
    config['audit_log_level'] = log_levels.get(log_level, "comprehensive")
    
    # Compliance mode settings
    config['fedramp_mode'] = True
    config['compliance_mode'] = True
    config['deployment_type'] = 'fedramp_phishing'
    config['deploy_gophish'] = True
    config['deploy_phishing_webserver'] = True
    config['deploy_tracker'] = True
    config['enable_audit_logging'] = True
    
    # Debug options
    config['debug_mode'] = confirm_action("Enable debug mode (extra verbose Ansible output)?", default=True)
    
    print(f"\n{COLORS['GREEN']}Deploying FedRAMP compliant phishing infrastructure...{COLORS['RESET']}")
    execute_phishing_deployment(config)

def deploy_ephemeral_mta():
    """Deploy ephemeral MTA for high OPSEC phishing"""
    config = gather_phishing_parameters()
    if not config:
        return
    
    # Additional ephemeral MTA configuration
    print(f"\n{COLORS['BLUE']}Ephemeral MTA Configuration{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}Note: Ephemeral MTAs are designed for short-term use{COLORS['RESET']}")
    
    config['deployment_type'] = 'ephemeral_mta'
    config['ephemeral_mta'] = True
    config['deploy_mta_front'] = True
    
    # Auto-destruct timer
    auto_destruct = confirm_action("Enable auto-destruct timer?", default=False)
    if auto_destruct:
        hours = input("Auto-destruct after how many hours [default: 24]: ") or "24"
        config['auto_destruct_hours'] = int(hours)
    
    print(f"\n{COLORS['GREEN']}Deploying ephemeral MTA...{COLORS['RESET']}")
    execute_phishing_deployment(config)

def execute_phishing_deployment(config):
    """Execute phishing infrastructure deployment"""
    clear_screen()
    print_banner()
    print(f"\n{COLORS['GREEN']}Starting phishing deployment...{COLORS['RESET']}")
    
    # Archive old logs before starting new deployment
    print(f"Archiving old logs...")
    archive_old_logs(max_logs_to_keep=5)  # Keep last 5 deployments
    
    # Set up logging
    log_file = setup_logging(config['deployment_id'], "phishing_deployment")
    
    # Display configuration summary
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"Deployment Type: {config['deployment_type']}")
    print(f"Deployment ID: {config['deployment_id']}")
    print(f"Provider: {config['provider']}")
    print(f"Domain: {config['phishing_domain']}")
    print(f"Email Template: {config.get('email_template', 'N/A')}")
    print(f"MTA Hostname: {config.get('mta_hostname', 'N/A')}")
    if config.get('fedramp_mode'):
        print(f"FedRAMP Mode: {COLORS['YELLOW']}ENABLED{COLORS['RESET']}")
        print(f"Authorization Reference: {config.get('authorization_reference', 'N/A')}")
        print(f"Audit Level: {config.get('audit_log_level', 'N/A')}")
    
    # Confirm deployment
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with phishing deployment?{COLORS['RESET']}", default=False):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return
    
    # Mark this as a phishing deployment for the deployment engine
    config['phishing_deployment'] = True
    
    # Execute the actual deployment using component-based approach
    success = execute_component_deployment(config)
    
    if success:
        print(f"\n{COLORS['GREEN']}✅ Phishing infrastructure deployed successfully!{COLORS['RESET']}")
        
        if config.get('ssh_after_deploy'):
            from utils.ssh_utils import ssh_to_instance
            ssh_to_instance(config)
    else:
        print(f"\n{COLORS['RED']}❌ Phishing infrastructure deployment failed.{COLORS['RESET']}")
    
    wait_for_input()

def execute_component_deployment(config):
    """Execute component-based phishing deployment"""
    import subprocess
    import os
    
    print(f"\n{COLORS['BLUE']}Executing phishing deployment: {config['deployment_type']}{COLORS['RESET']}")
    
    # Provider directory mapping
    provider_dirs = {
        "aws": "AWS",
        "linode": "Linode", 
        "flokinet": "FlokiNET"
    }
    
    # Component playbook mapping
    component_playbooks = {
        'deploy_mta_front': os.path.join(os.path.dirname(__file__), 'mta_front.yml'),
        'deploy_gophish': os.path.join(os.path.dirname(__file__), '..', '..', 'providers', provider_dirs[config['provider']], 'c2.yml'),
        'deploy_phishing_redirector': os.path.join(os.path.dirname(__file__), '..', '..', 'providers', provider_dirs[config['provider']], 'redirector.yml'),
        'deploy_phishing_webserver': os.path.join(os.path.dirname(__file__), 'phishing_webserver.yml'),
    }
    
    # Build extra vars for ansible as JSON (safe for special chars)
    import json as _json
    import tempfile as _tempfile
    extra_vars_dict = {}
    for key, value in config.items():
        if isinstance(value, (str, int, bool)):
            extra_vars_dict[key] = value

    deployed_components = []

    try:
        # Deploy each enabled component
        for component, playbook_path in component_playbooks.items():
            if config.get(component, False):
                print(f"\n{COLORS['YELLOW']}Deploying {component.replace('deploy_', '')}...{COLORS['RESET']}")

                # Check if playbook exists
                if not os.path.exists(playbook_path):
                    print(f"{COLORS['RED']}Error: Playbook not found: {playbook_path}{COLORS['RESET']}")
                    continue

                # Write vars to temp file (avoids CLI exposure)
                _vars_file = _tempfile.NamedTemporaryFile(
                    mode='w', suffix='.json', prefix='phish_vars_',
                    delete=False
                )
                _json.dump(extra_vars_dict, _vars_file)
                _vars_file.close()
                os.chmod(_vars_file.name, 0o600)

                # Build ansible command
                cmd = [
                    'ansible-playbook',
                    playbook_path,
                    '--extra-vars',
                    f'@{_vars_file.name}'
                ]

                print(f"{COLORS['GRAY']}Running: ansible-playbook {os.path.basename(playbook_path)}{COLORS['RESET']}")
                
                # Execute playbook
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(__file__))

                # Clean up temp vars file
                try:
                    os.unlink(_vars_file.name)
                except OSError:
                    pass

                if result.returncode == 0:
                    print(f"{COLORS['GREEN']}✅ {component.replace('deploy_', '')} deployed successfully{COLORS['RESET']}")
                    deployed_components.append(component)
                else:
                    print(f"{COLORS['RED']}❌ {component.replace('deploy_', '')} deployment failed{COLORS['RESET']}")
                    print(f"{COLORS['RED']}STDERR: {result.stderr}{COLORS['RESET']}")
                    return False
        
        # Deploy the orchestration playbook to save state
        print(f"\n{COLORS['YELLOW']}Saving deployment state...{COLORS['RESET']}")
        orchestration_playbook = os.path.join(os.path.dirname(__file__), 'deploy_phishing_infrastructure.yml')

        _orch_vars_file = _tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', prefix='phish_orch_',
            delete=False
        )
        _json.dump(extra_vars_dict, _orch_vars_file)
        _orch_vars_file.close()
        os.chmod(_orch_vars_file.name, 0o600)

        cmd = [
            'ansible-playbook',
            orchestration_playbook,
            '--extra-vars',
            f'@{_orch_vars_file.name}'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(__file__))

        try:
            os.unlink(_orch_vars_file.name)
        except OSError:
            pass

        if result.returncode == 0:
            print(f"{COLORS['GREEN']}✅ Deployment state saved{COLORS['RESET']}")
            return True
        else:
            print(f"{COLORS['RED']}❌ Failed to save deployment state{COLORS['RESET']}")
            print(f"{COLORS['RED']}STDERR: {result.stderr}{COLORS['RESET']}")
            return False
            
    except Exception as e:
        print(f"{COLORS['RED']}Deployment error: {str(e)}{COLORS['RESET']}")
        return False

if __name__ == "__main__":
    phishing_menu()
