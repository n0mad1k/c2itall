#!/usr/bin/env python3
"""
Attack Box deployment module
Deploy hardened attack boxes for initial access, manual testing, and reconnaissance
"""

import os
import sys
import logging
import glob

# Add the project root to the path so we can import utils
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils.common import (
    COLORS, clear_screen, print_banner, generate_deployment_id, 
    setup_logging, get_public_ip, confirm_action, wait_for_input,
    archive_old_logs
)
from utils.provider_utils import select_provider, gather_provider_config
from utils.ssh_utils import generate_ssh_key
from utils.name_generator import generate_attack_box_name
from utils.naming_utils import get_deployment_name_with_options, show_naming_relationship

def attack_box_menu():
    """Display the attack box deployment menu"""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}ATTACK BOX DEPLOYMENT{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}====================={COLORS['RESET']}")
        print(f"1) Deploy Quick Recon Box {COLORS['GREEN']}*FAST*{COLORS['RESET']} {COLORS['GRAY']}(Kali + Basic Tools - ~2-3 min){COLORS['RESET']}")
        print(f"2) Deploy Kali Attack Box {COLORS['GRAY']}(Full Tools & Setup - ~15-20 min){COLORS['RESET']}")
        print(f"3) Deploy Custom Ubuntu Attack Box")
        print(f"99) Return to Main Menu")
        
        choice = input(f"\nSelect an option: ")
        
        if choice == "1":
            deploy_quick_recon_box()
        elif choice == "2":
            deploy_kali_attack_box()
        elif choice == "3":
            deploy_ubuntu_attack_box()
        elif choice == "99":
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()

# Quick Recon Box now uses the regular attack box deployment with minimal settings

def gather_attack_box_parameters(attack_box_type="kali"):
    """Collect parameters specific to attack box deployments"""
    clear_screen()
    print_banner()
    print(f"{COLORS['WHITE']}ATTACK BOX SETUP - {attack_box_type.upper()}{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}{'=' * (20 + len(attack_box_type))}{COLORS['RESET']}")
    
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
    
    # Attack box specific configuration
    print(f"\n{COLORS['BLUE']}Attack Box Configuration{COLORS['RESET']}")
    
    # Set deployment type
    config['deployment_type'] = 'attack_box'
    
    # Attack box type
    config['attack_box_type'] = attack_box_type
    
    # Attack box name with common naming options
    config['attack_box_name'] = get_deployment_name_with_options(
        deployment_type='attack_box',
        deployment_id=config['deployment_id'],
        prefix='a-'
    )
    
    # Attack box image mapping
    if attack_box_type == "kali":
        config['attack_box_image'] = "linode/kali"
    elif attack_box_type == "ubuntu":
        config['attack_box_image'] = "linode/ubuntu22.04"
    else:
        config['attack_box_image'] = "linode/ubuntu22.04"  # Default fallback
    
    # Instance sizing based on attack box type
    print(f"\n{COLORS['GREEN']}Instance Size Selection:{COLORS['RESET']}")
    print(f"1) Small (2 CPU, 4GB RAM) - Basic reconnaissance")
    print(f"2) Medium (4 CPU, 8GB RAM) - Standard penetration testing")
    print(f"3) Large (8 CPU, 16GB RAM) - Heavy exploitation/cracking")
    print(f"4) XLarge (16 CPU, 32GB RAM) - Advanced research/development")
    
    size_choice = input(f"Select instance size [2]: ").strip() or "2"
    size_mapping = {
        "1": {"type": "g6-standard-2", "name": "small"},
        "2": {"type": "g6-standard-4", "name": "medium"}, 
        "3": {"type": "g6-standard-8", "name": "large"},
        "4": {"type": "g6-standard-16", "name": "xlarge"}
    }
    
    if size_choice in size_mapping:
        config['instance_size'] = size_mapping[size_choice]['name']
        if provider == "linode":
            config['linode_instance_type'] = size_mapping[size_choice]['type']
    else:
        config['instance_size'] = "medium"
        config['linode_instance_type'] = "g6-standard-4"
    
    # SSH key generation using attack box name for consistency
    ssh_key_path = generate_ssh_key(config['attack_box_name'])
    if ssh_key_path:
        config['ssh_key_path'] = ssh_key_path + ".pub"
        print(f"{COLORS['GREEN']}SSH key generated: {ssh_key_path}{COLORS['RESET']}")
    else:
        print(f"{COLORS['RED']}Failed to generate SSH key{COLORS['RESET']}")
        return None
    
    # Additional tools selection
    print(f"\n{COLORS['BLUE']}Additional Tools & Features:{COLORS['RESET']}")
    
    # Custom domain for C2 comms (optional)
    domain = input(f"Domain for attack box (optional, for C2 comms): ").strip()
    if domain:
        config['domain'] = domain
        config['setup_domain'] = True
    else:
        config['setup_domain'] = False
    
    # VPN setup
    setup_vpn = input(f"Setup VPN server on attack box? [y/N]: ").strip().lower()
    config['setup_vpn'] = setup_vpn in ['y', 'yes']
    
    # Tor setup
    setup_tor = input(f"Setup Tor proxy? [y/N]: ").strip().lower()
    config['setup_tor'] = setup_tor in ['y', 'yes']
    
    # Custom wordlists
    custom_wordlists = input(f"Download custom wordlists? [y/N]: ").strip().lower()
    config['custom_wordlists'] = custom_wordlists in ['y', 'yes']
    
    # Set operator IP for security
    config['operator_ip'] = get_public_ip()
    if config['operator_ip']:
        print(f"{COLORS['GREEN']}Detected operator IP: {config['operator_ip']}{COLORS['RESET']}")
    
    # SSH after deploy
    ssh_after = input(f"\nSSH to attack box after deployment? [Y/n]: ").strip().lower()
    config['ssh_after_deploy'] = ssh_after not in ['n', 'no']
    
    # Auto-teardown on failure option
    print(f"\n{COLORS['BLUE']}Deployment Options:{COLORS['RESET']}")
    
    # Enhanced OPSEC mode
    opsec_mode = input(f"Enable enhanced OPSEC mode? (for sensitive operations) [y/N]: ").strip().lower()
    config['enhanced_opsec'] = opsec_mode in ['y', 'yes']
    
    if config['enhanced_opsec']:
        print(f"{COLORS['YELLOW']}🔒 Enhanced OPSEC mode enabled:{COLORS['RESET']}")
        print(f"  • Working directory: /root/{config['deployment_id']} (not 'operator')")
        print(f"  • No 'trashpanda' references in files or aliases")
        print(f"  • Generic script names and comments")
        print(f"  • Minimal logging and history")
        print(f"  • No obvious pentesting tool signatures in configs")
        config['work_dir'] = f"/root/{config['deployment_id']}"
        config['tool_name'] = "toolkit"
        config['project_name'] = config['deployment_id']
    else:
        print(f"{COLORS['CYAN']}💡 Standard mode - using TrashPanda branding and structure{COLORS['RESET']}")
        config['work_dir'] = "/root/operator"
        config['tool_name'] = "trashpanda"
        config['project_name'] = "operator"
    
    # Check for global auto-teardown flag
    global_auto_teardown = os.environ.get('C2ITALL_AUTO_TEARDOWN', '').lower() == 'true'
    
    if global_auto_teardown:
        config['auto_teardown_on_fail'] = True
        print(f"{COLORS['YELLOW']}⚠️  Auto-teardown enabled globally - failed deployments will be cleaned up automatically{COLORS['RESET']}")
    else:
        auto_teardown = input(f"Auto-teardown on deployment failure? (for testing/overnight runs) [y/N]: ").strip().lower()
        config['auto_teardown_on_fail'] = auto_teardown in ['y', 'yes']
        
        if config['auto_teardown_on_fail']:
            print(f"{COLORS['YELLOW']}⚠️  Auto-teardown enabled - failed deployments will be cleaned up automatically{COLORS['RESET']}")
        else:
            print(f"{COLORS['CYAN']}💡 Failed deployments will prompt for cleanup confirmation{COLORS['RESET']}")
    
    # Set deployment type
    config['deployment_type'] = f'{attack_box_type}_attack_box'
    
    return config

def deploy_kali_attack_box():
    """Deploy Kali Linux attack box"""
    config = gather_attack_box_parameters("kali")
    if not config:
        return
    
    config['attack_box_image'] = 'linode/kali'
    config['default_user'] = 'root'
    
    print(f"\n{COLORS['GREEN']}Deploying Kali Linux attack box...{COLORS['RESET']}")
    execute_attack_box_deployment(config)

def deploy_parrot_attack_box():
    """Deploy Parrot Security attack box"""
    config = gather_attack_box_parameters("parrot")
    if not config:
        return
    
    config['attack_box_image'] = 'linode/debian11'  # Will install Parrot tools
    config['default_user'] = 'root'
    
    print(f"\n{COLORS['GREEN']}Deploying Parrot Security attack box...{COLORS['RESET']}")
    execute_attack_box_deployment(config)

def deploy_ubuntu_attack_box():
    """Deploy custom Ubuntu attack box"""
    config = gather_attack_box_parameters("ubuntu")
    if not config:
        return
    
    config['attack_box_image'] = 'linode/ubuntu22.04'
    config['default_user'] = 'root'
    
    print(f"\n{COLORS['GREEN']}Deploying Ubuntu attack box...{COLORS['RESET']}")
    execute_attack_box_deployment(config)

def deploy_quick_recon_box():
    """Deploy streamlined attack box focused on OPSEC and initial reconnaissance"""
    config = gather_quick_recon_parameters()
    if not config:
        return
    
    config['attack_box_image'] = 'linode/kali'  # Kali Linux base
    config['default_user'] = 'root'
    config['deployment_type'] = 'quick_recon_box'
    config['attack_box_type'] = 'quick_recon'
    config['quick_deployment'] = True
    config['enhanced_opsec'] = True  # Always enable OPSEC
    
    print(f"\n{COLORS['GREEN']}Deploying Quick Recon Box (minimal tools + OPSEC)...{COLORS['RESET']}")
    execute_attack_box_deployment(config)

def gather_quick_recon_parameters():
    """Collect parameters for quick recon box deployment - streamlined"""
    clear_screen()
    print_banner()
    print(f"{COLORS['WHITE']}QUICK RECON BOX SETUP{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}====================={COLORS['RESET']}")
    print(f"{COLORS['CYAN']}Minimal deployment - basic tools + Tor + optional VPN{COLORS['RESET']}")
    print(f"{COLORS['GRAY']}• Kali Linux base with core tools (nmap, nc, curl, dig, whois, tor){COLORS['RESET']}")
    print(f"{COLORS['GRAY']}• Add whatever tools you need after deployment{COLORS['RESET']}")
    print(f"{COLORS['GRAY']}• Fast deployment - under 5 minutes{COLORS['RESET']}")
    
    config = {}
    
    # Generate deployment ID
    config['deployment_id'] = generate_deployment_id()
    print(f"\nDeployment ID: {COLORS['CYAN']}{config['deployment_id']}{COLORS['RESET']}")
    
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
    
    # Quick recon specific configuration
    config['deployment_type'] = 'quick_recon_box'
    config['attack_box_type'] = 'quick_recon'
    
    # Attack box name with recon prefix
    config['attack_box_name'] = get_deployment_name_with_options(
        deployment_type='quick_recon',
        deployment_id=config['deployment_id'],
        prefix='qr-'
    )
    
    # Force small instance for speed and cost
    print(f"\n{COLORS['GREEN']}Instance: Small (2 CPU, 4GB RAM) - Optimized for recon{COLORS['RESET']}")
    config['instance_size'] = "small"
    if provider == "linode":
        config['linode_instance_type'] = "g6-standard-2"
    
    # SSH key generation
    ssh_key_path = generate_ssh_key(config['attack_box_name'])
    if ssh_key_path:
        config['ssh_key_path'] = ssh_key_path + ".pub"
        print(f"{COLORS['GREEN']}SSH key generated: {ssh_key_path}{COLORS['RESET']}")
    else:
        print(f"{COLORS['RED']}Failed to generate SSH key{COLORS['RESET']}")
        return None
    
    # Minimal OPSEC configuration
    print(f"\n{COLORS['BLUE']}Quick OPSEC Configuration:{COLORS['RESET']}")
    
    # Always enable Tor
    config['setup_tor'] = True
    print(f"✓ Tor proxy enabled (for anonymous operations)")
    
    # Optional VPN
    setup_vpn = input(f"Setup VPN server? [y/N]: ").strip().lower()
    config['setup_vpn'] = setup_vpn in ['y', 'yes']
    
    # No domain by default (keep minimal)
    config['setup_domain'] = False
    
    # Set operator IP for security
    config['operator_ip'] = get_public_ip()
    if config['operator_ip']:
        print(f"{COLORS['GREEN']}Operator IP: {config['operator_ip']}{COLORS['RESET']}")
    
    # SSH after deploy
    ssh_after = input(f"SSH after deployment? [Y/n]: ").strip().lower()
    config['ssh_after_deploy'] = ssh_after not in ['n', 'no']
    
    # Enhanced OPSEC (always enabled)
    config['enhanced_opsec'] = True
    config['work_dir'] = f"/root/{config['deployment_id']}"
    config['tool_name'] = "toolkit"
    config['project_name'] = config['deployment_id']
    
    # Auto-teardown option
    auto_teardown = input(f"Auto-teardown on failure? [y/N]: ").strip().lower()
    config['auto_teardown_on_fail'] = auto_teardown in ['y', 'yes']
    
    # Set deployment flags
    config['default_user'] = 'root'
    config['attack_box_deployment'] = True
    config['ssh_user'] = 'root'
    
    return config

def deploy_windows_attack_box():
    """Deploy Windows attack box"""
    print(f"\n{COLORS['YELLOW']}Windows attack box deployment coming soon...{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}This will include Cobalt Strike, Metasploit, and Windows-specific tools{COLORS['RESET']}")
    wait_for_input()

def deploy_multiple_attack_boxes():
    """Deploy multiple attack boxes for large engagements"""
    print(f"\n{COLORS['BLUE']}Multiple Attack Box Deployment{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}This will deploy multiple attack boxes for distributed operations{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}Coming soon...{COLORS['RESET']}")
    wait_for_input()

def execute_attack_box_deployment(config):
    """Execute attack box infrastructure deployment"""
    clear_screen()
    print_banner()
    print(f"\n{COLORS['GREEN']}Starting attack box deployment...{COLORS['RESET']}")
    
    # Set up logging (archiving is now handled globally)
    log_file = setup_logging(config['deployment_id'], "attack_box_deployment")
    
    # Display configuration summary
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"Deployment Type: {config['deployment_type']}")
    print(f"Deployment ID: {config['deployment_id']}")
    print(f"Attack Box Name: {config['attack_box_name']}")
    
    # Show naming relationship if attack box is named after another deployment
    naming_info = show_naming_relationship(
        config['attack_box_name'], 
        config['deployment_id'], 
        'attack_box'
    )
    if naming_info:
        print(f"  └─ {naming_info['relationship_text']}")
        print(f"  └─ {naming_info['purpose_text']}")
    
    print(f"Provider: {config['provider']}")
    print(f"Attack Box Type: {config['attack_box_type']}")
    print(f"Instance Size: {config['instance_size']}")
    if config.get('domain'):
        print(f"Domain: {config['domain']}")
    print(f"VPN Setup: {'Yes' if config['setup_vpn'] else 'No'}")
    print(f"Tor Setup: {'Yes' if config['setup_tor'] else 'No'}")
    
    # Show SSH key information
    if config.get('ssh_key_path'):
        ssh_key_name = os.path.basename(config['ssh_key_path']).replace('.pub', '')
        print(f"SSH Key: {ssh_key_name}")
        print(f"  └─ Use: ssh -i ~/.ssh/{ssh_key_name} root@<ip>")
    
    # Confirm deployment
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with attack box deployment?{COLORS['RESET']}", default=True):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return
    
    # Set attack box deployment flag
    config['attack_box_deployment'] = True
    
    # Execute the actual deployment using the deployment engine
    from utils.deployment_engine import deploy_infrastructure
    success = deploy_infrastructure(config)
    
    if success:
        print(f"\n{COLORS['GREEN']}Attack box deployed successfully!{COLORS['RESET']}")
        
        # Display credentials file location
        credentials_file = f"logs/deployment_info_{config['deployment_id']}.txt"
        if os.path.exists(credentials_file):
            print(f"\n{COLORS['CYAN']}📁 Credentials saved to: {credentials_file}{COLORS['RESET']}")
            print(f"{COLORS['YELLOW']}⚠️  Keep this file secure - it contains your root password!{COLORS['RESET']}")
        
        print(f"\n{COLORS['CYAN']}Next Steps:{COLORS['RESET']}")
        print(f"1. SSH to your attack box using the saved credentials")
        print(f"2. Run initial security updates")
        print(f"3. Configure VPN if enabled")
        print(f"4. Begin reconnaissance")
        
        if config.get('ssh_after_deploy'):
            from utils.ssh_utils import ssh_to_instance
            ssh_to_instance(config)
    else:
        print(f"\n{COLORS['RED']}Attack box deployment failed.{COLORS['RESET']}")
    
    wait_for_input()

if __name__ == "__main__":
    attack_box_menu()
