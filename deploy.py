#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import time
import yaml
import json
import random
import string
import shutil
from datetime import datetime

# Constants
PROVIDERS = ["aws", "linode", "flokinet"]
DEFAULT_REGION = {
    "aws": "us-east-1",
    "linode": "us-east",
    "flokinet": "anonymous"
}
DEFAULT_SIZE = {
    "aws": "t2.micro",
    "linode": "g6-standard-1",
    "flokinet": "standard"
}

def setup_argparse():
    """Set up and return the argument parser"""
    parser = argparse.ArgumentParser(description='Deploy Red Team infrastructure')
    
    # Provider selection
    parser.add_argument('-p', '--provider', choices=PROVIDERS, help='Provider to use for deployment')
    
    # AWS-specific arguments
    parser.add_argument('--aws-key', help='AWS access key')
    parser.add_argument('--aws-secret', help='AWS secret key')
    parser.add_argument('--aws-region', help=f'AWS region (default: random from vars.yaml)')
    
    # Linode-specific arguments
    parser.add_argument('--linode-token', help='Linode API token')
    parser.add_argument('--linode-region', help=f'Linode region (default: random from vars.yaml)')
    
    # FlokiNET-specific arguments
    parser.add_argument('--flokinet', action='store_true', help='Use FlokiNET as the provider (manual setup required)')
    parser.add_argument('--flokinet-redirector-ip', help='FlokiNET redirector IP address')
    parser.add_argument('--flokinet-c2-ip', help='FlokiNET C2 server IP address')
    
    # General arguments
    parser.add_argument('--ssh-key', help='Path to SSH private key')
    parser.add_argument('--ssh-user', help='SSH username (default: from vars.yaml or "root")')
    parser.add_argument('--size', help='Size/type of the instances')
    parser.add_argument('--region', help='Region for the instances')
    parser.add_argument('--redirector-name', help='Name for the redirector instance (default: random)')
    parser.add_argument('--c2-name', help='Name for the C2 instance (default: random)')
    parser.add_argument('--teardown', action='store_true', help='Tear down existing infrastructure')
    
    # Deployment options
    parser.add_argument('--redirector-only', action='store_true', help='Deploy only the redirector')
    parser.add_argument('--c2-only', action='store_true', help='Deploy only the C2 server')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode for verbose output')
    parser.add_argument('--domain', help='Domain name for the C2 infrastructure')
    parser.add_argument('--letsencrypt-email', help='Email for Let\'s Encrypt certificate')
    
    # OPSEC settings
    parser.add_argument('--disable-history', action='store_true', help='Disable command history on the servers')
    parser.add_argument('--secure-memory', action='store_true', help='Enable secure memory settings')
    parser.add_argument('--zero-logs', action='store_true', help='Enable zero-logs configuration')
    
    return parser.parse_args()

def load_vars_file(provider):
    """Load vars.yaml for the specified provider"""
    vars_file = f"{provider}/vars.yaml"
    if os.path.exists(vars_file):
        try:
            with open(vars_file, 'r') as f:
                vars_data = yaml.safe_load(f)
                print(f"[+] Loaded configuration from {vars_file}")
                return vars_data
        except Exception as e:
            print(f"[!] Warning: Failed to load {vars_file}: {e}")
    else:
        print(f"[!] Warning: {vars_file} not found")
    
    return {}

def load_config(args):
    """Load configuration from vars.yaml, environment variables, and arguments"""
    config = {}
    
    # Determine provider
    provider = args.provider
    if args.flokinet:
        provider = 'flokinet'
    
    if not provider:
        # Check config.yml for a saved provider
        if os.path.exists('config.yml'):
            try:
                with open('config.yml', 'r') as f:
                    saved_config = yaml.safe_load(f)
                    provider = saved_config.get('provider')
                    print(f"[+] Using saved provider from config.yml: {provider}")
            except Exception as e:
                print(f"[!] Warning: Failed to load config.yml: {e}")
    
    # If still no provider, try each vars.yaml to see which ones exist
    if not provider:
        for p in PROVIDERS:
            if os.path.exists(f"{p}/vars.yaml"):
                provider = p
                print(f"[+] Auto-detected provider from {p}/vars.yaml")
                break
    
    # If still no provider, default to 'aws'
    if not provider:
        provider = 'aws'
        print(f"[!] No provider specified, defaulting to {provider}")
    
    config['provider'] = provider
    
    # Load vars.yaml for the selected provider
    vars_data = load_vars_file(provider)
    
    # Override with environment variables and command line arguments
    if provider == 'aws':
        config['aws_key'] = args.aws_key or os.environ.get('AWS_ACCESS_KEY_ID') or vars_data.get('aws_access_key')
        config['aws_secret'] = args.aws_secret or os.environ.get('AWS_SECRET_ACCESS_KEY') or vars_data.get('aws_secret_key')
        
        # Get region choices from vars.yaml
        config['aws_region_choices'] = vars_data.get('aws_region_choices', [DEFAULT_REGION['aws']])
        
        # Set region (explicitly provided, or keep it None for random selection later)
        config['aws_region'] = args.aws_region
        
        # Load AMI map
        config['ami_map'] = vars_data.get('ami_map', {})
        
    elif provider == 'linode':
        config['linode_token'] = args.linode_token or os.environ.get('LINODE_TOKEN') or vars_data.get('linode_token')
        
        # Get region choices from vars.yaml
        config['linode_region_choices'] = vars_data.get('region_choices', [DEFAULT_REGION['linode']])
        
        # Set region (explicitly provided, or keep it None for random selection later)
        config['linode_region'] = args.linode_region
        
    elif provider == 'flokinet':
        config['flokinet_redirector_ip'] = args.flokinet_redirector_ip or vars_data.get('redirector_ip')
        config['flokinet_c2_ip'] = args.flokinet_c2_ip or vars_data.get('c2_ip')
        
        # Get region choices from vars.yaml
        config['flokinet_region_choices'] = vars_data.get('flokinet_region_choices', [DEFAULT_REGION['flokinet']])
    
    # General configuration from vars.yaml
    config['ssh_key'] = args.ssh_key or vars_data.get('ssh_key_path')
    config['ssh_user'] = args.ssh_user or vars_data.get('ssh_user', 'root')
    
    # Instance size from vars.yaml or default
    if provider == 'aws':
        config['size'] = args.size or vars_data.get('aws_instance_type', DEFAULT_SIZE['aws'])
    elif provider == 'linode':
        config['size'] = args.size or vars_data.get('plan', DEFAULT_SIZE['linode'])
    else:
        config['size'] = args.size or DEFAULT_SIZE.get(provider, 'small')
    
    # Set region to None to trigger randomization later if not explicitly provided
    config['region'] = args.region
    
    # Generate random instance names if not provided - OPSEC improvement
    rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    timestamp = int(time.time()) % 10000  # Last 4 digits of timestamp for brevity
    
    # OPSEC: Use generic names that don't indicate purpose
    config['redirector_name'] = args.redirector_name or f"srv-{rand_suffix}-{timestamp}"
    config['c2_name'] = args.c2_name or f"node-{rand_suffix}-{timestamp}"
    
    # Other flags
    config['teardown'] = args.teardown
    config['redirector_only'] = args.redirector_only
    config['c2_only'] = args.c2_only
    config['debug'] = args.debug
    
    # Domain and email
    config['domain'] = args.domain or vars_data.get('domain', 'example.com')
    config['letsencrypt_email'] = args.letsencrypt_email or vars_data.get('letsencrypt_email', 'admin@example.com')
    
    # OPSEC settings - default to enabled for better security
    config['disable_history'] = args.disable_history if args.disable_history is not None else vars_data.get('disable_history', True)
    config['secure_memory'] = args.secure_memory if args.secure_memory is not None else vars_data.get('secure_memory', True)
    config['zero_logs'] = args.zero_logs if args.zero_logs is not None else vars_data.get('zero_logs', True)
    
    # Generate random SSH key for this deployment if not specified
    if not config.get('ssh_key') and provider != 'flokinet':
        config['ssh_key'] = generate_ssh_key(rand_suffix)
    
    # GoPhish settings
    config['gophish_admin_port'] = vars_data.get('gophish_admin_port', str(random.randint(2000, 9000)))
    config['smtp_auth_user'] = vars_data.get('smtp_auth_user', f"user{random.randint(1000, 9999)}")
    
    # Generate strong random password if not specified
    if not vars_data.get('smtp_auth_pass'):
        charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>?"
        random_pass = ''.join(random.choices(charset, k=20))
        config['smtp_auth_pass'] = random_pass
    else:
        config['smtp_auth_pass'] = vars_data.get('smtp_auth_pass')
    
    # Set random SSH port for better OPSEC
    config['ssh_port'] = vars_data.get('ssh_port', random.randint(20000, 65000))
    
    return config

def select_region(config):
    """Select region randomly from choices or use explicitly provided region"""
    provider = config['provider']
    
    if provider == 'aws':
        if config.get('aws_region'):
            selected_region = config['aws_region']
            print(f"[+] Using specified AWS region: {selected_region}")
        else:
            # Randomize for OPSEC
            region_choices = config.get('aws_region_choices', [DEFAULT_REGION['aws']])
            
            # If multiple regions available, select randomly
            if len(region_choices) > 1:
                # Weighted selection favoring less common regions for better OPSEC
                weights = [1.5 if 'gov' not in r and 'us-east' not in r else 1.0 for r in region_choices]
                selected_region = random.choices(region_choices, weights=weights, k=1)[0]
            else:
                selected_region = region_choices[0]
                
            print(f"[+] Randomly selected AWS region: {selected_region}")
        config['aws_region'] = selected_region
        return selected_region
    
    elif provider == 'linode':
        if config.get('linode_region'):
            selected_region = config['linode_region']
            print(f"[+] Using specified Linode region: {selected_region}")
        else:
            # Randomize for OPSEC
            region_choices = config.get('linode_region_choices', [DEFAULT_REGION['linode']])
            # Favor less common regions for better OPSEC
            weights = [1.5 if 'us' not in r else 1.0 for r in region_choices]
            selected_region = random.choices(region_choices, weights=weights, k=1)[0]
            print(f"[+] Randomly selected Linode region: {selected_region}")
        config['linode_region'] = selected_region
        return selected_region
    
    elif provider == 'flokinet':
        if config.get('region'):
            selected_region = config['region']
            print(f"[+] Using specified FlokiNET region: {selected_region}")
        else:
            region_choices = config.get('flokinet_region_choices', [DEFAULT_REGION['flokinet']])
            selected_region = random.choice(region_choices)
            print(f"[+] Randomly selected FlokiNET region: {selected_region}")
        config['region'] = selected_region
        return selected_region
    
    # Fallback
    if config.get('region'):
        return config['region']
    
    return DEFAULT_REGION.get(provider, 'us-east')

def validate_config(config):
    """Validate the configuration"""
    provider = config['provider']
    
    if provider == 'aws':
        if not config.get('aws_key') or not config.get('aws_secret'):
            print("[-] Error: AWS credentials must be provided")
            print("    Use --aws-key and --aws-secret, or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
            return False
    
    if provider == 'linode':
        if not config.get('linode_token'):
            print("[-] Error: Linode token must be provided")
            print("    Use --linode-token or set LINODE_TOKEN environment variable")
            return False
    
    if provider == 'flokinet':
        # For FlokiNET, we'll prompt for IPs if not provided
        if (not config.get('flokinet_redirector_ip') and not config['c2_only']) or \
           (not config.get('flokinet_c2_ip') and not config['redirector_only']):
            print("[*] FlokiNET IPs not fully specified - will prompt during deployment")
            # This is not a failure case anymore, just a warning
    
    if not config.get('ssh_key') and provider != 'flokinet':
        print("[*] SSH key not provided, will generate one")
        config['ssh_key'] = generate_ssh_key()
        if not config['ssh_key']:
            return False
    
    # Check for deployment logic issues
    if config['redirector_only'] and config['c2_only']:
        print("[-] Error: Cannot specify both --redirector-only and --c2-only")
        return False
    
    return True

def deploy_aws(config):
    """Deploy infrastructure using AWS provider"""
    print("[+] Deploying AWS infrastructure...")
    
    # Set AWS environment variables
    os.environ['AWS_ACCESS_KEY_ID'] = config['aws_key']
    os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret']
    
    # Create a temporary inventory file for Ansible
    with open('inventory_aws.yml', 'w') as f:
        f.write("---\n")
        f.write("all:\n")
        f.write("  vars:\n")
        f.write(f"    ansible_ssh_private_key_file: {config['ssh_key']}\n")
        f.write(f"    ansible_user: {config['ssh_user']}\n")
        f.write(f"    ansible_python_interpreter: /usr/bin/python3\n")
        f.write("  children:\n")
        f.write("    redirectors:\n")
        f.write("      hosts:\n")
        f.write("        redirector:\n")
        f.write("          ansible_host: '{{ redirector_ip }}'\n")
        f.write("    c2servers:\n")
        f.write("      hosts:\n")
        f.write("        c2:\n")
        f.write("          ansible_host: '{{ c2_ip }}'\n")
    
    # Run AWS provisioning playbook
    try:
        # Create extra_vars dictionary with all config values 
        extra_vars = {
            'aws_access_key': config['aws_key'],
            'aws_secret_key': config['aws_secret'],
            'aws_region': config['aws_region'],
            'ami_map': config['ami_map'],
            'size': config['size'],
            'aws_instance_type': config['size'],
            'redirector_name': config['redirector_name'],
            'c2_name': config['c2_name'],
            'teardown': config['teardown'],
            'disable_history': config['disable_history'],
            'secure_memory': config['secure_memory'],
            'zero_logs': config['zero_logs'],
            'redirector_only': config['redirector_only'],
            'c2_only': config['c2_only'],
            'debug': config['debug'],
            'domain': config['domain'],
            'letsencrypt_email': config['letsencrypt_email'],
            'gophish_admin_port': config['gophish_admin_port'],
            'smtp_auth_user': config['smtp_auth_user'],
            'smtp_auth_pass': config['smtp_auth_pass'],
        }
        
        extra_vars_str = ' '.join([f"{k}={v}" for k, v in extra_vars.items() if not isinstance(v, dict)])
        
        # Handle the ami_map special case
        ami_map_str = ""
        if config['ami_map']:
            ami_map_str = f"ami_map='{json.dumps(config['ami_map'])}'"
        
        # Determine playbook to run based on deployment mode
        if config['redirector_only']:
            playbook = "AWS/redirector.yml"
            cmd = f"ansible-playbook -i inventory_aws.yml {playbook} -e '{extra_vars_str} {ami_map_str}'"
            
            if config['debug']:
                print(f"[+] Running: {cmd}")
            
            subprocess.run(cmd, shell=True, check=True)
        elif config['c2_only']:
            playbook = "AWS/c2.yml"
            cmd = f"ansible-playbook -i inventory_aws.yml {playbook} -e '{extra_vars_str} {ami_map_str}'"
            
            if config['debug']:
                print(f"[+] Running: {cmd}")
            
            subprocess.run(cmd, shell=True, check=True)
        else:
            # For full deployment, run redirector first, then C2
            # First deploy redirector
            redirector_cmd = f"ansible-playbook -i inventory_aws.yml AWS/redirector.yml -e '{extra_vars_str} {ami_map_str}'"
            if config['debug']:
                print(f"[+] Running: {redirector_cmd}")
            subprocess.run(redirector_cmd, shell=True, check=True)
            
            # Then deploy C2 server with redirector IP
            c2_cmd = f"ansible-playbook -i inventory_aws.yml AWS/c2.yml -e '{extra_vars_str} {ami_map_str}'"
            if config['debug']:
                print(f"[+] Running: {c2_cmd}")
            subprocess.run(c2_cmd, shell=True, check=True)
        
        print("[+] AWS infrastructure deployed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: Failed to deploy AWS infrastructure: {e}")
        return False
    finally:
        # Clean up temporary inventory file
        if os.path.exists('inventory_aws.yml'):
            os.remove('inventory_aws.yml')

def deploy_linode(config):
    """Deploy infrastructure using Linode provider"""
    print("[+] Deploying Linode infrastructure...")
    
    # Set Linode environment variables
    os.environ['LINODE_TOKEN'] = config['linode_token']
    
    # Create a temporary inventory file for Ansible
    with open('inventory_linode.yml', 'w') as f:
        f.write("---\n")
        f.write("all:\n")
        f.write("  vars:\n")
        f.write(f"    ansible_ssh_private_key_file: {config['ssh_key']}\n")
        f.write(f"    ansible_user: {config['ssh_user']}\n")
        f.write(f"    ansible_python_interpreter: /usr/bin/python3\n")
        f.write("  children:\n")
        f.write("    redirectors:\n")
        f.write("      hosts:\n")
        f.write("        redirector:\n")
        f.write("          ansible_host: '{{ redirector_ip }}'\n")
        f.write("    c2servers:\n")
        f.write("      hosts:\n")
        f.write("        c2:\n")
        f.write("          ansible_host: '{{ c2_ip }}'\n")
    
    # Run Linode provisioning playbook
    try:
        extra_vars = {
            'linode_token': config['linode_token'],
            'region': config['linode_region'],
            'plan': config['size'],
            'redirector_name': config['redirector_name'],
            'c2_name': config['c2_name'],
            'teardown': config['teardown'],
            'disable_history': config['disable_history'],
            'secure_memory': config['secure_memory'],
            'zero_logs': config['zero_logs'],
            'redirector_only': config['redirector_only'],
            'c2_only': config['c2_only'],
            'debug': config['debug'],
            'domain': config['domain'],
            'letsencrypt_email': config['letsencrypt_email'],
            'gophish_admin_port': config['gophish_admin_port'],
            'smtp_auth_user': config['smtp_auth_user'],
            'smtp_auth_pass': config['smtp_auth_pass'],
        }
        
        extra_vars_str = ' '.join([f"{k}={v}" for k, v in extra_vars.items()])
        
        # Determine playbook to run based on deployment mode
        if config['redirector_only']:
            playbook = "Linode/redirector.yml"
            cmd = f"ansible-playbook -i inventory_linode.yml {playbook} -e '{extra_vars_str}'"
            
            if config['debug']:
                print(f"[+] Running: {cmd}")
            
            subprocess.run(cmd, shell=True, check=True)
        elif config['c2_only']:
            playbook = "Linode/c2.yml"
            cmd = f"ansible-playbook -i inventory_linode.yml {playbook} -e '{extra_vars_str}'"
            
            if config['debug']:
                print(f"[+] Running: {cmd}")
            
            subprocess.run(cmd, shell=True, check=True)
        else:
            # For full deployment, run redirector first, then C2
            # First deploy redirector
            redirector_cmd = f"ansible-playbook -i inventory_linode.yml Linode/redirector.yml -e '{extra_vars_str}'"
            if config['debug']:
                print(f"[+] Running: {redirector_cmd}")
            subprocess.run(redirector_cmd, shell=True, check=True)
            
            # Then deploy C2 server with redirector IP
            c2_cmd = f"ansible-playbook -i inventory_linode.yml Linode/c2.yml -e '{extra_vars_str}'"
            if config['debug']:
                print(f"[+] Running: {c2_cmd}")
            subprocess.run(c2_cmd, shell=True, check=True)
        
        print("[+] Linode infrastructure deployed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: Failed to deploy Linode infrastructure: {e}")
        return False
    finally:
        # Clean up temporary inventory file
        if os.path.exists('inventory_linode.yml'):
            os.remove('inventory_linode.yml')

def deploy_flokinet(config):
    """Deploy infrastructure using FlokiNET provider"""
    print("[+] Deploying FlokiNET infrastructure...")
    
    # OPSEC: Use the random SSH port from config
    ssh_port = config.get('ssh_port', random.randint(20000, 65000))
    print(f"[+] Using SSH port: {ssh_port}")
    
    # Prompt for IP addresses if not provided
    redirector_ip = config.get('flokinet_redirector_ip')
    c2_ip = config.get('flokinet_c2_ip')
    
    # Handle partial deployment modes
    if config['redirector_only'] and not redirector_ip:
        redirector_ip = input("[?] Enter FlokiNET redirector IP address: ")
        if not redirector_ip:
            print("[-] Error: Redirector IP is required for deployment")
            return False
        # Use a placeholder for C2 if we're only deploying redirector
        c2_ip = "127.0.0.1"
    
    elif config['c2_only'] and not c2_ip:
        c2_ip = input("[?] Enter FlokiNET C2 server IP address: ")
        if not c2_ip:
            print("[-] Error: C2 server IP is required for deployment")
            return False
        
        # If we're only deploying C2, but need redirector IP for configuration
        if not redirector_ip:
            # Try to read existing redirector IP from saved config
            try:
                with open('FlokiNET/vars.yaml', 'r') as f:
                    existing_config = yaml.safe_load(f)
                    if existing_config and 'redirector_ip' in existing_config:
                        redirector_ip = existing_config['redirector_ip']
                        if redirector_ip == "__REDIRECTOR_IP__":  # Placeholder
                            redirector_ip = None
            except (FileNotFoundError, yaml.YAMLError):
                pass
            
            # If still no redirector IP, prompt for it
            if not redirector_ip:
                redirector_ip = input("[?] Enter existing redirector IP address (needed for C2 configuration): ")
                if not redirector_ip:
                    print("[-] Error: Existing redirector IP is required to configure C2 server")
                    return False
    
    # Full deployment - need both IPs
    elif not config['redirector_only'] and not config['c2_only']:
        if not redirector_ip:
            redirector_ip = input("[?] Enter FlokiNET redirector IP address: ")
        if not c2_ip:
            c2_ip = input("[?] Enter FlokiNET C2 server IP address: ")
        
        if not redirector_ip or not c2_ip:
            print("[-] Error: Both redirector and C2 IPs are required for full deployment")
            return False
    
    # Update config with obtained IPs
    config['flokinet_redirector_ip'] = redirector_ip
    config['flokinet_c2_ip'] = c2_ip
    
    # Create FlokiNET directory if it doesn't exist
    if not os.path.exists('FlokiNET'):
        print("[+] Creating FlokiNET directory structure...")
        os.makedirs('FlokiNET', exist_ok=True)
    
    # Prepare vars.yaml with dynamic IPs
    prepare_flokinet_vars(config)
    
    # Create temporary inventory files for Ansible with randomized names for OPSEC
    inventory_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    redirector_inventory = None
    c2_inventory = None
    
    if not config['c2_only']:
        redirector_inventory = f'inventory_r_{inventory_suffix}.yml'
        with open(redirector_inventory, 'w') as f:
            os.chmod(redirector_inventory, 0o600)  # Secure permissions
            f.write("---\n")
            f.write("redirector:\n")
            f.write(f"  hosts:\n")
            f.write(f"    redirector:\n")
            f.write(f"      ansible_host: {redirector_ip}\n")
            f.write(f"      ansible_user: {config['ssh_user']}\n")
            if config.get('ssh_key'):
                f.write(f"      ansible_ssh_private_key_file: {config['ssh_key']}\n")
            f.write(f"      ansible_python_interpreter: /usr/bin/python3\n")
            f.write(f"      ansible_port: {ssh_port}\n")  # Use custom SSH port
    
    if not config['redirector_only']:
        c2_inventory = f'inventory_c_{inventory_suffix}.yml'
        with open(c2_inventory, 'w') as f:
            os.chmod(c2_inventory, 0o600)  # Secure permissions
            f.write("---\n")
            f.write("c2:\n")
            f.write(f"  hosts:\n")
            f.write(f"    c2:\n")
            f.write(f"      ansible_host: {c2_ip}\n")
            f.write(f"      ansible_user: {config['ssh_user']}\n")
            if config.get('ssh_key'):
                f.write(f"      ansible_ssh_private_key_file: {config['ssh_key']}\n")
            f.write(f"      ansible_python_interpreter: /usr/bin/python3\n")
            f.write(f"      ansible_port: {ssh_port}\n")  # Use custom SSH port
    
    # Run FlokiNET provisioning playbooks
    try:
        # Build extra vars string
        extra_vars = {
            'redirector_ip': redirector_ip,
            'c2_ip': c2_ip,
            'disable_history': config['disable_history'],
            'secure_memory': config['secure_memory'],
            'zero_logs': config['zero_logs'],
            'domain': config['domain'],
            'letsencrypt_email': config['letsencrypt_email'],
            'gophish_admin_port': config['gophish_admin_port'],
            'smtp_auth_user': config['smtp_auth_user'],
            'smtp_auth_pass': config['smtp_auth_pass'],
            'ssh_port': ssh_port
        }
        
        extra_vars_str = ' '.join([f"{k}='{v}'" for k, v in extra_vars.items()])
        
        # Common provisioning for both servers
        if not config['c2_only'] and redirector_inventory:
            print("[+] Provisioning FlokiNET redirector...")
            cmd = f"ansible-playbook -i {redirector_inventory} FlokiNET/provision.yml -e '{extra_vars_str}'"
            if config['debug']:
                print(f"[+] Running: {cmd}")
            subprocess.run(cmd, shell=True, check=True)
            
            # Run redirector-specific playbook
            print("[+] Configuring FlokiNET redirector...")
            cmd = f"ansible-playbook -i {redirector_inventory} FlokiNET/redirector.yml -e '{extra_vars_str}'"
            if config['debug']:
                print(f"[+] Running: {cmd}")
            subprocess.run(cmd, shell=True, check=True)
        
        if not config['redirector_only'] and c2_inventory:
            print("[+] Provisioning FlokiNET C2 server...")
            cmd = f"ansible-playbook -i {c2_inventory} FlokiNET/provision.yml -e '{extra_vars_str}'"
            if config['debug']:
                print(f"[+] Running: {cmd}")
            subprocess.run(cmd, shell=True, check=True)
            
            # Run C2-specific playbook
            print("[+] Configuring FlokiNET C2 server...")
            cmd = f"ansible-playbook -i {c2_inventory} FlokiNET/c2.yml -e '{extra_vars_str}'"
            if config['debug']:
                print(f"[+] Running: {cmd}")
            subprocess.run(cmd, shell=True, check=True)
        
        print("[+] FlokiNET infrastructure deployed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: Failed to deploy FlokiNET infrastructure: {e}")
        return False
    finally:
        # Clean up temporary inventory files
        for inv_file in [redirector_inventory, c2_inventory]:
            if inv_file and os.path.exists(inv_file):
                # Securely overwrite before removal for better OPSEC
                with open(inv_file, 'w') as f:
                    f.write('\0' * 1024)  # Overwrite with null bytes
                os.remove(inv_file)
                if config['debug']:
                    print(f"[+] Removed temporary inventory file: {inv_file}")

def prepare_flokinet_vars(config):
    """Prepare FlokiNET vars.yaml with dynamic values"""
    vars_file = 'FlokiNET/vars.yaml'
    
    # Check if template exists, create it if not
    if not os.path.exists(vars_file):
        # Default template content with enhanced OPSEC
        template = {
            'flokinet_region_choices': ['iceland', 'romania', 'finland', 'netherlands'],
            'redirector_ip': config['flokinet_redirector_ip'],
            'c2_ip': config['flokinet_c2_ip'],
            'domain': config['domain'],
            'redirector_subdomain': 'cdn',
            'c2_subdomain': 'mail',
            'letsencrypt_email': config['letsencrypt_email'],
            'ssh_port': config.get('ssh_port', random.randint(20000, 65000)),
            'ssh_user': config['ssh_user'],
            'ssh_key_path': config.get('ssh_key', '~/.ssh/id_ed25519.pub'),
            'c2_framework': 'sliver',
            'shell_handler_port': random.randint(10000, 65000),  # Random port for better OPSEC
            'shell_handler_protocol': 'http',
            'disable_history': config['disable_history'],
            'secure_memory': config['secure_memory'],
            'zero_logs': config['zero_logs'],
            'log_rotation_hours': 6,
            'secure_delete_tools': True,
            'memory_clear_interval': 60,
            'infrastructure_lifespan': 72,
            'auto_rotate_certs': True,
            'cert_rotation_days': 30,
            'gophish_admin_port': config.get('gophish_admin_port', str(random.randint(2000, 9000))),
            'gophish_admin_domain': f"admin.{config['domain']}",
            'gophish_site_domain': f"portal.{config['domain']}",
            'smtp_auth_user': config.get('smtp_auth_user', f"user{random.randint(1000, 9999)}"),
            'smtp_auth_pass': config.get('smtp_auth_pass', ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=20)))
        }
        
        # Write template to file with secure permissions
        with open(vars_file, 'w') as f:
            os.chmod(vars_file, 0o600)  # Readable only by owner
            yaml.dump(template, f, default_flow_style=False)
        print(f"[+] Created new FlokiNET configuration in {vars_file} (mode 0600)")
    else:
        # Read existing vars
        with open(vars_file, 'r') as f:
            vars_data = yaml.safe_load(f)
        
        # Update with dynamic values
        vars_data['redirector_ip'] = config['flokinet_redirector_ip']
        vars_data['c2_ip'] = config['flokinet_c2_ip']
        
        # Update domain and email if provided
        vars_data['domain'] = config['domain']
        vars_data['letsencrypt_email'] = config['letsencrypt_email']
        
        # Update OPSEC settings
        vars_data['disable_history'] = config['disable_history']
        vars_data['secure_memory'] = config['secure_memory']
        vars_data['zero_logs'] = config['zero_logs']
        vars_data['ssh_port'] = config.get('ssh_port', vars_data.get('ssh_port', 22222))
        
        # Write updated vars back to file
        with open(vars_file, 'w') as f:
            yaml.dump(vars_data, f, default_flow_style=False)
        print(f"[+] Updated existing FlokiNET configuration in {vars_file}")

def ensure_provider_files_exist(config):
    """Ensure necessary files exist for the provider"""
    provider = config['provider']
    # Check for required directories
    if not os.path.exists(provider):
        print(f"[+] Creating {provider} directory structure...")
        os.makedirs(provider, exist_ok=True)
    
    # Basic file existence checks
    required_files = {
        'aws': ['redirector.yml', 'c2.yml'],
        'linode': ['redirector.yml', 'c2.yml'],
        'flokinet': ['provision.yml', 'redirector.yml', 'c2.yml']
    }
    
    # Check for shared files directory
    if not os.path.exists('files'):
        print("[+] Creating shared files directory...")
        os.makedirs('files', exist_ok=True)
    
    # Check for essential OPSEC scripts
    essential_scripts = [
        'clean-logs.sh',
        'persistent-listener.sh',
        'secure-exit.sh',
        'serve-beacons.sh'
    ]
    
    missing_files = []
    
    # Check provider-specific files
    for file in required_files.get(provider.lower(), []):
        full_path = f"{provider}/{file}"
        if not os.path.exists(full_path):
            missing_files.append(full_path)
    
    # Check shared OPSEC scripts
    for script in essential_scripts:
        if not os.path.exists(f"files/{script}"):
            missing_files.append(f"files/{script}")
    
    if missing_files:
        print(f"[!] Warning: The following files are missing:")
        for file in missing_files:
            print(f"    - {file}")
        print(f"[!] You may need to create these files before deployment will work.")
        return False
    
    return True

def generate_ssh_key(instance_label=None):
    """Generate a new SSH key with randomized name for better OPSEC"""
    # Create a unique key name based on instance label or random string
    if not instance_label:
        instance_label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    key_name = f"c2ingred_{instance_label}_{int(time.time())}"
    key_path = os.path.expanduser(f"~/.ssh/{key_name}")
    
    print(f"[+] Generating new SSH key: {key_path}")
    try:
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", ""], check=True)
        # Set proper permissions
        os.chmod(key_path, 0o600)
        os.chmod(f"{key_path}.pub", 0o644)
        return key_path
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: Failed to generate SSH key: {e}")
        return None

def interactive_config():
    """Interactively collect configuration"""
    config = {}
    
    # Initialize deployment mode flags (these were missing)
    config['redirector_only'] = False
    config['c2_only'] = False
    
    # Select provider
    print("\n=== Provider Selection ===")
    print("Available providers:")
    for i, provider in enumerate(PROVIDERS):
        print(f"  {i+1}. {provider}")
    
    while True:
        try:
            choice = int(input("\nSelect provider (1-3): ")) - 1
            if 0 <= choice < len(PROVIDERS):
                config['provider'] = PROVIDERS[choice]
                break
            else:
                print("Invalid choice. Please enter a number between 1 and 3.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    # Provider-specific configuration
    if config['provider'] == 'aws':
        print("\n=== AWS Configuration ===")
        
        # Try to load defaults from vars.yaml
        aws_vars = load_vars_file('AWS')
        default_key = aws_vars.get('aws_access_key', '')
        default_secret = aws_vars.get('aws_secret_key', '')
        
        config['aws_key'] = input(f"AWS Access Key [{default_key[:4]}{'*'*(len(default_key)-4) if default_key else ''}]: ") or default_key
        config['aws_secret'] = input(f"AWS Secret Key [{default_secret[:4]}{'*'*(len(default_secret)-4) if default_secret else ''}]: ") or default_secret
        
        # Region choices
        region_choices = aws_vars.get('aws_region_choices', [DEFAULT_REGION['aws']])
        print("\nAvailable AWS regions:")
        for i, region in enumerate(region_choices):
            print(f"  {i+1}. {region}")
        
        use_random = input("\nUse random region? (Y/n): ").lower() != 'n'
        if use_random:
            config['aws_region'] = None  # Will be randomized later
        else:
            while True:
                try:
                    region_choice = int(input(f"Select region (1-{len(region_choices)}): ")) - 1
                    if 0 <= region_choice < len(region_choices):
                        config['aws_region'] = region_choices[region_choice]
                        break
                except ValueError:
                    pass
                print(f"Invalid choice. Please enter a number between 1 and {len(region_choices)}.")
        
        # Ask for architecture type (if not already set)
        if not config.get('redirector_only') and not config.get('c2_only'):
            print("\nDeployment architecture:")
            print("  1. Combined (single server for both redirector and C2)")
            print("  2. Split (separate servers for redirector and C2)")
            arch_choice = input("\nSelect architecture (1-2, default: 2): ") or "2"
            if arch_choice == "1":
                config['redirector_only'] = False
                config['c2_only'] = False
            else:
                # For split architecture, ask which components to deploy
                comp_choice = input("\nDeploy (1: Both components, 2: Redirector only, 3: C2 only, default: 1): ") or "1"
                if comp_choice == "2":
                    config['redirector_only'] = True
                    config['c2_only'] = False
                elif comp_choice == "3":
                    config['redirector_only'] = False
                    config['c2_only'] = True
                else:
                    config['redirector_only'] = False
                    config['c2_only'] = False
    
    elif config['provider'] == 'linode':
        print("\n=== Linode Configuration ===")
        
        # Try to load defaults from vars.yaml
        linode_vars = load_vars_file('Linode')
        default_token = linode_vars.get('linode_token', '')
        
        config['linode_token'] = input(f"Linode API Token [{default_token[:4]}{'*'*(len(default_token)-4) if default_token else ''}]: ") or default_token
        
        # Region choices
        region_choices = linode_vars.get('region_choices', [DEFAULT_REGION['linode']])
        print("\nAvailable Linode regions:")
        for i, region in enumerate(region_choices):
            print(f"  {i+1}. {region}")
        
        use_random = input("\nUse random region? (Y/n): ").lower() != 'n'
        if use_random:
            config['linode_region'] = None  # Will be randomized later
        else:
            while True:
                try:
                    region_choice = int(input(f"Select region (1-{len(region_choices)}): ")) - 1
                    if 0 <= region_choice < len(region_choices):
                        config['linode_region'] = region_choices[region_choice]
                        break
                except ValueError:
                    pass
                print(f"Invalid choice. Please enter a number between 1 and {len(region_choices)}.")
        
        # Ask for architecture type (if not already set)
        if not config.get('redirector_only') and not config.get('c2_only'):
            print("\nDeployment architecture:")
            print("  1. Combined (single server for both redirector and C2)")
            print("  2. Split (separate servers for redirector and C2)")
            arch_choice = input("\nSelect architecture (1-2, default: 2): ") or "2"
            if arch_choice == "1":
                config['redirector_only'] = False
                config['c2_only'] = False
            else:
                # For split architecture, ask which components to deploy
                comp_choice = input("\nDeploy (1: Both components, 2: Redirector only, 3: C2 only, default: 1): ") or "1"
                if comp_choice == "2":
                    config['redirector_only'] = True
                    config['c2_only'] = False
                elif comp_choice == "3":
                    config['redirector_only'] = False
                    config['c2_only'] = True
                else:
                    config['redirector_only'] = False
                    config['c2_only'] = False
    
    elif config['provider'] == 'flokinet':
        print("\n=== FlokiNET Configuration ===")
        print("Note: FlokiNET requires manual server setup due to their privacy focus")
        
        # Try to load defaults from vars.yaml
        flokinet_vars = load_vars_file('FlokiNET')
        
        # Deployment mode
        print("\nDeployment mode:")
        print("  1. Full deployment (redirector and C2)")
        print("  2. Redirector only")
        print("  3. C2 server only")
        
        while True:
            try:
                mode = int(input("\nSelect deployment mode (1-3): "))
                if 1 <= mode <= 3:
                    break
                else:
                    print("Invalid choice. Please enter a number between 1 and 3.")
            except ValueError:
                print("Invalid input. Please enter a number.")
        
        # Set deployment flags
        if mode == 2:
            config['redirector_only'] = True
            config['c2_only'] = False
            config['flokinet_redirector_ip'] = input("FlokiNET Redirector IP: ")
        elif mode == 3:
            config['redirector_only'] = False
            config['c2_only'] = True
            config['flokinet_c2_ip'] = input("FlokiNET C2 Server IP: ")
            
            # Need redirector IP for configuration
            config['flokinet_redirector_ip'] = input("Existing Redirector IP (for configuration): ")
        else:
            config['redirector_only'] = False
            config['c2_only'] = False
            config['flokinet_redirector_ip'] = input("FlokiNET Redirector IP: ")
            config['flokinet_c2_ip'] = input("FlokiNET C2 Server IP: ")
    
    # General configuration
    print("\n=== General Configuration ===")
    
    # SSH key and user
    default_ssh_user = config.get('ssh_user', 'root')
    config['ssh_user'] = input(f"SSH Username (default: {default_ssh_user}): ") or default_ssh_user
    
    default_ssh_key = '~/.ssh/id_rsa'
    if config['provider'] == 'aws':
        ssh_key = input(f"Path to SSH private key (leave empty to generate): ")
    else:
        ssh_key = input(f"Path to SSH private key (default: {default_ssh_key}): ") or default_ssh_key
    
    if not ssh_key and config['provider'] == 'aws':
        ssh_key = generate_ssh_key()
    config['ssh_key'] = ssh_key
    
    # Domain configuration
    default_domain = 'example.com'
    config['domain'] = input(f"Domain name for infrastructure (default: {default_domain}): ") or default_domain
    
    if config['domain'] != default_domain:
        default_email = f"admin@{config['domain']}"
        config['letsencrypt_email'] = input(f"Email for Let's Encrypt certificate (default: {default_email}): ") or default_email
    else:
        config['letsencrypt_email'] = 'admin@example.com'
    
    # OPSEC settings
    print("\n=== OPSEC Configuration ===")
    disable_history = input("Disable command history? (Y/n): ").lower() or "y"
    config['disable_history'] = disable_history.startswith('y')
    
    secure_memory = input("Enable secure memory settings? (Y/n): ").lower() or "y"
    config['secure_memory'] = secure_memory.startswith('y')
    
    zero_logs = input("Enable zero-logs configuration? (Y/n): ").lower() or "y"
    config['zero_logs'] = zero_logs.startswith('y')
    
    return config

def cleanup_sensitive_files(config):
    """Clean up sensitive files after deployment for better OPSEC"""
    # Files to potentially clean up (prompt user first)
    sensitive_files = []
    
    # Add config file
    if os.path.exists('config.yml'):
        sensitive_files.append('config.yml')
    
    # Add log files
    for f in os.listdir('.'):
        if f.startswith('deployment_') and f.endswith('.log'):
            sensitive_files.append(f)
    
    # Add inventory files
    for f in os.listdir('.'):
        if f.startswith('inventory_') and f.endswith('.yml'):
            sensitive_files.append(f)
    
    # If there are sensitive files and user wants to clean up
    if sensitive_files:
        print("\n[!] The following sensitive files remain from deployment:")
        for f in sensitive_files:
            print(f"    - {f}")
        
        cleanup = input("\n[?] Would you like to securely delete these files? (y/N): ").lower()
        if cleanup.startswith('y'):
            for f in sensitive_files:
                try:
                    # Secure overwrite then delete
                    with open(f, 'wb') as file:
                        # Overwrite with random data 3 times
                        for _ in range(3):
                            file.write(os.urandom(os.path.getsize(f)))
                            file.flush()
                            os.fsync(file.fileno())
                    
                    # Finally remove
                    os.remove(f)
                    print(f"[+] Securely deleted: {f}")
                except Exception as e:
                    print(f"[!] Error deleting {f}: {e}")
    
    # Remind about SSH keys
    if config.get('ssh_key') and os.path.exists(config['ssh_key']):
        print(f"\n[!] Remember to secure or remove your SSH key after use: {config['ssh_key']}")
        secure_key = input("[?] Would you like to secure this SSH key now? (y/N): ").lower()
        if secure_key.startswith('y'):
            try:
                # Rename the SSH key with random suffix
                key_dir = os.path.dirname(config['ssh_key'])
                key_base = os.path.basename(config['ssh_key'])
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                new_key_path = os.path.join(key_dir, f"{key_base}.{timestamp}.bak")
                
                # Move the key and public key
                shutil.move(config['ssh_key'], new_key_path)
                if os.path.exists(f"{config['ssh_key']}.pub"):
                    shutil.move(f"{config['ssh_key']}.pub", f"{new_key_path}.pub")
                
                # Set permissions
                os.chmod(new_key_path, 0o400)  # Read-only by owner
                if os.path.exists(f"{new_key_path}.pub"):
                    os.chmod(f"{new_key_path}.pub", 0o400)
                
                print(f"[+] SSH key secured and renamed to: {new_key_path}")
                print(f"[+] This key is now read-only (mode 0400)")
            except Exception as e:
                print(f"[!] Error securing SSH key: {e}")
    
    return True

def save_config(config):
    """Save configuration to config.yml file"""
    # Make a copy to avoid modifying the original
    config_to_save = config.copy()
    
    # Remove ALL sensitive data before saving
    sensitive_keys = [
        'aws_key', 'aws_secret', 'linode_token', 
        'smtp_auth_pass', 'ssh_key', 'ssh_key_path',
        'flokinet_redirector_ip', 'flokinet_c2_ip',
        'c2_ip', 'redirector_ip'
    ]
    
    for key in sensitive_keys:
        if key in config_to_save:
            # Replace with asterisks, preserving first 2 chars for reference
            value = config_to_save[key]
            if isinstance(value, str) and len(value) > 4:
                config_to_save[key] = f"{value[:2]}{'*' * (len(value) - 2)}"
            else:
                config_to_save[key] = '***'
    
    # Use a more secure way to write sensitive files
    # Ensure the file doesn't exist first to prevent race conditions
    if os.path.exists('config.yml'):
        os.remove('config.yml')
    
    # Create with restricted permissions
    with open('config.yml', 'w') as f:
        os.chmod('config.yml', 0o600)  # Readable only by owner
        yaml.dump(config_to_save, f, default_flow_style=False)
    
    print(f"[+] Configuration saved to config.yml (mode 0600)")
    
    # Create deployment log with timestamp but with minimal sensitive info
    log_file = f"deployment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    # Create with restricted permissions
    with open(log_file, 'w') as f:
        os.chmod(log_file, 0o600)  # Readable only by owner
        
        f.write(f"# C2ingRed Deployment Log\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Log general info
        f.write(f"Provider: {config['provider']}\n")
        
        # Log provider-specific info without exposing sensitive details
        if config['provider'] == 'aws':
            f.write(f"AWS Region: {config.get('aws_region', 'random')}\n")
            f.write(f"Instance Type: {config.get('size', 'default')}\n")
            f.write(f"Redirector Name: {config['redirector_name']}\n")
            f.write(f"C2 Name: {config['c2_name']}\n")
        elif config['provider'] == 'linode':
            f.write(f"Linode Region: {config.get('linode_region', 'random')}\n")
            f.write(f"Plan: {config.get('size', 'default')}\n")
            f.write(f"Redirector Name: {config['redirector_name']}\n")
            f.write(f"C2 Name: {config['c2_name']}\n")
        elif config['provider'] == 'flokinet':
            # IPs are sensitive for FlokiNET, only log region
            f.write(f"FlokiNET Region: {config.get('region', 'anonymous')}\n")
            # Note that we're not logging IPs directly
        
        # Log domain info if provided
        if config.get('domain'):
            f.write(f"Domain: {config['domain']}\n")
            if not config.get('c2_only'):
                f.write(f"Redirector Domain: cdn.{config['domain']}\n")
            if not config.get('redirector_only'):
                f.write(f"C2 Domain: mail.{config['domain']}\n")
        
        # Log OPSEC settings
        f.write(f"\nOPSEC Settings:\n")
        f.write(f"- Zero-logs: {'Enabled' if config.get('zero_logs') else 'Disabled'}\n")
        f.write(f"- Secure memory: {'Enabled' if config.get('secure_memory') else 'Disabled'}\n")
        f.write(f"- History disabled: {'Yes' if config.get('disable_history') else 'No'}\n")
        f.write(f"- Non-standard SSH port: {config.get('ssh_port', 'Default')}\n")
    
    print(f"[+] Deployment log saved to {log_file} (mode 0600)")

def main():
    """Main function"""
    print("========================================")
    print("C2ingRed - Red Team Infrastructure Setup")
    print("========================================")
    
    args = setup_argparse()
    
    # Interactive mode if no arguments provided
    if len(sys.argv) == 1:
        config = interactive_config()
    else:
        config = load_config(args)
    
    # Validate configuration
    if not validate_config(config):
        return
    
    # Select region
    select_region(config)
    
    # Ensure provider files exist
    if not ensure_provider_files_exist(config):
        proceed = input("\n[?] Continue despite missing files? (y/N): ").lower()
        if not proceed.startswith('y'):
            print("[-] Deployment aborted.")
            return
    
    # Save configuration
    save_config(config)
    
    success = False
    try:
        # Deploy infrastructure based on provider
        if config['provider'] == 'aws':
            success = deploy_aws(config)
        elif config['provider'] == 'linode':
            success = deploy_linode(config)
        elif config['provider'] == 'flokinet':
            success = deploy_flokinet(config)
        else:
            print(f"[-] Error: Unsupported provider: {config['provider']}")
            return
    finally:
        # OPSEC: Always offer to clean up sensitive files, regardless of success
        if not config.get('debug'):  # Skip cleanup in debug mode
            cleanup_sensitive_files(config)
    
    if success:
        print("\n[+] Deployment completed successfully!")
        if config['provider'] != 'flokinet':
            print("\n[+] Your infrastructure is now ready to use!")
            print(f"[+] Redirector: {config['redirector_name']}")
            print(f"[+] C2 Server: {config['c2_name']}")
        else:
            print("\n[+] Your FlokiNET infrastructure is now configured with:")
            print(f"[+] Zero-logs configuration")
            print(f"[+] Automated shell handler")
            print(f"[+] Sliver C2 framework")
            print(f"[+] Anti-forensics capabilities")
            print("\n[+] To use the automated shell handler, configure your Rubber Ducky with:")
            print(f"[+] Redirector IP: {config['flokinet_redirector_ip']}")
            if config.get('domain'):
                print(f"[+] or Domain: cdn.{config['domain']}")
            print(f"[+] Port: {config.get('shell_handler_port', 4444)} (shell handler port)")
            
            # Remind about DNS configuration
            if config.get('domain'):
                print("\n[!] Don't forget to configure your DNS records:")
                if not config.get('c2_only'):
                    print(f"[!] - Add A record for cdn.{config['domain']} pointing to {config['flokinet_redirector_ip']}")
                if not config.get('redirector_only'):
                    print(f"[!] - Add A record for mail.{config['domain']} pointing to {config['flokinet_c2_ip']}")
    else:
        print("\n[-] Deployment failed.")
        
    # Display non-standard SSH port warning if applicable
    if success and config.get('ssh_port') != 22:
        print(f"\n[!] IMPORTANT: Non-standard SSH port {config.get('ssh_port')} is being used")
        print(f"[!] Future SSH connections will require: ssh -p {config.get('ssh_port')} user@host")

if __name__ == "__main__":
    main()