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
import re
import socket
import paramiko
import logging
import glob
from datetime import datetime

# Disable Ansible host key checking
os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"

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

def normalize_provider_name(provider_name):
    """Normalize provider name to expected capitalization"""
    if not provider_name:
        return None
        
    provider_map = {
        'aws': 'AWS',
        'linode': 'Linode', 
        'flokinet': 'FlokiNET'
    }
    
    normalized = provider_map.get(provider_name.lower())
    if normalized:
        return normalized
    
    return provider_name

def setup_argparse():
    """Set up and return the argument parser"""
    parser = argparse.ArgumentParser(description='Deploy C2itAll Red Team infrastructure')
    
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
    
    # Post-deployment options
    parser.add_argument('--ssh-after-deploy', action='store_true', help='SSH into the instance after deployment')
    parser.add_argument('--copy-ssh-key', action='store_true', help='Copy SSH key to the server for passwordless login')
    parser.add_argument('--run-tests', action='store_true', help='Run tests after deployment')
    
    # Tracker module integration
    parser.add_argument('--deploy-tracker', action='store_true', help='Deploy tracker module')
    parser.add_argument('--tracker-domain', help='Domain name for the tracker server')
    parser.add_argument('--tracker-email', help='Email for the tracker server Let\'s Encrypt certificate')
    parser.add_argument('--tracker-name', help='Name for the tracker engagement')
    parser.add_argument('--tracker-ipinfo-token', help='IPinfo API token for tracker geolocation data')
    parser.add_argument('--tracker-setup-ssl', action='store_true', help='Set up SSL certificates for tracker')
    parser.add_argument('--tracker-create-pixel', action='store_true', help='Create email tracking pixel')
    
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
    config['ssh_after_deploy'] = args.ssh_after_deploy
    config['copy_ssh_key'] = args.copy_ssh_key
    config['run_tests'] = args.run_tests
    
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
        # Only use letters and digits for safety - no special characters
        charset = string.ascii_letters + string.digits
        random_pass = ''.join(random.choices(charset, k=20))
        config['smtp_auth_pass'] = random_pass
    else:
        config['smtp_auth_pass'] = vars_data.get('smtp_auth_pass')
    
    # Set random SSH port for better OPSEC
    config['ssh_port'] = vars_data.get('ssh_port', random.randint(20000, 65000))
    
    # Tracker module settings
    config['deploy_tracker'] = args.deploy_tracker
    config['tracker_domain'] = args.tracker_domain
    config['tracker_email'] = args.tracker_email
    config['tracker_name'] = args.tracker_name
    config['tracker_ipinfo_token'] = args.tracker_ipinfo_token
    config['tracker_setup_ssl'] = args.tracker_setup_ssl
    config['tracker_create_pixel'] = args.tracker_create_pixel
    
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

def verify_key_file_permissions(key_path):
    """Verify and fix SSH key file permissions"""
    try:
        # Check if key file exists
        if not os.path.exists(key_path):
            print(f"[-] SSH key file not found: {key_path}")
            return False
        
        # Fix permissions
        current_mode = os.stat(key_path).st_mode & 0o777
        if current_mode != 0o600:
            print(f"[!] SSH key has incorrect permissions: {oct(current_mode)[2:]}. Fixing to 0600...")
            os.chmod(key_path, 0o600)
            print(f"[+] SSH key permissions fixed")
        
        return True
    except Exception as e:
        print(f"[-] Error verifying key file permissions: {e}")
        return False

def parse_ansible_error(stderr):
    """Parse ansible error output to extract useful information"""
    error_info = {}
    
    # Look for common ansible error patterns
    if "FAILED! => " in stderr:
        # Extract the JSON error part
        error_start = stderr.find("FAILED! => ")
        error_text = stderr[error_start:].split("\n")[0]
        # Remove the "FAILED! => " prefix
        error_text = error_text.replace("FAILED! => ", "")
        
        try:
            # Try to parse as JSON
            error_info = json.loads(error_text)
        except:
            # If not valid JSON, use the text as is
            error_info = {"msg": error_text}
    
    # Look for common error messages
    if "SSH Error:" in stderr:
        error_info["ssh_error"] = True
    
    if "No such file or directory" in stderr:
        error_info["file_not_found"] = True
    
    if "Permission denied" in stderr:
        error_info["permission_denied"] = True
    
    if "The API Token provided is not valid" in stderr:
        error_info["invalid_api_token"] = True
    
    return error_info

def setup_error_logging():
    """Setup error logging and ensure log directory exists"""
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # Set up global log file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, f"deployment_{timestamp}.log")
    
    # Configure logging
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG if '--debug' in sys.argv else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Log start of script
    logging.info("C2itAll deployment script started")
    
    return log_file

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
    
    # Tracker module validation 
    if config['deploy_tracker']:
        if not config.get('tracker_domain') and not config.get('tracker_ipinfo_token'):
            print("[-] Warning: Tracker deployment without domain or IPInfo token will have limited functionality")
    
    return True

def deploy_aws(config):
    """Deploy infrastructure using AWS provider"""
    print("[+] Deploying AWS infrastructure...")
    
    # Set AWS environment variables
    os.environ['AWS_ACCESS_KEY_ID'] = config['aws_key']
    os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret']
    
    # Create logs directory
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Only create one log file in the logs directory
    log_file = os.path.join(log_dir, f"deployment_{timestamp}_aws.log")
    
    print(f"[+] Creating deployment log at: {log_file}")
    
    # Prepare SSH key - for AWS we'll use AWS key pairs instead of local files
    ssh_key_name = config.get('ssh_key_name')
    if not ssh_key_name:
        # Generate a random key name for AWS
        rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        timestamp = int(time.time()) % 10000
        ssh_key_name = f"c2itall-{rand_suffix}-{timestamp}"
    
    config['ssh_key_name'] = ssh_key_name
    print(f"[+] Using AWS key pair name: {ssh_key_name}")
    
    # Create a temporary inventory file for Ansible
    inventory_file = f"inventory_aws_{int(time.time())}.yml"
    
    with open(log_file, 'a') as f:
        f.write(f"==== CREATING INVENTORY FILE: {inventory_file} ====\n")
    
    with open(inventory_file, 'w') as f:
        f.write("---\n")
        f.write("all:\n")
        f.write("  vars:\n")
        f.write(f"    ansible_ssh_private_key_file: ~/.ssh/{ssh_key_name}.pem\n")
        f.write(f"    ansible_user: {config.get('ssh_user', 'ec2-user')}\n")
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
    
    # Log inventory file content
    with open(log_file, 'a') as f:
        f.write(f"INVENTORY CONTENT:\n")
        with open(inventory_file, 'r') as inv:
            f.write(inv.read())
        f.write("\n==== END INVENTORY FILE ====\n\n")
    
    # Generate default names if not provided
    rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    timestamp = int(time.time()) % 10000
    redirector_name = config.get('redirector_name', f"srv-{rand_suffix}-{timestamp}")
    c2_name = config.get('c2_name', f"node-{rand_suffix}-{timestamp}")
    
    # Update config with generated names for logging
    config['redirector_name'] = redirector_name
    config['c2_name'] = c2_name
    
    # Log important information
    with open(log_file, 'a') as f:
        f.write(f"==== DEPLOYMENT INFORMATION ====\n")
        f.write(f"AWS Key Pair Name: {ssh_key_name}\n")
        f.write(f"Redirector Name: {redirector_name}\n")
        f.write(f"C2 Name: {c2_name}\n")
        f.write(f"AWS Region: {config.get('aws_region', 'default region')}\n")
        f.write(f"Domain: {config.get('domain', 'example.com')}\n")
        f.write(f"==== END DEPLOYMENT INFORMATION ====\n\n")
    
    # Track deployed instances and resources for cleanup if needed
    deployed_instances = []
    deployed_resources = []
    success = False
    
    try:
        # Create extra_vars dictionary with all config values 
        extra_vars = {
            'aws_access_key': config['aws_key'],
            'aws_secret_key': config['aws_secret'],
            'aws_region': config.get('aws_region', DEFAULT_REGION['aws']),
            'ami_map': config.get('ami_map', {}),
            'size': config.get('size', DEFAULT_SIZE['aws']),
            'aws_instance_type': config.get('size', DEFAULT_SIZE['aws']),
            'redirector_name': redirector_name,
            'c2_name': c2_name,
            'teardown': config.get('teardown', False),
            'disable_history': config.get('disable_history', True),
            'secure_memory': config.get('secure_memory', True),
            'zero_logs': config.get('zero_logs', True),
            'redirector_only': config.get('redirector_only', False),
            'c2_only': config.get('c2_only', False),
            'debug': config.get('debug', False),
            'domain': config.get('domain', 'example.com'),
            'letsencrypt_email': config.get('letsencrypt_email', 'admin@example.com'),
            'gophish_admin_port': config.get('gophish_admin_port', str(random.randint(2000, 9000))),
            'smtp_auth_user': config.get('smtp_auth_user', f"user{random.randint(1000, 9999)}"),
            'smtp_auth_pass': config.get('smtp_auth_pass', ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=20))),
            'key_name': ssh_key_name,
            'ssh_user': config.get('ssh_user', 'ec2-user'),
            'instance_label': c2_name if config.get('c2_only', False) else redirector_name,
            'private_key_path': f"~/.ssh/{ssh_key_name}",
        }
        
        # Format extra vars for command line, handling special characters
        extra_vars_list = []
        for k, v in extra_vars.items():
            if isinstance(v, bool):
                extra_vars_list.append(f"{k}={str(v).lower()}")
            elif isinstance(v, (int, float)):
                extra_vars_list.append(f"{k}={v}")
            elif isinstance(v, str):
                # Escape quotes in string values
                escaped_v = v.replace("'", "'\\''")
                extra_vars_list.append(f"{k}='{escaped_v}'")
            elif not isinstance(v, dict):  # Skip dict values
                extra_vars_list.append(f"{k}={v}")
        
        extra_vars_str = " ".join(extra_vars_list)
        
        # Handle the ami_map special case
        ami_map_str = ""
        if config.get('ami_map'):
            ami_map_str = f"ami_map='{json.dumps(config['ami_map'])}'"
        
        # Execute deployment based on deployment mode
        if extra_vars['redirector_only']:
            playbook = "AWS/redirector.yml"
            cmd = f"ansible-playbook -i {inventory_file} {playbook} -e '{extra_vars_str} {ami_map_str}'"
            
            with open(log_file, 'a') as f:
                f.write(f"==== RUNNING REDIRECTOR PLAYBOOK ====\n")
                f.write(f"Command: {cmd}\n\n")
            
            print(f"[+] Running: {cmd}")
            success, stdout, stderr = run_command_with_logging(cmd, config, log_file)
            if not success:
                print(f"[-] Redirector deployment failed. See {log_file} for details.")
                # Track created resources for cleanup
                try:
                    # Get instance ID for cleanup
                    instance_id = get_aws_instance_id(redirector_name, config)
                    if instance_id:
                        deployed_instances.append((redirector_name, instance_id))
                    # Also add key pair to resources for cleanup
                    deployed_resources.append(("key_pair", ssh_key_name))
                except Exception as e:
                    print(f"[!] Failed to get instance ID: {e}")
                return False, [log_file], deployed_instances + deployed_resources
            
            # Track deployed instances and resources
            instance_id = get_aws_instance_id(redirector_name, config)
            if instance_id:
                deployed_instances.append((redirector_name, instance_id))
            deployed_resources.append(("key_pair", ssh_key_name))
            
            # Store redirector IP and key path for SSH access later
            config['redirector_ip'] = get_aws_instance_ip(redirector_name, config)
            config['redirector_key_path'] = f"~/.ssh/{ssh_key_name}.pem"
            
        elif extra_vars['c2_only']:
            playbook = "AWS/c2.yml"
            cmd = f"ansible-playbook -i {inventory_file} {playbook} -e '{extra_vars_str} {ami_map_str}'"
            
            with open(log_file, 'a') as f:
                f.write(f"==== RUNNING C2 PLAYBOOK ====\n")
                f.write(f"Command: {cmd}\n\n")
            
            print(f"[+] Running: {cmd}")
            success, stdout, stderr = run_command_with_logging(cmd, config, log_file)
            if not success:
                print(f"[-] C2 server deployment failed. See {log_file} for details.")
                # Track created resources for cleanup
                try:
                    # Get instance ID for cleanup
                    instance_id = get_aws_instance_id(c2_name, config)
                    if instance_id:
                        deployed_instances.append((c2_name, instance_id))
                    # Also add key pair to resources for cleanup
                    deployed_resources.append(("key_pair", ssh_key_name))
                except Exception as e:
                    print(f"[!] Failed to get instance ID: {e}")
                return False, [log_file], deployed_instances + deployed_resources
            
            # Track deployed instances and resources
            instance_id = get_aws_instance_id(c2_name, config)
            if instance_id:
                deployed_instances.append((c2_name, instance_id))
            deployed_resources.append(("key_pair", ssh_key_name))
            
            # Store C2 IP and key path for SSH access later
            config['c2_ip'] = get_aws_instance_ip(c2_name, config)
            config['c2_key_path'] = f"~/.ssh/{ssh_key_name}.pem"
            
        else:
            # For full deployment, run redirector first, then C2
            # First deploy redirector
            redirector_cmd = f"ansible-playbook -i {inventory_file} AWS/redirector.yml -e '{extra_vars_str} {ami_map_str}'"
            
            with open(log_file, 'a') as f:
                f.write(f"==== RUNNING REDIRECTOR PLAYBOOK (FULL DEPLOYMENT) ====\n")
                f.write(f"Command: {redirector_cmd}\n\n")
            
            print(f"[+] Running: {redirector_cmd}")
            success, stdout, stderr = run_command_with_logging(redirector_cmd, config, log_file)
            if not success:
                print(f"[-] Redirector deployment failed. See {log_file} for details.")
                # Track created resources for cleanup
                try:
                    # Get instance ID for cleanup
                    instance_id = get_aws_instance_id(redirector_name, config)
                    if instance_id:
                        deployed_instances.append((redirector_name, instance_id))
                    # Also add key pair to resources for cleanup
                    deployed_resources.append(("key_pair", ssh_key_name))
                except Exception as e:
                    print(f"[!] Failed to get instance ID: {e}")
                return False, [log_file], deployed_instances + deployed_resources
            
            # Track deployed redirector
            instance_id = get_aws_instance_id(redirector_name, config)
            if instance_id:
                deployed_instances.append((redirector_name, instance_id))
            
            # Get and store redirector IP for C2 configuration
            redirector_ip = get_aws_instance_ip(redirector_name, config)
            config['redirector_ip'] = redirector_ip
            config['redirector_key_path'] = f"~/.ssh/{ssh_key_name}.pem"
            
            # Update extra vars with redirector IP
            extra_vars['redirector_ip'] = redirector_ip
            extra_vars_list.append(f"redirector_ip='{redirector_ip}'")
            extra_vars_str = " ".join(extra_vars_list)
            
            # Log updated extra_vars
            with open(log_file, 'a') as f:
                f.write(f"==== UPDATED EXTRA VARS WITH REDIRECTOR IP ====\n")
                f.write(f"redirector_ip: {redirector_ip}\n")
                f.write(f"==== END UPDATED EXTRA VARS ====\n\n")
            
            # Then deploy C2 server with redirector IP
            c2_cmd = f"ansible-playbook -i {inventory_file} AWS/c2.yml -e '{extra_vars_str} {ami_map_str}'"
            
            with open(log_file, 'a') as f:
                f.write(f"==== RUNNING C2 PLAYBOOK (FULL DEPLOYMENT) ====\n")
                f.write(f"Command: {c2_cmd}\n\n")
            
            print(f"[+] Running: {c2_cmd}")
            success, stdout, stderr = run_command_with_logging(c2_cmd, config, log_file)
            if not success:
                print(f"[-] C2 server deployment failed. See {log_file} for details.")
                # Track created resources for cleanup
                try:
                    # Get instance ID for cleanup
                    instance_id = get_aws_instance_id(c2_name, config)
                    if instance_id:
                        deployed_instances.append((c2_name, instance_id))
                except Exception as e:
                    print(f"[!] Failed to get instance ID: {e}")
                return False, [log_file], deployed_instances + deployed_resources
            
            # Track deployed C2
            instance_id = get_aws_instance_id(c2_name, config)
            if instance_id:
                deployed_instances.append((c2_name, instance_id))
            
            # Add key pair to resources
            deployed_resources.append(("key_pair", ssh_key_name))
            
            # Store C2 IP and key path for SSH access later
            config['c2_ip'] = get_aws_instance_ip(c2_name, config)
            config['c2_key_path'] = f"~/.ssh/{ssh_key_name}.pem"
        
        # Deploy tracker if requested
        if config.get('deploy_tracker'):
            with open(log_file, 'a') as f:
                f.write(f"==== DEPLOYING TRACKER MODULE ====\n")
            
            tracker_success = deploy_tracker_module(config)
            
            with open(log_file, 'a') as f:
                f.write(f"Tracker deployment {'succeeded' if tracker_success else 'failed'}\n")
                f.write(f"==== END TRACKER DEPLOYMENT ====\n\n")
            
            if not tracker_success:
                print("[!] Warning: Tracker deployment failed, but continuing with main deployment")
        
        print("[+] AWS infrastructure deployed successfully!")
        success = True
        
        # Log success
        with open(log_file, 'a') as f:
            f.write(f"==== DEPLOYMENT SUCCESSFUL ====\n")
            f.write(f"Deployed instances: {', '.join([n for n, _ in deployed_instances])}\n")
            f.write(f"Deployed resources: {', '.join([f'{t}: {n}' for t, n in deployed_resources])}\n")
            if 'redirector_ip' in config:
                f.write(f"Redirector IP: {config['redirector_ip']}\n")
            if 'c2_ip' in config:
                f.write(f"C2 IP: {config['c2_ip']}\n")
            f.write(f"==== END DEPLOYMENT SUCCESS ====\n\n")
        
        return success, [log_file], deployed_instances + deployed_resources
        
    except Exception as e:
        # Log exception details
        with open(log_file, 'a') as f:
            f.write(f"==== DEPLOYMENT ERROR ====\n")
            f.write(f"Error: {str(e)}\n")
            import traceback
            f.write(f"Traceback: {traceback.format_exc()}\n")
            f.write(f"==== END DEPLOYMENT ERROR ====\n\n")
        
        print(f"[-] Error: Failed to deploy AWS infrastructure: {e}")
        
        return False, [log_file], deployed_instances + deployed_resources
        
    finally:
        # Clean up temporary inventory file
        if os.path.exists(inventory_file):
            with open(log_file, 'a') as f:
                f.write(f"==== REMOVING INVENTORY FILE ====\n")
                f.write(f"Removing file: {inventory_file}\n")
            
            os.remove(inventory_file)
            
            with open(log_file, 'a') as f:
                f.write(f"Inventory file removed successfully\n")
                f.write(f"==== END REMOVAL ====\n\n")
        
        # If failure, clean up deployed instances
        if not success and (deployed_instances or deployed_resources):
            with open(log_file, 'a') as f:
                f.write(f"==== CLEANING UP DEPLOYED RESOURCES ====\n")
            
            print(f"[!] Cleaning up deployed resources due to failure...")
            
            # Clean up EC2 instances
            for instance_name, instance_id in deployed_instances:
                with open(log_file, 'a') as f:
                    f.write(f"Cleaning up instance: {instance_name} (ID: {instance_id})\n")
                
                try:
                    cleanup_cmd = f"aws ec2 terminate-instances --instance-ids {instance_id} --region {config.get('aws_region')}"
                    print(f"[+] Running cleanup command: {cleanup_cmd}")
                    subprocess.run(cleanup_cmd, shell=True, check=False)
                    print(f"[+] Terminated instance: {instance_name}")
                    
                    with open(log_file, 'a') as f:
                        f.write(f"Instance {instance_name} terminated successfully\n")
                except Exception as cleanup_err:
                    print(f"[!] Failed to terminate instance {instance_name}: {cleanup_err}")
                    
                    with open(log_file, 'a') as f:
                        f.write(f"Failed to terminate instance {instance_name}: {cleanup_err}\n")
            
            # Clean up other AWS resources (key pairs, etc.)
            for resource_type, resource_name in deployed_resources:
                with open(log_file, 'a') as f:
                    f.write(f"Cleaning up {resource_type}: {resource_name}\n")
                
                try:
                    if resource_type == "key_pair":
                        cleanup_cmd = f"aws ec2 delete-key-pair --key-name {resource_name} --region {config.get('aws_region')}"
                        print(f"[+] Running cleanup command: {cleanup_cmd}")
                        subprocess.run(cleanup_cmd, shell=True, check=False)
                        print(f"[+] Deleted key pair: {resource_name}")
                        
                        # Also remove local key file
                        local_key_path = f"~/.ssh/{resource_name}.pem"
                        expanded_path = os.path.expanduser(local_key_path)
                        if os.path.exists(expanded_path):
                            os.remove(expanded_path)
                            print(f"[+] Removed local key file: {local_key_path}")
                        
                        with open(log_file, 'a') as f:
                            f.write(f"{resource_type} {resource_name} deleted successfully\n")
                    # Add more resource types here if needed
                except Exception as cleanup_err:
                    print(f"[!] Failed to clean up {resource_type} {resource_name}: {cleanup_err}")
                    
                    with open(log_file, 'a') as f:
                        f.write(f"Failed to clean up {resource_type} {resource_name}: {cleanup_err}\n")
            
            with open(log_file, 'a') as f:
                f.write(f"==== END CLEANUP ====\n\n")

def deploy_linode(config):
    """Deploy infrastructure using Linode provider with improved logging"""
    print("[+] Deploying Linode infrastructure...")
    
    # Set Linode environment variables
    os.environ['LINODE_TOKEN'] = config['linode_token']
    
    # Prepare SSH key
    ssh_key, ssh_key_content = prepare_ssh_key(config)
    if not ssh_key or not ssh_key_content:
        print("[-] Failed to prepare SSH key, aborting deployment")
        return False, [], []
    
    # Create logs directory
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Only create one log file in the logs directory
    log_file = os.path.join(log_dir, f"deployment_{timestamp}_linode.log")
    
    print(f"[+] Creating deployment log at: {log_file}")
    
    # Create a temporary inventory file for Ansible with detailed logging
    inventory_file = f"inventory_linode_{int(time.time())}.yml"
    with open(log_file, 'a') as f:
        f.write(f"==== CREATING INVENTORY FILE: {inventory_file} ====\n")
    
    deployed_instances = []
    success = False
    
    try:
        # Write inventory file
        with open(inventory_file, 'w') as f:
            f.write("---\n")
            f.write("all:\n")
            f.write("  vars:\n")
            f.write(f"    ansible_ssh_private_key_file: {ssh_key}\n")
            f.write(f"    ansible_user: {config.get('ssh_user', 'root')}\n")
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
        
        # Log inventory file content
        with open(log_file, 'a') as f:
            f.write(f"INVENTORY CONTENT:\n")
            with open(inventory_file, 'r') as inv:
                f.write(inv.read())
            f.write("\n==== END INVENTORY FILE ====\n\n")
        
        # Generate default names if not provided
        rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        timestamp = int(time.time()) % 10000  # Last 4 digits of timestamp
        redirector_name = config.get('redirector_name', f"srv-{rand_suffix}-{timestamp}")
        c2_name = config.get('c2_name', f"node-{rand_suffix}-{timestamp}")
        
        # Update config with generated names for logging
        config['redirector_name'] = redirector_name
        config['c2_name'] = c2_name
        
        # Log important information
        with open(log_file, 'a') as f:
            f.write(f"==== DEPLOYMENT INFORMATION ====\n")
            f.write(f"SSH Key: {ssh_key}\n")
            f.write(f"Redirector Name: {redirector_name}\n")
            f.write(f"C2 Name: {c2_name}\n")
            f.write(f"Domain: {config.get('domain', 'example.com')}\n")
            f.write(f"==== END DEPLOYMENT INFORMATION ====\n\n")
        
        # Create vars.yml file for Ansible with variables
        vars_file = f"temp_vars_{int(time.time())}.yml"
        with open(vars_file, 'w') as f:
            # Essential variables that must match playbook expectations
            f.write(f"---\n")
            f.write(f"linode_token: '{config['linode_token']}'\n")
            f.write(f"redirector_name: '{redirector_name}'\n")
            f.write(f"c2_name: '{c2_name}'\n")
            f.write(f"region: '{config.get('linode_region', 'us-east')}'\n")
            f.write(f"plan: '{config.get('size', 'g6-standard-1')}'\n")
            f.write(f"domain: '{config.get('domain', 'example.com')}'\n")
            f.write(f"letsencrypt_email: '{config.get('letsencrypt_email', 'admin@example.com')}'\n")
            f.write(f"gophish_admin_port: '{config.get('gophish_admin_port', str(random.randint(2000, 9000)))}'\n")
            f.write(f"smtp_auth_user: '{config.get('smtp_auth_user', f'user{random.randint(1000, 9999)}')}'\n")
            # Only use alphanumeric characters for password to avoid escaping issues
            password = config.get('smtp_auth_pass', ''.join(random.choices(string.ascii_letters + string.digits, k=20)))
            f.write(f"smtp_auth_pass: '{password}'\n")
            f.write(f"ssh_key_path: '{ssh_key}'\n")
            f.write(f"ssh_user: '{config.get('ssh_user', 'root')}'\n")
            f.write(f"instance_label: '{c2_name if config.get('c2_only', False) else redirector_name}'\n")
            f.write(f"linode_image: 'linode/debian11'\n")
            # Boolean values
            f.write(f"teardown: {str(config.get('teardown', False)).lower()}\n")
            f.write(f"disable_history: {str(config.get('disable_history', True)).lower()}\n")
            f.write(f"secure_memory: {str(config.get('secure_memory', True)).lower()}\n")
            f.write(f"zero_logs: {str(config.get('zero_logs', True)).lower()}\n")
            f.write(f"redirector_only: {str(config.get('redirector_only', False)).lower()}\n")
            f.write(f"c2_only: {str(config.get('c2_only', False)).lower()}\n")
            f.write(f"debug: {str(config.get('debug', False)).lower()}\n")
        
        # Make the vars file readable only by owner
        os.chmod(vars_file, 0o600)
        
        # Log vars file creation
        with open(log_file, 'a') as f:
            f.write(f"==== CREATED VARS FILE: {vars_file} ====\n")
            f.write(f"(File contains sensitive data, not logging content)\n")
            f.write(f"==== END VARS FILE INFO ====\n\n")
        
        try:
            # Execute deployment based on deployment mode
            if config.get('redirector_only', False):
                playbook = "Linode/redirector.yml"
                cmd = f"ansible-playbook -i {inventory_file} {playbook} -e @{vars_file} -v"
                
                with open(log_file, 'a') as f:
                    f.write(f"==== RUNNING REDIRECTOR PLAYBOOK ====\n")
                    f.write(f"Command: {cmd}\n\n")
                
                print(f"[+] Running: {cmd}")
                success, stdout, stderr = run_command_with_logging(cmd, config, log_file)
                if not success:
                    print(f"[-] Redirector deployment failed. See {log_file} for details.")
                    # Get the deployed instance ID for cleanup - only if actually created
                    try:
                        linode_id = get_linode_id(redirector_name, config)
                        if linode_id:
                            deployed_instances.append((redirector_name, linode_id))
                    except Exception as e:
                        print(f"[!] Note: No instance to clean up: {e}")
                    return False, [log_file], deployed_instances
                
                # Store redirector IP and key path for SSH access later
                try:
                    linode_id = get_linode_id(redirector_name, config)
                    if linode_id:
                        deployed_instances.append((redirector_name, linode_id))
                        config['redirector_ip'] = get_linode_ip(linode_id, config)
                        config['redirector_key_path'] = ssh_key
                except Exception as e:
                    print(f"[!] Warning: Failed to get redirector IP: {e}")
                
            elif config.get('c2_only', False):
                playbook = "Linode/c2.yml"
                cmd = f"ansible-playbook -i {inventory_file} {playbook} -e @{vars_file} -v"
                
                with open(log_file, 'a') as f:
                    f.write(f"==== RUNNING C2 PLAYBOOK ====\n")
                    f.write(f"Command: {cmd}\n\n")
                
                print(f"[+] Running: {cmd}")
                success, stdout, stderr = run_command_with_logging(cmd, config, log_file)
                if not success:
                    print(f"[-] C2 server deployment failed. See {log_file} for details.")
                    # Get the deployed instance ID for cleanup - only if actually created
                    try:
                        linode_id = get_linode_id(c2_name, config)
                        if linode_id:
                            deployed_instances.append((c2_name, linode_id))
                    except Exception as e:
                        print(f"[!] Note: No instance to clean up: {e}")
                    return False, [log_file], deployed_instances
                
                # Store C2 IP and key path for SSH access later
                try:
                    linode_id = get_linode_id(c2_name, config)
                    if linode_id:
                        deployed_instances.append((c2_name, linode_id))
                        config['c2_ip'] = get_linode_ip(linode_id, config)
                        config['c2_key_path'] = ssh_key
                except Exception as e:
                    print(f"[!] Warning: Failed to get C2 IP: {e}")
                
            else:
                # For full deployment, run redirector first, then C2
                redirector_cmd = f"ansible-playbook -i {inventory_file} Linode/redirector.yml -e @{redirector_name} -v"
                
                with open(log_file, 'a') as f:
                    f.write(f"==== RUNNING REDIRECTOR PLAYBOOK (FULL DEPLOYMENT) ====\n")
                    f.write(f"Command: {redirector_cmd}\n\n")
                
                print(f"[+] Running: {redirector_cmd}")
                success, stdout, stderr = run_command_with_logging(redirector_cmd, config, log_file)
                if not success:
                    print(f"[-] Redirector deployment failed. See {log_file} for details.")
                    # Get the deployed instance ID for cleanup - only if actually created
                    try:
                        linode_id = get_linode_id(redirector_name, config)
                        if linode_id:
                            deployed_instances.append((redirector_name, linode_id))
                    except Exception as e:
                        print(f"[!] Note: No instance to clean up: {e}")
                    return False, [log_file], deployed_instances
                    
                # Get and store redirector IP for C2 configuration
                try:
                    linode_id = get_linode_id(redirector_name, config)
                    if linode_id:
                        deployed_instances.append((redirector_name, linode_id))
                        redirector_ip = get_linode_ip(linode_id, config)
                        config['redirector_ip'] = redirector_ip
                        config['redirector_key_path'] = ssh_key
                        
                        # Update vars file with redirector IP
                        with open(vars_file, 'a') as f:
                            f.write(f"redirector_ip: '{redirector_ip}'\n")
                            
                        with open(log_file, 'a') as f:
                            f.write(f"==== UPDATED VARS FILE WITH REDIRECTOR IP ====\n")
                            f.write(f"redirector_ip: {redirector_ip}\n")
                            f.write(f"==== END UPDATED VARS ====\n\n")
                except Exception as e:
                    print(f"[!] Warning: Failed to get redirector IP: {e}")
                    return False, [log_file], deployed_instances
                
                # Then deploy C2 server with redirector IP
                c2_cmd = f"ansible-playbook -i {inventory_file} Linode/c2.yml -e @{vars_file} -v"
                
                with open(log_file, 'a') as f:
                    f.write(f"==== RUNNING C2 PLAYBOOK (FULL DEPLOYMENT) ====\n")
                    f.write(f"Command: {c2_cmd}\n\n")
                
                print(f"[+] Running: {c2_cmd}")
                success, stdout, stderr = run_command_with_logging(c2_cmd, config, log_file)
                if not success:
                    print(f"[-] C2 server deployment failed. See {log_file} for details.")
                    # Get the deployed instance ID for cleanup - only if actually created
                    try:
                        linode_id = get_linode_id(c2_name, config)
                        if linode_id:
                            deployed_instances.append((c2_name, linode_id))
                    except Exception as e:
                        print(f"[!] Note: No instance to clean up: {e}")
                    return False, [log_file], deployed_instances
                
                # Store C2 IP and key path for SSH access later
                try:
                    linode_id = get_linode_id(c2_name, config)
                    if linode_id:
                        deployed_instances.append((c2_name, linode_id))
                        config['c2_ip'] = get_linode_ip(linode_id, config)
                        config['c2_key_path'] = ssh_key
                except Exception as e:
                    print(f"[!] Warning: Failed to get C2 IP: {e}")
                
        finally:
            # Securely remove the vars file
            try:
                if os.path.exists(vars_file):
                    # Overwrite with random data before removing
                    with open(vars_file, 'wb') as f:
                        f.write(os.urandom(1024))
                    os.remove(vars_file)
                    with open(log_file, 'a') as f:
                        f.write(f"==== SECURELY REMOVED VARS FILE ====\n")
            except Exception as e:
                print(f"[!] Warning: Failed to clean up vars file: {e}")
        
        # Deploy tracker if requested
        if config.get('deploy_tracker'):
            with open(log_file, 'a') as f:
                f.write(f"==== DEPLOYING TRACKER MODULE ====\n")
            
            tracker_success = deploy_tracker_module(config)
            
            with open(log_file, 'a') as f:
                f.write(f"Tracker deployment {'succeeded' if tracker_success else 'failed'}\n")
                f.write(f"==== END TRACKER DEPLOYMENT ====\n\n")
            
            if not tracker_success:
                print("[!] Warning: Tracker deployment failed, but continuing with main deployment")
        
        print("[+] Linode infrastructure deployed successfully!")
        success = True
        
        # Log success
        with open(log_file, 'a') as f:
            f.write(f"==== DEPLOYMENT SUCCESSFUL ====\n")
            f.write(f"Deployed instances: {', '.join([n for n, _ in deployed_instances])}\n")
            if 'redirector_ip' in config:
                f.write(f"Redirector IP: {config['redirector_ip']}\n")
            if 'c2_ip' in config:
                f.write(f"C2 IP: {config['c2_ip']}\n")
            f.write(f"==== END DEPLOYMENT SUCCESS ====\n\n")
        
        return success, [log_file], deployed_instances
        
    except Exception as e:
        # Log exception details
        with open(log_file, 'a') as f:
            f.write(f"==== DEPLOYMENT ERROR ====\n")
            f.write(f"Error: {str(e)}\n")
            import traceback
            f.write(f"Traceback: {traceback.format_exc()}\n")
            f.write(f"==== END DEPLOYMENT ERROR ====\n\n")
        
        print(f"[-] Error: Failed to deploy Linode infrastructure: {e}")
        
        # Additional error information
        with open(log_file, 'a') as f:
            f.write(f"Failed deployment, deployed instances that need cleanup: {deployed_instances}\n")
        
        return False, [log_file], deployed_instances
        
    finally:
        # Clean up temporary inventory file
        if os.path.exists(inventory_file):
            with open(log_file, 'a') as f:
                f.write(f"==== REMOVING INVENTORY FILE ====\n")
                f.write(f"Removing file: {inventory_file}\n")
            
            os.remove(inventory_file)
            
            with open(log_file, 'a') as f:
                f.write(f"Inventory file removed successfully\n")
                f.write(f"==== END REMOVAL ====\n\n")
        
        # If failure, clean up deployed instances with better error handling
        if not success and deployed_instances:
            with open(log_file, 'a') as f:
                f.write(f"==== CLEANING UP DEPLOYED INSTANCES ====\n")
            
            print(f"[!] Cleaning up deployed instances due to failure...")
            
            for instance_name, instance_id in deployed_instances:
                with open(log_file, 'a') as f:
                    f.write(f"Checking if instance exists: {instance_name} (ID: {instance_id})\n")
                
                # First verify if the instance actually exists before attempting deletion
                instance_exists = False
                try:
                    # Check if instance exists
                    check_cmd = f"linode-cli linodes list --json --label {instance_name}"
                    result = subprocess.run(check_cmd, shell=True, check=False, capture_output=True, text=True)
                    if result.returncode == 0 and result.stdout.strip() != "[]" and result.stdout.strip() != "":
                        instance_exists = True
                        with open(log_file, 'a') as f:
                            f.write(f"Instance {instance_name} exists and will be deleted\n")
                    else:
                        with open(log_file, 'a') as f:
                            f.write(f"Instance {instance_name} doesn't exist or already deleted\n")
                except Exception as check_err:
                    print(f"[!] Error checking if instance exists: {check_err}")
                    with open(log_file, 'a') as f:
                        f.write(f"Error checking instance: {check_err}\n")
                
                # Only attempt deletion if the instance exists
                if instance_exists:
                    try:
                        cleanup_cmd = f"linode-cli linodes delete {instance_id} --yes"
                        print(f"[+] Running cleanup command: {cleanup_cmd}")
                        subprocess.run(cleanup_cmd, shell=True, check=False)
                        print(f"[+] Deleted instance: {instance_name}")
                        
                        with open(log_file, 'a') as f:
                            f.write(f"Instance {instance_name} deleted successfully\n")
                    except Exception as cleanup_err:
                        print(f"[!] Failed to delete instance {instance_name}: {cleanup_err}")
                        
                        with open(log_file, 'a') as f:
                            f.write(f"Failed to delete instance {instance_name}: {cleanup_err}\n")
            
            with open(log_file, 'a') as f:
                f.write(f"==== END CLEANUP ====\n\n")
        
        # If this is a new key and deployment failed, remove it
        if not success and ssh_key and ssh_key.startswith(os.path.expanduser("~/.ssh/c2itall_")):
            try:
                with open(log_file, 'a') as f:
                    f.write(f"==== REMOVING GENERATED SSH KEY ====\n")
                    f.write(f"Removing SSH key: {ssh_key}\n")
                
                os.remove(ssh_key)
                if os.path.exists(f"{ssh_key}.pub"):
                    os.remove(f"{ssh_key}.pub")
                print(f"[+] Removed generated SSH key due to deployment failure")
                
                with open(log_file, 'a') as f:
                    f.write(f"SSH key removed successfully\n")
                    f.write(f"==== END SSH KEY REMOVAL ====\n\n")
            except Exception as key_err:
                print(f"[!] Failed to remove SSH key {ssh_key}: {key_err}")
                
                with open(log_file, 'a') as f:
                    f.write(f"Failed to remove SSH key: {key_err}\n")
                    f.write(f"==== END SSH KEY REMOVAL ====\n\n")

def deploy_flokinet(config):
    """Deploy infrastructure using FlokiNET provider"""
    print("[+] Deploying FlokiNET infrastructure...")
    
    # Prepare SSH key
    ssh_key, ssh_key_content = prepare_ssh_key(config)
    if not ssh_key or not ssh_key_content:
        print("[-] Failed to prepare SSH key, aborting deployment")
        return False, [], []
    
    # Create logs directory
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Only create one log file in the logs directory
    log_file = os.path.join(log_dir, f"deployment_{timestamp}_flokinet.log")
    
    print(f"[+] Creating deployment log at: {log_file}")
    
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
            return False, [], []
        # Use a placeholder for C2 if we're only deploying redirector
        c2_ip = "127.0.0.1"
    
    elif config['c2_only'] and not c2_ip:
        c2_ip = input("[?] Enter FlokiNET C2 server IP address: ")
        if not c2_ip:
            print("[-] Error: C2 server IP is required for deployment")
            return False, [], []
        
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
                    return False, [], []
    
    # Full deployment - need both IPs
    elif not config['redirector_only'] and not config['c2_only']:
        if not redirector_ip:
            redirector_ip = input("[?] Enter FlokiNET redirector IP address: ")
        if not c2_ip:
            c2_ip = input("[?] Enter FlokiNET C2 server IP address: ")
        
        if not redirector_ip or not c2_ip:
            print("[-] Error: Both redirector and C2 IPs are required for full deployment")
            return False, [], []
    
    # Update config with obtained IPs
    config['flokinet_redirector_ip'] = redirector_ip
    config['flokinet_c2_ip'] = c2_ip
    
    # Create FlokiNET directory if it doesn't exist
    if not os.path.exists('FlokiNET'):
        print("[+] Creating FlokiNET directory structure...")
        os.makedirs('FlokiNET', exist_ok=True)
    
    # Prepare vars.yaml with dynamic IPs
    prepare_flokinet_vars(config)
    
    # Log important information
    with open(log_file, 'a') as f:
        f.write(f"==== DEPLOYMENT INFORMATION ====\n")
        f.write(f"SSH Key: {ssh_key}\n")
        f.write(f"SSH Port: {ssh_port}\n")
        f.write(f"Redirector IP: {redirector_ip}\n")
        f.write(f"C2 IP: {c2_ip}\n")
        f.write(f"Domain: {config.get('domain', 'example.com')}\n")
        f.write(f"==== END DEPLOYMENT INFORMATION ====\n\n")
    
    # Create temporary inventory files for Ansible with randomized names for OPSEC
    inventory_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    redirector_inventory = None
    c2_inventory = None
    
    deployed_resources = []
    success = False
    
    try:
        # Track resources for potential cleanup
        deployed_resources = [
            ("redirector_ip", redirector_ip),
            ("c2_ip", c2_ip)
        ]
        
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
                f.write(f"      ansible_ssh_private_key_file: {ssh_key}\n")
                f.write(f"      ansible_python_interpreter: /usr/bin/python3\n")
                f.write(f"      ansible_port: {ssh_port}\n")  # Use custom SSH port
            
            # Log inventory file content
            with open(log_file, 'a') as f:
                f.write(f"==== REDIRECTOR INVENTORY: {redirector_inventory} ====\n")
                with open(redirector_inventory, 'r') as inv:
                    f.write(inv.read())
                f.write("\n==== END REDIRECTOR INVENTORY ====\n\n")
        
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
                f.write(f"      ansible_ssh_private_key_file: {ssh_key}\n")
                f.write(f"      ansible_python_interpreter: /usr/bin/python3\n")
                f.write(f"      ansible_port: {ssh_port}\n")  # Use custom SSH port
            
            # Log inventory file content
            with open(log_file, 'a') as f:
                f.write(f"==== C2 INVENTORY: {c2_inventory} ====\n")
                with open(c2_inventory, 'r') as inv:
                    f.write(inv.read())
                f.write("\n==== END C2 INVENTORY ====\n\n")
        
        # Build extra vars string
        extra_vars = {
            'redirector_ip': redirector_ip,
            'c2_ip': c2_ip,
            'disable_history': config.get('disable_history', True),
            'secure_memory': config.get('secure_memory', True),
            'zero_logs': config.get('zero_logs', True),
            'domain': config.get('domain', 'example.com'),
            'letsencrypt_email': config.get('letsencrypt_email', 'admin@example.com'),
            'gophish_admin_port': config.get('gophish_admin_port', str(random.randint(2000, 9000))),
            'smtp_auth_user': config.get('smtp_auth_user', f"user{random.randint(1000, 9999)}"),
            'smtp_auth_pass': config.get('smtp_auth_pass', ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=20))),
            'ssh_port': ssh_port,
            'ssh_key_path': ssh_key,
            'ssh_user': config.get('ssh_user', 'root'),
        }
        
        # Format extra vars for command line, handling special characters
        extra_vars_list = []
        for k, v in extra_vars.items():
            if isinstance(v, bool):
                extra_vars_list.append(f"{k}={str(v).lower()}")
            elif isinstance(v, (int, float)):
                extra_vars_list.append(f"{k}={v}")
            elif isinstance(v, str):
                # Escape quotes in string values
                escaped_v = v.replace("'", "'\\''")
                extra_vars_list.append(f"{k}='{escaped_v}'")
        
        extra_vars_str = " ".join(extra_vars_list)
        
        # Log extra vars for debugging (masking sensitive info)
        with open(log_file, 'a') as f:
            f.write("==== EXTRA VARS ====\n")
            for k, v in extra_vars.items():
                if k in ['smtp_auth_pass']:
                    v_masked = str(v)[:4] + '****' if v else 'None'
                    f.write(f"{k}: {v_masked}\n")
                else:
                    f.write(f"{k}: {v}\n")
            f.write("==== END EXTRA VARS ====\n\n")
        
        # Common provisioning for both servers
        if not config['c2_only'] and redirector_inventory:
            print("[+] Provisioning FlokiNET redirector...")
            cmd = f"ansible-playbook -i {redirector_inventory} FlokiNET/provision.yml -e '{extra_vars_str}'"
            
            with open(log_file, 'a') as f:
                f.write(f"==== RUNNING REDIRECTOR PROVISION PLAYBOOK ====\n")
                f.write(f"Command: {cmd}\n\n")
            
            if config['debug']:
                print(f"[+] Running: {cmd}")
                
            success, stdout, stderr = run_command_with_logging(cmd, config, log_file)
            if not success:
                print(f"[-] Redirector provisioning failed. See {log_file} for details.")
                return False, [log_file], deployed_resources
            
            # Run redirector-specific playbook
            print("[+] Configuring FlokiNET redirector...")
            cmd = f"ansible-playbook -i {redirector_inventory} FlokiNET/redirector.yml -e '{extra_vars_str}'"
            
            with open(log_file, 'a') as f:
                f.write(f"==== RUNNING REDIRECTOR CONFIGURATION PLAYBOOK ====\n")
                f.write(f"Command: {cmd}\n\n")
            
            if config['debug']:
                print(f"[+] Running: {cmd}")
                
            success, stdout, stderr = run_command_with_logging(cmd, config, log_file)
            if not success:
                print(f"[-] Redirector configuration failed. See {log_file} for details.")
                return False, [log_file], deployed_resources
            
            # Store SSH key path for later
            config['redirector_ip'] = redirector_ip
            config['redirector_key_path'] = ssh_key
        
        if not config['redirector_only'] and c2_inventory:
            print("[+] Provisioning FlokiNET C2 server...")
            cmd = f"ansible-playbook -i {c2_inventory} FlokiNET/provision.yml -e '{extra_vars_str}'"
            
            with open(log_file, 'a') as f:
                f.write(f"==== RUNNING C2 PROVISION PLAYBOOK ====\n")
                f.write(f"Command: {cmd}\n\n")
            
            if config['debug']:
                print(f"[+] Running: {cmd}")
                
            success, stdout, stderr = run_command_with_logging(cmd, config, log_file)
            if not success:
                print(f"[-] C2 server provisioning failed. See {log_file} for details.")
                return False, [log_file], deployed_resources
            
            # Run C2-specific playbook
            print("[+] Configuring FlokiNET C2 server...")
            cmd = f"ansible-playbook -i {c2_inventory} FlokiNET/c2.yml -e '{extra_vars_str}'"
            
            with open(log_file, 'a') as f:
                f.write(f"==== RUNNING C2 CONFIGURATION PLAYBOOK ====\n")
                f.write(f"Command: {cmd}\n\n")
            
            if config['debug']:
                print(f"[+] Running: {cmd}")
                
            success, stdout, stderr = run_command_with_logging(cmd, config, log_file)
            if not success:
                print(f"[-] C2 server configuration failed. See {log_file} for details.")
                return False, [log_file], deployed_resources
            
            # Store SSH key path for later
            config['c2_ip'] = c2_ip
            config['c2_key_path'] = ssh_key
        
        # Deploy tracker if requested
        if config.get('deploy_tracker'):
            with open(log_file, 'a') as f:
                f.write(f"==== DEPLOYING TRACKER MODULE ====\n")
            
            tracker_success = deploy_tracker_module(config)
            
            with open(log_file, 'a') as f:
                f.write(f"Tracker deployment {'succeeded' if tracker_success else 'failed'}\n")
                f.write(f"==== END TRACKER DEPLOYMENT ====\n\n")
            
            if not tracker_success:
                print("[!] Warning: Tracker deployment failed, but continuing with main deployment")
        
        print("[+] FlokiNET infrastructure deployed successfully!")
        success = True
        
        # Log success
        with open(log_file, 'a') as f:
            f.write(f"==== DEPLOYMENT SUCCESSFUL ====\n")
            if not config['c2_only']:
                f.write(f"Redirector IP: {redirector_ip}\n")
            if not config['redirector_only']:
                f.write(f"C2 IP: {c2_ip}\n")
            f.write(f"==== END DEPLOYMENT SUCCESS ====\n\n")
        
        return success, [log_file], deployed_resources
    
    except Exception as e:
        # Log exception details
        with open(log_file, 'a') as f:
            f.write(f"==== DEPLOYMENT ERROR ====\n")
            f.write(f"Error: {str(e)}\n")
            import traceback
            f.write(f"Traceback: {traceback.format_exc()}\n")
            f.write(f"==== END DEPLOYMENT ERROR ====\n\n")
        
        print(f"[-] Error: Failed to deploy FlokiNET infrastructure: {e}")
        
        return False, [log_file], deployed_resources
    
    finally:
        # Clean up temporary inventory files
        for inv_file in [redirector_inventory, c2_inventory]:
            if inv_file and os.path.exists(inv_file):
                # Securely overwrite before removal for better OPSEC
                with open(inv_file, 'w') as f:
                    f.write('\0' * 1024)  # Overwrite with null bytes
                os.remove(inv_file)
                
                with open(log_file, 'a') as f:
                    f.write(f"Inventory file {inv_file} removed successfully\n")
                
                if config.get('debug'):
                    print(f"[+] Removed temporary inventory file: {inv_file}")
        
        # If this is a new key and deployment failed, remove it
        if not success and ssh_key and ssh_key.startswith(os.path.expanduser("~/.ssh/c2itall_")):
            try:
                with open(log_file, 'a') as f:
                    f.write(f"==== REMOVING GENERATED SSH KEY ====\n")
                    f.write(f"Removing SSH key: {ssh_key}\n")
                
                os.remove(ssh_key)
                if os.path.exists(f"{ssh_key}.pub"):
                    os.remove(f"{ssh_key}.pub")
                print(f"[+] Removed generated SSH key due to deployment failure")
                
                with open(log_file, 'a') as f:
                    f.write(f"SSH key removed successfully\n")
                    f.write(f"==== END SSH KEY REMOVAL ====\n\n")
            except Exception as key_err:
                print(f"[!] Failed to remove SSH key {ssh_key}: {key_err}")
                
                with open(log_file, 'a') as f:
                    f.write(f"Failed to remove SSH key: {key_err}\n")
                    f.write(f"==== END SSH KEY REMOVAL ====\n\n")

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
        'AWS': ['redirector.yml', 'c2.yml'],
        'Linode': ['redirector.yml', 'c2.yml'],
        'FlokiNET': ['provision.yml', 'redirector.yml', 'c2.yml']
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
    for file in required_files.get(provider, []):
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

def generate_random_string(length=12):
    """Generate a random string of letters and digits."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_ssh_key(key_name):
    """Generate an SSH key with the given key name."""
    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, exist_ok=True)

    private_key_path = os.path.join(ssh_dir, key_name)
    public_key_path = f"{private_key_path}.pub"

    print(f"Generating SSH key: {key_name}")
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", private_key_path, "-N", "", "-C", ""],
        check=True
    )

    os.chmod(private_key_path, 0o600)
    return private_key_path, public_key_path

def prepare_ssh_key(config):
    """Prepare and validate SSH key, generating a new one if needed"""
    # Check if SSH key is provided
    ssh_key = config.get('ssh_key')
    
    # If key not provided or doesn't exist, generate a new one
    if not ssh_key or not os.path.exists(os.path.expanduser(ssh_key)):
        if ssh_key and not os.path.exists(os.path.expanduser(ssh_key)):
            print(f"[-] Warning: Specified SSH key {ssh_key} not found")
        
        ssh_key = generate_ssh_key()
        if not ssh_key:
            return None, None
        
        config['ssh_key'] = ssh_key
    
    # Make sure we're using the expanded path
    ssh_key = os.path.expanduser(ssh_key)
    
    # Ensure the public key exists
    ssh_public_key = f"{ssh_key}.pub"
    if not os.path.exists(ssh_public_key):
        print(f"[-] Warning: SSH public key not found at {ssh_public_key}, generating new key pair")
        ssh_key = generate_ssh_key()
        if not ssh_key:
            return None, None
        
        config['ssh_key'] = ssh_key
        ssh_public_key = f"{ssh_key}.pub"
    
    # Read the public key content
    try:
        with open(ssh_public_key, 'r') as f:
            ssh_key_content = f.read().strip()
        
        # Verify and fix permissions
        current_mode = os.stat(ssh_key).st_mode & 0o777
        if current_mode != 0o600:
            print(f"[!] SSH key has incorrect permissions: {oct(current_mode)[2:]}. Fixing to 0600...")
            os.chmod(ssh_key, 0o600)
            print(f"[+] SSH key permissions fixed")
        
        return ssh_key, ssh_key_content
    except Exception as e:
        print(f"[-] Error reading SSH public key: {e}")
        return None, None

def get_instance_ip(instance_name, config):
    """Get the IP address of an EC2 instance by name"""
    try:
        cmd = [
            "aws", "ec2", "describe-instances", 
            "--filters", f"Name=tag:Name,Values={instance_name}", 
            "--query", "Reservations[0].Instances[0].PublicIpAddress", 
            "--output", "text",
            "--region", config.get('aws_region', 'us-east-1')
        ]
        
        result = subprocess.check_output(cmd).decode().strip()
        
        if result == "None" or not result:
            # Try again with a different command format that works better in some AWS CLI versions
            cmd = [
                "aws", "ec2", "describe-instances", 
                "--filters", f"Name=tag:Name,Values={instance_name}",
                "Name=instance-state-name,Values=running",
                "--query", "Reservations[*].Instances[*].PublicIpAddress",
                "--output", "text",
                "--region", config.get('aws_region', 'us-east-1')
            ]
            result = subprocess.check_output(cmd).decode().strip()
            
        if result and result != "None":
            print(f"[+] Found IP address for {instance_name}: {result}")
            return result
        else:
            print(f"[-] Could not find IP address for instance {instance_name}")
            return None
    except subprocess.CalledProcessError as e:
        print(f"[-] Error getting instance IP: {e}")
        return None

def get_linode_id(instance_name, config):
    """Get the ID of a Linode instance by name with better error handling"""
    try:
        cmd = [
            "linode-cli", "--json", "linodes", "list", 
            "--label", instance_name
        ]
        
        result = subprocess.check_output(cmd, stderr=subprocess.PIPE)
        
        # Parse the JSON response
        instances = json.loads(result.decode())
        
        if instances and len(instances) > 0:
            linode_id = instances[0]['id']
            print(f"[+] Found Linode ID for {instance_name}: {linode_id}")
            return linode_id
        else:
            print(f"[*] No Linode instance found with name: {instance_name}")
            return None
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.decode() if e.stderr else "No error output"
        print(f"[*] Linode CLI failed when looking up instance {instance_name}: {error_output}")
        return None
    except json.JSONDecodeError as e:
        print(f"[*] JSON parsing error when looking up instance {instance_name}: {e}")
        return None
    except Exception as e:
        print(f"[*] Unexpected error getting Linode ID for {instance_name}: {e}")
        return None

def get_linode_id(instance_name, config):
    """Get the ID of a Linode instance by name with better error handling"""
    try:
        cmd = [
            "linode-cli", "--json", "linodes", "list", 
            "--label", instance_name
        ]
        
        result = subprocess.check_output(cmd, stderr=subprocess.PIPE)
        
        # Parse the JSON response
        instances = json.loads(result.decode())
        
        if instances and len(instances) > 0:
            linode_id = instances[0]['id']
            print(f"[+] Found Linode ID for {instance_name}: {linode_id}")
            return linode_id
        else:
            print(f"[*] No Linode instance found with name: {instance_name}")
            return None
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.decode() if e.stderr else "No error output"
        print(f"[*] Linode CLI failed when looking up instance {instance_name}: {error_output}")
        return None
    except json.JSONDecodeError as e:
        print(f"[*] JSON parsing error when looking up instance {instance_name}: {e}")
        return None
    except Exception as e:
        print(f"[*] Unexpected error getting Linode ID for {instance_name}: {e}")
        return None

def ssh_to_c2(config):
    """SSH into the C2 server after successful deployment"""
    print("[+] Attempting to SSH into C2 server...")
    
    # Get C2 server details
    c2_ip = config.get('c2_ip')
    key_path = config.get('c2_key_path')
    
    # Check if we have the necessary information
    if not c2_ip:
        print(f"[-] Error: No C2 IP address found")
        return False
    
    if not key_path:
        print(f"[-] Error: No SSH key path found for C2 server")
        return False
    
    # Determine user and port
    user = config.get('ssh_user', 'root')
    port = config.get('ssh_port', 22)
    
    # Wait a few seconds to ensure everything is fully set up
    print(f"[+] Waiting 10 seconds for SSH to be fully ready on {c2_ip}...")
    time.sleep(10)
    
    # Build the SSH command
    ssh_cmd = [
        "ssh", 
        "-i", key_path,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",  # For OPSEC, don't store the host key
    ]
    
    # Add port if not standard
    if port != 22:
        ssh_cmd.extend(["-p", str(port)])
    
    # Add user and host
    ssh_cmd.append(f"{user}@{c2_ip}")
    
    print(f"[+] Connecting to C2 server at {c2_ip}...")
    print(f"[+] SSH command: {' '.join(ssh_cmd)}")
    
    try:
        # Execute SSH command
        subprocess.call(ssh_cmd)
        return True
    except Exception as e:
        print(f"[-] Error SSHing to C2 server: {e}")
        return False


def cleanup_interrupted_deployment(provider, deployed_instances, generated_ssh_keys):
    """Clean up resources after an interrupted deployment"""
    print("[+] Cleaning up deployed resources...")
    
    # Clean up based on provider
    if provider.lower() == 'aws':
        for instance in deployed_instances:
            if isinstance(instance, tuple) and len(instance) >= 2:
                instance_name, instance_id = instance
                try:
                    print(f"[+] Terminating AWS instance: {instance_name} (ID: {instance_id})")
                    cmd = f"aws ec2 terminate-instances --instance-ids {instance_id}"
                    subprocess.run(cmd, shell=True, check=False)
                except Exception as e:
                    print(f"[!] Error terminating AWS instance {instance_name}: {e}")
    
    elif provider.lower() == 'linode':
        for instance in deployed_instances:
            if isinstance(instance, tuple) and len(instance) >= 2:
                instance_name, instance_id = instance
                try:
                    print(f"[+] Deleting Linode instance: {instance_name} (ID: {instance_id})")
                    cmd = f"linode-cli linodes delete {instance_id} --yes"
                    subprocess.run(cmd, shell=True, check=False)
                except Exception as e:
                    print(f"[!] Error deleting Linode instance {instance_name}: {e}")
    
    elif provider.lower() == 'flokinet':
        print("[!] FlokiNET instances must be cleaned up manually through their web interface.")
        print("[!] Please log in to your FlokiNET account and remove the deployed instances.")
    
    # Clean up generated SSH keys
    for ssh_key in generated_ssh_keys:
        try:
            print(f"[+] Removing generated SSH key: {ssh_key}")
            if os.path.exists(ssh_key):
                os.remove(ssh_key)
            if os.path.exists(f"{ssh_key}.pub"):
                os.remove(f"{ssh_key}.pub")
        except Exception as e:
            print(f"[!] Error removing SSH key {ssh_key}: {e}")
    
    print("[+] Cleanup completed.")

def run_command_with_logging(cmd, config, log_file=None):
    """Run a command and log both stdout and stderr to the deployment log"""
    try:
        print(f"[+] Running: {cmd}")
        
        # If no log file specified, create or use the deployment log
        if not log_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, f"deployment_{timestamp}.log")
        
        # Append command to log file
        with open(log_file, 'a') as f:
            f.write(f"\n\n==== COMMAND EXECUTION: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ====\n")
            f.write(f"COMMAND: {cmd}\n\n")
            f.write("OUTPUT:\n")
        
        # Execute the command and capture output
        process = subprocess.Popen(
            cmd, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Read output in real-time
        stdout_data = ""
        stderr_data = ""
        
        # Read and process output
        while True:
            # Use communicate with timeout to avoid hanging
            try:
                # Small timeout to read incrementally
                stdout, stderr = process.communicate(timeout=0.5)
                stdout_data += stdout
                stderr_data += stderr
                
                # Write to log file
                with open(log_file, 'a') as f:
                    if stdout:
                        f.write(f"STDOUT: {stdout}")
                        print(stdout.strip())
                    if stderr:
                        f.write(f"STDERR: {stderr}")
                        print(stderr.strip(), file=sys.stderr)
                
                # If process has completed, break
                if process.poll() is not None:
                    break
                    
            except subprocess.TimeoutExpired:
                # Timeout expired, continue to next iteration
                continue
        
        # Get return code
        return_code = process.poll()
        
        # Log completion status
        with open(log_file, 'a') as f:
            f.write(f"\nRETURN CODE: {return_code}\n")
            f.write(f"==== END COMMAND EXECUTION ====\n\n")
        
        # Check if command succeeded
        if return_code != 0:
            raise subprocess.CalledProcessError(return_code, cmd, stdout_data, stderr_data)
            
        return True, stdout_data, stderr_data
        
    except subprocess.CalledProcessError as e:
        # Log error details
        with open(log_file, 'a') as f:
            f.write(f"\nERROR: Command failed with return code {e.returncode}\n")
            f.write("==== END COMMAND EXECUTION WITH ERROR ====\n\n")
        
        print(f"[-] Command failed with return code {e.returncode}")
        return False, e.stdout, e.stderr
        
    except Exception as e:
        # Log unexpected error
        with open(log_file, 'a') as f:
            f.write(f"\nUNEXPECTED ERROR: {str(e)}\n")
            f.write("==== END COMMAND EXECUTION WITH UNEXPECTED ERROR ====\n\n")
        
        print(f"[-] Unexpected error running command: {e}")
        return False, "", str(e)

def run_tests(config):
    """Run basic connectivity and functionality tests"""
    print("[+] Running connectivity tests...")
    
    # Test both redirector and C2 if both were deployed
    if not config.get('redirector_only') and not config.get('c2_only'):
        # Test redirector first
        redirector_ip = config.get('redirector_ip')
        if redirector_ip:
            print(f"[+] Testing redirector at {redirector_ip}...")
            try:
                # Try to ping the redirector
                ping_cmd = ["ping", "-c", "3", redirector_ip]
                subprocess.run(ping_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print(f"[+] Redirector ping test successful")
                
                # Test SSH connection
                test_ssh(redirector_ip, config.get('redirector_key_path'), config.get('ssh_user', 'root'), config.get('ssh_port', 22))
                
                # Test HTTP(S) connectivity if deployed with a domain
                if config.get('domain') != 'example.com':
                    test_http(f"https://cdn.{config['domain']}")
            except subprocess.CalledProcessError as e:
                print(f"[-] Redirector connectivity test failed: {e}")
        
        # Then test C2
        c2_ip = config.get('c2_ip')
        if c2_ip:
            print(f"[+] Testing C2 server at {c2_ip}...")
            try:
                # Try to ping the C2 server
                ping_cmd = ["ping", "-c", "3", c2_ip]
                subprocess.run(ping_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print(f"[+] C2 server ping test successful")
                
                # Test SSH connection
                test_ssh(c2_ip, config.get('c2_key_path'), config.get('ssh_user', 'root'), config.get('ssh_port', 22))
                
                # Test HTTP(S) connectivity if deployed with a domain
                if config.get('domain') != 'example.com':
                    test_http(f"https://mail.{config['domain']}")
            except subprocess.CalledProcessError as e:
                print(f"[-] C2 server connectivity test failed: {e}")
    
    # Test only redirector if that's all that was deployed
    elif config.get('redirector_only'):
        redirector_ip = config.get('redirector_ip')
        if redirector_ip:
            print(f"[+] Testing redirector at {redirector_ip}...")
            try:
                # Try to ping the redirector
                ping_cmd = ["ping", "-c", "3", redirector_ip]
                subprocess.run(ping_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print(f"[+] Redirector ping test successful")
                
                # Test SSH connection
                test_ssh(redirector_ip, config.get('redirector_key_path'), config.get('ssh_user', 'root'), config.get('ssh_port', 22))
                
                # Test HTTP(S) connectivity if deployed with a domain
                if config.get('domain') != 'example.com':
                    test_http(f"https://cdn.{config['domain']}")
            except subprocess.CalledProcessError as e:
                print(f"[-] Redirector connectivity test failed: {e}")
    
    # Test only C2 if that's all that was deployed
    elif config.get('c2_only'):
        c2_ip = config.get('c2_ip')
        if c2_ip:
            print(f"[+] Testing C2 server at {c2_ip}...")
            try:
                # Try to ping the C2 server
                ping_cmd = ["ping", "-c", "3", c2_ip]
                subprocess.run(ping_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print(f"[+] C2 server ping test successful")
                
                # Test SSH connection
                test_ssh(c2_ip, config.get('c2_key_path'), config.get('ssh_user', 'root'), config.get('ssh_port', 22))
                
                # Test HTTP(S) connectivity if deployed with a domain
                if config.get('domain') != 'example.com':
                    test_http(f"https://mail.{config['domain']}")
            except subprocess.CalledProcessError as e:
                print(f"[-] C2 server connectivity test failed: {e}")
    
    print("[+] Tests completed")
    return True

def test_ssh(ip, key_path, user, port):
    """Test SSH connectivity to a server"""
    print(f"[+] Testing SSH connectivity to {ip}...")
    try:
        # Use the paramiko library for a programmatic SSH connection test
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect with timeout
        client.connect(ip, port=port, username=user, key_filename=key_path, timeout=10)
        
        # Run a simple command to check if the connection works
        stdin, stdout, stderr = client.exec_command("echo SSH test successful")
        response = stdout.read().decode().strip()
        
        # Close the connection
        client.close()
        
        print(f"[+] SSH test result: {response}")
        return True
    except Exception as e:
        print(f"[-] SSH connectivity test failed: {e}")
        return False

def test_http(url):
    """Test HTTP(S) connectivity to a URL"""
    print(f"[+] Testing HTTP(S) connectivity to {url}...")
    try:
        # Use requests library with a timeout
        response = subprocess.run(["curl", "-s", "-k", "-L", "--connect-timeout", "10", url], check=True, stdout=subprocess.PIPE)
        
        # Check if we got a response
        if response.stdout:
            print(f"[+] HTTP(S) test successful")
            return True
        else:
            print(f"[-] HTTP(S) test returned empty response")
            return False
    except subprocess.CalledProcessError as e:
        print(f"[-] HTTP(S) connectivity test failed: {e}")
        return False

def deploy_with_error_handling(provider_func, config):
    """Deploy with better error handling and logs"""
    logs_created = []
    deployed_resources = []
    
    try:
        result, logs, resources = provider_func(config)
        logs_created.extend(logs)
        deployed_resources.extend(resources)
        return result, logs_created, deployed_resources
    except subprocess.CalledProcessError as e:
        # Log detailed error information
        error_log = log_debug_info(e.cmd, e)
        if error_log:
            logs_created.append(error_log)
        print(f"[-] Deployment failed: {e}. See {error_log} for detailed debug information.")
        return False, logs_created, deployed_resources
    except Exception as e:
        error_log = log_debug_info("Unknown command", e)
        if error_log:
            logs_created.append(error_log)
        print(f"[-] Unexpected error during deployment: {e}. See {error_log} for details.")
        return False, logs_created, deployed_resources

def deploy_tracker_module(config):
    """Deploy tracker module alongside the C2 infrastructure"""
    if not config.get('deploy_tracker'):
        return True
    
    print("[+] Deploying tracker module...")
    
    # Make sure the module exists
    tracker_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules/tracker")
    if not os.path.exists(tracker_dir):
        print(f"[-] Error: Tracker module directory not found at {tracker_dir}")
        print("[-] Make sure the tracker module is installed in the modules/tracker directory")
        return False
    
    # Prepare tracker deploy command
    tracker_script = os.path.join(tracker_dir, "Tools/deploy_tracker.py")
    if not os.path.exists(tracker_script):
        print(f"[-] Error: Tracker deployment script not found at {tracker_script}")
        return False
    
    # Build command arguments
    tracker_cmd = [
        "python3", tracker_script,
        "--quick-deploy"  # Use quick deployment mode
    ]
    
    # Add domain if specified
    if config.get('tracker_domain'):
        tracker_cmd.extend(["--domain", config['tracker_domain']])
    else:
        tracker_cmd.append("--ip-only")
    
    # Add email if specified
    if config.get('tracker_email'):
        tracker_cmd.extend(["--email", config['tracker_email']])
    
    # Add tracker name if specified
    if config.get('tracker_name'):
        tracker_cmd.extend(["--engagement-name", config['tracker_name']])
    
    # Add IPinfo token if specified
    if config.get('tracker_ipinfo_token'):
        tracker_cmd.extend(["--ipinfo-token", config['tracker_ipinfo_token']])
    
    # Add SSL setup if requested
    if config.get('tracker_setup_ssl'):
        tracker_cmd.append("--setup-ssl")
    
    # Add tracking pixel creation if requested
    if config.get('tracker_create_pixel'):
        tracker_cmd.append("--create-pixel")
    
    # Run the tracker deployment command
    try:
        print(f"[+] Running tracker deployment: {' '.join(tracker_cmd)}")
        subprocess.run(tracker_cmd, check=True)
        print("[+] Tracker module deployed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Error deploying tracker module: {e}")
        return False

def interactive_config():
    """Interactively collect configuration"""
    config = {}
    
    # Initialize deployment mode flags
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
        
        # Ask for architecture type
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
        
        # Ask for architecture type
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
    
    # Post-deployment options
    print("\n=== Post-Deployment Options ===")
    ssh_after_deploy = input("SSH into instance after deployment? (y/N): ").lower()
    config['ssh_after_deploy'] = ssh_after_deploy.startswith('y')
    
    run_tests = input("Run connectivity tests after deployment? (y/N): ").lower()
    config['run_tests'] = run_tests.startswith('y')
    
    # Tracker module deployment
    print("\n=== Tracker Module ===")
    deploy_tracker = input("Deploy tracker module alongside C2 infrastructure? (y/N): ").lower()
    config['deploy_tracker'] = deploy_tracker.startswith('y')
    
    if config['deploy_tracker']:
        # Additional tracker configuration
        print("\n=== Tracker Configuration ===")
        config['tracker_domain'] = input("Domain for tracker (leave empty to use server IP): ")
        
        if config['tracker_domain']:
            config['tracker_email'] = input(f"Email for tracker Let's Encrypt certificate: ") or config['letsencrypt_email']
            
            setup_ssl = input("Set up SSL for tracker? (Y/n): ").lower() or "y"
            config['tracker_setup_ssl'] = setup_ssl.startswith('y')
        
        config['tracker_name'] = input("Tracker engagement name (leave empty for random): ")
        config['tracker_ipinfo_token'] = input("IPinfo API token for geolocation (optional): ")
        
        create_pixel = input("Create email tracking pixel? (Y/n): ").lower() or "y"
        config['tracker_create_pixel'] = create_pixel.startswith('y')
    
    return config

def cleanup_sensitive_files(config):
    """Clean up sensitive files after deployment for better OPSEC"""
    print("\n[+] Starting cleanup of sensitive files...")
    
    # Files to potentially clean up (prompt user first)
    sensitive_files = []
    
    # Add config file
    if os.path.exists('config.yml'):
        sensitive_files.append('config.yml')
        print(f"[+] Found sensitive file: config.yml")
    
    # Add log files - be more specific about deployment logs
    log_patterns = ['deployment_*.log', 'deployment_*_linode.log', 'deployment_*_aws.log']
    log_count = 0
    
    # Search in current directory
    for pattern in log_patterns:
        for f in glob.glob(pattern):
            sensitive_files.append(f)
            print(f"[+] Found sensitive log file: {f}")
            log_count += 1
    
    # Also check the logs directory if it exists
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    if os.path.exists(log_dir):
        for pattern in log_patterns:
            for f in glob.glob(os.path.join(log_dir, pattern)):
                sensitive_files.append(f)
                print(f"[+] Found sensitive log file in logs directory: {f}")
                log_count += 1
    
    print(f"[+] Found {log_count} deployment log files")
    
    # Add inventory files
    inventory_count = 0
    for f in glob.glob('inventory_*.yml'):
        sensitive_files.append(f)
        print(f"[+] Found sensitive inventory file: {f}")
        inventory_count += 1
    
    print(f"[+] Found {inventory_count} inventory files")
    
    # If there are sensitive files and user wants to clean up
    if sensitive_files:
        print("\n[!] The following sensitive files remain from deployment:")
        for f in sensitive_files:
            print(f"    - {f}")
        
        cleanup = input("\n[?] Would you like to securely delete these files? (y/N): ").lower()
        if cleanup.startswith('y'):
            for f in sensitive_files:
                try:
                    print(f"[+] Securely deleting: {f}")
                    # Secure overwrite then delete
                    with open(f, 'wb') as file:
                        # Overwrite with random data 3 times
                        for i in range(3):
                            file_size = os.path.getsize(f)
                            file.write(os.urandom(file_size))
                            file.flush()
                            os.fsync(file.fileno())
                            print(f"[+] Completed overwrite pass {i+1}/3")
                    
                    # Finally remove
                    os.remove(f)
                    print(f"[+] Successfully deleted: {f}")
                except Exception as e:
                    print(f"[!] Error deleting {f}: {e}")
    else:
        print("[+] No sensitive files found to clean up")
    
    # Remind about SSH keys
    if config.get('ssh_key') and os.path.exists(os.path.expanduser(config['ssh_key'])):
        ssh_key = os.path.expanduser(config['ssh_key'])
        print(f"\n[!] Remember to secure or remove your SSH key after use: {ssh_key}")
        secure_key = input("[?] Would you like to secure this SSH key now? (y/N): ").lower()
        if secure_key.startswith('y'):
            try:
                # Rename the SSH key with random suffix
                key_dir = os.path.dirname(ssh_key)
                key_base = os.path.basename(ssh_key)
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                new_key_path = os.path.join(key_dir, f"{key_base}.{timestamp}.bak")
                
                print(f"[+] Renaming SSH key to: {new_key_path}")
                
                # Move the key and public key
                shutil.move(ssh_key, new_key_path)
                if os.path.exists(f"{ssh_key}.pub"):
                    shutil.move(f"{ssh_key}.pub", f"{new_key_path}.pub")
                    print(f"[+] Also renamed public key")
                
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
    """Save configuration to config.yml file and create detailed deployment log"""
    # Make a copy to avoid modifying the original
    config_to_save = config.copy()
    
    # Remove ALL sensitive data before saving
    sensitive_keys = [
        'aws_key', 'aws_secret', 'linode_token', 
        'smtp_auth_pass', 'ssh_key_content',
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
        # Instead of removing, just open in write mode to overwrite
        pass
    
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
        
        f.write(f"# C2itAll Deployment Log\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Log general info
        f.write(f"Provider: {config['provider']}\n")
        
        # Log SSH key information
        f.write(f"SSH Key: {config.get('ssh_key', 'Not specified')}\n")
        if 'ssh_key_name' in config:
            f.write(f"SSH Key Name: {config['ssh_key_name']}\n")
        
        # Log custom SSH port if used
        if config.get('ssh_port') and config.get('ssh_port') != 22:
            f.write(f"SSH Port: {config['ssh_port']}\n")
        
        # Log provider-specific info without exposing sensitive details
        if config['provider'] == 'aws':
            f.write(f"AWS Region: {config.get('aws_region', 'random')}\n")
            f.write(f"Instance Type: {config.get('size', 'default')}\n")
            f.write(f"Redirector Name: {config.get('redirector_name', 'Not specified')}\n")
            f.write(f"C2 Name: {config.get('c2_name', 'Not specified')}\n")
        elif config['provider'] == 'linode':
            f.write(f"Linode Region: {config.get('linode_region', 'random')}\n")
            f.write(f"Plan: {config.get('plan', 'default')}\n")
            f.write(f"Redirector Name: {config.get('redirector_name', 'Not specified')}\n")
            f.write(f"C2 Name: {config.get('c2_name', 'Not specified')}\n")
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
        
        # Log gophish admin port
        if config.get('gophish_admin_port'):
            f.write(f"GoPhish Admin Port: {config['gophish_admin_port']}\n")
        
        # Log SMTP auth user
        if config.get('smtp_auth_user'):
            f.write(f"SMTP Auth User: {config['smtp_auth_user']}\n")
        
        # Log OPSEC settings
        f.write(f"\nOPSEC Settings:\n")
        f.write(f"- Zero-logs: {'Enabled' if config.get('zero_logs') else 'Disabled'}\n")
        f.write(f"- Secure memory: {'Enabled' if config.get('secure_memory') else 'Disabled'}\n")
        f.write(f"- History disabled: {'Yes' if config.get('disable_history') else 'No'}\n")
        f.write(f"- Non-standard SSH port: {config.get('ssh_port', 'Default')}\n")
        
        # Log tracker module info if deployed
        if config.get('deploy_tracker'):
            f.write(f"\nTracker Module:\n")
            f.write(f"- Tracker Domain: {config.get('tracker_domain', 'IP-based')}\n")
            f.write(f"- Engagement Name: {config.get('tracker_name', 'Auto-generated')}\n")
            f.write(f"- Email Pixel: {'Enabled' if config.get('tracker_create_pixel') else 'Disabled'}\n")
    
    print(f"[+] Deployment log saved to {log_file} (mode 0600)")

def show_deployment_summary(config):
    """Display a summary of the deployed infrastructure"""
    print("\n" + "="*60)
    print(" C2itAll Deployment Summary")
    print("="*60)
    
    # Show provider
    print(f"Provider: {config['provider']}")
    
    # Show infrastructure components
    if config.get('c2_only'):
        print("\nC2 Server:")
        print(f"  Name: {config.get('c2_name', 'c2')}")
        print(f"  IP: {config.get('c2_ip', 'Not available')}")
        if config.get('domain') != 'example.com':
            print(f"  Domain: mail.{config['domain']}")
    
    elif config.get('redirector_only'):
        print("\nRedirector:")
        print(f"  Name: {config.get('redirector_name', 'redirector')}")
        print(f"  IP: {config.get('redirector_ip', 'Not available')}")
        if config.get('domain') != 'example.com':
            print(f"  Domain: cdn.{config['domain']}")
    
    else:
        print("\nFull Infrastructure:")
        print("\n- Redirector:")
        print(f"  Name: {config.get('redirector_name', 'redirector')}")
        print(f"  IP: {config.get('redirector_ip', 'Not available')}")
        if config.get('domain') != 'example.com':
            print(f"  Domain: cdn.{config['domain']}")
        
        print("\n- C2 Server:")
        print(f"  Name: {config.get('c2_name', 'c2')}")
        print(f"  IP: {config.get('c2_ip', 'Not available')}")
        if config.get('domain') != 'example.com':
            print(f"  Domain: mail.{config['domain']}")
    
    # Show SSH connection details
    print("\nSSH Access:")
    user = config.get('ssh_user', 'root')
    
    if config.get('redirector_ip') and not config.get('c2_only'):
        redirector_key = config.get('redirector_key_path', config.get('ssh_key', 'No key available'))
        port = config.get('ssh_port', 22)
        print(f"  Redirector: ssh -i {redirector_key}{' -p ' + str(port) if port != 22 else ''} {user}@{config.get('redirector_ip')}")
    
    if config.get('c2_ip') and not config.get('redirector_only'):
        c2_key = config.get('c2_key_path', config.get('ssh_key', 'No key available'))
        port = config.get('ssh_port', 22)
        print(f"  C2 Server: ssh -i {c2_key}{' -p ' + str(port) if port != 22 else ''} {user}@{config.get('c2_ip')}")
    
    # Show domain configuration if used
    if config.get('domain') != 'example.com':
        print("\nDomain Configuration:")
        print(f"  Domain: {config['domain']}")
        print("  Required DNS Records:")
        if not config.get('c2_only'):
            print(f"    cdn.{config['domain']} -> {config.get('redirector_ip', 'IP_NOT_AVAILABLE')}")
        if not config.get('redirector_only'):
            print(f"    mail.{config['domain']} -> {config.get('c2_ip', 'IP_NOT_AVAILABLE')}")
    
    # Show tracker details if deployed
    if config.get('deploy_tracker'):
        print("\nTracker Module:")
        print(f"  Engagement: {config.get('tracker_name', 'Auto-generated')}")
        if config.get('tracker_domain'):
            print(f"  Domain: {config['tracker_domain']}")
            print(f"  DNS Record: {config['tracker_domain']} -> {config.get('redirector_ip', config.get('c2_ip', 'IP_NOT_AVAILABLE'))}")
        else:
            print(f"  Access: http://{config.get('redirector_ip', config.get('c2_ip', 'IP_NOT_AVAILABLE'))}")
        
        if config.get('tracker_create_pixel'):
            print("  Email Tracking: Enabled")
            hostname = config.get('tracker_domain') or config.get('redirector_ip', config.get('c2_ip', 'IP_NOT_AVAILABLE'))
            protocol = "https" if config.get('tracker_setup_ssl') else "http"
            print(f"  Tracking Pixel: <img src=\"{protocol}://{hostname}/track-open?email=TARGET_EMAIL\" width=\"1\" height=\"1\" style=\"display:none;\">")
    
    print("\nFor more details, see deployment log file.")
    print("="*60)

def log_debug_info(command, error, log_file=None):
    """Log detailed debug information when a deployment fails"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # If no log file is specified, create one
    if not log_file:
        log_file = f"deployment_error_{int(time.time())}.log"
    
    with open(log_file, 'a') as f:
        f.write(f"==== ERROR LOG: {timestamp} ====\n")
        f.write(f"COMMAND: {command}\n")
        f.write(f"ERROR: {str(error)}\n\n")
        
        # Try to get additional error information from ansible logs
        try:
            # Look for ansible log files
            ansible_logs = [file for file in os.listdir('/tmp') if 'ansible-' in file and '.log' in file]
            if ansible_logs:
                f.write("ANSIBLE LOGS:\n")
                # Get the most recent ansible log
                latest_log = sorted(ansible_logs, key=lambda x: os.path.getmtime(os.path.join('/tmp', x)))[-1]
                with open(os.path.join('/tmp', latest_log), 'r') as log:
                    f.write(log.read())
        except Exception as e:
            f.write(f"Failed to retrieve ansible logs: {e}\n")
        
        f.write("==== END ERROR LOG ====\n\n")
    
    print(f"[+] Debug information logged to {log_file}")
    return log_file

def main():
    """Main function"""
    print("========================================")
    print("C2itAll - Red Team Infrastructure Setup")
    print("========================================")
    
    # Set up error logging
    error_log_file = setup_error_logging()
    
    # Track deployed resources for cleanup on interruption
    deployed_instances = []
    generated_ssh_keys = []
    
    try:
        args = setup_argparse()
        
        # Interactive mode if no arguments provided
        if len(sys.argv) == 1:
            config = interactive_config()
        else:
            config = load_config(args)
        
        # Normalize provider name to proper capitalization
        config['provider'] = normalize_provider_name(config['provider'])
        
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
        
        # Keep track of any generated SSH keys
        if config.get('ssh_key') and config['ssh_key'].startswith(os.path.expanduser("~/.ssh/c2itall_")):
            generated_ssh_keys.append(config['ssh_key'])
        
        # Track deployment logs
        deployment_logs = []
        
        # Deploy infrastructure based on provider
        success = False
        
        try:
            if config['provider'].lower() == 'aws':
                # Verify SSH key permissions before deployment
                if config.get('ssh_key'):
                    verify_key_file_permissions(os.path.expanduser(config['ssh_key']))
                
                success, logs, aws_resources = deploy_with_error_handling(deploy_aws, config)
                deployment_logs.extend(logs)
                deployed_instances.extend(aws_resources)
                
            elif config['provider'].lower() == 'linode':
                # Verify SSH key permissions before deployment
                if config.get('ssh_key'):
                    verify_key_file_permissions(os.path.expanduser(config['ssh_key']))
                
                success, logs, linode_resources = deploy_with_error_handling(deploy_linode, config)
                deployment_logs.extend(logs)
                deployed_instances.extend(linode_resources)
                
            elif config['provider'].lower() == 'flokinet':
                success, logs, flokinet_resources = deploy_with_error_handling(deploy_flokinet, config)
                deployment_logs.extend(logs)
                deployed_instances.extend(flokinet_resources)
                
            else:
                print(f"[-] Error: Unsupported provider: {config['provider']}")
                return
        
        except Exception as e:
            error_log = log_debug_info("Unexpected error", e, error_log_file)
            if error_log:
                deployment_logs.append(error_log)
            
            print(f"[-] Unexpected error during deployment: {e}")
            print(f"[+] See {error_log_file} for detailed error information")
            success = False
        
        # Show result and handle cleanup
        if success:
            print("\n[+] Deployment completed successfully!")
            show_deployment_summary(config)
            
            # Only SSH if deployment was successful and user requested it
            if config.get('ssh_after_deploy'):
                print("\n[+] Preparing to SSH into C2 server...")
                ssh_to_c2(config)
        else:
            print("\n[-] Deployment failed.")
            if error_log_file:
                print(f"[+] Check {error_log_file} for detailed error information")
        
        # Add all discovered logs to the config
        config['deployment_logs'] = deployment_logs
        
        # Always ask if user wants to clean up sensitive files
        cleanup_option = "y/N" if not success else "Y/n"
        cleanup_default = "n" if not success else "y"
        
        cleanup = input(f"\n[?] Would you like to clean up sensitive files{' despite deployment failure' if not success else ''}? ({cleanup_option}): ").lower() or cleanup_default
        
        if cleanup.startswith('y'):
            cleanup_sensitive_files(config)
    
    except KeyboardInterrupt:
        print("\n\n[!] Deployment interrupted by user (Ctrl+C).")
        
        if deployed_instances:
            print(f"[!] The following resources were deployed:")
            for instance in deployed_instances:
                if isinstance(instance, tuple) and len(instance) >= 2:
                    print(f"    - {instance[0]} (ID: {instance[1]})")
                else:
                    print(f"    - {instance}")
            
            cleanup = input("\n[?] Would you like to clean up deployed resources before exiting? (Y/n): ").lower() or "y"
            
            if cleanup.startswith('y'):
                cleanup_interrupted_deployment(config['provider'], deployed_instances, generated_ssh_keys)
            else:
                print("[!] Deployed resources will remain active. You will need to clean them up manually.")
        
        print("[+] Exiting...")
        sys.exit(1)

if __name__ == "__main__":
    main()