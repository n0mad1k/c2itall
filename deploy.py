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
import logging
import tempfile
from datetime import datetime

# Disable Ansible host key checking
os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"

# Constants for providers
PROVIDERS = ["aws", "linode", "flokinet"]
DEFAULT_SSH_USER = {
    "aws": "kali",
    "linode": "root",
    "flokinet": "root"
}

# Directory names - maintain correct case for each provider
PROVIDER_DIRS = {
    "aws": "AWS",
    "linode": "Linode",
    "flokinet": "FlokiNET"
}

def setup_logging():
    """Set up logging for the deployment"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, f"deployment_{timestamp}.log")
    
    # Configure file handler to log DEBUG and above
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,  # Changed from INFO to DEBUG
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Add console handler for INFO level and above
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    
    logging.info("Deployment started")
    return log_file

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='C2itAll - Red Team Infrastructure Setup',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Provider selection
    parser.add_argument('-p', '--provider', choices=PROVIDERS, default=None, help='Provider to use for deployment')
    
    # AWS-specific arguments
    parser.add_argument('--aws-key', help='AWS access key')
    parser.add_argument('--aws-secret', help='AWS secret key')
    parser.add_argument('--aws-region', help='AWS region (default: random from vars.yaml)')
    
    # Linode-specific arguments
    parser.add_argument('--linode-token', help='Linode API token')
    parser.add_argument('--linode-region', help='Linode region (default: random from vars.yaml)')
    
    # FlokiNET-specific arguments
    parser.add_argument('--flokinet', action='store_true', help='Use FlokiNET as the provider')
    parser.add_argument('--flokinet-redirector-ip', help='FlokiNET redirector IP address')
    parser.add_argument('--flokinet-c2-ip', help='FlokiNET C2 server IP address')
    
    # General arguments
    parser.add_argument('--ssh-key', help='Path to SSH private key')
    parser.add_argument('--ssh-user', help='SSH username (default: provider-specific)')
    parser.add_argument('--size', help='Size of the instance (default: provider-specific)')
    parser.add_argument('--region', help='Generic region parameter')
    parser.add_argument('--redirector-name', help='Name for the redirector instance (default: random)')
    parser.add_argument('--c2-name', help='Name for the C2 instance (default: random)')
    
    # Common arguments
    parser.add_argument('--teardown', action='store_true', help='Tear down existing infrastructure')
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
    
    # Test options
    parser.add_argument('--run-tests', action='store_true', help='Run deployment tests')
    
    # Tracker deployment options
    parser.add_argument('--deploy-tracker', action='store_true', help='Deploy phishing email tracking server')
    parser.add_argument('--tracker-domain', help='Domain name for the tracker server')
    parser.add_argument('--tracker-email', help='Email for Let\'s Encrypt certificate for tracker')
    parser.add_argument('--tracker-name', help='Name for tracker instance (default: random)')
    parser.add_argument('--tracker-ipinfo-token', help='IPinfo.io API token for geolocation')
    parser.add_argument('--tracker-setup-ssl', action='store_true', help='Set up SSL for tracker')
    parser.add_argument('--tracker-create-pixel', action='store_true', help='Create tracking pixel')
    
    # Interactive mode
    parser.add_argument('--interactive', action='store_true', help='Run in interactive wizard mode')
    
    return parser.parse_args()

def interactive_setup():
    """Interactive setup wizard for deployment"""
    config = {}
    
    print("\n========================================")
    print("C2itAll - Interactive Setup Wizard")
    print("========================================\n")
    
    # Select provider
    print("Available cloud providers:")
    for i, provider in enumerate(PROVIDERS, 1):
        print(f"  {i}. {provider.capitalize()}")
    
    while True:
        try:
            provider_choice = int(input("\nSelect a provider (1-3): "))
            if 1 <= provider_choice <= len(PROVIDERS):
                config['provider'] = PROVIDERS[provider_choice - 1]
                break
            else:
                print(f"Please enter a number between 1 and {len(PROVIDERS)}")
        except ValueError:
            print("Please enter a valid number")
    
    # Load vars file for the selected provider
    provider_dir = config['provider'].capitalize()
    if config['provider'] == "aws":
        provider_dir = "AWS"
    elif config['provider'] == "flokinet":
        provider_dir = "FlokiNET"
        
    vars_file = f"{provider_dir}/vars.yaml"
    vars_data = {}
    
    if os.path.exists(vars_file):
        try:
            with open(vars_file, 'r') as f:
                vars_data = yaml.safe_load(f) or {}
            print(f"Loaded configuration from {vars_file}")
        except Exception as e:
            print(f"Warning: Failed to load {vars_file}: {e}")
    
    # Provider-specific configuration
    if config['provider'] == "aws":
        # Set defaults from vars file
        default_aws_key = vars_data.get('aws_access_key', '')
        default_aws_secret = vars_data.get('aws_secret_key', '')
        
        config['aws_access_key'] = input(f"\nAWS Access Key [{'*****' if default_aws_key else 'leave blank to use AWS CLI profile'}]: ") or default_aws_key
        config['aws_secret_key'] = input(f"AWS Secret Key [{'*****' if default_aws_secret else 'leave blank to use AWS CLI profile'}]: ") or default_aws_secret
        
        # Show available regions
        aws_regions = vars_data.get('aws_region_choices', [])
        if aws_regions:
            print("\nAvailable AWS regions:")
            for i, region in enumerate(aws_regions, 1):
                print(f"  {i}. {region}")
            
            while True:
                region_input = input("\nSelect a region (number) or press Enter for random: ")
                if not region_input:
                    config['aws_region'] = None  # Random
                    break
                try:
                    region_choice = int(region_input)
                    if 1 <= region_choice <= len(aws_regions):
                        config['aws_region'] = aws_regions[region_choice - 1]
                        break
                    else:
                        print(f"Please enter a number between 1 and {len(aws_regions)}")
                except ValueError:
                    print("Please enter a valid number or press Enter")
        else:
            default_region = vars_data.get('aws_region', 'us-east-1')
            config['aws_region'] = input(f"\nAWS Region [default: {default_region}]: ") or default_region
        
        # Instance size
        default_size = vars_data.get('aws_instance_type', 't2.medium')
        config['aws_instance_type'] = input(f"Instance Size [default: {default_size}]: ") or default_size
    
    elif config['provider'] == "linode":
        # Set defaults from vars file
        default_token = vars_data.get('linode_token', '')
        
        config['linode_token'] = input(f"\nLinode API Token [{'*****' if default_token else 'required'}]: ") or default_token
        
        # Show available regions
        linode_regions = vars_data.get('region_choices', [])
        if linode_regions:
            print("\nAvailable Linode regions:")
            for i, region in enumerate(linode_regions, 1):
                print(f"  {i}. {region}")
            
            while True:
                region_input = input("\nSelect a region (number) or press Enter for random: ")
                if not region_input:
                    config['linode_region'] = None  # Random
                    break
                try:
                    region_choice = int(region_input)
                    if 1 <= region_choice <= len(linode_regions):
                        config['linode_region'] = linode_regions[region_choice - 1]
                        break
                    else:
                        print(f"Please enter a number between 1 and {len(linode_regions)}")
                except ValueError:
                    print("Please enter a valid number or press Enter")
        else:
            # Use defaults or empty values if no regions are defined
            default_region = vars_data.get('linode_region', '')
            config['linode_region'] = input(f"\nLinode Region [default: {default_region or 'random'}]: ") or default_region
        
        # Instance size/plan
        default_plan = vars_data.get('plan', 'g6-standard-2')
        config['plan'] = input(f"Instance Plan [default: {default_plan}]: ") or default_plan
    
    elif config['provider'] == "flokinet":
        print("\nFlokiNET requires pre-provisioned servers.")
        
        # Set defaults from vars file
        default_redirector_ip = vars_data.get('redirector_ip', '')
        default_c2_ip = vars_data.get('c2_ip', '')
        default_ssh_user = vars_data.get('ssh_user', DEFAULT_SSH_USER['flokinet'])
        default_ssh_port = vars_data.get('ssh_port', 22)
        
        config['flokinet_redirector_ip'] = input(f"FlokiNET Redirector IP Address [default: {default_redirector_ip}]: ") or default_redirector_ip
        config['flokinet_c2_ip'] = input(f"FlokiNET C2 Server IP Address [default: {default_c2_ip}]: ") or default_c2_ip
        config['ssh_user'] = input(f"SSH User [default: {default_ssh_user}]: ") or default_ssh_user
        config['ssh_port'] = input(f"SSH Port [default: {default_ssh_port}]: ") or default_ssh_port
        
        ssh_key = input("Path to SSH Private Key [leave blank to generate new key]: ")
        if ssh_key:
            config['ssh_key'] = os.path.expanduser(ssh_key)
        else:
            config['ssh_key'] = None  # Will generate a new key
    
    # Deployment type
    print("\nDeployment type:")
    print("  1. Full deployment (Redirector + C2)")
    print("  2. Redirector only")
    print("  3. C2 server only")
    
    while True:
        try:
            deploy_choice = int(input("\nSelect deployment type (1-3): "))
            if deploy_choice == 1:
                config['redirector_only'] = False
                config['c2_only'] = False
                break
            elif deploy_choice == 2:
                config['redirector_only'] = True
                config['c2_only'] = False
                break
            elif deploy_choice == 3:
                config['redirector_only'] = False
                config['c2_only'] = True
                break
            else:
                print("Please enter a number between 1 and 3")
        except ValueError:
            print("Please enter a valid number")
    
    # Domain configuration
    default_domain = vars_data.get('domain', 'example.com')
    config['domain'] = input(f"\nDomain name [default: {default_domain}]: ") or default_domain
    
    default_email = vars_data.get('letsencrypt_email', f"admin@{config['domain']}")
    config['letsencrypt_email'] = input(f"Email for Let's Encrypt [default: {default_email}]: ") or default_email
    
    # Security options
    print("\nSecurity options:")
    default_disable_history = vars_data.get('disable_history', True)
    default_secure_memory = vars_data.get('secure_memory', True)
    default_zero_logs = vars_data.get('zero_logs', True)
    
    disable_history = input(f"Disable command history? (y/n) [default: {'y' if default_disable_history else 'n'}]: ").lower()
    secure_memory = input(f"Enable secure memory settings? (y/n) [default: {'y' if default_secure_memory else 'n'}]: ").lower()
    zero_logs = input(f"Enable zero-logs configuration? (y/n) [default: {'y' if default_zero_logs else 'n'}]: ").lower()
    
    config['disable_history'] = True if (disable_history == 'y' or (default_disable_history and disable_history != 'n')) else False
    config['secure_memory'] = True if (secure_memory == 'y' or (default_secure_memory and secure_memory != 'n')) else False
    config['zero_logs'] = True if (zero_logs == 'y' or (default_zero_logs and zero_logs != 'n')) else False
    
    # Post-deployment options
    config['ssh_after_deploy'] = input("\nSSH into instance after deployment? (y/n) [default: n]: ").lower() == 'y'
    
    # Debug mode
    config['debug'] = input("Enable debug mode? (y/n) [default: n]: ").lower() == 'y'
    
    # Additional options
    deploy_tracker = input("\nDeploy email tracking server? (y/n) [default: n]: ").lower()
    config['deploy_tracker'] = deploy_tracker == 'y'
    
    if config['deploy_tracker']:
        default_tracker_domain = f"track.{config['domain']}"
        config['tracker_domain'] = input(f"Tracker domain [default: {default_tracker_domain}]: ") or default_tracker_domain
        
        default_tracker_email = config['letsencrypt_email']
        config['tracker_email'] = input(f"Tracker Let's Encrypt email [default: {default_tracker_email}]: ") or default_tracker_email
        
        config['tracker_ipinfo_token'] = input("IPinfo.io API token [optional]: ")
        config['tracker_setup_ssl'] = input("Set up SSL for tracker? (y/n) [default: y]: ").lower() != 'n'
        config['tracker_create_pixel'] = input("Create tracking pixel? (y/n) [default: y]: ").lower() != 'n'
        
        # Generate random tracker name
        rand_suffix = generate_random_string()
        timestamp = int(time.time()) % 10000
        config['tracker_name'] = f"t-{rand_suffix}-{timestamp}"  # Changed from track- to t-
    
    # SSH key if not already set
    if 'ssh_key' not in config or not config['ssh_key']:
        ssh_key = input("\nPath to SSH Private Key [leave blank to generate new key]: ")
        if ssh_key:
            config['ssh_key'] = os.path.expanduser(ssh_key)
        else:
            # Generate SSH key
            config['ssh_key'] = generate_ssh_key()
    
    # Generate random instance names with new format
    rand_suffix = generate_random_string()
    timestamp = int(time.time()) % 10000
    config['redirector_name'] = f"r-{rand_suffix}-{timestamp}"  # Changed from srv- to r-
    config['c2_name'] = f"s-{rand_suffix}-{timestamp}"  # Changed from node- to s-
    
    # Additional settings from vars_data
    config['gophish_admin_port'] = vars_data.get('gophish_admin_port', str(random.randint(2000, 9000)))
    config['smtp_auth_user'] = vars_data.get('smtp_auth_user', f"user{random.randint(1000, 9999)}")
    config['smtp_auth_pass'] = vars_data.get('smtp_auth_pass', ''.join(random.choices(string.ascii_letters + string.digits, k=20)))
    config['shell_handler_port'] = vars_data.get('shell_handler_port', str(random.randint(4000, 65000)))
    
    # Set SSH key path for proper reference
    if config['ssh_key'].startswith(os.path.expanduser("~/.ssh/c2deploy_")):
        config['ssh_key_path'] = f"{config['ssh_key']}.pub"
    else:
        config['ssh_key_path'] = f"{config['ssh_key']}.pub"
        # Check if the public key exists
        if not os.path.exists(config['ssh_key_path']):
            # Try alternative extension
            alt_path = f"{config['ssh_key']}.pub"
            if os.path.exists(alt_path):
                config['ssh_key_path'] = alt_path
    
    print("\n========================================")
    print("Configuration Summary")
    print("========================================")
    for key, value in config.items():
        if key not in ['aws_secret_key', 'linode_token', 'smtp_auth_pass']:
            print(f"  {key}: {value}")
    
    confirm = input("\nProceed with deployment? (y/n): ").lower()
    if confirm != 'y':
        print("Deployment cancelled.")
        sys.exit(0)
    
    return config

def load_vars_file(provider):
    """Load vars.yaml for the specified provider"""
    if provider not in PROVIDER_DIRS:
        logging.warning(f"Unknown provider: {provider}")
        return {}
    
    # Use correct case for directory
    provider_dir = PROVIDER_DIRS[provider]
    vars_file = f"{provider_dir}/vars.yaml"
    
    if os.path.exists(vars_file):
        try:
            with open(vars_file, 'r') as f:
                vars_data = yaml.safe_load(f) or {}
                logging.info(f"Loaded configuration from {vars_file}")
                return vars_data
        except Exception as e:
            logging.warning(f"Failed to load {vars_file}: {e}")
    else:
        logging.warning(f"{vars_file} not found")
    
    return {}

def generate_random_string(length=8):
    """Generate a random string of letters and digits."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_ssh_key():
    """Generate an SSH key for deployment"""
    rand_suffix = generate_random_string()
    key_name = f"c2deploy_{rand_suffix}"
    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, exist_ok=True)

    private_key_path = os.path.join(ssh_dir, key_name)
    public_key_path = f"{private_key_path}.pub"

    logging.info(f"Generating SSH key: {key_name}")
    try:
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", private_key_path, "-N", "", "-C", ""],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        os.chmod(private_key_path, 0o600)
        logging.info(f"SSH key generated successfully: {private_key_path}")
        return private_key_path
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to generate SSH key: {e}")
        return None

def select_random_region(config):
    """Select a random region from the available regions for the provider"""
    provider = config['provider']
    
    region_choices = []
    if provider == "aws":
        region_choices = config.get("aws_region_choices", [])
    elif provider == "linode":
        # Look for both variations of the key name
        region_choices = config.get("region_choices", [])
        
        # Debug the vars_data content
        logging.debug(f"Linode config keys: {config.keys()}")
        
        if not region_choices:
            # Load directly from vars.yaml as fallback
            try:
                vars_file = "Linode/vars.yaml"
                if os.path.exists(vars_file):
                    with open(vars_file, 'r') as f:
                        vars_data = yaml.safe_load(f)
                        region_choices = vars_data.get('region_choices', [])
                        logging.debug(f"Loaded region_choices directly from {vars_file}: {region_choices}")
            except Exception as e:
                logging.warning(f"Failed to load regions from vars file: {e}")
    elif provider == "flokinet":
        region_choices = config.get("flokinet_region_choices", [])
    
    if not region_choices:
        logging.warning(f"No region choices found for {provider}")
        
        # Fallback regions by provider if none found in config
        if provider == "linode":
            region_choices = ["us-east", "us-central", "eu-west", "ap-south"]
            logging.info(f"Using fallback regions for Linode: {region_choices}")
    
    if not region_choices:
        return None
    
    # Select random region
    region = random.choice(region_choices)
    logging.info(f"Selected random {provider} region: {region}")
    return region

def create_inventory_file(config, deployment_type):
    """Create a temporary inventory file for Ansible based on deployment type"""
    inventory_content = []
    inventory_content.append("[all:vars]")
    
    # Add common variables
    if config.get('ssh_key'):
        inventory_content.append(f"ansible_ssh_private_key_file={config['ssh_key']}")
    if config.get('ssh_user'):
        inventory_content.append(f"ansible_user={config['ssh_user']}")
    if config.get('ssh_port'):
        inventory_content.append(f"ansible_port={config['ssh_port']}")
    
    # Set Python interpreter appropriately based on deployment type
    if deployment_type == "local":
        # For local execution, use the current Python interpreter
        inventory_content.append(f"ansible_python_interpreter={sys.executable}")
    else:
        # For remote hosts, let Ansible auto-detect the Python interpreter
        inventory_content.append("ansible_python_interpreter=auto")
    
    # Add specific host sections based on deployment type
    if deployment_type == "local":
        inventory_content.append("\n[local]")
        inventory_content.append("localhost ansible_connection=local")
    elif deployment_type == "redirector":
        inventory_content.append("\n[redirectors]")
        inventory_content.append(f"redirector ansible_host={config.get('redirector_ip', '127.0.0.1')}")
    elif deployment_type == "c2":
        inventory_content.append("\n[c2servers]")
        inventory_content.append(f"c2 ansible_host={config.get('c2_ip', '127.0.0.1')}")
    elif deployment_type == "tracker":
        inventory_content.append("\n[trackers]")
        inventory_content.append(f"tracker ansible_host={config.get('tracker_ip', '127.0.0.1')}")
    
    # Create temporary file
    fd, inventory_path = tempfile.mkstemp(prefix=f"inventory_{deployment_type}_", suffix=".ini")
    with os.fdopen(fd, 'w') as f:
        f.write("\n".join(inventory_content))
    
    logging.debug(f"Created inventory file at {inventory_path} with content:")
    logging.debug("\n".join(inventory_content))
    
    return inventory_path

def run_ansible_playbook(playbook, inventory, config, debug=False):
    """Run an Ansible playbook with the given inventory and config"""
    # Convert config dict to JSON for extra-vars
    # Filter out None values and complex objects
    extra_vars = {k: v for k, v in config.items() if v is not None and not isinstance(v, (dict, list, tuple))}
    
    # Handle the region parameter correctly
    if 'region' in extra_vars:
        # Set selected_region to match what the playbook expects
        extra_vars['selected_region'] = extra_vars['region']
    elif 'linode_region' in extra_vars:
        # Map linode_region to selected_region for compatibility
        extra_vars['selected_region'] = extra_vars['linode_region']
    
    # Explicitly set hard-coded user values rather than using templated defaults
    if 'ssh_user' in extra_vars:
        extra_vars.pop('ssh_user')
        if config['provider'] == 'linode':
            extra_vars['ssh_user'] = 'root'
        else:
            extra_vars['ssh_user'] = 'kali'
    
    # Remove the Python interpreter setting from extra_vars 
    # It should be set properly in the inventory file instead
    if 'ansible_python_interpreter' in extra_vars:
        extra_vars.pop('ansible_python_interpreter')
    
    extra_vars_json = json.dumps(extra_vars)
    
    # Set PYTHONPATH to include site-packages
    env = os.environ.copy()
    current_python = sys.executable
    python_path = subprocess.check_output(
        [current_python, "-c", "import sys; import site; print(':'.join(sys.path + site.getsitepackages()))"],
        text=True
    ).strip()
    env["PYTHONPATH"] = python_path
    
    # Build command
    cmd = [
        "ansible-playbook",
        "-i", inventory,
        playbook,
        "-e", extra_vars_json
    ]
    
    # Add verbosity if debug mode is enabled
    if debug:
        cmd.append("-vvv")
    else:
        # Always add some verbosity for basic output
        cmd.append("-v")
    
    # Log the command
    if debug:
        logging.debug(f"Running Ansible command: {' '.join(cmd)}")
    else:
        logging.info(f"Running Ansible playbook: {playbook}")
    
    # Run the command
    try:
        result = subprocess.run(
            cmd, 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            env=env  # Use the modified environment
        )
        logging.info(f"Playbook {playbook} executed successfully")
        return True, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        logging.error(f"Playbook {playbook} failed with exit code {e.returncode}")
        if debug:
            logging.error(f"Command stdout: {e.stdout}")
            logging.error(f"Command stderr: {e.stderr}")
        return False, e.stdout, e.stderr

def run_ansible_playbook(playbook, inventory, config, debug=False):
    """Run an Ansible playbook with the given inventory and config"""
    # Convert config dict to JSON for extra-vars
    # Filter out None values and complex objects
    extra_vars = {k: v for k, v in config.items() if v is not None and not isinstance(v, (dict, list, tuple))}
    
    # Handle the region parameter correctly
    if 'region' in extra_vars:
        # Set selected_region to match what the playbook expects
        extra_vars['selected_region'] = extra_vars['region']
    elif 'linode_region' in extra_vars:
        # Map linode_region to selected_region for compatibility
        extra_vars['selected_region'] = extra_vars['linode_region']
    
    # Explicitly set hard-coded user values rather than using templated defaults
    if 'ssh_user' in extra_vars:
        extra_vars.pop('ssh_user')
        if config['provider'] == 'linode':
            extra_vars['ssh_user'] = 'root'
        else:
            extra_vars['ssh_user'] = 'kali'
    
    # Use the current Python interpreter for all Ansible operations
    # This ensures any modules needed are available
    current_python = sys.executable
    extra_vars['ansible_python_interpreter'] = current_python
    
    extra_vars_json = json.dumps(extra_vars)
    
    # Set PYTHONPATH to include site-packages
    env = os.environ.copy()
    python_path = subprocess.check_output(
        [current_python, "-c", "import sys; import site; print(':'.join(sys.path + site.getsitepackages()))"],
        text=True
    ).strip()
    env["PYTHONPATH"] = python_path
    
    # Build command
    cmd = [
        "ansible-playbook",
        "-i", inventory,
        playbook,
        "-e", extra_vars_json
    ]
    
    # Add verbosity if debug mode is enabled
    if debug:
        cmd.append("-vvv")
    else:
        # Always add some verbosity for basic output
        cmd.append("-v")
    
    # Log the command
    if debug:
        logging.debug(f"Running Ansible command: {' '.join(cmd)}")
    else:
        logging.info(f"Running Ansible playbook: {playbook}")
    
    # Run the command
    try:
        result = subprocess.run(
            cmd, 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            env=env  # Use the modified environment
        )
        logging.info(f"Playbook {playbook} executed successfully")
        return True, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        logging.error(f"Playbook {playbook} failed with exit code {e.returncode}")
        if debug:
            logging.error(f"Command stdout: {e.stdout}")
            logging.error(f"Command stderr: {e.stderr}")
        return False, e.stdout, e.stderr

def deploy_infrastructure(config):
    """Deploy infrastructure based on provider and configuration"""
    provider = config['provider']
    logging.info(f"Deploying {provider} infrastructure...")
    
    # Set provider-specific environment variables
    if provider == "aws":
        if config.get('aws_access_key'):
            os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
        if config.get('aws_secret_key'):
            os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
    elif provider == "linode":
        if config.get('linode_token'):
            os.environ['LINODE_TOKEN'] = config['linode_token']
    
    # IMPORTANT: Ensure ssh_user is explicitly set to avoid template recursion
    if provider == "linode":
        config['ssh_user'] = "root"
    elif provider == "aws":
        config['ssh_user'] = "kali"
    
    # Select random region if not specified
    if not config.get('region'):
        if provider == "linode" and config.get('linode_region'):
            # Use the specified linode_region
            config['region'] = config['linode_region']
        elif provider == "aws" and config.get('aws_region'):
            # Use the specified aws_region
            config['region'] = config['aws_region']
        else:
            # If no specific region provided, select random
            config['region'] = select_random_region(config)
    
    # Set different instance sizes for redirector vs. C2
    if provider == "linode":
        # Store the original plan
        original_plan = config.get('plan', 'g6-standard-2')
        
        # For redirector, use smaller instance size regardless of what was specified
        if not config.get('c2_only'):
            redirector_config = config.copy()
            redirector_config['plan'] = 'g6-nanode-1'  # Smallest viable Linode plan
            
            # Use the correct case for provider directory
            provider_dir = PROVIDER_DIRS[provider]
            playbook = f"{provider_dir}/redirector.yml"
            inventory_path = create_inventory_file(redirector_config, "local")
            
            logging.info(f"Deploying redirector using {playbook} with plan: g6-nanode-1")
            redirector_success, stdout, stderr = run_ansible_playbook(
                playbook, inventory_path, redirector_config, redirector_config.get('debug', False)
            )
            
            # Log Ansible output
            if redirector_config.get('debug', False):
                logging.debug(f"Ansible stdout: {stdout}")
                if stderr:
                    logging.debug(f"Ansible stderr: {stderr}")
            
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
                
            if not redirector_success:
                logging.error("Redirector deployment failed")
                return False
        
        # For C2, use the original plan
        if not config.get('redirector_only'):
            # Restore original plan for C2
            config['plan'] = original_plan
            
            provider_dir = PROVIDER_DIRS[provider]
            playbook = f"{provider_dir}/c2.yml"
            inventory_path = create_inventory_file(config, "local")
            
            logging.info(f"Deploying C2 server using {playbook} with plan: {config['plan']}")
            c2_success, stdout, stderr = run_ansible_playbook(
                playbook, inventory_path, config, config.get('debug', False)
            )
            
            # Log Ansible output
            if config.get('debug', False):
                logging.debug(f"Ansible stdout: {stdout}")
                if stderr:
                    logging.debug(f"Ansible stderr: {stderr}")
            
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
                
            if not c2_success:
                logging.error("C2 server deployment failed")
                return False
    else:
        # For AWS and other providers, follow the same pattern but with their directory names
        provider_dir = PROVIDER_DIRS[provider]
        
        # Redirector deployment
        if not config.get('c2_only'):
            playbook = f"{provider_dir}/redirector.yml"
            inventory_path = create_inventory_file(config, "local")
            
            logging.info(f"Deploying redirector using {playbook}")
            redirector_success, stdout, stderr = run_ansible_playbook(
                playbook, inventory_path, config, config.get('debug', False)
            )
            
            # Log Ansible output
            if config.get('debug', False):
                logging.debug(f"Ansible stdout: {stdout}")
                if stderr:
                    logging.debug(f"Ansible stderr: {stderr}")
            
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
                
            if not redirector_success:
                logging.error("Redirector deployment failed")
                return False
        
        # C2 deployment
        if not config.get('redirector_only'):
            playbook = f"{provider_dir}/c2.yml"
            inventory_path = create_inventory_file(config, "local")
            
            logging.info(f"Deploying C2 server using {playbook}")
            c2_success, stdout, stderr = run_ansible_playbook(
                playbook, inventory_path, config, config.get('debug', False)
            )
            
            # Log Ansible output
            if config.get('debug', False):
                logging.debug(f"Ansible stdout: {stdout}")
                if stderr:
                    logging.debug(f"Ansible stderr: {stderr}")
            
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
                
            if not c2_success:
                logging.error("C2 server deployment failed")
                return False
    
    return True

def deploy_flokinet_redirector(config):
    """Deploy FlokiNET redirector separately"""
    logging.info("Deploying FlokiNET redirector...")
    
    # Verify redirector IP is provided
    if not config.get('flokinet_redirector_ip'):
        logging.error("FlokiNET redirector IP is required")
        return False
    
    # Set redirector_ip in config for inventory
    config['redirector_ip'] = config['flokinet_redirector_ip']
    
    # Create inventory file for redirector
    inventory_path = create_inventory_file(config, "redirector")
    
    # Run the playbook
    playbook = f"{PROVIDER_DIRS['flokinet']}/redirector.yml"
    try:
        success, stdout, stderr = run_ansible_playbook(
            playbook, inventory_path, config, config.get('debug', False)
        )
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return success
    except Exception as e:
        logging.error(f"FlokiNET redirector deployment failed: {e}")
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return False

def deploy_flokinet_c2(config):
    """Deploy FlokiNET C2 separately"""
    logging.info("Deploying FlokiNET C2 server...")
    
    # Verify C2 IP is provided
    if not config.get('flokinet_c2_ip'):
        logging.error("FlokiNET C2 IP is required")
        return False
    
    # Set c2_ip in config for inventory
    config['c2_ip'] = config['flokinet_c2_ip']
    
    # Create inventory file for C2
    inventory_path = create_inventory_file(config, "c2")
    
    # Run the playbook
    playbook = f"{PROVIDER_DIRS['flokinet']}/c2.yml"
    try:
        success, stdout, stderr = run_ansible_playbook(
            playbook, inventory_path, config, config.get('debug', False)
        )
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return success
    except Exception as e:
        logging.error(f"FlokiNET C2 deployment failed: {e}")
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return False

def run_tests(config):
    """Run deployment tests"""
    provider = config['provider']
    provider_dir = PROVIDER_DIRS.get(provider, provider.upper())
    
    logging.info(f"Running {provider} tests...")
    
    # Set provider-specific environment variables
    if provider == "aws":
        if config.get('aws_access_key'):
            os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
        if config.get('aws_secret_key'):
            os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
    elif provider == "linode":
        if config.get('linode_token'):
            os.environ['LINODE_TOKEN'] = config['linode_token']
    
    # Run tests playbook
    playbook = f"{provider_dir}/tests.yml"
    if os.path.exists(playbook):
        inventory_path = create_inventory_file(config, "local")
        try:
            success, stdout, stderr = run_ansible_playbook(
                playbook, inventory_path, config, config.get('debug', False)
            )
            
            # Clean up inventory file
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
            
            return success
        except Exception as e:
            logging.error(f"Tests failed: {e}")
            
            # Clean up inventory file
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
            
            return False
    else:
        logging.warning(f"No tests playbook found at {playbook}")



def ssh_to_instance(config):
    """SSH into the deployed instance"""
    logging.info("Connecting to instance via SSH...")
    
    # Determine which IP to use based on deployment type
    if config.get('deploy_tracker'):
        ip_key = 'tracker_ip'
        instance_type = 'tracker'
    elif config.get('redirector_only'):
        ip_key = 'redirector_ip'
        instance_type = 'redirector'
    else:
        ip_key = 'c2_ip'
        instance_type = 'C2 server'
    
    # Use provider-specific IP if available
    if config['provider'] == 'flokinet':
        if config.get('redirector_only') and config.get('flokinet_redirector_ip'):
            ip = config['flokinet_redirector_ip']
        elif config.get('c2_only') and config.get('flokinet_c2_ip'):
            ip = config['flokinet_c2_ip']
        else:
            ip = config.get(ip_key)
    else:
        ip = config.get(ip_key)
    
    if not ip:
        logging.error(f"No IP address found for {instance_type}")
        return False
    
    # Get SSH key and user
    ssh_key = config.get('ssh_key')
    if not ssh_key:
        logging.error("No SSH key specified")
        return False
    
    ssh_user = config.get('ssh_user')
    if not ssh_user:
        logging.error("No SSH user specified")
        return False
    
    # Build SSH command
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "IdentitiesOnly=yes",
        "-i", ssh_key,
        f"{ssh_user}@{ip}"
    ]
    
    # Add port if specified
    if config.get('ssh_port'):
        ssh_cmd.extend(["-p", str(config['ssh_port'])])
    
    logging.info(f"SSH command: {' '.join(ssh_cmd)}")
    
    # Execute SSH command
    try:
        subprocess.run(ssh_cmd)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"SSH connection failed: {e}")
        return False
    except KeyboardInterrupt:
        logging.info("SSH connection interrupted by user")
        return True

def cleanup_resources(config, interactive=True):
    """Clean up resources if deployment fails"""
    provider = config.get('provider')
    logging.info(f"Cleaning up {provider} resources...")
    
    # Use the correct case for provider directory
    provider_dir = PROVIDER_DIRS.get(provider, provider.upper())
    
    # If interactive, ask for confirmation before cleaning up
    if interactive:
        print("\n============================================================")
        print("Deployment failed or was interrupted. Resources to clean up:")
        redirector_name = config.get('redirector_name', 'None')
        c2_name = config.get('c2_name', 'None')
        print(f" - Redirector: {redirector_name}")
        print(f" - C2 Server: {c2_name}")
        print("============================================================")
        
        try:
            user_choice = input("\nDo you want to clean up these resources? (y/n): ").lower()
            if user_choice != 'y':
                logging.info("Cleanup cancelled by user")
                print("\nCleanup cancelled. Resources remain active.")
                print("You can clean them up later by running with --teardown")
                return False
        except KeyboardInterrupt:
            # Handle if the user presses Ctrl+C during input
            print("\nCleanup cancelled. Resources remain active.")
            print("You can clean them up later by running with --teardown")
            return False
    
    # Use Ansible for cleanup with confirmation set to false
    extra_vars = {
        "confirm_cleanup": False,  # Skip confirmation prompt
        "redirector_name": config.get('redirector_name'),
        "c2_name": config.get('c2_name'),
        "cleanup_redirector": True,
        "cleanup_c2": True
    }
    
    playbook = f"{provider_dir}/cleanup.yml"
    if os.path.exists(playbook):
        logging.info(f"Running cleanup playbook: {playbook}")
        inventory_path = create_inventory_file(config, "local")
        
        # Add extra vars to config for cleanup
        cleanup_config = config.copy()
        cleanup_config.update(extra_vars)
        
        try:
            success, stdout, stderr = run_ansible_playbook(
                playbook, inventory_path, cleanup_config, 
                cleanup_config.get('debug', False)
            )
            
            if not success:
                logging.error(f"Cleanup playbook failed: {stderr}")
                
                # Log what we attempted to clean up
                logging.error(f"Failed to clean up resources: redirector={config.get('redirector_name')}, c2={config.get('c2_name')}")
            else:
                logging.info("Cleanup completed successfully")
        except Exception as e:
            logging.error(f"Cleanup playbook failed: {e}")
        finally:
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
    else:
        logging.warning(f"No cleanup playbook found at {playbook}")
    
    # Clean up SSH key if we generated one
    ssh_key = config.get('ssh_key')
    if ssh_key and ssh_key.startswith(os.path.expanduser("~/.ssh/c2deploy_")):
        logging.info(f"Removing generated SSH key: {ssh_key}")
        try:
            os.remove(ssh_key)
            if os.path.exists(f"{ssh_key}.pub"):
                os.remove(f"{ssh_key}.pub")
        except Exception as e:
            logging.error(f"Failed to remove SSH key: {e}")
            
    return True

def check_dependencies():
    """Check if required dependencies are installed"""
    dependencies = {
        "ansible": "ansible-playbook --version",
        "aws": "aws --version",
        "linode-cli": "linode-cli --version",
    }
    
    missing = []
    for dep, cmd in dependencies.items():
        try:
            subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing.append(dep)
    
    if missing:
        logging.warning(f"Missing dependencies: {', '.join(missing)}")
        print("\nWarning: The following dependencies are missing or not in PATH:")
        for dep in missing:
            print(f"  - {dep}")
        print("\nPlease install them to ensure proper functionality.")
        print("You can install Python dependencies with: pip install -r requirements.txt")
        
        if "ansible" in missing:
            print("\nTo install Ansible: pip install ansible")
        
        if "aws" in missing:
            print("\nTo install AWS CLI: pip install awscli")
        
        if "linode-cli" in missing:
            print("\nTo install Linode CLI: pip install linode-cli")
        
        confirm = input("\nContinue anyway? (y/n): ").lower()
        if confirm != 'y':
            sys.exit(1)

def teardown_infrastructure(config):
    """Tear down existing infrastructure"""
    provider = config['provider']
    provider_dir = PROVIDER_DIRS.get(provider, provider.upper())
    logging.info(f"Tearing down {provider} infrastructure...")
    
    # Set provider-specific environment variables
    if provider == "aws":
        if config.get('aws_access_key'):
            os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
        if config.get('aws_secret_key'):
            os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
    elif provider == "linode":
        if config.get('linode_token'):
            os.environ['LINODE_TOKEN'] = config['linode_token']
    
    # Run cleanup playbook
    playbook = f"{provider_dir}/cleanup.yml"
    if os.path.exists(playbook):
        # Set confirm_cleanup to false to skip confirmation in playbook
        # This needs to be a plain string "false" instead of a boolean
        config['confirm_cleanup'] = "false"
        
        # Create inventory for local execution
        inventory_path = create_inventory_file(config, "local")
        
        try:
            success, stdout, stderr = run_ansible_playbook(
                playbook, inventory_path, config, config.get('debug', False)
            )
            
            if success:
                logging.info(f"Successfully tore down {provider} infrastructure")
            else:
                logging.error(f"Failed to tear down {provider} infrastructure")
                logging.error(stderr)
            
            # Clean up inventory
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
            
            return success
        except Exception as e:
            logging.error(f"Teardown failed: {e}")
            # Clean up inventory
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
            return False
    else:
        logging.error(f"No cleanup playbook found at {playbook}")
        return False

def deploy_tracker(config):
    """Deploy email tracking server"""
    provider = config['provider']
    provider_dir = PROVIDER_DIRS.get(provider, provider.upper())
    
    logging.info(f"Deploying tracker on {provider}...")
    
    # Set provider-specific environment variables
    if provider == "aws":
        if config.get('aws_access_key'):
            os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
        if config.get('aws_secret_key'):
            os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
    elif provider == "linode":
        if config.get('linode_token'):
            os.environ['LINODE_TOKEN'] = config['linode_token']
    
    # Determine playbook path
    playbook = f"{provider_dir}/tracker.yml"
    if not os.path.exists(playbook):
        logging.error(f"Tracker playbook not found at {playbook}")
        return False
    
    # Create inventory file
    inventory_path = create_inventory_file(config, "tracker")
    
    # Run the playbook
    try:
        success, stdout, stderr = run_ansible_playbook(
            playbook, inventory_path, config, config.get('debug', False)
        )
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return success
    except Exception as e:
        logging.error(f"Tracker deployment failed: {e}")
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return False

def main():
    """Main function to run the deployment"""
    # Display banner
    print("""
========================================
C2itAll - Red Team Infrastructure Setup
========================================
    """)
    
    # Set up logging
    log_file = setup_logging()
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Check dependencies
    check_dependencies()
    
    # Use interactive mode if specified
    if args.interactive:
        config = interactive_setup()
    else:
        # Override provider if --flokinet is specified
        if args.flokinet:
            args.provider = "flokinet"
        
        # Load variables from provider-specific vars.yaml if provider is specified
        vars_data = {}
        if args.provider:
            provider_dir = PROVIDER_DIRS.get(args.provider, args.provider.upper())
            vars_file = f"{provider_dir}/vars.yaml"
            if os.path.exists(vars_file):
                try:
                    with open(vars_file, 'r') as f:
                        vars_data = yaml.safe_load(f) or {}
                    logging.info(f"Loaded configuration from {vars_file}")
                except Exception as e:
                    logging.warning(f"Failed to load {vars_file}: {e}")
        
        # Build configuration by combining args and vars_data
        config = {}
        
        # Provider settings
        config['provider'] = args.provider
        
        # Copy all values from vars_data to config first
        for key, value in vars_data.items():
            config[key] = value
        
        # AWS settings
        if args.provider == "aws":
            config['aws_access_key'] = args.aws_key or vars_data.get('aws_access_key')
            config['aws_secret_key'] = args.aws_secret or vars_data.get('aws_secret_key')
            config['aws_region'] = args.aws_region or args.region or vars_data.get('aws_region')
            config['aws_region_choices'] = vars_data.get('aws_region_choices', [])
            config['ami_map'] = vars_data.get('ami_map', {})
            config['size'] = args.size or vars_data.get('aws_instance_type', 't2.medium')
        
        # Linode settings
        elif args.provider == "linode":
            config['linode_token'] = args.linode_token or vars_data.get('linode_token')
            config['linode_region'] = args.linode_region or args.region or vars_data.get('linode_region')
            # Ensure region_choices are correctly set
            config['region_choices'] = vars_data.get('region_choices', [])
            config['plan'] = args.size or vars_data.get('plan', 'g6-standard-2')
            config['image'] = vars_data.get('image', 'linode/kali')
            config['redirector_image'] = vars_data.get('redirector_image', 'linode/debian11')
        
        # FlokiNET settings
        elif args.provider == "flokinet":
            config['flokinet_redirector_ip'] = args.flokinet_redirector_ip or vars_data.get('redirector_ip')
            config['flokinet_c2_ip'] = args.flokinet_c2_ip or vars_data.get('c2_ip')
            config['flokinet_region_choices'] = vars_data.get('flokinet_region_choices', [])
            config['ssh_port'] = vars_data.get('ssh_port', 22)
        
        # SSH settings - explicitly set SSH user to avoid template recursion
        if args.provider == "linode":
            config['ssh_user'] = "root"
        elif args.provider == "aws":
            config['ssh_user'] = "kali"
        else:
            config['ssh_user'] = args.ssh_user or vars_data.get('ssh_user') or (DEFAULT_SSH_USER.get(args.provider) if args.provider else None)
            
        if args.ssh_key:
            config['ssh_key'] = os.path.expanduser(args.ssh_key)
        else:
            # Generate a key if no key is provided and we're not in teardown mode
            if not args.teardown:
                config['ssh_key'] = generate_ssh_key()
        
        # Generate random instance names with new format
        rand_suffix = generate_random_string()
        timestamp = int(time.time()) % 10000
        config['redirector_name'] = args.redirector_name or f"r-{rand_suffix}-{timestamp}"  # Changed from srv- to r-
        config['c2_name'] = args.c2_name or f"s-{rand_suffix}-{timestamp}"  # Changed from node- to s-
        config['tracker_name'] = args.tracker_name or f"t-{rand_suffix}-{timestamp}"  # Changed from track- to t-
        
        # Deployment options
        config['redirector_only'] = args.redirector_only
        config['c2_only'] = args.c2_only
        config['debug'] = args.debug
        config['domain'] = args.domain or vars_data.get('domain', 'example.com')
        config['letsencrypt_email'] = args.letsencrypt_email or vars_data.get('letsencrypt_email', f"admin@{config['domain']}")
        
        # OPSEC settings
        config['disable_history'] = args.disable_history if args.disable_history is not None else vars_data.get('disable_history', True)
        config['secure_memory'] = args.secure_memory if args.secure_memory is not None else vars_data.get('secure_memory', True)
        config['zero_logs'] = args.zero_logs if args.zero_logs is not None else vars_data.get('zero_logs', True)
        
        # Other settings from vars_data
        config['gophish_admin_port'] = vars_data.get('gophish_admin_port', str(random.randint(2000, 9000)))
        config['smtp_auth_user'] = vars_data.get('smtp_auth_user', f"user{random.randint(1000, 9999)}")
        config['smtp_auth_pass'] = vars_data.get('smtp_auth_pass', ''.join(random.choices(string.ascii_letters + string.digits, k=20)))
        config['shell_handler_port'] = vars_data.get('shell_handler_port', str(random.randint(4000, 65000)))
        
        # Tracker options
        config['deploy_tracker'] = args.deploy_tracker
        if args.deploy_tracker:
            config['tracker_domain'] = args.tracker_domain or f"track.{config['domain']}"
            config['tracker_email'] = args.tracker_email or config['letsencrypt_email']
            config['tracker_ipinfo_token'] = args.tracker_ipinfo_token
            config['tracker_setup_ssl'] = args.tracker_setup_ssl
            config['tracker_create_pixel'] = args.tracker_create_pixel
        
        # SSH after deploy
        config['ssh_after_deploy'] = args.ssh_after_deploy
        
        # Run tests
        config['run_tests'] = args.run_tests
        
        # Make sure we have the public key path if we're generating one
        if config.get('ssh_key') and config['ssh_key'].startswith(os.path.expanduser("~/.ssh/c2deploy_")):
            config['ssh_key_path'] = f"{config['ssh_key']}.pub"
        elif config.get('ssh_key'):
            config['ssh_key_path'] = f"{config['ssh_key']}.pub"
            # Check if the public key exists
            if not os.path.exists(config['ssh_key_path']):
                # Try alternative extension
                alt_path = f"{config['ssh_key']}.pub"
                if os.path.exists(alt_path):
                    config['ssh_key_path'] = alt_path
                elif not args.teardown:  # Only generate new key if not in teardown mode
                    logging.warning(f"Public key not found at {config['ssh_key_path']}. Generating a new key.")
                    config['ssh_key'] = generate_ssh_key()
                    config['ssh_key_path'] = f"{config['ssh_key']}.pub"
    
    # Validate deployment mode
    if config.get('redirector_only') and config.get('c2_only'):
        logging.error("Cannot specify both --redirector-only and --c2-only")
        return
    
    # Log configuration (excluding sensitive data)
    logging.info("Deployment configuration:")
    for key, value in config.items():
        if key not in ['aws_secret_key', 'linode_token', 'smtp_auth_pass', 'tracker_ipinfo_token']:
            if isinstance(value, (dict, list)):
                logging.info(f"  {key}: <complex data>")
            else:
                logging.info(f"  {key}: {value}")
    
    # Check if this is a teardown operation
    if args.teardown:
        teardown_infrastructure(config)
        return
    
    # Check if this is a test operation
    if args.run_tests:
        run_tests(config)
        return
    
    # Run deployment
    try:
        # Deploy tracker if requested
        if config.get('deploy_tracker'):
            success = deploy_tracker(config)
            if not success:
                logging.error("Tracker deployment failed!")
                cleanup_resources(config, interactive=True)
                return
            
            logging.info("Tracker deployment completed successfully!")
            
            # SSH into tracker if requested
            if config.get('ssh_after_deploy'):
                ssh_to_instance(config)
                
            return
        
        # Deploy main infrastructure
        success = deploy_infrastructure(config)
        
        if success:
            logging.info("Deployment completed successfully!")
            
            # SSH into instance if requested
            if config.get('ssh_after_deploy'):
                ssh_to_instance(config)
        else:
            logging.error("Deployment failed!")
            cleanup_resources(config, interactive=True)
    except KeyboardInterrupt:
        print("\n\nDeployment interrupted by user")
        logging.info("Deployment interrupted by user")
        try:
            cleanup_resources(config, interactive=True)
        except KeyboardInterrupt:
            print("\nCleanup interrupted. Resources may still exist.")
            logging.warning("Cleanup interrupted by user. Resources may still exist.")
    except Exception as e:
        logging.error(f"Deployment failed with error: {e}")
        if config.get('debug'):
            import traceback
            traceback.print_exc()
            logging.debug(traceback.format_exc())
        try:
            cleanup_resources(config, interactive=True)
        except KeyboardInterrupt:
            print("\nCleanup interrupted. Resources may still exist.")
            logging.warning("Cleanup interrupted by user. Resources may still exist.")

if __name__ == "__main__":
    main()