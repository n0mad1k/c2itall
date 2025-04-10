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

# Constants
PROVIDERS = ["aws", "linode", "flokinet"]
DEFAULT_SSH_USER = {
    "aws": "kali",
    "linode": "root",
    "flokinet": "root"
}

def setup_logging():
    """Set up logging for the deployment"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, f"deployment_{timestamp}.log")
    
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
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
    parser = argparse.ArgumentParser(description='Deploy C2 Red Team infrastructure')
    
    # Provider selection
    parser.add_argument('-p', '--provider', choices=PROVIDERS, default="aws", help='Provider to use for deployment')
    
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
    parser.add_argument('--region', help='Generic region parameter')
    parser.add_argument('--redirector-name', help='Name for the redirector instance (default: random)')
    parser.add_argument('--c2-name', help='Name for the C2 instance (default: random)')
    
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
    parser.add_argument('--teardown', action='store_true', help='Tear down existing infrastructure')
    
    return parser.parse_args()

def load_vars_file(provider):
    """Load vars.yaml for the specified provider"""
    vars_file = f"{provider}/vars.yaml"
    if os.path.exists(vars_file):
        try:
            with open(vars_file, 'r') as f:
                vars_data = yaml.safe_load(f)
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
        region_choices = config.get("region_choices", [])
    elif provider == "flokinet":
        region_choices = config.get("flokinet_region_choices", [])
    
    if not region_choices:
        logging.warning(f"No region choices found for {provider}")
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
    inventory_content.append("ansible_python_interpreter=/usr/bin/python3")
    
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
    extra_vars_json = json.dumps(extra_vars)
    
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
    
    # Log the command
    logging.debug(f"Running Ansible command: {' '.join(cmd)}")
    
    # Run the command
    try:
        result = subprocess.run(
            cmd, 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        logging.info(f"Playbook {playbook} executed successfully")
        return True, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        logging.error(f"Playbook {playbook} failed with exit code {e.returncode}")
        logging.error(f"Error output: {e.stderr}")
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
    
    # Select random region if not specified
    if provider == "aws" and not config.get('aws_region'):
        config['aws_region'] = select_random_region(config)
    elif provider == "linode" and not config.get('linode_region'):
        config['linode_region'] = select_random_region(config)
    
    # Determine playbook path based on deployment mode
    if config.get('redirector_only'):
        playbook = f"{provider}/redirector.yml"
        deployment_type = "redirector"
    elif config.get('c2_only'):
        playbook = f"{provider}/c2.yml"
        deployment_type = "c2"
    else:
        # Full deployment
        if provider == "flokinet":
            # FlokiNET requires separate deployments for redirector and C2
            redirector_success = deploy_flokinet_redirector(config)
            if not redirector_success:
                return False
            
            # If redirector deployed successfully, deploy C2
            return deploy_flokinet_c2(config)
        else:
            # AWS and Linode use a single playbook for full deployment
            playbook = f"{provider}/c2-deploy.yaml"
            deployment_type = "local"
    
    # Create inventory file
    inventory_path = create_inventory_file(config, deployment_type)
    
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
        logging.error(f"Deployment failed: {e}")
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return False

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
    playbook = "FlokiNET/redirector.yml"
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
    playbook = "FlokiNET/c2.yml"
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

def ssh_to_instance(config):
    """SSH into the deployed instance"""
    logging.info("Connecting to instance via SSH...")
    
    # Determine which IP to use based on deployment type
    if config.get('redirector_only'):
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

def cleanup_resources(config):
    """Clean up resources if deployment fails"""
    provider = config.get('provider')
    logging.info(f"Cleaning up {provider} resources...")
    
    # Use Ansible for cleanup
    playbook = f"{provider}/cleanup.yml"
    if os.path.exists(playbook):
        logging.info(f"Running cleanup playbook: {playbook}")
        inventory_path = create_inventory_file(config, "local")
        try:
            run_ansible_playbook(playbook, inventory_path, config)
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

def main():
    """Main function to run the deployment"""
    # Set up logging
    log_file = setup_logging()
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Override provider if --flokinet is specified
    if args.flokinet:
        args.provider = "flokinet"
    
    # Load variables from provider-specific vars.yaml
    vars_data = load_vars_file(args.provider)
    
    # Build configuration by combining args and vars_data
    config = {}
    
    # Provider settings
    config['provider'] = args.provider
    
    # AWS settings
    if args.provider == "aws":
        config['aws_access_key'] = args.aws_key or vars_data.get('aws_access_key')
        config['aws_secret_key'] = args.aws_secret or vars_data.get('aws_secret_key')
        config['aws_region'] = args.aws_region or args.region
        config['aws_region_choices'] = vars_data.get('aws_region_choices', [])
        config['ami_map'] = vars_data.get('ami_map', {})
    
    # Linode settings
    elif args.provider == "linode":
        config['linode_token'] = args.linode_token or vars_data.get('linode_token')
        config['linode_region'] = args.linode_region or args.region
        config['region_choices'] = vars_data.get('region_choices', [])
        config['plan'] = vars_data.get('plan', 'g6-standard-1')
        config['image'] = vars_data.get('image', 'linode/debian11')
    
    # FlokiNET settings
    elif args.provider == "flokinet":
        config['flokinet_redirector_ip'] = args.flokinet_redirector_ip or vars_data.get('redirector_ip')
        config['flokinet_c2_ip'] = args.flokinet_c2_ip or vars_data.get('c2_ip')
        config['flokinet_region_choices'] = vars_data.get('flokinet_region_choices', [])
        config['ssh_port'] = vars_data.get('ssh_port', 22)
    
    # SSH settings
    config['ssh_user'] = args.ssh_user or DEFAULT_SSH_USER.get(args.provider)
    if args.ssh_key:
        config['ssh_key'] = os.path.expanduser(args.ssh_key)
    else:
        config['ssh_key'] = generate_ssh_key()
    
    # Generate random instance names
    rand_suffix = generate_random_string()
    timestamp = int(time.time()) % 10000
    config['redirector_name'] = args.redirector_name or f"srv-{rand_suffix}-{timestamp}"
    config['c2_name'] = args.c2_name or f"node-{rand_suffix}-{timestamp}"
    
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
    
    # Validate deployment mode
    if config['redirector_only'] and config['c2_only']:
        logging.error("Cannot specify both --redirector-only and --c2-only")
        return
    
    # Log configuration (excluding sensitive data)
    logging.info("Deployment configuration:")
    for key, value in config.items():
        if key not in ['aws_secret_key', 'linode_token', 'smtp_auth_pass']:
            if isinstance(value, (dict, list)):
                logging.info(f"  {key}: <complex data>")
            else:
                logging.info(f"  {key}: {value}")
    
    # Run deployment
    try:
        success = deploy_infrastructure(config)
        
        if success:
            logging.info("Deployment completed successfully!")
            
            # SSH into instance if requested
            if args.ssh_after_deploy:
                ssh_to_instance(config)
        else:
            logging.error("Deployment failed!")
            cleanup_resources(config)
    except KeyboardInterrupt:
        logging.info("Deployment interrupted by user")
        cleanup_resources(config)
    except Exception as e:
        logging.error(f"Deployment failed with error: {e}")
        if config.get('debug'):
            import traceback
            logging.debug(traceback.format_exc())
        cleanup_resources(config)

if __name__ == "__main__":
    main()