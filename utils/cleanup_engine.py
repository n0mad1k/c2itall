#!/usr/bin/env python3
"""
Cleanup and teardown engine for C2ingRed deployments
"""

import os
import sys
import subprocess
import logging
import json
import glob

# Add project root to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils.common import COLORS, PROVIDER_DIRS, confirm_action

def teardown_by_deployment_id(deployment_id):
    """Teardown infrastructure by deployment ID"""
    print(f"\n{COLORS['BLUE']}Teardown Infrastructure by ID: {deployment_id}{COLORS['RESET']}")
    
    # Look for deployment logs to determine provider and configuration
    log_files = glob.glob(f"logs/deployment_{deployment_id}*.log")
    
    if not log_files:
        print(f"{COLORS['RED']}No deployment logs found for ID: {deployment_id}{COLORS['RESET']}")
        return False
    
    # Try to find deployment info files
    info_files = glob.glob(f"logs/deployment_info_{deployment_id}*.txt")
    
    if info_files:
        config = parse_deployment_info(info_files[0])
        if config:
            return execute_teardown(config)
    
    print(f"{COLORS['YELLOW']}Could not determine deployment configuration from logs{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}Manual cleanup may be required{COLORS['RESET']}")
    return False

def teardown_all_infrastructure():
    """Teardown all deployed infrastructure"""
    print(f"\n{COLORS['RED']}⚠️  WARNING: This will attempt to destroy ALL infrastructure!{COLORS['RESET']}")
    
    if not confirm_action("Are you absolutely sure?", default=False):
        return False
    
    # Find all deployment info files
    info_files = glob.glob("logs/deployment_info_*.txt")
    
    if not info_files:
        print(f"{COLORS['GREEN']}No deployment info files found - nothing to teardown{COLORS['RESET']}")
        return True
    
    print(f"Found {len(info_files)} deployments to teardown:")
    
    success_count = 0
    for info_file in info_files:
        config = parse_deployment_info(info_file)
        if config:
            deployment_id = config.get('deployment_id', 'unknown')
            print(f"\nTearing down deployment: {deployment_id}")
            if execute_teardown(config):
                success_count += 1
    
    print(f"\n{COLORS['GREEN']}Successfully tore down {success_count}/{len(info_files)} deployments{COLORS['RESET']}")
    return success_count == len(info_files)

def parse_deployment_info(info_file):
    """Parse deployment info from file to extract configuration"""
    try:
        config = {}
        with open(info_file, 'r') as f:
            lines = f.readlines()
        
        in_config_section = False
        for line in lines:
            line = line.strip()
            
            if line == "Configuration:":
                in_config_section = True
                continue
            elif line.startswith("-" * 30):
                continue
            elif line.startswith("Access Information:"):
                break
                
            if in_config_section and ": " in line:
                key, value = line.split(": ", 1)
                
                # Convert string values back to appropriate types
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                elif value.lower() == 'none':
                    value = None
                
                config[key] = value
        
        return config
    except Exception as e:
        logging.error(f"Failed to parse deployment info from {info_file}: {e}")
        return None

def execute_teardown(config):
    """Execute teardown based on configuration"""
    provider = config.get('provider')
    deployment_id = config.get('deployment_id')
    
    if not provider or not deployment_id:
        print(f"{COLORS['RED']}Missing provider or deployment ID{COLORS['RESET']}")
        return False
    
    print(f"{COLORS['BLUE']}Executing teardown for {provider} deployment {deployment_id}...{COLORS['RESET']}")
    
    # Set up logging for teardown
    from utils.common import setup_logging
    setup_logging(deployment_id, "teardown")
    
    try:
        # Set provider-specific environment variables
        set_provider_environment_for_teardown(config)
        
        # Get correct provider directory
        provider_dir = PROVIDER_DIRS.get(provider, provider.capitalize())
        
        # Execute teardown playbook
        playbook = f"providers/{provider_dir}/cleanup.yml"
        
        if not os.path.exists(playbook):
            print(f"{COLORS['YELLOW']}Teardown playbook not found: {playbook}{COLORS['RESET']}")
            print(f"{COLORS['YELLOW']}Manual cleanup required{COLORS['RESET']}")
            return manual_cleanup_guidance(config)
        
        success = run_teardown_playbook(playbook, config)
        
        if success:
            # Clean up local SSH keys
            cleanup_ssh_keys_for_deployment(deployment_id)
            
            # Move deployment logs to cleanup folder
            archive_deployment_logs(deployment_id)
            
            print(f"{COLORS['GREEN']}Teardown completed successfully{COLORS['RESET']}")
        else:
            print(f"{COLORS['RED']}Teardown failed - manual cleanup may be required{COLORS['RESET']}")
        
        return success
        
    except Exception as e:
        logging.error(f"Teardown execution failed: {e}")
        print(f"{COLORS['RED']}Teardown execution failed: {e}{COLORS['RESET']}")
        return False

def set_provider_environment_for_teardown(config):
    """Set provider-specific environment variables for teardown"""
    provider = config.get('provider')
    
    if provider == "aws":
        if config.get('aws_access_key'):
            os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
        if config.get('aws_secret_key'):
            os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
    elif provider == "linode":
        # Try to get token from config first, then from vars file
        if config.get('linode_token'):
            os.environ['LINODE_TOKEN'] = config['linode_token']
        else:
            # Load token from provider vars file
            try:
                from utils.common import load_vars_file, PROVIDER_DIRS
                provider_dir = PROVIDER_DIRS.get(provider, provider.capitalize())
                vars_file = f"providers/{provider_dir}/vars.yaml"
                vars_data = load_vars_file(vars_file)
                if vars_data and vars_data.get('linode_token'):
                    os.environ['LINODE_TOKEN'] = vars_data['linode_token']
                    config['linode_token'] = vars_data['linode_token']  # Add to config for later use
                else:
                    logging.warning("Linode token not found in vars file - cleanup may fail")
            except Exception as e:
                logging.warning(f"Failed to load Linode token from vars file: {e}")

def run_teardown_playbook(playbook, config):
    """Run the teardown Ansible playbook"""
    try:
        cmd = [
            'ansible-playbook',
            playbook,
            '--extra-vars', create_teardown_vars(config)
        ]
        
        if config.get('debug'):
            cmd.append('-vvv')
        
        logging.info(f"Executing teardown: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        
        if result.returncode == 0:
            logging.info("Teardown playbook executed successfully")
            return True
        else:
            logging.error(f"Teardown playbook failed with return code {result.returncode}")
            logging.error(f"STDOUT: {result.stdout}")
            logging.error(f"STDERR: {result.stderr}")
            return False
            
    except Exception as e:
        logging.error(f"Error executing teardown playbook: {e}")
        return False

def create_teardown_vars(config):
    """Create Ansible extra vars for teardown"""
    teardown_vars = {
        'deployment_id': config.get('deployment_id'),
        'provider': config.get('provider'),
        'operation': 'teardown'
    }
    
    # Add instance names for proper cleanup
    if config.get('redirector_name'):
        teardown_vars['redirector_name'] = config['redirector_name']
    if config.get('c2_name'):
        teardown_vars['c2_name'] = config['c2_name']
    if config.get('tracker_name'):
        teardown_vars['tracker_name'] = config['tracker_name']
    if config.get('attack_box_name'):
        teardown_vars['attack_box_name'] = config['attack_box_name']
    
    # Add provider-specific vars if present
    if config.get('aws_access_key'):
        teardown_vars['aws_access_key'] = config['aws_access_key']
    if config.get('aws_secret_key'):
        teardown_vars['aws_secret_key'] = config['aws_secret_key']
    if config.get('aws_region'):
        teardown_vars['aws_region'] = config['aws_region']
    if config.get('linode_token'):
        teardown_vars['linode_token'] = config['linode_token']
    if config.get('linode_region'):
        teardown_vars['linode_region'] = config['linode_region']
    
    return json.dumps(teardown_vars)

def cleanup_ssh_keys_for_deployment(deployment_id):
    """Clean up SSH keys for a specific deployment"""
    ssh_dir = os.path.expanduser("~/.ssh")
    key_pattern = f"c2deploy_{deployment_id}*"
    
    for key_file in glob.glob(os.path.join(ssh_dir, key_pattern)):
        try:
            os.remove(key_file)
            logging.info(f"Removed SSH key: {key_file}")
        except Exception as e:
            logging.warning(f"Failed to remove SSH key {key_file}: {e}")

def archive_deployment_logs(deployment_id):
    """Archive deployment logs after successful teardown"""
    try:
        # Create archive directory
        archive_dir = "logs/archive"
        os.makedirs(archive_dir, exist_ok=True)
        
        # Move all files related to this deployment
        log_patterns = [
            f"logs/deployment_{deployment_id}*",
            f"logs/deployment_info_{deployment_id}*",
            f"logs/teardown_{deployment_id}*"
        ]
        
        for pattern in log_patterns:
            for file_path in glob.glob(pattern):
                archive_path = os.path.join(archive_dir, os.path.basename(file_path))
                os.rename(file_path, archive_path)
                logging.info(f"Archived: {file_path} -> {archive_path}")
                
    except Exception as e:
        logging.warning(f"Failed to archive logs for {deployment_id}: {e}")

def manual_cleanup_guidance(config):
    """Provide manual cleanup guidance when automated teardown isn't available"""
    provider = config.get('provider')
    deployment_id = config.get('deployment_id')
    
    print(f"\n{COLORS['YELLOW']}Manual Cleanup Required{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}========================{COLORS['RESET']}")
    print(f"Deployment ID: {deployment_id}")
    print(f"Provider: {provider}")
    
    if provider == "aws":
        print(f"\nAWS Resources to check:")
        print(f"- EC2 instances with tags containing: {deployment_id}")
        print(f"- Security groups with names containing: {deployment_id}")
        print(f"- Key pairs with names containing: {deployment_id}")
        print(f"- EIPs associated with the deployment")
        
    elif provider == "linode":
        print(f"\nLinode Resources to check:")
        print(f"- Linodes with labels containing: {deployment_id}")
        print(f"- NodeBalancers with labels containing: {deployment_id}")
        print(f"- Firewalls with labels containing: {deployment_id}")
        
    elif provider == "flokinet":
        print(f"\nFlokiNET Resources to check:")
        print(f"- Check your FlokiNET control panel for resources created")
        print(f"- Look for servers with the deployment ID: {deployment_id}")
    
    print(f"\nLocal cleanup:")
    print(f"- SSH keys: ~/.ssh/c2deploy_{deployment_id}*")
    print(f"- Log files: logs/*{deployment_id}*")
    
    return False  # Manual cleanup required

if __name__ == "__main__":
    print("Cleanup engine loaded")
