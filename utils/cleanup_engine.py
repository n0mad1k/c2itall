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
import re
import tempfile

# Add project root to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils.common import COLORS, PROVIDER_DIRS, confirm_action
from utils.provider_registry import (
    infrastructure_adapter, list_infrastructure_states,
    load_infrastructure_state, prepare_provider_environment,
    provider_cleanup_guidance, provider_cleanup_is_automated,
    provider_teardown_vars, requested_workload, uses_legacy_routes,
    workload_route,
)

def teardown_by_deployment_id(deployment_id):
    """Teardown infrastructure by deployment ID"""
    print(f"\n{COLORS['BLUE']}Teardown Infrastructure by ID: {deployment_id}{COLORS['RESET']}")
    try:
        state = load_infrastructure_state(deployment_id)
    except (ValueError, KeyError, OSError) as exc:
        logging.error('Invalid infrastructure recovery state: %s', exc)
        return False
    if state is not None:
        return execute_teardown(state)
    
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
    
    try:
        states = list_infrastructure_states()
    except (ValueError, KeyError, OSError) as exc:
        logging.error('Invalid infrastructure recovery state: %s', exc)
        return False
    configs = {(state['provider'], state['deployment_id']): state for state in states}
    for info_file in info_files:
        config = parse_deployment_info(info_file)
        if config:
            configs.setdefault((config.get('provider'), config.get('deployment_id')), config)
    if not configs:
        print(f"{COLORS['GREEN']}No deployment info files found - nothing to teardown{COLORS['RESET']}")
        return True
    
    print(f"Found {len(configs)} deployments to teardown:")
    
    success_count = 0
    for config in configs.values():
        if config:
            deployment_id = config.get('deployment_id', 'unknown')
            print(f"\nTearing down deployment: {deployment_id}")
            if execute_teardown(config):
                success_count += 1
    
    print(f"\n{COLORS['GREEN']}Successfully tore down {success_count}/{len(configs)} deployments{COLORS['RESET']}")
    return success_count == len(configs)

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
    adapter = workload_route(config)
    legacy = uses_legacy_routes(provider, requested_workload(config))
    if adapter is None and not legacy:
        adapter = infrastructure_adapter(provider)
    if adapter is not None:
        return adapter.cleanup(config)
    if not legacy:
        logging.error('Provider has no cleanup route for this workload')
        return False
    return execute_legacy_teardown(config)


def execute_legacy_teardown(config):
    """Run preserved cleanup without re-entering the provider registry."""
    provider = config.get('provider')
    deployment_id = config.get('deployment_id')
    
    if not provider or not deployment_id:
        print(f"{COLORS['RED']}Missing provider or deployment ID{COLORS['RESET']}")
        return False
    if not provider_cleanup_is_automated(provider):
        return manual_cleanup_guidance(config)
    
    print(f"{COLORS['BLUE']}Executing teardown for {provider} deployment {deployment_id}...{COLORS['RESET']}")
    
    # Set up logging for teardown
    from utils.common import setup_logging
    setup_logging(deployment_id, "teardown")
    
    try:
        # Set provider-specific environment variables
        set_provider_environment_for_teardown(config)
        
        # Get correct provider directory
        provider_dir = PROVIDER_DIRS.get(provider, provider.capitalize())
        
        # Execute teardown playbook. Provider playbooks must return nonzero
        # unless their final inventory proves owned resources are absent.
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
    """Compatibility shim for registry-routed teardown environment setup."""
    return prepare_provider_environment(config, teardown=True)

def run_teardown_playbook(playbook, config):
    """Run the teardown Ansible playbook"""
    variables_path = None
    try:
        fd, variables_path = tempfile.mkstemp(
            suffix='.json', prefix='c2itall_teardown_')
        os.chmod(variables_path, 0o600)
        with os.fdopen(fd, 'w') as variables:
            variables.write(create_teardown_vars(config))
        cmd = [
            'ansible-playbook',
            playbook,
            '--extra-vars', '@' + variables_path,
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
    finally:
        if variables_path and os.path.exists(variables_path):
            os.unlink(variables_path)

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
    
    teardown_vars.update(provider_teardown_vars(config))
    
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
    
    guidance = provider_cleanup_guidance(provider, deployment_id)
    if guidance:
        label = PROVIDER_DIRS.get(provider, str(provider))
        print(f"\n{label} Resources to check:")
        for item in guidance:
            print(f"- {item}")
    
    print(f"\nLocal cleanup:")
    print(f"- SSH keys: ~/.ssh/c2deploy_{deployment_id}*")
    print(f"- Log files: logs/*{deployment_id}*")
    
    return False  # Manual cleanup required

if __name__ == "__main__":
    print("Cleanup engine loaded")
