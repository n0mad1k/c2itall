#!/usr/bin/env python3
"""
Standalone teardown script for C2itall deployments
This script can be used to teardown infrastructure when the main menu fails
"""

import os
import sys
import subprocess
import logging
import json
import glob
import argparse
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from utils.common import COLORS, PROVIDER_DIRS, setup_logging
    from utils.provider_registry import (
        prepare_provider_environment, provider_cleanup_guidance,
        requested_workload, workload_route, uses_legacy_routes,
    )
except ImportError as e:
    print(f"Error importing utils: {e}")
    print("Make sure you're running this from the c2itall directory")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='C2itall Standalone Teardown Tool')
    parser.add_argument('--deployment-id', help='Specific deployment ID to teardown')
    parser.add_argument('--list', action='store_true', help='List all deployments')
    parser.add_argument('--all', action='store_true', help='Teardown all deployments')
    parser.add_argument('--select', action='store_true', help='Interactively select deployment to teardown')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--force', action='store_true', help='Skip confirmation prompts')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    
    print(f"{COLORS['BLUE']}C2itall Standalone Teardown Tool{COLORS['RESET']}")
    print(f"{COLORS['BLUE']}================================{COLORS['RESET']}")
    
    if args.list:
        return 0 if list_deployments() else 1
    elif args.all:
        return 0 if teardown_all_deployments(force=args.force) else 1
    elif args.deployment_id:
        return 0 if teardown_deployment(args.deployment_id, force=args.force) else 1
    elif args.select:
        return 0 if select_and_teardown_deployment() else 1
    else:
        interactive_mode()

def discover_deployments():
    """Combine recovery state and legacy logs before any destructive action.

    Adapter state is authoritative for matching provider/ID records. Conflicting
    IDs and unreadable records abort discovery instead of hiding deployments.
    """
    from utils.provider_registry import list_infrastructure_states, uses_legacy_routes
    try:
        deployments = []
        by_id = {}
        adapter_ids = set()
        for config in list_infrastructure_states():
            deployment_id = config.get('deployment_id')
            if not deployment_id or deployment_id in by_id:
                raise ValueError('Missing or ambiguous adapter deployment ID')
            by_id[deployment_id] = config
            adapter_ids.add(deployment_id)
            deployments.append(config)
        for info_file in glob.glob("logs/deployment_info_*.txt"):
            config = parse_deployment_info(info_file)
            if not config or not config.get('deployment_id') or not config.get('provider'):
                raise ValueError('Cannot identify deployment in ' + info_file)
            deployment_id = config['deployment_id']
            if deployment_id in by_id:
                if (deployment_id in adapter_ids and
                        config['provider'] == by_id[deployment_id]['provider']):
                    continue
                raise ValueError('Ambiguous deployment ID: ' + deployment_id)
            if not uses_legacy_routes(config['provider']):
                raise ValueError('Missing adapter recovery state for ' + deployment_id)
            by_id[deployment_id] = config
            deployments.append(config)
        return deployments, adapter_ids
    except (OSError, ValueError, KeyError) as error:
        print(f"{COLORS['RED']}Cannot discover deployments: {error}{COLORS['RESET']}")
        return None


def teardown_adapter_state(state, force=False):
    """Keep adapter cleanup pinned to its discovered state, even if logs change."""
    print(f"Provider: {state['provider']}")
    if not force and input('Proceed with infrastructure teardown? (yes/no): ').strip().lower() != 'yes':
        print('Teardown cancelled')
        return False
    from utils.provider_registry import infrastructure_adapter
    try:
        adapter = workload_route(state) or infrastructure_adapter(state['provider'])
        if adapter is None:
            raise ValueError('Infrastructure adapter is unavailable')
        # The adapter owns exact key cleanup and state archival. Never follow it
        # with legacy prefix-based key deletion or fall back after failure.
        return adapter.cleanup(state)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"{COLORS['RED']}Infrastructure cleanup failed: {error}{COLORS['RESET']}")
        return False


def list_deployments():
    """List all available deployments"""
    print(f"\n{COLORS['CYAN']}Available Deployments:{COLORS['RESET']}")
    
    discovered = discover_deployments()
    if discovered is None:
        return False
    deployments, adapter_ids = discovered
    if not deployments:
        print(f"{COLORS['GREEN']}No deployments found{COLORS['RESET']}")
        return True
    
    print(f"Found {len(deployments)} deployments:\n")
    
    for i, config in enumerate(deployments, 1):
        deployment_id = config.get('deployment_id', 'unknown')
        provider = config.get('provider', 'unknown')
        domain = config.get('domain', 'N/A')
        status = config.get('status', 'unknown')
        
        print(f"{i}. Deployment ID: {deployment_id}")
        print(f"   Provider: {provider}")
        print(f"   Domain: {domain}")
        print(f"   Status: {status}")
        
        # Show instance names if available
        instances = []
        if config.get('redirector_name'):
            instances.append(f"Redirector: {config['redirector_name']}")
        if config.get('c2_name'):
            instances.append(f"C2: {config['c2_name']}")
        if config.get('tracker_name'):
            instances.append(f"Tracker: {config['tracker_name']}")
        if config.get('attack_box_name'):
            instances.append(f"Attack Box: {config['attack_box_name']}")
        
        if instances:
            print(f"   Instances: {', '.join(instances)}")
        
        print()
    return True

def interactive_mode():
    """Interactive teardown mode"""
    while True:
        print(f"\n{COLORS['WHITE']}Teardown Options:{COLORS['RESET']}")
        print("1) List all deployments")
        print("2) Select deployment to teardown")
        print("3) Teardown all deployments")
        print("4) Manual cleanup guidance")
        print("5) Exit")
        
        choice = input(f"\nSelect option (1-5): ").strip()
        
        if choice == "1":
            list_deployments()
        elif choice == "2":
            select_and_teardown_deployment()
        elif choice == "3":
            teardown_all_deployments()
        elif choice == "4":
            show_manual_cleanup_guidance()
        elif choice == "5":
            print(f"{COLORS['GREEN']}Goodbye!{COLORS['RESET']}")
            break
        else:
            print(f"{COLORS['RED']}Invalid option{COLORS['RESET']}")

def teardown_deployment(deployment_id, force=False):
    """Teardown a specific deployment"""
    print(f"\n{COLORS['BLUE']}Tearing down deployment: {deployment_id}{COLORS['RESET']}")
    from utils.provider_registry import load_infrastructure_state
    try:
        state = load_infrastructure_state(deployment_id)
    except (OSError, ValueError, KeyError) as error:
        print(f"{COLORS['RED']}Cannot read infrastructure recovery state: {error}{COLORS['RESET']}")
        return False
    if state is not None:
        return teardown_adapter_state(state, force=force)

    # Find deployment info
    info_files = glob.glob(f"logs/deployment_info_{deployment_id}*.txt")
    
    if not info_files:
        print(f"{COLORS['RED']}No deployment info found for ID: {deployment_id}{COLORS['RESET']}")
        print(f"{COLORS['YELLOW']}Available deployments:{COLORS['RESET']}")
        list_deployments()
        return False
    
    config = parse_deployment_info(info_files[0])
    if not config:
        print(f"{COLORS['RED']}Could not parse deployment configuration{COLORS['RESET']}")
        return False
    
    # Show what will be torn down
    provider = config.get('provider', 'unknown')
    print(f"Provider: {provider}")
    
    instances_to_delete = []
    if config.get('redirector_name'):
        instances_to_delete.append(f"Redirector: {config['redirector_name']}")
    if config.get('c2_name'):
        instances_to_delete.append(f"C2: {config['c2_name']}")
    if config.get('tracker_name'):
        instances_to_delete.append(f"Tracker: {config['tracker_name']}")
    if config.get('attack_box_name'):
        instances_to_delete.append(f"Attack Box: {config['attack_box_name']}")
    
    if instances_to_delete:
        print(f"Instances to delete:")
        for instance in instances_to_delete:
            print(f"  - {instance}")
    else:
        print(f"{COLORS['YELLOW']}No instances found in configuration{COLORS['RESET']}")
    
    # Confirm deletion
    if not force:
        confirm = input(f"\n{COLORS['YELLOW']}Proceed with teardown? (yes/no): {COLORS['RESET']}").strip().lower()
        if confirm != 'yes':
            print(f"{COLORS['GREEN']}Teardown cancelled{COLORS['RESET']}")
            return False
    
    # Set up logging
    log_file = setup_logging(deployment_id, "teardown")
    print(f"Teardown logs will be written to: {log_file}")
    
    # Execute teardown
    success = execute_teardown(config)
    
    if success:
        print(f"\n{COLORS['GREEN']}Teardown completed successfully!{COLORS['RESET']}")
        # Clean up SSH keys
        cleanup_ssh_keys(deployment_id)
        # Archive logs
        archive_logs(deployment_id)
    else:
        print(f"\n{COLORS['RED']}Teardown failed or incomplete{COLORS['RESET']}")
        print(f"Check logs for details: {log_file}")
    
    return success

def teardown_all_deployments(force=False):
    """Teardown discovered adapter deployments and existing legacy deployments."""
    discovered = discover_deployments()
    if discovered is None:
        return False
    deployments, adapter_ids = discovered
    if not deployments:
        print(f"{COLORS['GREEN']}No deployments found{COLORS['RESET']}")
        return True
    print(f"Found {len(deployments)} deployments to teardown")
    for config in deployments:
        print(f"  {config['provider']}: {config['deployment_id']}")
    if not force:
        confirm = input(f"{COLORS['YELLOW']}Type 'DESTROY' to confirm: {COLORS['RESET']}")
        if confirm != "DESTROY":
            print(f"{COLORS['GREEN']}Operation cancelled{COLORS['RESET']}")
            return False
    success_count = 0
    for config in deployments:
        deployment_id = config['deployment_id']
        print(f"\n{COLORS['CYAN']}Tearing down: {deployment_id}{COLORS['RESET']}")
        if deployment_id in adapter_ids:
            success = teardown_adapter_state(config, force=True)
        else:
            success = execute_teardown(config)
            if success:
                cleanup_ssh_keys(deployment_id)
                archive_logs(deployment_id)
        if success:
            success_count += 1
        else:
            print(f"{COLORS['RED']}{deployment_id} teardown failed{COLORS['RESET']}")
    print(f"\n{COLORS['BLUE']}Summary: {success_count}/{len(deployments)} deployments torn down{COLORS['RESET']}")
    return success_count == len(deployments)

def parse_deployment_info(info_file):
    """Parse deployment info file"""
    try:
        config = {}
        with open(info_file, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if ": " in line and not line.startswith("-"):
                parts = line.split(": ", 1)
                if len(parts) == 2:
                    key, value = parts
                    
                    # Convert string values
                    if value.lower() == 'true':
                        value = True
                    elif value.lower() == 'false':
                        value = False
                    elif value.lower() == 'none':
                        value = None
                    
                    config[key] = value
        
        return config
    except Exception as e:
        print(f"{COLORS['RED']}Error parsing {info_file}: {e}{COLORS['RESET']}")
        return None

def execute_teardown(config):
    """Prefer the registered workload cleanup, then preserve legacy behavior."""
    provider = config.get('provider')

    if not provider:
        print(f"{COLORS['RED']}No provider specified in configuration{COLORS['RESET']}")
        return False

    adapter = workload_route(config)
    if adapter is not None:
        cleanup_with_legacy = getattr(type(adapter), 'cleanup_with_legacy', None)
        if callable(cleanup_with_legacy):
            return adapter.cleanup_with_legacy(config, execute_legacy_teardown)
        return adapter.cleanup(config)
    if not uses_legacy_routes(provider, requested_workload(config)):
        print(f"{COLORS['RED']}Provider has no cleanup route for this workload{COLORS['RESET']}")
        return False
    return execute_legacy_teardown(config)


def execute_legacy_teardown(config):
    """Execute the standalone tool's preserved legacy cleanup path."""
    provider = config.get('provider')

    # Set provider environment
    set_provider_environment(config)
    
    # Get provider directory
    provider_dir = PROVIDER_DIRS.get(provider, provider.capitalize())
    cleanup_playbook = f"providers/{provider_dir}/cleanup.yml"
    
    if not os.path.exists(cleanup_playbook):
        print(f"{COLORS['RED']}Cleanup playbook not found: {cleanup_playbook}{COLORS['RESET']}")
        show_manual_cleanup_guidance(config)
        return False
    
    print(f"Using cleanup playbook: {cleanup_playbook}")
    
    # Create extra vars
    extra_vars = create_extra_vars(config)
    
    # Build ansible command - use venv ansible if available
    venv_ansible = os.path.join(os.path.dirname(__file__), 'venv', 'bin', 'ansible-playbook')
    if os.path.exists(venv_ansible):
        ansible_cmd = venv_ansible
        # Set Python interpreter for the venv
        venv_python = os.path.join(os.path.dirname(__file__), 'venv', 'bin', 'python')
        os.environ['ANSIBLE_PYTHON_INTERPRETER'] = venv_python
    else:
        ansible_cmd = 'ansible-playbook'
    
    cmd = [
        ansible_cmd,
        cleanup_playbook,
        '--extra-vars', extra_vars,
        '-v'
    ]
    
    print(f"Executing: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        print(f"Return code: {result.returncode}")
        if result.stdout:
            print(f"STDOUT:\n{result.stdout}")
        if result.stderr:
            print(f"STDERR:\n{result.stderr}")
        
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print(f"{COLORS['RED']}Teardown timed out after 5 minutes{COLORS['RESET']}")
        return False
    except Exception as e:
        print(f"{COLORS['RED']}Error executing teardown: {e}{COLORS['RESET']}")
        return False

def set_provider_environment(config):
    """Delegate legacy teardown environment setup to provider metadata."""
    return prepare_provider_environment(config, teardown=True)

def create_extra_vars(config):
    """Create Ansible extra variables"""
    extra_vars = {
        'deployment_id': config.get('deployment_id'),
        'provider': config.get('provider'),
        'skip_confirmation': True
    }
    
    # Add instance names
    if config.get('redirector_name'):
        extra_vars['redirector_name'] = config['redirector_name']
    if config.get('c2_name'):
        extra_vars['c2_name'] = config['c2_name']
    if config.get('tracker_name'):
        extra_vars['tracker_name'] = config['tracker_name']
    if config.get('attack_box_name'):
        extra_vars['attack_box_name'] = config['attack_box_name']
    
    return json.dumps(extra_vars)

def cleanup_ssh_keys(deployment_id):
    """Clean up SSH keys for deployment"""
    ssh_dir = os.path.expanduser("~/.ssh")
    patterns = [
        f"c2deploy_{deployment_id}*",
        f"attack-box-{deployment_id}*",
        f"a-{deployment_id}*"
    ]
    
    removed_keys = []
    for pattern in patterns:
        for key_file in glob.glob(os.path.join(ssh_dir, pattern)):
            try:
                os.remove(key_file)
                removed_keys.append(key_file)
            except Exception as e:
                print(f"{COLORS['YELLOW']}Warning: Could not remove {key_file}: {e}{COLORS['RESET']}")
    
    if removed_keys:
        print(f"Removed SSH keys: {', '.join([os.path.basename(k) for k in removed_keys])}")
    else:
        print("No SSH keys found to remove")

def archive_logs(deployment_id):
    """Archive logs for the deployment"""
    try:
        archive_dir = "logs/archive"
        os.makedirs(archive_dir, exist_ok=True)
        
        patterns = [
            f"logs/deployment_{deployment_id}*",
            f"logs/deployment_info_{deployment_id}*",
            f"logs/teardown_{deployment_id}*"
        ]
        
        archived_files = []
        for pattern in patterns:
            for file_path in glob.glob(pattern):
                filename = os.path.basename(file_path)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                archive_filename = f"{timestamp}_{filename}"
                archive_path = os.path.join(archive_dir, archive_filename)
                
                os.rename(file_path, archive_path)
                archived_files.append(archive_filename)
        
        if archived_files:
            print(f"Archived logs: {', '.join(archived_files)}")
        else:
            print("No logs found to archive")
            
    except Exception as e:
        print(f"{COLORS['YELLOW']}Warning: Could not archive logs: {e}{COLORS['RESET']}")

def show_manual_cleanup_guidance(config=None):
    """Show manual cleanup guidance"""
    print(f"\n{COLORS['CYAN']}Manual Cleanup Guidance{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}========================{COLORS['RESET']}")
    
    if config:
        provider = config.get('provider', 'unknown')
        deployment_id = config.get('deployment_id', 'unknown')
        
        print(f"Deployment ID: {deployment_id}")
        print(f"Provider: {provider}")
        
        guidance = provider_cleanup_guidance(provider, deployment_id)
        if guidance:
            label = PROVIDER_DIRS.get(provider, str(provider))
            print(f"\n{label} cleanup steps:")
            for index, item in enumerate(guidance, 1):
                print(f"{index}. {item}")
    
    print(f"\nLocal cleanup:")
    print(f"1. SSH keys in ~/.ssh/ starting with c2deploy_, attack-box-, or a-")
    print(f"2. Log files in logs/ directory")
    print(f"3. Any temporary files or state files")

def select_and_teardown_deployment():
    """Interactive deployment selection for teardown"""
    print(f"\n{COLORS['CYAN']}Select Deployment to Teardown:{COLORS['RESET']}")
    
    discovered = discover_deployments()
    if discovered is None:
        return False
    deployments, adapter_ids = discovered
    if not deployments:
        print(f"{COLORS['GREEN']}No deployments found{COLORS['RESET']}")
        return True
    
    print(f"\nFound {len(deployments)} deployments:")
    print("=" * 40)
    
    # Display deployments with selection numbers
    for i, config in enumerate(deployments, 1):
        deployment_id = config.get('deployment_id', 'unknown')
        provider = config.get('provider', 'unknown')
        domain = config.get('domain', 'N/A')
        
        print(f"{i}. {COLORS['WHITE']}{deployment_id}{COLORS['RESET']}")
        print(f"   Provider: {provider}")
        print(f"   Domain: {domain}")
        
        # Show instance names if available
        instances = []
        if config.get('redirector_name'):
            instances.append(f"Redirector: {config['redirector_name']}")
        if config.get('c2_name'):
            instances.append(f"C2: {config['c2_name']}")
        if config.get('tracker_name'):
            instances.append(f"Tracker: {config['tracker_name']}")
        if config.get('attack_box_name'):
            instances.append(f"Attack Box: {config['attack_box_name']}")
        
        if instances:
            print(f"   Instances: {', '.join(instances)}")
        print()
    
    # Get user selection
    while True:
        try:
            selection = input(f"\nSelect deployment to teardown (1-{len(deployments)}), or 'q' to quit: ").strip()
            
            if selection.lower() == 'q':
                print(f"{COLORS['GREEN']}Selection cancelled{COLORS['RESET']}")
                return False
            
            selection_num = int(selection)
            if 1 <= selection_num <= len(deployments):
                selected_deployment = deployments[selection_num - 1]
                deployment_id = selected_deployment.get('deployment_id', 'unknown')
                
                print(f"\n{COLORS['YELLOW']}Selected deployment: {deployment_id}{COLORS['RESET']}")
                
                # Confirm selection and proceed with teardown
                confirm = input(f"Proceed with teardown of {deployment_id}? (yes/no): ").strip().lower()
                if confirm == 'yes':
                    if deployment_id in adapter_ids:
                        return teardown_adapter_state(selected_deployment, force=True)
                    return teardown_deployment(deployment_id)
                print(f"{COLORS['GREEN']}Teardown cancelled{COLORS['RESET']}")
                return False
            else:
                print(f"{COLORS['RED']}Please enter a number between 1 and {len(deployments)}{COLORS['RESET']}")
        except ValueError:
            print(f"{COLORS['RED']}Please enter a valid number or 'q' to quit{COLORS['RESET']}")

if __name__ == "__main__":
    sys.exit(main())
