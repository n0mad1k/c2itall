#!/usr/bin/env python3
"""
SSH utilities for C2ingRed deployment system
"""

import os
import subprocess
import logging
import re
import glob
from .common import COLORS, generate_random_string

def generate_ssh_key(deployment_id=None):
    """Generate an SSH key for deployment with proper tracking for cleanup"""
    # Use deployment_id if provided, otherwise generate random suffix
    if not deployment_id:
        deployment_id = generate_random_string(6)
    
    ssh_key_path = os.path.expanduser(f"~/.ssh/c2deploy_{deployment_id}")
    ssh_key_pub_path = f"{ssh_key_path}.pub"
    
    # Check if key already exists
    if os.path.exists(ssh_key_path):
        logging.info(f"SSH key already exists at {ssh_key_path}")
        return ssh_key_path
    
    try:
        # Generate the SSH key
        subprocess.run([
            "ssh-keygen", "-t", "rsa", "-b", "4096", 
            "-f", ssh_key_path, "-q", "-N", ""
        ], check=True)
        
        # Set proper permissions
        os.chmod(ssh_key_path, 0o600)
        
        # Track generated keys for cleanup
        if not hasattr(generate_ssh_key, 'generated_keys'):
            generate_ssh_key.generated_keys = []
        generate_ssh_key.generated_keys.append(ssh_key_path)
        
        logging.info(f"Generated SSH key: {ssh_key_path}")
        return ssh_key_path
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to generate SSH key: {e}")
        return None

def get_ssh_public_key(private_key_path):
    """Get the public key content from a private key file"""
    public_key_path = f"{private_key_path}.pub"
    
    if not os.path.exists(public_key_path):
        logging.error(f"Public key file not found: {public_key_path}")
        return None
    
    try:
        with open(public_key_path, 'r') as f:
            return f.read().strip()
    except Exception as e:
        logging.error(f"Failed to read public key: {e}")
        return None

def extract_attack_box_ip_from_logs(config):
    """Extract attack box IP from deployment logs or Ansible output"""
    deployment_id = config.get('deployment_id', 'unknown')
    
    # Check deployment log file first
    log_files_to_check = [
        f"logs/deployment_{deployment_id}.log",
        # Also check archived logs
        f"logs/archive/deployment_{deployment_id}.log"
    ]
    
    # Check for timestamped archived logs
    archive_pattern = f"logs/archive/*_deployment_{deployment_id}.log"
    archived_logs = glob.glob(archive_pattern)
    if archived_logs:
        # Get the most recent archived log
        log_files_to_check.append(max(archived_logs, key=os.path.getmtime))
    
    for log_file in log_files_to_check:
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    content = f.read()
                    # Look for various IP patterns in the log
                    ip_patterns = [
                        r'"attack_box_ip":\s*"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"',
                        r'attack_box_ip.*?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
                        r'"ipv4":\s*\["([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"\]',
                        r'ansible_host["\s]*=[\s]*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
                        r'instance_ip["\s]*:[\s]*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
                        r'Target: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
                        r'IP["\s]*:[\s]*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
                        # Look for IP in Ansible task output patterns
                        r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+:\s+ok=',
                        r'PLAY RECAP.*?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
                        r'changed: \[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]',
                        r'ok: \[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]'
                    ]
                    
                    for pattern in ip_patterns:
                        match = re.search(pattern, content)
                        if match:
                            ip = match.group(1)
                            logging.info(f"Extracted attack box IP from logs: {ip}")
                            return ip
            except Exception as e:
                logging.warning(f"Could not read deployment log {log_file}: {e}")
    
    # Check deployment info file
    info_file = f"logs/deployment_info_{deployment_id}.txt"
    if os.path.exists(info_file):
        try:
            with open(info_file, 'r') as f:
                content = f.read()
                # Look for IP in SSH command or other contexts
                ip_patterns = [
                    r'root@([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
                    r'Instance IP:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
                    r'IP["\s]*:[\s]*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
                ]
                
                for pattern in ip_patterns:
                    match = re.search(pattern, content)
                    if match:
                        ip = match.group(1)
                        logging.info(f"Extracted attack box IP from deployment info: {ip}")
                        return ip
        except Exception as e:
            logging.warning(f"Could not read deployment info: {e}")
    
    logging.warning("Could not extract attack box IP from logs")
    return None

def ssh_to_instance(config):
    """SSH into an instance after deployment"""
    ssh_key_path = config.get('ssh_key_path', '').replace('.pub', '')
    
    # Handle attack box deployments
    if config.get('attack_box_deployment'):
        instance_ip = config.get('attack_box_ip')
        instance_name = config.get('attack_box_name', 'attack box')
        
        # If no IP stored in config, try to extract from deployment logs
        if not instance_ip:
            instance_ip = extract_attack_box_ip_from_logs(config)
            
    # Determine which instance to connect to for C2 deployments
    elif config.get('c2_only') or (not config.get('redirector_only') and not config.get('deploy_tracker')):
        # Connect to C2 server
        instance_ip = config.get('c2_ip')
        instance_name = config.get('c2_name', 'C2 server')
    elif config.get('redirector_only'):
        # Connect to redirector
        instance_ip = config.get('redirector_ip') 
        instance_name = config.get('redirector_name', 'redirector')
    elif config.get('deploy_tracker') and not config.get('integrated_tracker'):
        # Connect to tracker
        instance_ip = config.get('tracker_ip')
        instance_name = config.get('tracker_name', 'tracker')
    else:
        # Default to C2 server
        instance_ip = config.get('c2_ip')
        instance_name = config.get('c2_name', 'C2 server')
    
    if not instance_ip:
        print(f"{COLORS['RED']}No instance IP found for SSH connection{COLORS['RESET']}")
        return
    
    ssh_user = config.get('ssh_user', 'root')
    
    print(f"{COLORS['GREEN']}Connecting to {instance_name} ({instance_ip})...{COLORS['RESET']}")
    
    ssh_command = [
        "ssh", 
        "-i", ssh_key_path,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "IdentitiesOnly=yes",
        f"{ssh_user}@{instance_ip}"
    ]
    
    try:
        subprocess.run(ssh_command)
    except KeyboardInterrupt:
        print(f"\n{COLORS['YELLOW']}SSH session ended{COLORS['RESET']}")
    except Exception as e:
        print(f"{COLORS['RED']}SSH connection failed: {e}{COLORS['RESET']}")

def cleanup_ssh_keys(deployment_id=None, keep_keys=False):
    """Clean up generated SSH keys"""
    if keep_keys:
        return
    
    if hasattr(generate_ssh_key, 'generated_keys'):
        for key_path in generate_ssh_key.generated_keys:
            # Only remove keys we generated for this deployment
            if deployment_id and f"_{deployment_id}" in key_path:
                try:
                    if os.path.exists(key_path):
                        os.remove(key_path)
                    if os.path.exists(f"{key_path}.pub"):
                        os.remove(f"{key_path}.pub")
                    logging.info(f"Removed SSH key: {key_path}")
                except Exception as e:
                    logging.error(f"Failed to remove SSH key {key_path}: {e}")
