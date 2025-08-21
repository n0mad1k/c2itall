#!/usr/bin/env python3
"""
Common utilities and constants for C2ingRed deployment system
"""

import os
import sys
import random
import string
import logging
import subprocess
import re
from datetime import datetime

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

# Color codes for terminal output
COLORS = {
    "RESET": "\033[0m",
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "PURPLE": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "GRAY": "\033[90m"
}

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print the C2ingRed banner"""
    banner = f"""
{COLORS['BLUE']}========================================================{COLORS['RESET']}
{COLORS['BLUE']}   ██████╗██████╗ ██╗███╗   ██╗ ██████╗ ██████╗ ███████╗██████╗{COLORS['RESET']}
{COLORS['BLUE']}  ██╔════╝╚════██╗██║████╗  ██║██╔════╝ ██╔══██╗██╔════╝██╔══██╗{COLORS['RESET']}
{COLORS['BLUE']}  ██║      █████╔╝██║██╔██╗ ██║██║  ███╗██████╔╝█████╗  ██║  ██║{COLORS['RESET']}
{COLORS['BLUE']}  ██║     ██╔═══╝ ██║██║╚██╗██║██║   ██║██╔══██╗██╔══╝  ██║  ██║{COLORS['RESET']}
{COLORS['BLUE']}  ╚██████╗███████╗██║██║ ╚████║╚██████╔╝██║  ██║███████╗██████╔╝{COLORS['RESET']}
{COLORS['BLUE']}   ╚═════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝{COLORS['RESET']}
{COLORS['BLUE']}                                                                {COLORS['RESET']}
{COLORS['BLUE']}  Red Team Infrastructure Deployment Tool                       {COLORS['RESET']}
{COLORS['BLUE']}========================================================{COLORS['RESET']}
    """
    print(banner)

def generate_random_string(length=8):
    """Generate a random string of letters and digits."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_deployment_id():
    """Generate a consistent deployment ID for all resources in this deployment"""
    from utils.name_generator import generate_deployment_id as generate_verb_animal_id
    return generate_verb_animal_id()

def archive_old_logs(max_logs_to_keep=2):
    """Archive old log files to keep logs directory clean - more aggressive archiving"""
    import glob
    import shutil
    from pathlib import Path
    
    log_dir = "logs"
    archive_dir = os.path.join(log_dir, "archive")
    
    if not os.path.exists(log_dir):
        return
    
    # Create archive directory if it doesn't exist
    os.makedirs(archive_dir, exist_ok=True)
    
    # Get all log files (excluding archive directory) - ANY existing logs should be archived
    log_files = []
    for pattern in ["deployment_*.log", "teardown_*.log", "20*.log"]:
        log_files.extend(glob.glob(os.path.join(log_dir, pattern)))
    
    # Remove duplicates and filter out archive directory
    log_files = [f for f in set(log_files) if "archive" not in f]
    
    # Sort by modification time (newest first)
    log_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    
    # Archive ALL deployment logs to keep directory clean for new deployments
    if len(log_files) > 0:
        print(f"Found {len(log_files)} log files to archive")
        
        archived_count = 0
        for log_file in log_files:
            try:
                filename = os.path.basename(log_file)
                # Add timestamp to archived filename to prevent conflicts
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                archived_filename = f"{timestamp}_{filename}"
                archive_path = os.path.join(archive_dir, archived_filename)
                
                shutil.move(log_file, archive_path)
                archived_count += 1
                print(f"Archived: {filename} -> archive/{archived_filename}")
            except Exception as e:
                print(f"Failed to archive {log_file}: {e}")
        
        if archived_count > 0:
            print(f"Archived {archived_count} log files to {archive_dir}")
    
    # Also archive old deployment info files
    info_files = glob.glob(os.path.join(log_dir, "deployment_info_*.txt"))
    
    if len(info_files) > 0:
        print(f"Found {len(info_files)} info files to archive")
        for info_file in info_files:
            try:
                filename = os.path.basename(info_file)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                archived_filename = f"{timestamp}_{filename}"
                archive_path = os.path.join(archive_dir, archived_filename)
                
                shutil.move(info_file, archive_path)
                print(f"Archived: {filename} -> archive/{archived_filename}")
            except Exception as e:
                print(f"Failed to archive {info_file}: {e}")

def setup_logging(deployment_id=None, operation_type="deployment"):
    """Set up logging for the deployment or teardown"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    # Archive old logs before starting new deployment
    if operation_type == "deployment":
        archive_old_logs()
    
    # Create distinct log files for deployment vs teardown operations
    if operation_type == "teardown":
        log_file = os.path.join(log_dir, f"teardown_{deployment_id}.log")
    else:
        log_file = os.path.join(log_dir, f"deployment_{deployment_id}.log")
    
    # Clear any existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    
    # Configure file handler to log DEBUG and above for full verbosity
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    
    # Add console handler for INFO level and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('[%(levelname)s] %(message)s')
    console_handler.setFormatter(console_formatter)
    
    # Configure root logger
    root_logger.setLevel(logging.DEBUG)  # Capture everything at root level
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    logging.info(f"{operation_type.capitalize()} operation started")
    logging.info(f"Deployment ID: {deployment_id}")
    logging.info(f"Full verbose output will be captured in: {log_file}")
    return log_file

def load_vars_file(provider):
    """Load vars.yaml for the specified provider"""
    if provider not in PROVIDER_DIRS:
        return {}
    
    # Use correct case for directory
    provider_dir = PROVIDER_DIRS[provider]
    vars_file = f"providers/{provider_dir}/vars.yaml"
    
    if os.path.exists(vars_file):
        try:
            import yaml
            with open(vars_file, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logging.error(f"Failed to load {vars_file}: {e}")
            return {}
    else:
        logging.warning(f"Vars file not found: {vars_file}")
        return {}

def validate_ip_address(ip):
    """Validate IP address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(pattern, ip) is not None

def get_public_ip():
    """Get the user's public IP address"""
    try:
        import requests
        return requests.get('https://api.ipify.org', timeout=5).text.strip()
    except:
        return None

def confirm_action(message, default=False):
    """Ask for user confirmation with a yes/no prompt"""
    prompt = f"{message} ({'Y/n' if default else 'y/N'}): "
    response = input(prompt).lower().strip()
    
    if not response:
        return default
    
    return response in ['y', 'yes']

def wait_for_input(message="Press Enter to continue..."):
    """Wait for user input before continuing"""
    input(f"\n{message}")
