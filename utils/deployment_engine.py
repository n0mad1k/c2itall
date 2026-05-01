#!/usr/bin/env python3
"""
Deployment engine for C2ingRed infrastructure deployments
"""

import os
import sys
import subprocess
import logging
import json

# Add project root to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from utils.common import COLORS, PROVIDER_DIRS

_SECRET_KEYS = frozenset({
    'linode_token', 'aws_access_key', 'aws_secret_key', 'flokinet_api_key',
    'smtp_auth_pass', 'smtp_password', 'ftp_password', 'api_key',
    'password', 'secret', 'token',
})


def deploy_infrastructure(config):
    """
    Deploy infrastructure based on the provided configuration.

    Args:
        config: Dictionary containing deployment configuration

    Returns:
        bool: True if deployment succeeded, False otherwise
    """
    provider = config.get('provider')
    deployment_id = config.get('deployment_id')

    if not provider or not deployment_id:
        logging.error("Missing provider or deployment ID in configuration")
        return False

    # Determine which playbook to use
    playbook = determine_playbook(config)

    if not playbook:
        logging.error("Could not determine appropriate playbook for deployment")
        return False

    if not os.path.exists(playbook):
        logging.error(f"Playbook not found: {playbook}")
        print(f"{COLORS['RED']}Playbook not found: {playbook}{COLORS['RESET']}")
        return False

    logging.info(f"Using playbook: {playbook}")

    # Set provider-specific environment variables
    set_provider_environment(config)

    # Execute the deployment
    return execute_playbook(playbook, config)


def determine_playbook(config):
    """
    Determine the correct playbook based on deployment configuration.

    Args:
        config: Deployment configuration dictionary

    Returns:
        str: Path to the playbook file
    """
    provider = config.get('provider')
    provider_dir = PROVIDER_DIRS.get(provider, provider.capitalize())
    base_path = f"providers/{provider_dir}"

    # Attack box deployment
    if config.get('attack_box_deployment'):
        return f"{base_path}/attack_box.yml"

    # Redirector-only deployment
    if config.get('redirector_only'):
        return f"{base_path}/redirector.yml"

    # Tracker deployment
    if config.get('tracker_deployment'):
        return f"{base_path}/tracker.yml"

    # Phishing infrastructure deployment
    if config.get('phishing_deployment'):
        # Check for provider-specific phishing playbook first
        provider_specific = f"{base_path}/{provider}_phishing.yml"
        if os.path.exists(provider_specific):
            return provider_specific
        return f"{base_path}/phishing.yml"

    # Chat server deployment
    if config.get('chat_deployment'):
        return f"{base_path}/chat_server.yml"

    # C2 deployment (default for C2 infrastructure)
    if config.get('c2_only') or config.get('deploy_c2') or config.get('c2_framework'):
        return f"{base_path}/c2.yml"

    # Default to C2 playbook
    return f"{base_path}/c2.yml"


def set_provider_environment(config):
    """
    Set provider-specific environment variables for deployment.

    Args:
        config: Deployment configuration dictionary
    """
    provider = config.get('provider')

    if provider == "aws":
        if config.get('aws_access_key'):
            os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
        if config.get('aws_secret_key'):
            os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
        if config.get('aws_region'):
            os.environ['AWS_DEFAULT_REGION'] = config['aws_region']

    elif provider == "linode":
        if config.get('linode_token'):
            os.environ['LINODE_TOKEN'] = config['linode_token']
        else:
            # Pull from Infisical at runtime
            try:
                token = subprocess.check_output(
                    [os.path.expanduser('~/.local/bin/creds'), 'get', 'LINODE_TOKEN', 'homelab'],
                    text=True, stderr=subprocess.DEVNULL,
                ).strip()
                if token:
                    os.environ['LINODE_TOKEN'] = token
                    config['linode_token'] = token
            except Exception as e:
                logging.warning(f"Failed to load Linode token from Infisical: {e}")

    elif provider == "flokinet":
        if config.get('flokinet_api_key'):
            os.environ['FLOKINET_API_KEY'] = config['flokinet_api_key']


def execute_playbook(playbook, config):
    """
    Execute an Ansible playbook with the provided configuration.

    Args:
        playbook: Path to the Ansible playbook
        config: Deployment configuration dictionary

    Returns:
        bool: True if playbook executed successfully, False otherwise
    """
    import tempfile
    secret_vars_file = None
    try:
        # Build the ansible-playbook command
        cmd = [
            'ansible-playbook',
            playbook,
            '--extra-vars', create_extra_vars(config)
        ]

        # Webrunner runs many nodes in parallel — increase fork count
        if 'webrunner' in playbook:
            cmd += ['-f', '50']

        # Write sensitive vars to a temp file (0o600) so they reach Ansible as
        # variables without appearing in process listings or the main extra-vars JSON.
        # Read from environment (set by set_provider_environment) so this works even
        # when config was passed as a copy ({**config}) that didn't capture the token.
        secret_vars = {}
        if os.environ.get('LINODE_TOKEN'):
            secret_vars['linode_token'] = os.environ['LINODE_TOKEN']
        if os.environ.get('AWS_ACCESS_KEY_ID'):
            secret_vars['aws_access_key'] = os.environ['AWS_ACCESS_KEY_ID']
        if os.environ.get('AWS_SECRET_ACCESS_KEY'):
            secret_vars['aws_secret_key'] = os.environ['AWS_SECRET_ACCESS_KEY']
        if os.environ.get('FLOKINET_API_KEY'):
            secret_vars['flokinet_api_key'] = os.environ['FLOKINET_API_KEY']
        # Also pick up any remaining secret keys from config dict (e.g. smtp_auth_pass)
        for k, v in config.items():
            if v is not None and k not in secret_vars and any(s in k.lower() for s in _SECRET_KEYS):
                secret_vars[k] = v
        if secret_vars:
            fd, secret_vars_file = tempfile.mkstemp(suffix='.json', prefix='ansible_secret_')
            os.chmod(secret_vars_file, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump(secret_vars, f)
            cmd += ['--extra-vars', f'@{secret_vars_file}']

        # Add verbosity if debug mode is enabled
        if config.get('debug'):
            cmd.append('-vvv')

        logging.info(f"Executing: {' '.join(cmd[:3])} ...")

        # Get log file path for output
        log_file = f"logs/deployment_{config['deployment_id']}.log"

        # Execute the playbook — log file restricted to owner-only (contains Ansible output)
        log_fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with open(log_fd, 'a') as log_output:
            # Write command to log
            log_output.write(f"\n{'='*60}\n")
            log_output.write(f"Executing playbook: {playbook}\n")
            log_output.write(f"{'='*60}\n\n")
            log_output.flush()

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )

            # Stream output to both console and log file
            for line in process.stdout:
                # Write to log file
                log_output.write(line)
                log_output.flush()

                # Print select lines to console for user feedback
                if should_print_line(line):
                    print(line.rstrip())

            process.wait()

            if process.returncode == 0:
                logging.info("Playbook executed successfully")
                save_deployment_info(config)
                return True
            else:
                logging.error(f"Playbook failed with return code {process.returncode}")
                print(f"\n{COLORS['RED']}Deployment failed. Check logs for details: {log_file}{COLORS['RESET']}")
                return False

    except FileNotFoundError:
        logging.error("ansible-playbook command not found. Is Ansible installed?")
        print(f"{COLORS['RED']}Error: ansible-playbook not found. Please install Ansible.{COLORS['RESET']}")
        return False
    except Exception as e:
        logging.error(f"Error executing playbook: {e}")
        print(f"{COLORS['RED']}Error executing playbook: {e}{COLORS['RESET']}")
        return False
    finally:
        if secret_vars_file and os.path.exists(secret_vars_file):
            os.unlink(secret_vars_file)


def should_print_line(line):
    """
    Determine if a line should be printed to console.
    Filters out verbose Ansible output to show only key information.

    Args:
        line: Output line from Ansible

    Returns:
        bool: True if line should be printed
    """
    # Always show task names and important messages
    important_patterns = [
        'TASK [',
        'PLAY [',
        'ok:',
        'changed:',
        'failed:',
        'fatal:',
        'skipping:',
        'PLAY RECAP',
        '=> {',
        'msg:',
        'IP Address:',
        'Instance ID:',
    ]

    for pattern in important_patterns:
        if pattern in line:
            return True

    return False


def create_extra_vars(config):
    """
    Create JSON string of extra variables for Ansible.

    Args:
        config: Deployment configuration dictionary

    Returns:
        str: JSON string of variables
    """
    # Credentials are passed via environment variables (set_provider_environment).
    # Strip them here so they never appear in --extra-vars or process listings.
    extra_vars = {}

    for key, value in config.items():
        if value is None:
            continue
        if any(secret in key.lower() for secret in _SECRET_KEYS):
            continue
        if isinstance(value, bool):
            extra_vars[key] = value
        elif isinstance(value, (str, int, float, list, dict)):
            extra_vars[key] = value

    return json.dumps(extra_vars)


def save_deployment_info(config):
    """
    Save deployment information to a file for later reference/cleanup.

    Args:
        config: Deployment configuration dictionary
    """
    try:
        deployment_id = config.get('deployment_id')
        info_file = f"logs/deployment_info_{deployment_id}.txt"

        with open(info_file, 'w') as f:
            f.write(f"Deployment Information\n")
            f.write(f"{'='*50}\n")
            f.write(f"Deployment ID: {deployment_id}\n")
            f.write(f"Provider: {config.get('provider')}\n")
            f.write(f"Deployment Type: {config.get('deployment_type', 'unknown')}\n")
            f.write(f"\n")
            f.write(f"Configuration:\n")
            f.write(f"{'-'*30}\n")

            # Write key configuration items
            keys_to_save = [
                'provider', 'deployment_id', 'deployment_type',
                'attack_box_name', 'c2_name', 'redirector_name', 'tracker_name',
                'chat_server_name',
                'domain', 'c2_subdomain', 'redirector_subdomain',
                'c2_framework', 'redirector_type',
                'linode_region', 'aws_region',
                'setup_vpn', 'setup_tor',
                'ssh_key_path',
                'matrix_admin_user', 'enable_bot_support'
            ]

            for key in keys_to_save:
                if key in config and config[key] is not None:
                    # Don't save sensitive data
                    if 'password' in key.lower() or 'token' in key.lower() or 'secret' in key.lower():
                        continue
                    f.write(f"{key}: {config[key]}\n")

            f.write(f"\n")
            f.write(f"Access Information:\n")
            f.write(f"{'-'*30}\n")
            f.write(f"(Instance IPs will be displayed in Ansible output above)\n")

        logging.info(f"Deployment info saved to: {info_file}")

    except Exception as e:
        logging.warning(f"Failed to save deployment info: {e}")


if __name__ == "__main__":
    print("Deployment engine loaded")
