#!/usr/bin/env python3
"""
AWS provider utilities for C2ingRed deployment system
"""

import os
import subprocess
import logging
from .common import COLORS, load_vars_file


INFISICAL_FOLDER = 'aws'


def load_aws_credentials(provider_vars=None):
    """Load AWS keys from Infisical, then the environment, then vars.yaml."""
    key = secret = ''
    creds = os.path.expanduser('~/.local/bin/creds')
    try:
        key = subprocess.check_output(
            [creds, 'get', 'AWS_ACCESS_KEY', INFISICAL_FOLDER],
            text=True, stderr=subprocess.DEVNULL).strip()
        secret = subprocess.check_output(
            [creds, 'get', 'AWS_SECRET_KEY', INFISICAL_FOLDER],
            text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        key = secret = ''
    if not (key and secret):
        key = os.environ.get('AWS_ACCESS_KEY_ID', '')
        secret = os.environ.get('AWS_SECRET_ACCESS_KEY', '')
    if not (key and secret):
        if provider_vars is None:
            provider_vars = load_vars_file('aws')
        key = provider_vars.get('aws_access_key', '') or ''
        secret = provider_vars.get('aws_secret_key', '') or ''
        if 'YOUR_AWS' in key:
            key = secret = ''
    return {'aws_access_key': key, 'aws_secret_key': secret}


def prepare_aws_environment(config, teardown=False):
    """Export the controller credentials; load them when the config lacks them."""
    if not (config.get('aws_access_key') and config.get('aws_secret_key')):
        loaded = load_aws_credentials()
        if loaded['aws_access_key'] and loaded['aws_secret_key']:
            config.update(loaded)
        else:
            logging.warning('AWS credentials were not found in Infisical, '
                            'the environment or vars.yaml')
    if config.get('aws_access_key'):
        os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
    if config.get('aws_secret_key'):
        os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
    if not teardown and config.get('aws_region'):
        os.environ['AWS_DEFAULT_REGION'] = config['aws_region']


def apply_aws_profile(config, workload, profile, value):
    """Translate neutral workload tuning into AWS instance types."""
    if workload != 'attack_box' or profile != 'instance_size':
        return config
    sizes = {
        'small': 't3.small',
        'medium': 't3.medium',
        'large': 't3.large',
        'xlarge': 't3.xlarge',
    }
    if value not in sizes:
        raise ValueError('Unsupported AWS attack-box instance size')
    config['aws_instance_type'] = sizes[value]
    return config


def get_aws_credentials(provider_vars=None):
    """Get AWS credentials: Infisical first, then environment, vars.yaml, prompt."""
    creds = load_aws_credentials(provider_vars)
    key, secret = creds['aws_access_key'], creds['aws_secret_key']

    print(f"\n{COLORS['BLUE']}AWS Configuration{COLORS['RESET']}")
    if key and secret:
        print(f"  AWS credentials loaded")
    else:
        key = input("AWS Access Key: ").strip()
        secret = input("AWS Secret Key: ").strip()

    return {'aws_access_key': key, 'aws_secret_key': secret}

def select_aws_regions(provider_vars=None) -> list[str]:
    """Return region list — single entry if user specified one, all regions if blank (random per-node)."""
    if not provider_vars:
        provider_vars = load_vars_file('aws')

    regions = provider_vars.get('aws_region_choices', ['us-east-1'])

    print(f"\nAvailable AWS regions:")
    for i, region in enumerate(regions, 1):
        print(f"  {i:2}. {region}")

    region_input = input("\nSelect region (number or leave blank for random per-node): ").strip()

    if not region_input:
        return regions

    try:
        idx = int(region_input)
        if 1 <= idx <= len(regions):
            return [regions[idx - 1]]
    except ValueError:
        pass

    print(f"{COLORS['RED']}Invalid input, using random per-node regions{COLORS['RESET']}")
    return regions

def gather_aws_config():
    """Gather all AWS-specific configuration"""
    provider_vars = load_vars_file('aws')
    config = {}

    aws_creds = get_aws_credentials(provider_vars)
    config.update(aws_creds)

    aws_regions = select_aws_regions(provider_vars)
    config['aws_regions'] = aws_regions
    config['aws_region'] = aws_regions[0]

    config['ami_map'] = provider_vars.get('ami_map', {})
    config['aws_instance_type'] = provider_vars.get('aws_instance_type', 't3.micro')
    config['aws_volume_size'] = provider_vars.get('aws_volume_size', 20)

    return config
