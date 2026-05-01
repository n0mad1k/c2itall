#!/usr/bin/env python3
"""
AWS provider utilities for C2ingRed deployment system
"""

import os
import subprocess
import logging
from .common import COLORS, load_vars_file

def get_aws_credentials(provider_vars=None):
    """Get AWS credentials — Infisical first, vars.yaml fallback, then prompt."""
    key = ''
    secret = ''

    try:
        key = subprocess.check_output(
            [os.path.expanduser('~/.local/bin/creds'), 'get', 'AWS_ACCESS_KEY_ID', 'homelab'],
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
        secret = subprocess.check_output(
            [os.path.expanduser('~/.local/bin/creds'), 'get', 'AWS_SECRET_ACCESS_KEY', 'homelab'],
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        pass

    if not key:
        if not provider_vars:
            provider_vars = load_vars_file('aws')
        key = provider_vars.get('aws_access_key', '')
        secret = provider_vars.get('aws_secret_key', '')
        if key and 'YOUR_AWS' in key:
            key = ''
            secret = ''

    print(f"\n{COLORS['BLUE']}AWS Configuration{COLORS['RESET']}")
    if key:
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
