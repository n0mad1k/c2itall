#!/usr/bin/env python3
"""
Linode provider utilities for C2ingRed deployment system
"""

import os
import logging
import subprocess
from .common import COLORS, load_vars_file

def get_linode_credentials(provider_vars=None):
    """Get Linode API token — Infisical first, vars.yaml fallback, then prompt."""
    default_token = ''

    try:
        default_token = subprocess.check_output(
            [os.path.expanduser('~/.local/bin/creds'), 'get', 'LINODE_TOKEN', 'homelab'],
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        pass

    if not default_token:
        if not provider_vars:
            provider_vars = load_vars_file('linode')
        default_token = provider_vars.get('linode_token', '')

    print(f"\n{COLORS['BLUE']}Linode Configuration{COLORS['RESET']}")
    token = input(f"Linode API Token [{'*****' if default_token else 'required'}]: ") or default_token

    if not token:
        print(f"{COLORS['RED']}Linode API token is required{COLORS['RESET']}")
        return None

    return {'linode_token': token}

def select_linode_regions(provider_vars=None) -> list[str]:
    """Return region list — single entry if user specified one, all regions if blank (random per-node)."""
    if not provider_vars:
        provider_vars = load_vars_file('linode')

    regions = provider_vars.get('region_choices', ['us-east'])

    print(f"\nAvailable Linode regions:")
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

def gather_linode_config():
    """Gather all Linode-specific configuration"""
    provider_vars = load_vars_file('linode')
    config = {}

    linode_creds = get_linode_credentials(provider_vars)
    if not linode_creds:
        return None
    config.update(linode_creds)

    linode_regions = select_linode_regions(provider_vars)
    config['linode_regions'] = linode_regions
    config['linode_region'] = linode_regions[0]

    config['linode_instance_type'] = provider_vars.get('linode_instance_type', 'g6-nanode-1')
    config['linode_image'] = provider_vars.get('linode_image', 'linode/debian12')

    return config
