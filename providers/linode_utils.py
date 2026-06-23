#!/usr/bin/env python3
"""
Linode provider utilities for C2ingRed deployment system
"""

import random
import logging
from ..utils.common import COLORS, load_vars_file

def get_linode_credentials(provider_vars=None):
    """Get Linode API token from user or vars file"""
    if not provider_vars:
        provider_vars = load_vars_file('linode')
    
    default_token = provider_vars.get('linode_token', '')
    
    print(f"\n{COLORS['BLUE']}Linode Configuration{COLORS['RESET']}")
    token = input(f"Linode API Token [{'*****' if default_token else 'required'}]: ") or default_token
    
    if not token:
        print(f"{COLORS['RED']}Linode API token is required{COLORS['RESET']}")
        return None
    
    return {'linode_token': token}

def select_linode_region(provider_vars=None, component=None):
    """Let the user select a Linode region"""
    if not provider_vars:
        provider_vars = load_vars_file('linode')
    
    regions = provider_vars.get('region_choices', [])
    component_str = f" for {component}" if component else ""
    
    if not regions:
        print(f"{COLORS['YELLOW']}No regions found for Linode, using us-east{COLORS['RESET']}")
        return "us-east"
    
    print(f"\nAvailable Linode regions{component_str}:")
    for i, region in enumerate(regions, 1):
        print(f"  {i}. {region}")
    
    region_input = input(f"\nSelect region{component_str} (number or leave blank for random): ")
    
    if not region_input:
        return random.choice(regions)
    
    try:
        region_choice = int(region_input)
        if 1 <= region_choice <= len(regions):
            return regions[region_choice - 1]
        else:
            print(f"{COLORS['RED']}Invalid choice, using random region{COLORS['RESET']}")
            return random.choice(regions)
    except ValueError:
        print(f"{COLORS['RED']}Invalid input, using random region{COLORS['RESET']}")
        return random.choice(regions)

def gather_linode_config():
    """Gather all Linode-specific configuration"""
    provider_vars = load_vars_file('linode')
    config = {}
    
    # Get credentials
    linode_creds = get_linode_credentials(provider_vars)
    if not linode_creds:
        return None
    config.update(linode_creds)
    
    # Get region
    config['linode_region'] = select_linode_region(provider_vars)
    
    # Additional Linode-specific settings
    config['linode_instance_type'] = provider_vars.get('linode_instance_type', 'g6-nanode-1')
    config['linode_image'] = provider_vars.get('linode_image', 'linode/kali')
    
    return config
