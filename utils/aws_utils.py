#!/usr/bin/env python3
"""
AWS provider utilities for C2ingRed deployment system
"""

import random
import logging
from .common import COLORS, load_vars_file, confirm_action

def get_aws_credentials(provider_vars=None):
    """Get AWS credentials from user or vars file"""
    if not provider_vars:
        provider_vars = load_vars_file('aws')
    
    default_aws_key = provider_vars.get('aws_access_key', '')
    default_aws_secret = provider_vars.get('aws_secret_key', '')
    
    print(f"\n{COLORS['BLUE']}AWS Configuration{COLORS['RESET']}")
    aws_key = input(f"AWS Access Key [{'*****' if default_aws_key else 'leave blank to use AWS CLI profile'}]: ") or default_aws_key
    aws_secret = input(f"AWS Secret Key [{'*****' if default_aws_secret else 'leave blank to use AWS CLI profile'}]: ") or default_aws_secret
    
    return {
        'aws_access_key': aws_key,
        'aws_secret_key': aws_secret
    }

def select_aws_region(provider_vars=None, component=None):
    """Let the user select an AWS region"""
    if not provider_vars:
        provider_vars = load_vars_file('aws')
    
    regions = provider_vars.get('aws_region_choices', [])
    component_str = f" for {component}" if component else ""
    
    if not regions:
        print(f"{COLORS['YELLOW']}No regions found for AWS, using us-east-1{COLORS['RESET']}")
        return "us-east-1"
    
    print(f"\nAvailable AWS regions{component_str}:")
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

def gather_aws_config():
    """Gather all AWS-specific configuration"""
    provider_vars = load_vars_file('aws')
    config = {}
    
    # Get credentials
    aws_creds = get_aws_credentials(provider_vars)
    config.update(aws_creds)
    
    # Get region
    config['aws_region'] = select_aws_region(provider_vars)
    
    # Additional AWS-specific settings
    config['aws_instance_type'] = provider_vars.get('aws_instance_type', 't3.micro')
    config['aws_volume_size'] = provider_vars.get('aws_volume_size', 20)
    
    return config
