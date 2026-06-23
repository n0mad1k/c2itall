#!/usr/bin/env python3
"""
FlokiNET provider utilities for C2ingRed deployment system
"""

import logging
from ..utils.common import COLORS, load_vars_file, validate_ip_address

def get_flokinet_credentials(provider_vars=None):
    """Get FlokiNET server IPs from user or vars file"""
    if not provider_vars:
        provider_vars = load_vars_file('flokinet')
    
    default_redirector_ip = provider_vars.get('redirector_ip', '')
    default_c2_ip = provider_vars.get('c2_ip', '')
    
    print(f"\n{COLORS['BLUE']}FlokiNET Configuration{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}Note: FlokiNET requires pre-provisioned servers{COLORS['RESET']}")
    
    redirector_ip = input(f"FlokiNET Redirector IP Address [default: {default_redirector_ip}]: ") or default_redirector_ip
    c2_ip = input(f"FlokiNET C2 Server IP Address [default: {default_c2_ip}]: ") or default_c2_ip
    
    # Validate IP addresses
    if redirector_ip and not validate_ip_address(redirector_ip):
        print(f"{COLORS['RED']}Invalid redirector IP address{COLORS['RESET']}")
        return None
    
    if c2_ip and not validate_ip_address(c2_ip):
        print(f"{COLORS['RED']}Invalid C2 server IP address{COLORS['RESET']}")
        return None
    
    return {
        'flokinet_redirector_ip': redirector_ip,
        'flokinet_c2_ip': c2_ip
    }

def gather_flokinet_config():
    """Gather all FlokiNET-specific configuration"""
    provider_vars = load_vars_file('flokinet')
    config = {}
    
    # Get server IPs
    flokinet_ips = get_flokinet_credentials(provider_vars)
    if not flokinet_ips:
        return None
    config.update(flokinet_ips)
    
    # FlokiNET-specific settings
    config['ssh_user'] = 'root'  # FlokiNET typically uses root
    
    return config
