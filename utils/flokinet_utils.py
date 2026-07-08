#!/usr/bin/env python3
"""
FlokiNET provider utilities for C2ingRed deployment system
"""

import logging
from .common import COLORS, load_vars_file, validate_ip_address

def get_flokinet_credentials(provider_vars=None):
    """Get FlokiNET server IPs from user or vars file"""
    if not provider_vars:
        provider_vars = load_vars_file('flokinet')
    
    default_redirector_ip = provider_vars.get('redirector_ip', '')
    default_c2_ip = provider_vars.get('c2_ip', '')
    default_mta_ip = provider_vars.get('mta_ip', '')
    default_webserver_ip = provider_vars.get('webserver_ip', '')
    default_gophish_ip = provider_vars.get('gophish_ip', '')

    print(f"\n{COLORS['BLUE']}FlokiNET Configuration{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}Note: FlokiNET requires pre-provisioned servers{COLORS['RESET']}")

    redirector_ip = input(f"FlokiNET Redirector IP Address [default: {default_redirector_ip}]: ") or default_redirector_ip
    c2_ip = input(f"FlokiNET C2 Server IP Address [default: {default_c2_ip}]: ") or default_c2_ip
    mta_ip = input(f"FlokiNET MTA Front IP Address (optional) [default: {default_mta_ip}]: ") or default_mta_ip
    webserver_ip = input(f"FlokiNET Phishing Webserver IP Address (optional) [default: {default_webserver_ip}]: ") or default_webserver_ip
    gophish_ip = input(f"FlokiNET GoPhish Server IP Address (optional) [default: {default_gophish_ip}]: ") or default_gophish_ip

    # Validate IP addresses
    if redirector_ip and not validate_ip_address(redirector_ip):
        print(f"{COLORS['RED']}Invalid redirector IP address{COLORS['RESET']}")
        return None

    if c2_ip and not validate_ip_address(c2_ip):
        print(f"{COLORS['RED']}Invalid C2 server IP address{COLORS['RESET']}")
        return None

    if mta_ip and not validate_ip_address(mta_ip):
        print(f"{COLORS['RED']}Invalid MTA front IP address{COLORS['RESET']}")
        return None

    if webserver_ip and not validate_ip_address(webserver_ip):
        print(f"{COLORS['RED']}Invalid phishing webserver IP address{COLORS['RESET']}")
        return None

    if gophish_ip and not validate_ip_address(gophish_ip):
        print(f"{COLORS['RED']}Invalid GoPhish server IP address{COLORS['RESET']}")
        return None

    return {
        'redirector_ip': redirector_ip,
        'c2_ip': c2_ip,
        'mta_ip': mta_ip,
        'webserver_ip': webserver_ip,
        'gophish_ip': gophish_ip,
        'flokinet_redirector_ip': redirector_ip,
        'flokinet_c2_ip': c2_ip,
        'flokinet_mta_ip': mta_ip,
        'flokinet_webserver_ip': webserver_ip,
        'flokinet_gophish_ip': gophish_ip
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
