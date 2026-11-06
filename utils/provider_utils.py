#!/usr/bin/env python3
"""
Provider selection and configuration utilities
"""

from .common import COLORS, PROVIDERS
from .aws_utils import gather_aws_config
from .linode_utils import gather_linode_config
from .flokinet_utils import gather_flokinet_config

def available_providers(capability=None):
    """Existing menus retain their providers; Azure has one explicit capability."""
    if capability == 'infrastructure':
        return ['azure']
    return [provider for provider in PROVIDERS if provider != 'azure']


def select_provider(capability=None):
    """Let the user select a cloud provider"""
    providers = available_providers(capability)
    print(f"\n{COLORS['BLUE']}Available cloud providers:{COLORS['RESET']}")
    for i, provider in enumerate(providers, 1):
        print(f"  {i}. {provider.capitalize()}")
    
    while True:
        try:
            provider_choice = input(f"\nSelect a provider (1-{len(providers)} or 99 to cancel): ")
            if provider_choice == "99":
                return None
            
            provider_choice = int(provider_choice)
            if 1 <= provider_choice <= len(providers):
                return providers[provider_choice - 1]
            else:
                print(f"{COLORS['RED']}Please enter a number between 1 and {len(providers)}{COLORS['RESET']}")
        except ValueError:
            print(f"{COLORS['RED']}Please enter a valid number{COLORS['RESET']}")

def gather_provider_config(provider):
    """Gather configuration for the specified provider"""
    if provider == "azure":
        from .azure_utils import gather_azure_config
        return gather_azure_config()
    elif provider == "aws":
        return gather_aws_config()
    elif provider == "linode":
        return gather_linode_config()
    elif provider == "flokinet":
        return gather_flokinet_config()
    else:
        print(f"{COLORS['RED']}Unknown provider: {provider}{COLORS['RESET']}")
        return None
