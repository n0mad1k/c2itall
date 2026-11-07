#!/usr/bin/env python3
"""
Provider selection and configuration utilities
"""

from .common import COLORS, PROVIDERS
from .provider_registry import (
    provider_dispatcher, providers_for, workload_route,
)
from .ssh_utils import generate_ssh_key

def available_providers(capability=None, legacy_fallback=False):
    """Advertise registered handlers plus explicitly allowed legacy providers."""
    return providers_for(capability, legacy_fallback=legacy_fallback)


def select_provider(capability=None, legacy_fallback=False):
    """Let the user select a cloud provider"""
    providers = available_providers(capability, legacy_fallback=legacy_fallback)
    if not providers:
        print('No provider implements this capability.')
        return None
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

def gather_provider_config(provider, capability=None, legacy_fallback=False):
    """Gather configuration for the specified provider"""
    dispatcher = provider_dispatcher(provider)
    if dispatcher is not None:
        return dispatcher.gather_config(capability, legacy_fallback=legacy_fallback)
    print(f"{COLORS['RED']}Unknown provider: {provider}{COLORS['RESET']}")
    return None


def prepare_module_ssh_key(config, key_name):
    """Prepare a legacy module key unless the native route owns recovery keys.

    Returns ``(ready, private_key_path)``. A successful provider-owned key
    yields ``(True, None)`` because it is created only after durable deployment
    intent has been persisted by that adapter.
    """
    provider_managed = config.get('provider_manages_ssh_key', False)
    if type(provider_managed) is not bool:
        raise ValueError('provider_manages_ssh_key must be a boolean')
    if provider_managed:
        return True, None
    private_key = generate_ssh_key(key_name)
    if not private_key:
        return False, None
    config['ssh_key_path'] = private_key + '.pub'
    return True, private_key


def apply_provider_profile(config, profile, value):
    """Apply workload tuning through its selected provider adapter."""
    adapter = workload_route(config)
    if adapter is not None:
        adapter.apply_profile(config, profile, value)
    return config
