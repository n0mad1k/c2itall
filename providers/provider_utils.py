#!/usr/bin/env python3
"""Compatibility import for the canonical provider dispatcher utilities.

Older callers imported provider helpers from ``providers.provider_utils``.
Keep that path working while ensuring selection and configuration use the
shared registry in ``utils.provider_utils``.
"""

from utils.provider_utils import (  # noqa: F401
    available_providers,
    gather_provider_config,
    select_provider,
)

__all__ = [
    'available_providers',
    'gather_provider_config',
    'select_provider',
]
