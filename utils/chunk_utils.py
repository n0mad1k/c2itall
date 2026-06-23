#!/usr/bin/env python3
import ipaddress
from utils.cidr_resolver import get_country_cidrs


def ip_count(cidr: str) -> int:
    try:
        return ipaddress.ip_network(cidr, strict=False).num_addresses
    except ValueError:
        return 0


def chunk_cidrs(all_cidrs: list[str], chunk_size: int) -> list[dict]:
    chunks = []
    current_cidrs: list[str] = []
    current_count = 0

    for cidr in all_cidrs:
        n = ip_count(cidr)
        if n == 0:
            continue
        if current_count > 0 and current_count + n > chunk_size * 1.5:
            chunks.append({'cidrs': current_cidrs, 'ip_count': current_count})
            current_cidrs = []
            current_count = 0
        current_cidrs.append(cidr)
        current_count += n
        if current_count >= chunk_size:
            chunks.append({'cidrs': current_cidrs, 'ip_count': current_count})
            current_cidrs = []
            current_count = 0

    if current_cidrs:
        chunks.append({'cidrs': current_cidrs, 'ip_count': current_count})

    return chunks


__all__ = ['get_country_cidrs', 'chunk_cidrs', 'ip_count']
