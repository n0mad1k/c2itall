#!/usr/bin/env python3
import ipaddress
import sys
from pathlib import Path


def _try_load_geo_scout() -> bool:
    candidates = [
        Path(__file__).parents[2] / 'geo-scout',
        Path.home() / 'tools' / 'geo-scout',
    ]
    for p in candidates:
        if (p / 'lib' / 'cidr.py').exists():
            if str(p) not in sys.path:
                sys.path.insert(0, str(p))
            return True
    return False


def ip_count(cidr: str) -> int:
    try:
        return ipaddress.ip_network(cidr, strict=False).num_addresses
    except ValueError:
        return 0


def get_country_cidrs(country_codes: list[str], exclude_map: dict[str, list] | None = None) -> dict[str, list[str]]:
    if exclude_map is None:
        exclude_map = {}

    _try_load_geo_scout()
    try:
        from lib.cidr import fetch_rir_data, load_index, get_cidrs, merge_cidrs
    except ImportError:
        return {cc.upper(): [] for cc in country_codes}

    fetch_rir_data()
    index = load_index()
    result = {}
    for cc in country_codes:
        cc = cc.upper()
        cidrs = get_cidrs(cc, index)
        cidrs = merge_cidrs(cidrs, exclude_map.get(cc, []))
        result[cc] = cidrs
    return result


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
