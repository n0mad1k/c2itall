#!/usr/bin/env python3
import math

INSTANCE_RATES = {
    'linode': {
        'g6-nanode-1':  0.0075,
        'g6-standard-2': 0.018,
        'g6-standard-4': 0.036,
        'g6-standard-8': 0.072,
    },
    'aws': {
        't3.micro':  0.0104,
        't3.small':  0.0208,
        't3.medium': 0.0416,
        't3.large':  0.0832,
    },
    'flokinet': {
        'vps-1': 0.0083,
        'vps-2': 0.0139,
        'vps-4': 0.0278,
    },
}

SCAN_MODES = {
    'geo-scout':      {'rate': 3000,  'desc': 'masscan + nmap + probe fingerprinting'},
    'masscan-only':   {'rate': 10000, 'desc': 'masscan port discovery only'},
    'nmap-only':      {'rate': 500,   'desc': 'nmap full fingerprint only'},
    'masscan+nmap':   {'rate': 5000,  'desc': 'masscan + nmap (no probes)'},
    'masscan+nuclei': {'rate': 5000,  'desc': 'masscan discovery + nuclei CVE template'},
}

PRESETS = {
    'sprint':   {'chunk_size': 500_000,   'label': 'Sprint',   'desc': '~500K IPs/node'},
    'balanced': {'chunk_size': 2_000_000, 'label': 'Balanced', 'desc': '~2M IPs/node  (recommended)'},
    'economy':  {'chunk_size': 5_000_000, 'label': 'Economy',  'desc': '~5M IPs/node'},
}

DEFAULT_INSTANCE = {
    'linode':   'g6-nanode-1',
    'aws':      't3.small',
    'flokinet': 'vps-2',
}

BILLING_MINIMUM = {
    'linode':   1.0,
    'aws':      0.017,  # billed per second, ~1 min minimum in practice
    'flokinet': 1.0,
}


NMAP_TIME_PER_HOST_SEC = 10   # empirical: nmap -sV -T4 per host, seconds
MASSCAN_HIT_RATE = 0.01       # fraction of scanned IPs that have open ports
_NMAP_WORKERS = 10            # must match WEBRUNNER_NMAP_WORKERS default


def estimate_scan_hours(ip_count: int, n_ports: int, rate: int, scan_mode: str = 'masscan-only') -> float:
    if rate <= 0:
        return 0.0
    masscan_hours = (ip_count * n_ports / rate) / 3600
    if scan_mode in ('masscan+nmap', 'geo-scout'):
        nmap_hosts = ip_count * MASSCAN_HIT_RATE
        nmap_hours = (nmap_hosts * NMAP_TIME_PER_HOST_SEC) / (_NMAP_WORKERS * 3600)
        return masscan_hours + nmap_hours
    return masscan_hours


def node_cost(provider: str, instance_type: str, scan_hours: float) -> float:
    rate = INSTANCE_RATES.get(provider, {}).get(instance_type, 0.018)
    billed_hours = max(scan_hours, BILLING_MINIMUM.get(provider, 1.0))
    return rate * billed_hours


def fmt_hours(h: float) -> str:
    total_mins = int(h * 60)
    hrs, mins = divmod(total_mins, 60)
    return f"{hrs}h {mins:02d}m" if hrs else f"{mins}m"


def fmt_ip_count(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.0f}K"
    return str(n)


# Tor adds ~5x latency overhead for TCP probes; masscan bypasses proxychains (raw sockets)
# so only nmap/probe phases are affected — modes that include masscan see partial impact
TOR_RATE_MULTIPLIER = 0.2


def build_estimate_table(
    total_ips: int,
    n_ports: int,
    providers: list[str],
    scan_mode: str,
    use_tor: bool = False,
) -> list[dict]:
    mode_rate = SCAN_MODES.get(scan_mode, {'rate': 3000})['rate']
    if use_tor and scan_mode != 'masscan-only':
        mode_rate = int(mode_rate * TOR_RATE_MULTIPLIER)
    rows = []
    for preset_key, preset in PRESETS.items():
        n_chunks = max(1, math.ceil(total_ips / preset['chunk_size']))
        typical_ips = min(preset['chunk_size'], total_ips)
        hours_per_node = estimate_scan_hours(typical_ips, n_ports, mode_rate, scan_mode)
        total_cost = 0.0
        for i in range(n_chunks):
            chunk_ips = min(preset['chunk_size'], total_ips - i * preset['chunk_size'])
            chunk_hours = estimate_scan_hours(chunk_ips, n_ports, mode_rate, scan_mode)
            provider = providers[i % len(providers)]
            instance = DEFAULT_INSTANCE.get(provider, 'g6-standard-2')
            total_cost += node_cost(provider, instance, chunk_hours)
        rows.append({
            'preset': preset_key,
            'label': preset['label'],
            'desc': preset['desc'],
            'n_nodes': n_chunks,
            'hours_per_node': hours_per_node,
            'total_cost_usd': total_cost,
        })
    return rows
