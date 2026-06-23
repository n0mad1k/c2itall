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


# ── Empirical timing constants ────────────────────────────────────────────────
# Per-host nmap time by timing template (seconds, -sV --version-intensity 5)
NMAP_TIME_BY_TIMING = {
    1: 60.0,   # T1 sneaky
    2: 30.0,   # T2 polite
    3: 15.0,   # T3 normal
    4: 10.0,   # T4 aggressive (baseline)
}

# Average per-target time for typical nuclei CVE template (1–3 HTTP requests).
# Heavy templates with many requests/matchers will run 2–5× longer.
NUCLEI_TIME_PER_TARGET_SEC = 5.0

# TCP banner grab time (geo-scout probe phase)
PROBE_TIME_PER_HOST_SEC = 3.0

# Default fraction of scanned IPs with open ports on common ports.
# Real-world range: 0.5%–5% depending on ports & geography.
MASSCAN_HIT_RATE = 0.01

# Defaults — must match WEBRUNNER tuning defaults
_NMAP_WORKERS = 10
_NUCLEI_RATE = 150
_NUCLEI_CONCURRENCY = 25

# Tor latency multiplier — applies ONLY to TCP probe phases (nmap/nuclei/probe).
# Masscan uses raw sockets and bypasses proxychains entirely — Tor cannot
# protect masscan SYN packets. The cloud node's IP is exposed to every
# masscan target regardless of this setting.
TOR_PHASE_MULTIPLIER = 5.0

# Per-node provisioning overhead (apt install, optional nuclei download).
# Nodes provision in parallel so this is roughly constant.
PROVISION_OVERHEAD_HOURS = 5 / 60


def estimate_scan_hours(
    ip_count: int,
    n_ports: int,
    rate: int,
    scan_mode: str = 'masscan-only',
    *,
    nmap_timing: int = 4,
    nmap_workers: int = _NMAP_WORKERS,
    nuclei_rate: int = _NUCLEI_RATE,
    nuclei_concurrency: int = _NUCLEI_CONCURRENCY,
    hit_rate: float = MASSCAN_HIT_RATE,
    use_tor: bool = False,
) -> float:
    """Phase-decomposed scan time estimate. Returns hours per node."""
    if rate <= 0:
        return PROVISION_OVERHEAD_HOURS

    nmap_workers = max(nmap_workers, 1)
    seconds = 0.0

    # masscan phase: raw sockets, no Tor penalty (Tor cannot proxy raw sockets)
    if scan_mode in ('masscan-only', 'masscan+nmap', 'geo-scout', 'masscan+nuclei'):
        seconds += ip_count * n_ports / rate

    # nmap-only phase: every IP gets full -sV fingerprint
    if scan_mode == 'nmap-only':
        per_host = NMAP_TIME_BY_TIMING.get(nmap_timing, 10.0)
        if use_tor:
            per_host *= TOR_PHASE_MULTIPLIER
        seconds += (ip_count * per_host) / nmap_workers

    # nmap fingerprint phase: only on masscan hits
    if scan_mode in ('masscan+nmap', 'geo-scout'):
        nmap_hosts = ip_count * hit_rate
        per_host = NMAP_TIME_BY_TIMING.get(nmap_timing, 10.0)
        if use_tor:
            per_host *= TOR_PHASE_MULTIPLIER
        seconds += (nmap_hosts * per_host) / nmap_workers

    # probe banner phase: geo-scout only, on masscan hits
    if scan_mode == 'geo-scout':
        probe_hosts = ip_count * hit_rate
        per_probe = PROBE_TIME_PER_HOST_SEC
        if use_tor:
            per_probe *= TOR_PHASE_MULTIPLIER
        seconds += (probe_hosts * per_probe) / nmap_workers

    # nuclei phase: only on masscan-discovered ip:port pairs
    if scan_mode == 'masscan+nuclei':
        nuclei_targets = ip_count * hit_rate
        per_target = NUCLEI_TIME_PER_TARGET_SEC
        if use_tor:
            per_target *= TOR_PHASE_MULTIPLIER
        rate_throughput = float(nuclei_rate)
        parallel_throughput = nuclei_concurrency / per_target
        effective_rps = max(min(rate_throughput, parallel_throughput), 1.0)
        seconds += nuclei_targets / effective_rps

    return seconds / 3600 + PROVISION_OVERHEAD_HOURS


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


def build_estimate_table(
    total_ips: int,
    n_ports: int,
    providers: list[str],
    scan_mode: str,
    use_tor: bool = False,
    tuning: dict | None = None,
) -> list[dict]:
    tuning = tuning or {}
    masscan_rate = int(tuning.get('masscan_rate') or SCAN_MODES.get(scan_mode, {'rate': 3000})['rate'])

    kwargs = dict(
        nmap_timing=int(tuning.get('nmap_timing', 4)),
        nmap_workers=int(tuning.get('nmap_workers', _NMAP_WORKERS)),
        nuclei_rate=int(tuning.get('nuclei_rate', _NUCLEI_RATE)),
        nuclei_concurrency=int(tuning.get('nuclei_concurrency', _NUCLEI_CONCURRENCY)),
        hit_rate=float(tuning.get('hit_rate', MASSCAN_HIT_RATE)),
        use_tor=use_tor,
    )

    rows = []
    for preset_key, preset in PRESETS.items():
        n_chunks = max(1, math.ceil(total_ips / preset['chunk_size']))
        typical_ips = min(preset['chunk_size'], total_ips)
        hours_per_node = estimate_scan_hours(typical_ips, n_ports, masscan_rate, scan_mode, **kwargs)
        total_cost = 0.0
        for i in range(n_chunks):
            chunk_ips = min(preset['chunk_size'], total_ips - i * preset['chunk_size'])
            chunk_hours = estimate_scan_hours(chunk_ips, n_ports, masscan_rate, scan_mode, **kwargs)
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
