#!/usr/bin/env python3
"""
WEBRUNNER — Distributed geo-targeted recon scanning module for c2itall
Provisions cloud nodes across multiple providers, distributes CIDR space,
runs masscan/nmap/geo-scout in parallel, collects and merges results.
"""

import json
import os
import sys
from pathlib import Path

_base = os.path.join(os.path.dirname(__file__), '..', '..')
if _base not in sys.path:
    sys.path.insert(0, _base)

from utils.common import (
    COLORS, clear_screen, print_banner, wait_for_input,
    get_public_ip, load_vars_file,
)
from utils.ssh_utils import generate_ssh_key
from utils.name_generator import generate_deployment_id
from utils.naming_utils import get_deployment_name_with_options
from utils.deployment_engine import execute_playbook, set_provider_environment
from utils.chunk_utils import get_country_cidrs, chunk_cidrs, ip_count
from utils.provider_rates import (
    PRESETS, SCAN_MODES, DEFAULT_INSTANCE,
    build_estimate_table, fmt_hours, fmt_ip_count,
)

GEO_SCOUT_INPUTS = Path(__file__).parents[3] / 'geo-scout' / 'inputs'

SUPPORTED_PROVIDERS = ['linode', 'aws', 'flokinet']
PROVIDER_LABELS = {'linode': 'Linode', 'aws': 'AWS', 'flokinet': 'FlokiNET'}


# ── menu ──────────────────────────────────────────────────────────────────────

def webrunner_menu():
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['CYAN']}WEBRUNNER — Distributed Geo-Targeted Recon{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}==========================================={COLORS['RESET']}")
        print(f"1) New Scan Deployment")
        print(f"\n99) Return to Main Menu")

        choice = input(f"\nSelect: ").strip()
        if choice == "1":
            config = gather_webrunner_parameters()
            if config:
                execute_webrunner_deployment(config)
                wait_for_input()
        elif choice == "99":
            break
        else:
            print(f"{COLORS['RED']}Invalid option.{COLORS['RESET']}")
            wait_for_input()


# ── parameter gathering ───────────────────────────────────────────────────────

def _select_countries() -> tuple[list[str], dict[str, list], str]:
    print(f"\n{COLORS['BLUE']}Country Selection:{COLORS['RESET']}")
    print(f"1) Use geo-scout countries.yaml")
    print(f"2) Enter country codes manually")

    choice = input("Select [1]: ").strip() or "1"
    exclude_map: dict[str, list] = {}

    if choice == "1":
        default_path = str(GEO_SCOUT_INPUTS / 'countries.yaml')
        raw = input(f"Path [{default_path}]: ").strip()
        path = Path(raw) if raw else GEO_SCOUT_INPUTS / 'countries.yaml'

        if not path.exists():
            print(f"{COLORS['RED']}File not found: {path}{COLORS['RESET']}")
            return [], {}, ""

        import yaml
        with open(path) as f:
            data = yaml.safe_load(f)

        countries = data.get('countries', [])
        codes = [c['code'].upper() for c in countries]
        for c in countries:
            if c.get('exclude_cidrs'):
                exclude_map[c['code'].upper()] = c['exclude_cidrs']
        return codes, exclude_map, str(path)

    raw = input("Country codes (comma-separated, e.g. RU,IR,CN): ").strip()
    codes = [c.strip().upper() for c in raw.split(',') if c.strip()]
    return codes, exclude_map, "manual"


def _select_scan_mode() -> str:
    print(f"\n{COLORS['BLUE']}Scan Mode:{COLORS['RESET']}")
    modes = list(SCAN_MODES.items())
    for i, (key, val) in enumerate(modes, 1):
        print(f"{i}) {key:<20} {val['desc']}")

    choice = input("Select [1]: ").strip() or "1"
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(modes):
            return modes[idx][0]
    except ValueError:
        pass
    return 'geo-scout'


def _select_providers() -> list[str]:
    print(f"\n{COLORS['BLUE']}Provider Selection (multi-select):{COLORS['RESET']}")
    for i, key in enumerate(SUPPORTED_PROVIDERS, 1):
        print(f"{i}) {PROVIDER_LABELS[key]}")

    raw = input("Select providers (e.g. 1 or 1,2) [1]: ").strip() or "1"
    selected = []
    for part in raw.split(','):
        try:
            idx = int(part.strip()) - 1
            if 0 <= idx < len(SUPPORTED_PROVIDERS):
                key = SUPPORTED_PROVIDERS[idx]
                if key not in selected:
                    selected.append(key)
        except ValueError:
            pass
    return selected or ['linode']


def _get_targets_info(scan_mode: str) -> tuple[str, list[int]]:
    if scan_mode == 'geo-scout':
        default = str(GEO_SCOUT_INPUTS / 'targets.yaml')
        raw = input(f"Path to targets.yaml [{default}]: ").strip()
        path = raw or default

        import yaml
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            ports: set[int] = set()
            for t in data.get('targets', []):
                ports.update(t.get('ports', []))
            return path, sorted(ports)
        except Exception as e:
            print(f"{COLORS['YELLOW']}Could not load targets ({e}), using defaults.{COLORS['RESET']}")
            return path, [22, 80, 443, 8080, 8443]

    default_ports = "22,80,443,8080,8443"
    raw = input(f"Ports to scan [{default_ports}]: ").strip() or default_ports
    ports_list: list[int] = []
    for p in raw.split(','):
        try:
            ports_list.append(int(p.strip()))
        except ValueError:
            pass
    return "", sorted(set(ports_list)) or [80, 443, 22]


def _show_estimate_table(total_ips: int, n_ports: int, providers: list[str], scan_mode: str):
    rows = build_estimate_table(total_ips, n_ports, providers, scan_mode)

    W = COLORS['WHITE']
    C = COLORS['CYAN']
    Y = COLORS['YELLOW']
    G = COLORS['GREEN']
    R = COLORS['RESET']

    print(f"\n{C}{'─' * 70}{R}")
    print(f"{C}  WEBRUNNER — Cost & Time Estimate{R}")
    print(f"{W}  Total: {fmt_ip_count(total_ips)} IPs   {n_ports} ports   Mode: {scan_mode}{R}")
    print(f"{W}  Providers: {', '.join(PROVIDER_LABELS[p] for p in providers)}{R}")
    print(f"{C}{'─' * 70}{R}")
    print(f"  {'Preset':<14} {'Nodes':>6} {'IPs/Node':>10} {'Time/Node':>12} {'Total $':>10}")
    print(f"  {'─' * 56}")

    for row in rows:
        star = " *" if row['preset'] == 'balanced' else "  "
        color = G if row['preset'] == 'balanced' else W
        ips_per_node = total_ips // row['n_nodes'] if row['n_nodes'] else total_ips
        print(
            f"{color}{star}{row['label']:<12} {row['n_nodes']:>6} "
            f"{fmt_ip_count(ips_per_node):>10} "
            f"{fmt_hours(row['hours_per_node']):>12} "
            f"${row['total_cost_usd']:>9.2f}{R}"
        )

    print(f"{C}{'─' * 70}{R}")
    print(f"{Y}  * = recommended (Pareto-optimal: speed vs. billing minimum){R}\n")


def gather_webrunner_parameters() -> dict | None:
    clear_screen()
    print_banner()
    print(f"{COLORS['CYAN']}WEBRUNNER — New Scan Deployment{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}================================{COLORS['RESET']}\n")

    engagement = input("Engagement name: ").strip()
    if not engagement:
        print(f"{COLORS['RED']}Engagement name required.{COLORS['RESET']}")
        wait_for_input()
        return None

    country_codes, exclude_map, _ = _select_countries()
    if not country_codes:
        print(f"{COLORS['RED']}No countries selected.{COLORS['RESET']}")
        wait_for_input()
        return None

    print(f"{COLORS['GREEN']}Countries: {', '.join(country_codes)}{COLORS['RESET']}")

    scan_mode = _select_scan_mode()
    providers = _select_providers()
    print(f"{COLORS['GREEN']}Providers: {', '.join(PROVIDER_LABELS[p] for p in providers)}{COLORS['RESET']}")

    targets_file, ports = _get_targets_info(scan_mode)

    print(f"\n{COLORS['CYAN']}[*] Resolving CIDR data for {len(country_codes)} countries...{COLORS['RESET']}")
    cc_cidrs = get_country_cidrs(country_codes, exclude_map)
    total_ips = sum(
        sum(ip_count(c) for c in cidrs)
        for cidrs in cc_cidrs.values()
    )

    if total_ips == 0:
        print(f"{COLORS['RED']}No IPs resolved. Ensure geo-scout RIR data is available.{COLORS['RESET']}")
        wait_for_input()
        return None

    print(f"{COLORS['GREEN']}Total: {fmt_ip_count(total_ips)} IPs across {len(country_codes)} countries{COLORS['RESET']}")

    _show_estimate_table(total_ips, len(ports), providers, scan_mode)

    print(f"{COLORS['BLUE']}Select deployment preset:{COLORS['RESET']}")
    preset_list = list(PRESETS.items())
    for i, (key, val) in enumerate(preset_list, 1):
        star = " (recommended)" if key == 'balanced' else ""
        print(f"{i}) {val['label']}{star} — {val['desc']}")
    print(f"4) Custom chunk size")

    preset_choice = input("Select [2]: ").strip() or "2"

    if preset_choice == "4":
        raw = input("IPs per node: ").strip()
        try:
            chunk_size = int(raw.replace(',', '').replace('_', ''))
            preset_key = 'custom'
        except ValueError:
            chunk_size = PRESETS['balanced']['chunk_size']
            preset_key = 'balanced'
    else:
        try:
            idx = int(preset_choice) - 1
            if 0 <= idx < len(preset_list):
                preset_key, preset_val = preset_list[idx]
                chunk_size = preset_val['chunk_size']
            else:
                preset_key = 'balanced'
                chunk_size = PRESETS['balanced']['chunk_size']
        except ValueError:
            preset_key = 'balanced'
            chunk_size = PRESETS['balanced']['chunk_size']

    opsec_raw = input(f"\nEnhanced OPSEC mode? (randomize names, auto-teardown) [y/N]: ").strip().lower()
    enhanced_opsec = opsec_raw in ['y', 'yes']

    print(f"\n{COLORS['CYAN']}[*] Generating deployment assets...{COLORS['RESET']}")
    deployment_id = generate_deployment_id()
    webrunner_name = get_deployment_name_with_options('webrunner', deployment_id, prefix='wr-')

    raw_key_path = generate_ssh_key(webrunner_name)
    if not raw_key_path:
        print(f"{COLORS['RED']}Failed to generate SSH key.{COLORS['RESET']}")
        wait_for_input()
        return None

    config: dict = {
        'engagement': engagement,
        'deployment_id': deployment_id,
        'deployment_type': 'webrunner',
        'webrunner_deployment': True,
        'webrunner_name': webrunner_name,
        'ssh_key_path': f"{raw_key_path}.pub",
        'ssh_key_name': os.path.basename(raw_key_path),
        'providers': providers,
        'scan_mode': scan_mode,
        'preset': preset_key,
        'chunk_size': chunk_size,
        'country_codes': country_codes,
        'ports': ports,
        'ports_str': ','.join(str(p) for p in ports),
        'targets_file': targets_file,
        'masscan_rate': SCAN_MODES.get(scan_mode, {}).get('rate', 3000),
        'enhanced_opsec': enhanced_opsec,
        'linode_instance_type': DEFAULT_INSTANCE.get('linode', 'g6-standard-2'),
        'linode_region': 'us-east',
        'aws_instance_type': DEFAULT_INSTANCE.get('aws', 't3.small'),
        'aws_region': 'us-east-1',
    }

    operator_ip = get_public_ip()
    if operator_ip:
        config['operator_ip'] = operator_ip
        print(f"{COLORS['GREEN']}Operator IP: {operator_ip}{COLORS['RESET']}")

    for provider in providers:
        vars_data = load_vars_file(provider)
        if vars_data:
            config.update({k: v for k, v in vars_data.items() if k not in config})

    print(f"{COLORS['CYAN']}[*] Distributing {fmt_ip_count(total_ips)} IPs across nodes...{COLORS['RESET']}")
    all_cidrs: list[str] = []
    for cc in country_codes:
        all_cidrs.extend(cc_cidrs.get(cc.upper(), []))

    chunks = chunk_cidrs(all_cidrs, chunk_size)
    node_chunks = [
        {
            'idx': i,
            'node_name': f"{webrunner_name}-{i + 1:02d}",
            'provider': providers[i % len(providers)],
            'cidrs': chunk['cidrs'],
            'ip_count': chunk['ip_count'],
        }
        for i, chunk in enumerate(chunks)
    ]

    print(f"{COLORS['GREEN']}Nodes: {len(node_chunks)} ({preset_key}, {fmt_ip_count(chunk_size)}/node){COLORS['RESET']}")

    print(f"\n{COLORS['YELLOW']}{'─' * 50}{COLORS['RESET']}")
    print(f"  Deployment:  {webrunner_name}")
    print(f"  Nodes:       {len(node_chunks)}")
    print(f"  Providers:   {', '.join(PROVIDER_LABELS[p] for p in providers)}")
    print(f"  Scan mode:   {scan_mode}")
    print(f"  Ports:       {', '.join(str(p) for p in ports[:8])}{'...' if len(ports) > 8 else ''}")
    print(f"  Total IPs:   {fmt_ip_count(total_ips)}")
    print(f"{COLORS['YELLOW']}{'─' * 50}{COLORS['RESET']}")

    confirm = input(f"\nDeploy {len(node_chunks)} nodes? [y/N]: ").strip().lower()
    if confirm not in ['y', 'yes']:
        print(f"{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return None

    config['node_chunks'] = node_chunks
    config['total_ips'] = total_ips
    return config


# ── execution ─────────────────────────────────────────────────────────────────

def execute_webrunner_deployment(config: dict):
    deployment_id = config['deployment_id']
    node_chunks = config.pop('node_chunks')

    os.makedirs('logs', exist_ok=True)
    chunks_file = f"logs/node_chunks_{deployment_id}.json"
    with open(chunks_file, 'w') as f:
        json.dump(node_chunks, f)
    config['node_chunks_file'] = chunks_file
    config['scanner_ip_log'] = f"logs/scanner_ips_{config['webrunner_name']}.txt"
    config['results_dir'] = f"logs/webrunner_{deployment_id}"

    for provider in config['providers']:
        set_provider_environment({**config, 'provider': provider})

    playbook = 'providers/webrunner.yml'
    n_nodes = len(node_chunks)

    print(f"\n{COLORS['CYAN']}[*] Launching WEBRUNNER — {n_nodes} nodes across "
          f"{', '.join(PROVIDER_LABELS[p] for p in config['providers'])}{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}    Provisioning may take several minutes per node.{COLORS['RESET']}\n")

    success = execute_playbook(playbook, config)

    if success:
        print(f"\n{COLORS['GREEN']}[+] WEBRUNNER complete.{COLORS['RESET']}")
        print(f"    Results:     logs/webrunner_{deployment_id}/")
        print(f"    Scanner IPs: logs/scanner_ips_{config['webrunner_name']}.txt")
        print(f"    Log:         logs/deployment_{deployment_id}.log")
    else:
        print(f"\n{COLORS['RED']}[-] WEBRUNNER failed. Check: logs/deployment_{deployment_id}.log{COLORS['RESET']}")
