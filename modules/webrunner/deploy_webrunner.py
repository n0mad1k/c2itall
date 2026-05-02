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
    COLORS, clear_screen, print_banner, generate_deployment_id,
    setup_logging, get_public_ip, confirm_action, wait_for_input,
)
from utils.provider_utils import gather_provider_config
from utils.ssh_utils import generate_ssh_key
from utils.naming_utils import show_naming_relationship
from utils.deployment_engine import execute_playbook, set_provider_environment
from utils.chunk_utils import get_country_cidrs, chunk_cidrs, ip_count
from utils.provider_rates import (
    PRESETS, SCAN_MODES, DEFAULT_INSTANCE,
    build_estimate_table, fmt_hours, fmt_ip_count,
)

WEBRUNNER_INPUTS = Path(__file__).parent / 'inputs'

SUPPORTED_PROVIDERS = ['linode', 'aws', 'flokinet']
PROVIDER_LABELS = {'linode': 'Linode', 'aws': 'AWS', 'flokinet': 'FlokiNET'}


# ── menu ──────────────────────────────────────────────────────────────────────

def webrunner_menu():
    config = gather_webrunner_parameters()
    if config:
        execute_webrunner_deployment(config)


# ── helpers ───────────────────────────────────────────────────────────────────

def _select_providers() -> list[str]:
    print(f"\n{COLORS['BLUE']}Provider Selection (multi-select):{COLORS['RESET']}")
    for i, key in enumerate(SUPPORTED_PROVIDERS, 1):
        print(f"  {i}) {PROVIDER_LABELS[key]}")

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


def _select_countries() -> tuple[list[str], dict[str, list]]:
    print(f"\n{COLORS['BLUE']}Country Selection:{COLORS['RESET']}")
    print(f"1) Use bundled countries.yaml")
    print(f"2) Enter country codes manually")

    choice = input("Select [1]: ").strip() or "1"
    exclude_map: dict[str, list] = {}

    if choice == "1":
        default_path = str(WEBRUNNER_INPUTS / 'countries.yaml')
        raw = input(f"Path [{default_path}]: ").strip()
        path = Path(raw) if raw else WEBRUNNER_INPUTS / 'countries.yaml'

        if not path.exists():
            print(f"{COLORS['RED']}File not found: {path}{COLORS['RESET']}")
            return [], {}

        import yaml
        with open(path) as f:
            data = yaml.safe_load(f)

        countries = data.get('countries', [])
        codes = [c['code'].upper() for c in countries]
        for c in countries:
            if c.get('exclude_cidrs'):
                exclude_map[c['code'].upper()] = c['exclude_cidrs']
        return codes, exclude_map

    raw = input("Country codes (comma-separated, e.g. RU,IR,CN): ").strip()
    codes = [c.strip().upper() for c in raw.split(',') if c.strip()]
    return codes, exclude_map


def _select_scan_mode() -> str:
    print(f"\n{COLORS['BLUE']}Scan Mode:{COLORS['RESET']}")
    modes = list(SCAN_MODES.items())
    for i, (key, val) in enumerate(modes, 1):
        print(f"  {i}) {key:<20} {val['desc']}")

    choice = input("Select [1]: ").strip() or "1"
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(modes):
            return modes[idx][0]
    except ValueError:
        pass
    return 'geo-scout'


def _load_vars_file(path: str) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        print(f"{COLORS['YELLOW']}  Vars file not found: {path} — continuing interactively{COLORS['RESET']}")
        return {}
    import yaml
    try:
        with open(p) as f:
            data = yaml.safe_load(f) or {}
        print(f"{COLORS['GREEN']}  Loaded vars: {p.name}{COLORS['RESET']}")
        return data
    except Exception as e:
        print(f"{COLORS['YELLOW']}  Could not parse vars file ({e}) — continuing interactively{COLORS['RESET']}")
        return {}


def _get_targets_info(scan_mode: str) -> tuple[str, list[int]]:
    if scan_mode == 'geo-scout':
        default = str(WEBRUNNER_INPUTS / 'targets.yaml')
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


def _get_nuclei_info(vars_overrides: dict) -> tuple[str, str]:
    """Returns (local_template_path, remote_template_path)."""
    print(f"\n{COLORS['BLUE']}Nuclei Template:{COLORS['RESET']}")
    if 'nuclei_template' in vars_overrides:
        local_path = vars_overrides['nuclei_template']
        print(f"  Template: {local_path} (from vars file)")
    else:
        local_path = input("  Path to nuclei template (.yaml): ").strip()
    if not local_path or not Path(local_path).exists():
        print(f"{COLORS['RED']}  Template not found: {local_path}{COLORS['RESET']}")
        return "", ""
    return local_path, "/root/webrunner/nuclei_template.yaml"


def _get_tuning_params(scan_mode: str, default_rate: int, vars_overrides: dict) -> dict:
    """Gather advanced tuning params. Returns dict of tuning config keys."""
    tuning: dict = {}
    show_header = True

    def _prompt(label: str, key: str, default, cast=int) -> None:
        nonlocal show_header
        if show_header:
            print(f"\n{COLORS['BLUE']}Advanced Tuning (Enter = use default):{COLORS['RESET']}")
            show_header = False
        if key in vars_overrides:
            tuning[key] = cast(vars_overrides[key])
            print(f"  {label}: {tuning[key]} (vars file)")
        else:
            raw = input(f"  {label} [{default}]: ").strip()
            tuning[key] = cast(raw) if raw else default

    _prompt("masscan rate (pkt/s)", "masscan_rate", default_rate)

    if scan_mode in ('masscan+nmap', 'geo-scout', 'masscan+nuclei'):
        pass  # masscan_rate already handled

    if scan_mode in ('masscan+nmap', 'geo-scout'):
        _prompt("nmap timing T1-T4", "nmap_timing", 4)
        _prompt("nmap per-host timeout (s)", "nmap_timeout", 60)
        _prompt("nmap parallel workers", "nmap_workers", 10)

    if scan_mode == 'masscan+nuclei':
        _prompt("nuclei rate limit (req/s)", "nuclei_rate", 150)
        _prompt("nuclei concurrency", "nuclei_concurrency", 25)
        _prompt("nuclei timeout (s)", "nuclei_timeout", 10)

    return tuning


def _show_estimate_table(total_ips: int, n_ports: int, providers: list[str], scan_mode: str, use_tor: bool = False):
    rows = build_estimate_table(total_ips, n_ports, providers, scan_mode, use_tor=use_tor)

    C = COLORS['CYAN']
    W = COLORS['WHITE']
    Y = COLORS['YELLOW']
    G = COLORS['GREEN']
    R = COLORS['RESET']

    tor_note = "  [Tor: estimates reflect nmap/probe latency]" if use_tor else ""
    print(f"\n{C}{'─' * 70}{R}")
    print(f"{C}  WEBRUNNER — Cost & Time Estimate{R}")
    print(f"{W}  Total: {fmt_ip_count(total_ips)} IPs   {n_ports} ports   Mode: {scan_mode}{R}")
    print(f"{W}  Providers: {', '.join(PROVIDER_LABELS[p] for p in providers)}{Y}{tor_note}{R}")
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


# ── parameter gathering ───────────────────────────────────────────────────────

def gather_webrunner_parameters() -> dict | None:
    clear_screen()
    print_banner()
    print(f"{COLORS['WHITE']}WEBRUNNER SETUP{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}==============={COLORS['RESET']}")

    config: dict = {}

    # Deployment ID
    config['deployment_id'] = generate_deployment_id()
    print(f"Deployment ID: {COLORS['CYAN']}{config['deployment_id']}{COLORS['RESET']}")

    # Optional vars file — pre-fills tuning defaults
    vars_raw = input("Vars file (optional, skip to configure interactively): ").strip()
    vars_overrides = _load_vars_file(vars_raw)

    # Engagement name — auto if blank
    raw_eng = input(f"Engagement name [{config['deployment_id']}]: ").strip()
    config['engagement'] = raw_eng or config['deployment_id']

    # Provider selection — multi-select, each provider prompts for creds + region
    providers = _select_providers()
    config['providers'] = providers

    for provider in providers:
        provider_config = gather_provider_config(provider)
        if not provider_config:
            return None
        config.update(provider_config)

    print(f"{COLORS['GREEN']}Providers: {', '.join(PROVIDER_LABELS[p] for p in providers)}{COLORS['RESET']}")

    # Deployment type
    config['deployment_type'] = 'webrunner'
    config['webrunner_deployment'] = True

    # Naming — auto-derive from deployment_id, no second prompt
    config['webrunner_name'] = f"wr-{config['deployment_id']}"

    # SSH key
    ssh_key_path = generate_ssh_key(config['webrunner_name'])
    if not ssh_key_path:
        print(f"{COLORS['RED']}Failed to generate SSH key.{COLORS['RESET']}")
        return None
    config['ssh_key_path'] = f"{ssh_key_path}.pub"
    config['ssh_key_name'] = os.path.basename(ssh_key_path)
    print(f"{COLORS['GREEN']}SSH key generated: {ssh_key_path}{COLORS['RESET']}")

    # Country / CIDR selection
    country_codes, exclude_map = _select_countries()
    if not country_codes:
        print(f"{COLORS['RED']}No countries selected.{COLORS['RESET']}")
        return None
    config['country_codes'] = country_codes
    print(f"{COLORS['GREEN']}Countries: {', '.join(country_codes)}{COLORS['RESET']}")

    # Scan mode
    scan_mode = _select_scan_mode()
    config['scan_mode'] = scan_mode

    # Nuclei template (masscan+nuclei only)
    config['nuclei_template_local'] = ''
    config['nuclei_template_remote'] = ''
    if scan_mode == 'masscan+nuclei':
        local_tmpl, remote_tmpl = _get_nuclei_info(vars_overrides)
        if not local_tmpl:
            return None
        config['nuclei_template_local'] = local_tmpl
        config['nuclei_template_remote'] = remote_tmpl

    # Targets / ports
    targets_file, ports = _get_targets_info(scan_mode)
    config['targets_file'] = targets_file
    config['ports'] = ports
    config['ports_str'] = ','.join(str(p) for p in ports)
    config['masscan_rate'] = SCAN_MODES.get(scan_mode, {}).get('rate', 3000)

    # Resolve CIDR data
    print(f"\n{COLORS['CYAN']}[*] Resolving CIDR data for {len(country_codes)} countries...{COLORS['RESET']}")
    cc_cidrs = get_country_cidrs(country_codes, exclude_map)
    total_ips = sum(sum(ip_count(c) for c in cidrs) for cidrs in cc_cidrs.values())

    if total_ips == 0:
        print(f"{COLORS['RED']}No IPs resolved. Check your country codes or network connectivity.{COLORS['RESET']}")
        return None

    print(f"{COLORS['GREEN']}Total: {fmt_ip_count(total_ips)} IPs across {len(country_codes)} countries{COLORS['RESET']}")
    config['total_ips'] = total_ips

    # Tor routing — ask before estimate so table reflects the slowdown
    tor_raw = input(f"\nRoute scans through Tor? [y/N]: ").strip().lower()
    config['use_tor'] = tor_raw in ['y', 'yes']
    if config['use_tor']:
        if scan_mode == 'masscan-only':
            print(f"{COLORS['YELLOW']}  Warning: masscan uses raw sockets and bypasses proxychains — Tor has no effect in masscan-only mode.{COLORS['RESET']}")
        elif scan_mode in ('geo-scout', 'masscan+nmap'):
            print(f"{COLORS['YELLOW']}  Note: masscan phase bypasses Tor (raw sockets); nmap and probe phases will use Tor.{COLORS['RESET']}")
        else:
            print(f"{COLORS['YELLOW']}  Tor routing enabled — all nmap traffic will use proxychains → SOCKS5 9050.{COLORS['RESET']}")

    # Cost / time estimate — reflects Tor throughput impact
    _show_estimate_table(total_ips, len(ports), providers, scan_mode, use_tor=config['use_tor'])

    # Preset selection
    print(f"{COLORS['BLUE']}Select deployment preset:{COLORS['RESET']}")
    preset_list = list(PRESETS.items())
    for i, (key, val) in enumerate(preset_list, 1):
        star = " (recommended)" if key == 'balanced' else ""
        print(f"  {i}) {val['label']}{star} — {val['desc']}")
    print(f"  4) Custom chunk size")

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

    config['preset'] = preset_key
    config['chunk_size'] = chunk_size

    config['cidr_country_map_file'] = ''  # filled in execute_webrunner_deployment

    # Distribute CIDRs into node chunks
    all_cidrs: list[str] = []
    for cc in country_codes:
        all_cidrs.extend(cc_cidrs.get(cc.upper(), []))

    chunks = chunk_cidrs(all_cidrs, chunk_size)

    # Build per-provider region pools for round-robin assignment
    provider_regions: dict[str, list[str]] = {}
    for p in providers:
        if p == 'linode':
            provider_regions[p] = config.get('linode_regions', [config.get('linode_region', 'us-east')])
        elif p == 'aws':
            provider_regions[p] = config.get('aws_regions', [config.get('aws_region', 'us-east-1')])
        elif p == 'flokinet':
            provider_regions[p] = [config.get('flokinet_region', 'default')]
        else:
            provider_regions[p] = ['default']

    provider_counters: dict[str, int] = {p: 0 for p in providers}
    node_chunks = []
    for i, chunk in enumerate(chunks):
        provider = providers[i % len(providers)]
        regions = provider_regions[provider]
        region = regions[provider_counters[provider] % len(regions)]
        provider_counters[provider] += 1
        node_chunks.append({
            'idx': i,
            'node_name': f"{config['webrunner_name']}-{i + 1:02d}",
            'provider': provider,
            'region': region,
            'cidrs': chunk['cidrs'],
            'ip_count': chunk['ip_count'],
        })

    config['node_chunks'] = node_chunks
    print(f"{COLORS['GREEN']}Nodes: {len(node_chunks)} ({preset_key}, {fmt_ip_count(chunk_size)}/node){COLORS['RESET']}")

    # Warn if any provider's node count exceeds safe per-region quota
    _PROVIDER_CAPS = {'linode': 20, 'aws': 32, 'flokinet': 10}
    provider_node_counts: dict[str, int] = {}
    for nc in node_chunks:
        provider_node_counts[nc['provider']] = provider_node_counts.get(nc['provider'], 0) + 1
    for p, count in provider_node_counts.items():
        n_regions = len(provider_regions.get(p, ['default']))
        cap = _PROVIDER_CAPS.get(p, 20)
        per_region = (count + n_regions - 1) // n_regions
        if per_region > cap:
            print(f"{COLORS['YELLOW']}  Warning: {count} {PROVIDER_LABELS[p]} nodes across {n_regions} region(s) "
                  f"= ~{per_region}/region; default quota is ~{cap}/region.{COLORS['RESET']}")

    # Operator IP
    config['operator_ip'] = get_public_ip()
    if config['operator_ip']:
        print(f"{COLORS['GREEN']}Operator IP: {config['operator_ip']}{COLORS['RESET']}")

    # Advanced tuning
    default_rate = config['masscan_rate']
    tuning = _get_tuning_params(scan_mode, default_rate, vars_overrides)
    config.update(tuning)

    # OPSEC / teardown options
    print(f"\n{COLORS['BLUE']}Deployment Options:{COLORS['RESET']}")

    opsec_raw = input(f"Enhanced OPSEC mode? (randomize node names, minimal logging) [y/N]: ").strip().lower()
    config['enhanced_opsec'] = opsec_raw in ['y', 'yes']

    teardown_raw = input(f"Teardown nodes after scan completes? [Y/n]: ").strip().lower()
    config['teardown_after_scan'] = teardown_raw not in ['n', 'no']

    if config['teardown_after_scan']:
        print(f"{COLORS['YELLOW']}  Nodes will be destroyed automatically when scan completes.{COLORS['RESET']}")
    else:
        print(f"{COLORS['CYAN']}  Nodes will remain running after scan — remember to teardown manually.{COLORS['RESET']}")

    # Apply per-provider instance defaults if not set by gather_provider_config
    if 'linode_instance_type' not in config:
        config['linode_instance_type'] = DEFAULT_INSTANCE.get('linode', 'g6-nanode-1')
    if 'aws_instance_type' not in config:
        config['aws_instance_type'] = DEFAULT_INSTANCE.get('aws', 't3.small')

    return config


# ── execution ─────────────────────────────────────────────────────────────────

def execute_webrunner_deployment(config: dict):
    clear_screen()
    print_banner()
    print(f"\n{COLORS['GREEN']}Starting WEBRUNNER deployment...{COLORS['RESET']}")

    log_file = setup_logging(config['deployment_id'], "webrunner_deployment")

    node_chunks = config.pop('node_chunks')
    n_nodes = len(node_chunks)

    # Summary
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"  Deployment ID:  {config['deployment_id']}")
    print(f"  Name:           {config['webrunner_name']}")

    naming_info = show_naming_relationship(config['webrunner_name'], config['deployment_id'], 'webrunner')
    if naming_info:
        print(f"  └─ {naming_info['relationship_text']}")

    print(f"  Engagement:     {config['engagement']}")
    print(f"  Providers:      {', '.join(PROVIDER_LABELS[p] for p in config['providers'])}")
    print(f"  Nodes:          {n_nodes} ({config['preset']}, {fmt_ip_count(config['chunk_size'])}/node)")
    print(f"  Scan mode:      {config['scan_mode']}")
    print(f"  Ports:          {', '.join(str(p) for p in config['ports'][:8])}{'...' if len(config['ports']) > 8 else ''}")
    print(f"  masscan rate:   {config.get('masscan_rate', '—')} pkt/s")
    if config['scan_mode'] in ('masscan+nmap', 'geo-scout'):
        print(f"  nmap:           T{config.get('nmap_timing', 4)}  timeout={config.get('nmap_timeout', 60)}s  workers={config.get('nmap_workers', 10)}")
    if config['scan_mode'] == 'masscan+nuclei':
        tmpl_name = os.path.basename(config.get('nuclei_template_local', ''))
        print(f"  nuclei:         {tmpl_name}  rate={config.get('nuclei_rate', 150)}  concurrency={config.get('nuclei_concurrency', 25)}  timeout={config.get('nuclei_timeout', 10)}s")
    print(f"  Total IPs:      {fmt_ip_count(config['total_ips'])}")
    print(f"  Tor routing:    {'Yes' if config['use_tor'] else 'No'}")
    print(f"  Enhanced OPSEC: {'Yes' if config['enhanced_opsec'] else 'No'}")
    print(f"  Teardown after: {'Yes' if config['teardown_after_scan'] else 'No'}")

    if config.get('ssh_key_path'):
        key_name = os.path.basename(config['ssh_key_path']).replace('.pub', '')
        print(f"  SSH Key:        {key_name}")

    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with WEBRUNNER deployment?{COLORS['RESET']}", default=True):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return

    # Write node chunks file — absolute paths so Ansible lookup('file',...) works
    # regardless of playbook-relative CWD
    logs_dir = os.path.abspath(os.path.join(_base, 'logs'))
    os.makedirs(logs_dir, exist_ok=True)

    # Save CIDR→country map for merge_results per-country attribution
    cc_map_file = os.path.join(logs_dir, f"cidr_country_map_{config['deployment_id']}.json")
    if config.get('country_codes'):
        from utils.chunk_utils import get_country_cidrs
        cc_cidrs_saved = get_country_cidrs(config['country_codes'], {})
        with open(cc_map_file, 'w') as f:
            json.dump(cc_cidrs_saved, f)
        config['cidr_country_map_file'] = cc_map_file

    chunks_file = os.path.join(logs_dir, f"node_chunks_{config['deployment_id']}.json")
    with open(chunks_file, 'w') as f:
        json.dump(node_chunks, f)

    config['node_chunks_file'] = chunks_file
    config['scanner_ip_log'] = os.path.join(logs_dir, f"scanner_ips_{config['webrunner_name']}.txt")
    config['results_dir'] = os.path.join(logs_dir, f"webrunner_{config['deployment_id']}")

    for provider in config['providers']:
        set_provider_environment({**config, 'provider': provider})

    playbook = 'providers/webrunner.yml'

    print(f"\n{COLORS['CYAN']}[*] Launching WEBRUNNER — {n_nodes} nodes across "
          f"{', '.join(PROVIDER_LABELS[p] for p in config['providers'])}{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}    Provisioning may take several minutes per node.{COLORS['RESET']}\n")

    success = execute_playbook(playbook, config)

    if success:
        print(f"\n{COLORS['GREEN']}[+] WEBRUNNER complete.{COLORS['RESET']}")
        print(f"    Results:     logs/webrunner_{config['deployment_id']}/")
        print(f"    Scanner IPs: logs/scanner_ips_{config['webrunner_name']}.txt")
        print(f"    Log:         logs/deployment_{config['deployment_id']}.log")
    else:
        print(f"\n{COLORS['RED']}[-] WEBRUNNER failed. Check: logs/deployment_{config['deployment_id']}.log{COLORS['RESET']}")

    wait_for_input()
