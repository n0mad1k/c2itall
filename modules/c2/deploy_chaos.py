#!/usr/bin/env python3
"""
Chaos C2 — c2itall integration module
Deploy and manage the Chaos C2 framework (Havoc fork) locally or on a remote host.
"""

import os
import sys
import subprocess
import glob

# Add parent paths for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from utils.common import COLORS, clear_screen, print_banner, wait_for_input

# ─── Path Registry ────────────────────────────────────────────────────────────

CHAOS_PATH = os.path.expanduser('~/tools/chaos')
INSTALL_SH  = os.path.join(CHAOS_PATH, 'Install.sh')
TEAMSERVER  = os.path.join(CHAOS_PATH, 'teamserver')
DATA_DIR    = os.path.join(CHAOS_PATH, 'data')
LOGS_DIR    = os.path.join(DATA_DIR, 'logs')
WS_PATH_FILE = os.path.join(DATA_DIR, '.ws_path')
PROFILES_DIR = os.path.join(CHAOS_PATH, 'profiles')


# ─── SSH helpers ──────────────────────────────────────────────────────────────

def _build_ssh_cmd(host, ssh_user, ssh_port, ssh_key, command=None, interactive=False):
    """Build an SSH command list."""
    cmd = ['ssh']
    if ssh_key:
        cmd.extend(['-i', ssh_key])
    cmd.extend(['-p', str(ssh_port)])
    known_hosts = os.path.expanduser('~/.ssh/c2deploy_chaos_known_hosts')
    cmd.extend([
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', f'UserKnownHostsFile={known_hosts}',
        '-o', 'IdentitiesOnly=yes',
    ])
    if interactive:
        cmd.append('-t')
    cmd.append(f'{ssh_user}@{host}')
    if command:
        cmd.append(command)
    return cmd


def _build_scp_cmd(ssh_port, ssh_key=None):
    """Build base SCP command with consistent SSH options."""
    known_hosts = os.path.expanduser('~/.ssh/c2deploy_chaos_known_hosts')
    cmd = [
        'scp',
        '-P', str(ssh_port),
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', f'UserKnownHostsFile={known_hosts}',
    ]
    if ssh_key:
        cmd.extend(['-i', ssh_key])
    return cmd


# ─── Remote target prompt ─────────────────────────────────────────────────────

def _prompt_remote_target():
    """Prompt for host/user/port/key. Returns (host, user, port, key) or None on cancel."""
    print(f"\n{COLORS['CYAN']}Remote Target{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}============={COLORS['RESET']}")

    host = input(f"  Remote host (IP or hostname): ").strip()
    if not host:
        print(f"{COLORS['YELLOW']}No host provided{COLORS['RESET']}")
        return None, None, None, None

    ssh_user = input(f"  SSH user [{COLORS['CYAN']}root{COLORS['RESET']}]: ").strip() or 'root'
    ssh_port_raw = input(f"  SSH port [{COLORS['CYAN']}22{COLORS['RESET']}]: ").strip() or '22'
    try:
        ssh_port = int(ssh_port_raw)
    except ValueError:
        ssh_port = 22

    ssh_key = input(f"  SSH key path (blank for default): ").strip() or None
    return host, ssh_user, ssh_port, ssh_key


# ─── Profile selection ────────────────────────────────────────────────────────

def _select_profile(label="Select profile"):
    """List available profiles and let the user choose one. Returns path or None."""
    profiles = []
    if os.path.isdir(PROFILES_DIR):
        for ext in ('*.toml', '*.yaotl', '*.yaml', '*.yml'):
            profiles.extend(glob.glob(os.path.join(PROFILES_DIR, ext)))
        profiles.sort()

    if not profiles:
        print(f"  {COLORS['YELLOW']}No profiles found in {PROFILES_DIR}{COLORS['RESET']}")
        manual = input(f"  Enter profile path manually (blank to cancel): ").strip()
        return manual or None

    print(f"\n  {COLORS['CYAN']}{label}:{COLORS['RESET']}")
    for i, p in enumerate(profiles, 1):
        print(f"  {i}) {os.path.basename(p)}")

    raw = input(f"\n  Select [1]: ").strip() or '1'
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(profiles):
            return profiles[idx]
    except ValueError:
        pass

    print(f"  {COLORS['YELLOW']}Invalid selection — using first profile{COLORS['RESET']}")
    return profiles[0]


# ─── Local actions ────────────────────────────────────────────────────────────

def _deploy_local():
    """Run Install.sh locally after a pre-flight check."""
    if not os.path.exists(INSTALL_SH):
        print(f"\n{COLORS['RED']}Install.sh not found at {INSTALL_SH}{COLORS['RESET']}")
        print(f"{COLORS['YELLOW']}Clone the Chaos repo to ~/tools/chaos first{COLORS['RESET']}")
        wait_for_input()
        return

    print(f"\n{COLORS['CYAN']}Running pre-flight check (Install.sh --check)...{COLORS['RESET']}")
    check_result = subprocess.run(
        ['bash', INSTALL_SH, '--check'],
        cwd=CHAOS_PATH,
        capture_output=True,
        text=True,
    )
    if check_result.stdout:
        print(check_result.stdout)
    if check_result.stderr:
        print(check_result.stderr)

    if check_result.returncode != 0:
        print(f"{COLORS['YELLOW']}Pre-flight check reported issues (rc={check_result.returncode}) — continue anyway? (y/N): {COLORS['RESET']}", end='')
        if input().strip().lower() != 'y':
            wait_for_input()
            return

    print(f"\n{COLORS['CYAN']}Installing Chaos C2 locally...{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}Note: script may require sudo — you may be prompted for your password.{COLORS['RESET']}\n")
    try:
        subprocess.run(['bash', INSTALL_SH], cwd=CHAOS_PATH)
    except KeyboardInterrupt:
        print(f"\n{COLORS['YELLOW']}Installation interrupted{COLORS['RESET']}")
    wait_for_input()


def _deploy_remote():
    """SCP the chaos repo to a remote host and run Install.sh over SSH."""
    if not os.path.isdir(CHAOS_PATH):
        print(f"\n{COLORS['RED']}Chaos source not found at {CHAOS_PATH}{COLORS['RESET']}")
        wait_for_input()
        return

    host, ssh_user, ssh_port, ssh_key = _prompt_remote_target()
    if not host:
        wait_for_input()
        return

    remote_staging = '/tmp/chaos-deploy'

    print(f"\n{COLORS['CYAN']}Creating remote staging directory on {ssh_user}@{host}...{COLORS['RESET']}")
    mkdir_cmd = _build_ssh_cmd(host, ssh_user, ssh_port, ssh_key,
                                f'rm -rf {remote_staging} && mkdir -p {remote_staging}')
    result = subprocess.run(mkdir_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{COLORS['RED']}Failed to create remote staging dir: {result.stderr}{COLORS['RESET']}")
        wait_for_input()
        return

    print(f"{COLORS['CYAN']}Copying Chaos to {ssh_user}@{host}:{remote_staging}...{COLORS['RESET']}")
    scp_cmd = _build_scp_cmd(ssh_port, ssh_key)
    scp_cmd.extend(['-r', CHAOS_PATH + '/'])
    scp_cmd.append(f'{ssh_user}@{host}:{remote_staging}/')
    result = subprocess.run(scp_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{COLORS['RED']}SCP failed: {result.stderr}{COLORS['RESET']}")
        wait_for_input()
        return
    print(f"  {COLORS['GREEN']}Files copied{COLORS['RESET']}")

    print(f"\n{COLORS['CYAN']}Running Install.sh on {host}...{COLORS['RESET']}")
    install_cmd_str = f'cd {remote_staging} && bash Install.sh'
    ssh_install = _build_ssh_cmd(host, ssh_user, ssh_port, ssh_key,
                                  install_cmd_str, interactive=True)
    try:
        subprocess.run(ssh_install)
    except KeyboardInterrupt:
        print(f"\n{COLORS['YELLOW']}Remote install interrupted{COLORS['RESET']}")

    wait_for_input()


def _start_teamserver():
    """Start the Chaos teamserver with a selected profile."""
    if not os.path.exists(TEAMSERVER):
        print(f"\n{COLORS['RED']}teamserver binary not found at {TEAMSERVER}{COLORS['RESET']}")
        print(f"{COLORS['YELLOW']}Run 'Deploy Chaos (local)' first to build it{COLORS['RESET']}")
        wait_for_input()
        return

    profile = _select_profile("Select listener profile")
    if not profile:
        print(f"{COLORS['YELLOW']}No profile selected — aborting{COLORS['RESET']}")
        wait_for_input()
        return

    print(f"\n{COLORS['CYAN']}Starting Chaos teamserver with profile: {os.path.basename(profile)}{COLORS['RESET']}")
    print(f"{COLORS['GRAY']}Press Ctrl+C to stop{COLORS['RESET']}\n")
    try:
        subprocess.run([TEAMSERVER, '-p', profile], cwd=CHAOS_PATH)
    except KeyboardInterrupt:
        print(f"\n{COLORS['YELLOW']}Teamserver stopped by user{COLORS['RESET']}")
    wait_for_input()


def _stop_teamserver():
    """Find and kill the teamserver process."""
    print(f"\n{COLORS['CYAN']}Looking for running teamserver process...{COLORS['RESET']}")
    result = subprocess.run(
        ['pgrep', '-f', 'teamserver'],
        capture_output=True, text=True
    )
    pids = result.stdout.strip().splitlines()

    if not pids:
        print(f"{COLORS['YELLOW']}No teamserver process found{COLORS['RESET']}")
        wait_for_input()
        return

    print(f"  Found PID(s): {', '.join(pids)}")
    confirm = input(f"  {COLORS['YELLOW']}Kill these processes? (y/N): {COLORS['RESET']}").strip().lower()
    if confirm != 'y':
        print(f"{COLORS['GREEN']}Cancelled{COLORS['RESET']}")
        wait_for_input()
        return

    for pid in pids:
        kill_result = subprocess.run(['kill', pid], capture_output=True, text=True)
        if kill_result.returncode == 0:
            print(f"  {COLORS['GREEN']}Killed PID {pid}{COLORS['RESET']}")
        else:
            print(f"  {COLORS['RED']}Failed to kill PID {pid}: {kill_result.stderr.strip()}{COLORS['RESET']}")
    wait_for_input()


def _show_status():
    """Check if teamserver is running, show WS path and active profile."""
    print(f"\n{COLORS['CYAN']}Chaos C2 Status{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}==============={COLORS['RESET']}")

    # Check for running process
    result = subprocess.run(['pgrep', '-a', '-f', 'teamserver'], capture_output=True, text=True)
    if result.stdout.strip():
        print(f"  Teamserver: {COLORS['GREEN']}RUNNING{COLORS['RESET']}")
        for line in result.stdout.strip().splitlines():
            print(f"  {COLORS['GRAY']}{line}{COLORS['RESET']}")
    else:
        print(f"  Teamserver: {COLORS['RED']}NOT RUNNING{COLORS['RESET']}")

    # Show WS path
    if os.path.exists(WS_PATH_FILE):
        with open(WS_PATH_FILE) as f:
            ws_path = f.read().strip()
        print(f"  WS Path:    {COLORS['CYAN']}{ws_path}{COLORS['RESET']}")
    else:
        print(f"  WS Path:    {COLORS['GRAY']}(not set){COLORS['RESET']}")

    # Show install dir
    if os.path.isdir(CHAOS_PATH):
        print(f"  Install:    {COLORS['GREEN']}{CHAOS_PATH}{COLORS['RESET']}")
    else:
        print(f"  Install:    {COLORS['RED']}NOT FOUND — {CHAOS_PATH}{COLORS['RESET']}")

    # Show available profiles
    if os.path.isdir(PROFILES_DIR):
        profiles = []
        for ext in ('*.toml', '*.yaotl', '*.yaml', '*.yml'):
            profiles.extend(glob.glob(os.path.join(PROFILES_DIR, ext)))
        if profiles:
            print(f"  Profiles:")
            for p in sorted(profiles):
                print(f"    {COLORS['GRAY']}{os.path.basename(p)}{COLORS['RESET']}")
        else:
            print(f"  Profiles:   {COLORS['YELLOW']}none found in {PROFILES_DIR}{COLORS['RESET']}")

    wait_for_input()


def _generate_payload():
    """Interactive payload generation: listener profile, arch, format, output path."""
    if not os.path.exists(TEAMSERVER):
        print(f"\n{COLORS['RED']}teamserver not found — build Chaos first{COLORS['RESET']}")
        wait_for_input()
        return

    print(f"\n{COLORS['CYAN']}Payload Generation{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}=================={COLORS['RESET']}")

    profile = _select_profile("Select listener profile for payload")
    if not profile:
        print(f"{COLORS['YELLOW']}No profile selected — aborting{COLORS['RESET']}")
        wait_for_input()
        return

    print(f"\n  Architecture:")
    print(f"  1) x86_64 (64-bit)")
    print(f"  2) x86    (32-bit)")
    arch_choice = input(f"  Select [1]: ").strip() or '1'
    arch = 'x86_64' if arch_choice != '2' else 'x86'

    print(f"\n  Format:")
    print(f"  1) exe  (Windows executable)")
    print(f"  2) dll  (Windows DLL)")
    print(f"  3) bin  (raw shellcode)")
    fmt_choice = input(f"  Select [1]: ").strip() or '1'
    fmt_map = {'1': 'exe', '2': 'dll', '3': 'bin'}
    fmt = fmt_map.get(fmt_choice, 'exe')

    default_out = os.path.join(CHAOS_PATH, 'payloads', f'payload_{arch}.{fmt}')
    out_path = input(f"\n  Output path [{COLORS['CYAN']}{default_out}{COLORS['RESET']}]: ").strip() or default_out

    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    print(f"\n{COLORS['CYAN']}Generating payload...{COLORS['RESET']}")
    cmd = [TEAMSERVER, 'generate', '--profile', profile,
           '--arch', arch, '--format', fmt, '--output', out_path]
    try:
        result = subprocess.run(cmd, cwd=CHAOS_PATH, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        if result.returncode == 0:
            print(f"{COLORS['GREEN']}Payload written to: {out_path}{COLORS['RESET']}")
        else:
            print(f"{COLORS['RED']}Payload generation failed (rc={result.returncode}){COLORS['RESET']}")
            print(f"{COLORS['YELLOW']}Note: 'generate' subcommand may differ in your build — check teamserver --help{COLORS['RESET']}")
    except FileNotFoundError:
        print(f"{COLORS['RED']}teamserver binary not executable — did the build complete?{COLORS['RESET']}")
    wait_for_input()


def _view_loot():
    """Tail structured JSON logs from data/logs/."""
    if not os.path.isdir(LOGS_DIR):
        print(f"\n{COLORS['YELLOW']}Logs directory not found: {LOGS_DIR}{COLORS['RESET']}")
        print(f"{COLORS['GRAY']}Logs will appear here after the teamserver has been started{COLORS['RESET']}")
        wait_for_input()
        return

    log_files = sorted(glob.glob(os.path.join(LOGS_DIR, '*.json')) +
                       glob.glob(os.path.join(LOGS_DIR, '*.log')))

    if not log_files:
        print(f"\n{COLORS['YELLOW']}No log files found in {LOGS_DIR}{COLORS['RESET']}")
        wait_for_input()
        return

    print(f"\n{COLORS['CYAN']}Available log files:{COLORS['RESET']}")
    for i, lf in enumerate(log_files, 1):
        size = os.path.getsize(lf)
        print(f"  {i}) {os.path.basename(lf)} ({size} bytes)")

    raw = input(f"\n  Select log to tail [1]: ").strip() or '1'
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(log_files):
            chosen = log_files[idx]
        else:
            chosen = log_files[0]
    except ValueError:
        chosen = log_files[0]

    lines_raw = input(f"  Lines to show [{COLORS['CYAN']}50{COLORS['RESET']}]: ").strip() or '50'
    try:
        lines = int(lines_raw)
    except ValueError:
        lines = 50

    print(f"\n{COLORS['CYAN']}--- {os.path.basename(chosen)} (last {lines} lines) ---{COLORS['RESET']}\n")
    try:
        result = subprocess.run(['tail', '-n', str(lines), chosen],
                                capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"{COLORS['RED']}Error reading log: {e}{COLORS['RESET']}")
    wait_for_input()


# ─── Main menu ────────────────────────────────────────────────────────────────

def chaos_menu():
    """Main entry point — called from c2itall deploy.py tools_menu()."""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}CHAOS C2{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}========{COLORS['RESET']}")
        print(f"  Havoc-based C2 framework")

        # Show whether source is available
        if os.path.isdir(CHAOS_PATH):
            ts_label = (f"{COLORS['GREEN']}built{COLORS['RESET']}"
                        if os.path.exists(TEAMSERVER)
                        else f"{COLORS['YELLOW']}not built{COLORS['RESET']}")
            print(f"  Source: {COLORS['GREEN']}{CHAOS_PATH}{COLORS['RESET']} (teamserver: {ts_label})")
        else:
            print(f"  Source: {COLORS['RED']}NOT FOUND — {CHAOS_PATH}{COLORS['RESET']}")
        print()

        print(f"1) Deploy Chaos {COLORS['CYAN']}(local — runs Install.sh){COLORS['RESET']}")
        print(f"2) Deploy Chaos {COLORS['CYAN']}(remote SSH — SCP + install){COLORS['RESET']}")
        print(f"3) Start Teamserver")
        print(f"4) Stop Teamserver")
        print(f"5) Show Status")
        print(f"6) Generate Payload")
        print(f"7) View Loot {COLORS['GRAY']}(tail data/logs/){COLORS['RESET']}")
        print(f"99) Return to Tools Menu")

        choice = input(f"\nSelect an option: ").strip()

        if choice == '1':
            _deploy_local()
        elif choice == '2':
            _deploy_remote()
        elif choice == '3':
            _start_teamserver()
        elif choice == '4':
            _stop_teamserver()
        elif choice == '5':
            _show_status()
        elif choice == '6':
            _generate_payload()
        elif choice == '7':
            _view_loot()
        elif choice == '99':
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()
