#!/usr/bin/env python3
"""
Recon & Red Team Tools — c2itall integration module
Provides local launch + remote deployment for Umbra suite and custom Red Team tools.
"""

import os
import sys
import subprocess
import glob
from datetime import datetime

# Add parent paths for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from utils.common import COLORS, clear_screen, print_banner, wait_for_input

# ─── Tool Path Registry ─────────────────────────────────────────────────────
C2ITALL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
UMBRA_PATH = os.path.join(C2ITALL_ROOT, "tools", "umbra")
REDTEAM_PATH = os.path.join(C2ITALL_ROOT, "tools", "redteam")

TOOLS = {
    # Umbra tools
    "umbra-launcher": {
        "path": os.path.join(UMBRA_PATH, "umbra.py"),
        "type": "python",
        "desc": "Unified Umbra Launcher",
        "deps": ["rich", "click", "aiohttp", "aiohttp-socks", "pillow", "beautifulsoup4"],
    },
    "um-scan": {
        "path": os.path.join(UMBRA_PATH, "um-scan.py"),
        "type": "python",
        "desc": "TCP Port Scanner",
        "deps": ["rich", "click", "aiohttp"],
    },
    "um-api": {
        "path": os.path.join(UMBRA_PATH, "um-api.py"),
        "type": "python",
        "desc": "API Endpoint Discovery",
        "deps": ["rich", "click", "aiohttp", "aiohttp-socks", "beautifulsoup4"],
    },
    "um-intel": {
        "path": os.path.join(UMBRA_PATH, "um-intel.py"),
        "type": "python",
        "desc": "Passive OSINT Aggregator",
        "deps": ["rich", "click", "aiohttp", "aiohttp-socks"],
    },
    "um-enum": {
        "path": os.path.join(UMBRA_PATH, "um-enum.py"),
        "type": "python",
        "desc": "Predictive URL Enumeration",
        "deps": ["rich", "click", "aiohttp", "aiohttp-socks", "beautifulsoup4"],
    },
    "um-fuzz": {
        "path": os.path.join(UMBRA_PATH, "um-fuzz.py"),
        "type": "python",
        "desc": "Web Path Discovery",
        "deps": ["rich", "click", "aiohttp", "aiohttp-socks"],
    },
    "um-hash": {
        "path": os.path.join(UMBRA_PATH, "um-hash.py"),
        "type": "python",
        "desc": "Gravatar Hash Extraction",
        "deps": ["rich", "click", "aiohttp", "aiohttp-socks", "beautifulsoup4"],
    },
    "um-wp": {
        "path": os.path.join(UMBRA_PATH, "um-wp.py"),
        "type": "python",
        "desc": "WordPress Detection",
        "deps": ["rich", "click", "aiohttp", "aiohttp-socks"],
    },
    "um-crack": {
        "path": os.path.join(UMBRA_PATH, "um-crack.py"),
        "type": "python",
        "desc": "Hash Cracker",
        "deps": ["rich", "click"],
    },
    "um-exif": {
        "path": os.path.join(UMBRA_PATH, "um-exif.py"),
        "type": "python",
        "desc": "EXIF Metadata Extraction",
        "deps": ["rich", "click", "aiohttp", "aiohttp-socks", "pillow"],
    },
    "um-vault": {
        "path": os.path.join(UMBRA_PATH, "um-vault.py"),
        "type": "python",
        "desc": "Master Database Aggregator",
        "deps": ["rich", "click"],
    },
    # Red Team tools
    "trashpanda": {
        "path": os.path.join(REDTEAM_PATH, "trashpanda", "trashpanda.py"),
        "type": "python",
        "desc": "Network Enumeration",
        "deps": [],
    },
    "ioc-u": {
        "path": os.path.join(REDTEAM_PATH, "ioc-u", "ioc-u.py"),
        "type": "python",
        "desc": "Blue Team Detection & Intel",
        "deps": ["scapy", "numpy", "scikit-learn"],
    },
    "lions-share": {
        "path": os.path.join(REDTEAM_PATH, "lions-share", "lions-share.py"),
        "type": "python",
        "desc": "SSHFS Mount & Backup",
        "deps": ["click", "python-crontab"],
        "sys_deps": ["sshfs", "rsync"],
    },
    "micro-scope": {
        "path": os.path.join(REDTEAM_PATH, "micro-scope", "micro-scope.py"),
        "type": "python",
        "desc": "Scope Verification",
        "deps": [],
    },
    "linkedout": {
        "path": os.path.join(REDTEAM_PATH, "linkedout", "linkedout.py"),
        "type": "python",
        "desc": "LinkedIn OSINT",
        "deps": ["selenium", "webdriver-manager", "beautifulsoup4"],
    },
    "ops-logger": {
        "path": os.path.join(REDTEAM_PATH, "ops-logger.sh"),
        "type": "bash",
        "desc": "Terminal Session Logging",
        "deps": [],
    },
    "freebird": {
        "path": os.path.join(REDTEAM_PATH, "freebird", "main.py"),
        "type": "python",
        "desc": "MITRE ATT&CK Framework",
        "deps": ["InquirerPy", "requests", "click"],
    },
    "regex-search": {
        "path": os.path.join(REDTEAM_PATH, "regex-search", "regex-search-tool.py"),
        "type": "python",
        "desc": "Sensitive Data Search",
        "deps": [],
    },
    "certipy-enum": {
        "path": os.path.join(REDTEAM_PATH, "certipy-enum.py"),
        "type": "python",
        "desc": "ADCS Enumeration",
        "deps": [],
    },
    "ping-sweep": {
        "path": os.path.join(REDTEAM_PATH, "ping-sweep.py"),
        "type": "python",
        "desc": "Network Discovery",
        "deps": [],
        "sys_deps": ["nmap"],
    },
    # Forensics / sandbox tools
    "ir-sandbox": {
        "path": os.path.expanduser("~/tools/ir-sandbox/ir-sandbox.py"),
        "type": "python",
        "desc": "Malware Analysis & IR Platform",
        "deps": [],
    },
    "link-sandbox": {
        "path": os.path.expanduser("~/tools/link-sandbox/analyze.py"),
        "type": "python",
        "desc": "Secure URL Analysis",
        "deps": [],
    },
    # Ops tools
    "ops-dashboard": {
        "path": os.path.join(C2ITALL_ROOT, "ops_dashboard.py"),
        "type": "python",
        "desc": "Real-Time Engagement Monitor",
        "deps": ["rich"],
    },
    "ops-bridge": {
        "path": os.path.join(C2ITALL_ROOT, "ops_bridge.py"),
        "type": "python",
        "desc": "Remote State Sync (rsync)",
        "deps": [],
        "sys_deps": ["rsync"],
    },
    "heartbeat-ingest": {
        "path": os.path.join(C2ITALL_ROOT, "heartbeat", "heartbeat_ingest.py"),
        "type": "python",
        "desc": "Heartbeat Receiver Server",
        "deps": [],
    },
}

# Tool groups for menu organization
UMBRA_TOOLS = [
    "umbra-launcher", "um-scan", "um-api", "um-intel", "um-enum",
    "um-fuzz", "um-hash", "um-wp", "um-crack", "um-exif", "um-vault",
]
REDTEAM_TOOLS = [
    "trashpanda", "ioc-u", "lions-share", "micro-scope", "linkedout",
    "ops-logger", "freebird", "regex-search", "certipy-enum", "ping-sweep",
]
OPS_TOOLS = ["ops-dashboard", "ops-bridge", "heartbeat-ingest"]

# Deployment tracking file
DEPLOY_LOG = os.path.expanduser("~/.c2itall_tool_deployments.log")


# ─── Utility Functions ──────────────────────────────────────────────────────

def check_tool_status(tool_name):
    """Check if a tool exists locally."""
    info = TOOLS.get(tool_name)
    if not info:
        return False
    return os.path.exists(info["path"])


def launch_local_tool(tool_name):
    """Launch a tool locally."""
    info = TOOLS.get(tool_name)
    if not info:
        print(f"{COLORS['RED']}Unknown tool: {tool_name}{COLORS['RESET']}")
        return

    if not os.path.exists(info["path"]):
        print(f"{COLORS['RED']}Tool not found: {info['path']}{COLORS['RESET']}")
        wait_for_input()
        return

    tool_dir = os.path.dirname(info["path"])

    if info["type"] == "python":
        cmd = [sys.executable, info["path"]]
    elif info["type"] == "bash":
        cmd = ["bash", info["path"]]
    else:
        print(f"{COLORS['RED']}Unknown tool type: {info['type']}{COLORS['RESET']}")
        return

    print(f"\n{COLORS['CYAN']}Launching {tool_name}...{COLORS['RESET']}\n")
    try:
        subprocess.run(cmd, cwd=tool_dir)
    except KeyboardInterrupt:
        print(f"\n{COLORS['YELLOW']}Tool interrupted{COLORS['RESET']}")
    except Exception as e:
        print(f"{COLORS['RED']}Error launching {tool_name}: {e}{COLORS['RESET']}")
        wait_for_input()


def log_deployment(host, tools_deployed, ssh_user, ssh_key):
    """Log a tool deployment for future SSH & Run."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(DEPLOY_LOG, "a") as f:
        tools_str = ",".join(tools_deployed)
        f.write(f"{ts}|{host}|{ssh_user}|{ssh_key}|{tools_str}\n")


def get_deployments():
    """Read deployment log and return list of deployments."""
    if not os.path.exists(DEPLOY_LOG):
        return []
    deployments = []
    with open(DEPLOY_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) >= 5:
                deployments.append({
                    "timestamp": parts[0],
                    "host": parts[1],
                    "ssh_user": parts[2],
                    "ssh_key": parts[3],
                    "tools": parts[4].split(","),
                })
    return deployments


def get_active_attack_boxes():
    """Get active attack box deployments from c2itall logs."""
    hosts = []
    log_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'logs')
    info_files = glob.glob(os.path.join(log_dir, "deployment_info_*.txt"))

    for info_file in info_files:
        try:
            with open(info_file) as f:
                content = f.read()
            # Extract IP and SSH info
            ip = None
            ssh_user = None
            ssh_key = None
            for line in content.splitlines():
                line = line.strip()
                if "IP:" in line or "attack_box_ip:" in line:
                    ip = line.split(":")[-1].strip().strip('"')
                elif "SSH User:" in line:
                    ssh_user = line.split(":")[-1].strip()
                elif "SSH Key:" in line:
                    ssh_key = line.split(":")[-1].strip()
            if ip:
                hosts.append({
                    "ip": ip,
                    "ssh_user": ssh_user or "root",
                    "ssh_key": ssh_key,
                    "source": os.path.basename(info_file),
                })
        except Exception:
            pass
    return hosts


# ─── Deployment Functions ───────────────────────────────────────────────────

def select_target_host():
    """Select a target host from active deployments or manual entry."""
    print(f"\n{COLORS['CYAN']}Select target machine:{COLORS['RESET']}")

    # Check c2itall active deployments
    attack_boxes = get_active_attack_boxes()
    if attack_boxes:
        print(f"\n  {COLORS['GREEN']}Active c2itall deployments:{COLORS['RESET']}")
        for i, box in enumerate(attack_boxes, 1):
            print(f"    {i}) {box['ip']} ({box['ssh_user']}@) — {box['source']}")
        print(f"    {len(attack_boxes) + 1}) Manual entry")

        choice = input(f"\n  Select: ").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(attack_boxes):
                box = attack_boxes[idx]
                return box["ip"], box["ssh_user"], box.get("ssh_key")
        except ValueError:
            pass
    else:
        print(f"  {COLORS['YELLOW']}No active c2itall deployments found{COLORS['RESET']}")

    # Manual entry
    host = input(f"\n  Enter target (user@host or host): ").strip()
    if not host:
        return None, None, None

    if "@" in host:
        ssh_user, host = host.split("@", 1)
    else:
        ssh_user = input(f"  SSH user [{COLORS['CYAN']}root{COLORS['RESET']}]: ").strip() or "root"

    ssh_key = input(f"  SSH key path (blank for default): ").strip() or None
    return host, ssh_user, ssh_key


def _build_ssh_cmd(host, ssh_user, ssh_key, command=None, interactive=False):
    """Build an SSH command list."""
    cmd = ["ssh"]
    if ssh_key:
        cmd.extend(["-i", ssh_key])
    # Use accept-new: trust on first connect, reject if key changes
    known_hosts = os.path.expanduser(f"~/.ssh/c2deploy_recon_known_hosts")
    cmd.extend([
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "IdentitiesOnly=yes",
    ])
    if interactive:
        cmd.append("-t")
    cmd.append(f"{ssh_user}@{host}")
    if command:
        cmd.append(command)
    return cmd


def _build_scp_cmd(ssh_key=None):
    """Build base SCP command with consistent SSH options."""
    known_hosts = os.path.expanduser(f"~/.ssh/c2deploy_recon_known_hosts")
    cmd = ["scp", "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={known_hosts}"]
    if ssh_key:
        cmd.extend(["-i", ssh_key])
    return cmd


def deploy_umbra_remote(host, ssh_user, ssh_key):
    """Deploy Umbra suite to remote machine."""
    print(f"\n{COLORS['CYAN']}Deploying Umbra to {ssh_user}@{host}...{COLORS['RESET']}")

    # Create remote directory
    ssh_cmd = _build_ssh_cmd(host, ssh_user, ssh_key, "mkdir -p /opt/umbra")
    result = subprocess.run(ssh_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{COLORS['RED']}Failed to create remote directory: {result.stderr}{COLORS['RESET']}")
        return False

    # SCP Umbra files
    scp_cmd = _build_scp_cmd(ssh_key)

    # Copy all Python files and wordlists
    py_files = glob.glob(os.path.join(UMBRA_PATH, "*.py"))
    if not py_files:
        print(f"{COLORS['RED']}No Umbra Python files found at {UMBRA_PATH}{COLORS['RESET']}")
        return False

    scp_cmd.extend(py_files)
    scp_cmd.append(f"{ssh_user}@{host}:/opt/umbra/")

    print(f"  Copying {len(py_files)} Python files...")
    result = subprocess.run(scp_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{COLORS['RED']}SCP failed: {result.stderr}{COLORS['RESET']}")
        return False

    # Copy wordlists if they exist
    wordlist_dir = os.path.join(UMBRA_PATH, "wordlists")
    if os.path.isdir(wordlist_dir):
        ssh_cmd = _build_ssh_cmd(host, ssh_user, ssh_key, "mkdir -p /opt/umbra/wordlists")
        subprocess.run(ssh_cmd, capture_output=True)

        scp_wl = _build_scp_cmd(ssh_key)
        scp_wl.extend(["-r", wordlist_dir + "/"])
        scp_wl.append(f"{ssh_user}@{host}:/opt/umbra/wordlists/")
        print(f"  Copying wordlists...")
        subprocess.run(scp_wl, capture_output=True)

    # Install pip dependencies
    all_deps = set()
    for tool in UMBRA_TOOLS:
        info = TOOLS.get(tool, {})
        all_deps.update(info.get("deps", []))

    if all_deps:
        deps_str = " ".join(sorted(all_deps))
        print(f"  Installing dependencies: {deps_str}")
        install_cmd = _build_ssh_cmd(host, ssh_user, ssh_key,
                                      f"pip3 install {deps_str} 2>/dev/null || pip install {deps_str}")
        result = subprocess.run(install_cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            print(f"{COLORS['YELLOW']}Warning: Some deps may have failed: {result.stderr[:200]}{COLORS['RESET']}")

    # Verify
    print(f"  Verifying installation...")
    verify_cmd = _build_ssh_cmd(host, ssh_user, ssh_key,
                                 "python3 -m py_compile /opt/umbra/um_tui.py && echo 'VERIFY_OK'")
    result = subprocess.run(verify_cmd, capture_output=True, text=True)
    if "VERIFY_OK" in result.stdout:
        print(f"{COLORS['GREEN']}Umbra deployed successfully to {host}:/opt/umbra/{COLORS['RESET']}")
        log_deployment(host, UMBRA_TOOLS, ssh_user, ssh_key or "default")
        return True
    else:
        print(f"{COLORS['RED']}Verification failed{COLORS['RESET']}")
        return False


def deploy_redteam_remote(host, ssh_user, ssh_key):
    """Deploy Red Team tools to remote machine."""
    print(f"\n{COLORS['CYAN']}Deploying Red Team tools to {ssh_user}@{host}...{COLORS['RESET']}")

    # Create remote directories
    ssh_cmd = _build_ssh_cmd(host, ssh_user, ssh_key,
                              "mkdir -p /opt/redteam/{trashpanda,ioc-u,lions-share,micro-scope,linkedout,freebird,regex-search}")
    subprocess.run(ssh_cmd, capture_output=True)

    deployed = []
    for tool_name in REDTEAM_TOOLS:
        info = TOOLS.get(tool_name)
        if not info:
            continue

        src_path = info["path"]
        if not os.path.exists(src_path):
            print(f"  {COLORS['YELLOW']}Skipping {tool_name}: not found locally{COLORS['RESET']}")
            continue

        # Determine remote path
        remote_dir = f"/opt/redteam/{tool_name}"
        src_dir = os.path.dirname(src_path)

        scp_cmd = _build_scp_cmd(ssh_key)

        # If it's a single file, just copy the file
        if os.path.isfile(src_path) and src_dir == os.path.dirname(src_path):
            ssh_mkdir = _build_ssh_cmd(host, ssh_user, ssh_key, f"mkdir -p {remote_dir}")
            subprocess.run(ssh_mkdir, capture_output=True)
            scp_cmd.extend([src_path, f"{ssh_user}@{host}:{remote_dir}/"])
        else:
            scp_cmd.extend(["-r", src_dir + "/"])
            scp_cmd.append(f"{ssh_user}@{host}:{remote_dir}/")

        result = subprocess.run(scp_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  {COLORS['GREEN']}Deployed: {tool_name}{COLORS['RESET']}")
            deployed.append(tool_name)
        else:
            print(f"  {COLORS['RED']}Failed: {tool_name} — {result.stderr[:100]}{COLORS['RESET']}")

    # Install deps for deployed tools
    all_deps = set()
    for tool_name in deployed:
        info = TOOLS.get(tool_name, {})
        all_deps.update(info.get("deps", []))

    if all_deps:
        deps_str = " ".join(sorted(all_deps))
        print(f"\n  Installing dependencies: {deps_str}")
        install_cmd = _build_ssh_cmd(host, ssh_user, ssh_key,
                                      f"pip3 install {deps_str} 2>/dev/null || pip install {deps_str}")
        subprocess.run(install_cmd, capture_output=True, text=True, timeout=120)

    if deployed:
        print(f"\n{COLORS['GREEN']}Deployed {len(deployed)} Red Team tools to {host}{COLORS['RESET']}")
        log_deployment(host, deployed, ssh_user, ssh_key or "default")
    return len(deployed) > 0


def ssh_run_tool(host, ssh_user, ssh_key, tool_path, interactive=True):
    """SSH into a remote machine and run a tool."""
    if interactive:
        cmd = _build_ssh_cmd(host, ssh_user, ssh_key, f"cd {os.path.dirname(tool_path)} && python3 {tool_path}",
                              interactive=True)
    else:
        cmd = _build_ssh_cmd(host, ssh_user, ssh_key, f"python3 {tool_path}")

    print(f"\n{COLORS['CYAN']}Connecting to {ssh_user}@{host}...{COLORS['RESET']}")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n{COLORS['YELLOW']}Session ended{COLORS['RESET']}")


def check_remote_tools(host, ssh_user, ssh_key):
    """Check which tools are installed on a remote machine."""
    print(f"\n{COLORS['CYAN']}Checking tools on {ssh_user}@{host}...{COLORS['RESET']}\n")

    # Check Umbra
    check_cmd = _build_ssh_cmd(host, ssh_user, ssh_key,
                                "ls /opt/umbra/*.py 2>/dev/null && echo '---DIVIDER---' && ls /opt/redteam/*/  2>/dev/null")
    result = subprocess.run(check_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"{COLORS['YELLOW']}Could not connect or no tools found{COLORS['RESET']}")
        return

    output = result.stdout
    if "---DIVIDER---" in output:
        umbra_part, redteam_part = output.split("---DIVIDER---", 1)
    else:
        umbra_part = output
        redteam_part = ""

    print(f"  {COLORS['WHITE']}Umbra Suite:{COLORS['RESET']}")
    if umbra_part.strip():
        for line in umbra_part.strip().splitlines():
            fname = os.path.basename(line.strip())
            print(f"    {COLORS['GREEN']}FOUND{COLORS['RESET']}  {fname}")
    else:
        print(f"    {COLORS['RED']}Not installed{COLORS['RESET']}")

    print(f"\n  {COLORS['WHITE']}Red Team Tools:{COLORS['RESET']}")
    if redteam_part.strip():
        for line in redteam_part.strip().splitlines():
            print(f"    {COLORS['GREEN']}FOUND{COLORS['RESET']}  {line.strip()}")
    else:
        print(f"    {COLORS['RED']}Not installed{COLORS['RESET']}")


# ─── Menu Functions ─────────────────────────────────────────────────────────

def umbra_submenu():
    """Submenu for Umbra Reconnaissance Suite."""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}UMBRA RECONNAISSANCE SUITE{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}=========================={COLORS['RESET']}")
        print(f"1)  um-scan   — TCP Port Scanner")
        print(f"2)  um-api    — API Endpoint Discovery")
        print(f"3)  um-intel  — OSINT Aggregator")
        print(f"4)  um-enum   — URL Enumeration")
        print(f"5)  um-fuzz   — Directory Fuzzer")
        print(f"6)  um-hash   — Hash Extraction")
        print(f"7)  um-wp     — WordPress Scanner")
        print(f"8)  um-crack  — Password Cracker")
        print(f"9)  um-exif   — EXIF Metadata")
        print(f"10) um-vault  — Database Manager")
        print(f"99) Back")

        choice = input(f"\nSelect: ").strip()

        tool_map = {
            "1": "um-scan", "2": "um-api", "3": "um-intel",
            "4": "um-enum", "5": "um-fuzz", "6": "um-hash",
            "7": "um-wp", "8": "um-crack", "9": "um-exif",
            "10": "um-vault",
        }

        if choice == "99":
            return
        elif choice in tool_map:
            launch_local_tool(tool_map[choice])
            wait_for_input()
        else:
            print(f"\n{COLORS['RED']}Invalid option{COLORS['RESET']}")
            wait_for_input()


def redteam_submenu():
    """Submenu for Red Team Operations Tools."""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}RED TEAM OPERATIONS TOOLS{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}========================={COLORS['RESET']}")
        print(f"1)  TrashPanda      — Network Enumeration")
        print(f"2)  IOC-U           — Blue Team Detection & Intel")
        print(f"3)  Lions-Share     — SSHFS Mount & Backup")
        print(f"4)  micro-scope     — Scope Verification")
        print(f"5)  linkedout       — LinkedIn OSINT")
        print(f"6)  ops-logger      — Terminal Session Logging")
        print(f"7)  freebird        — MITRE ATT&CK Framework")
        print(f"8)  regex-search    — Sensitive Data Search")
        print(f"9)  certipy-enum    — ADCS Enumeration")
        print(f"10) ping-sweep      — Network Discovery")
        print(f"99) Back")

        choice = input(f"\nSelect: ").strip()

        tool_map = {
            "1": "trashpanda", "2": "ioc-u", "3": "lions-share",
            "4": "micro-scope", "5": "linkedout", "6": "ops-logger",
            "7": "freebird", "8": "regex-search", "9": "certipy-enum",
            "10": "ping-sweep",
        }

        if choice == "99":
            return
        elif choice in tool_map:
            launch_local_tool(tool_map[choice])
            wait_for_input()
        else:
            print(f"\n{COLORS['RED']}Invalid option{COLORS['RESET']}")
            wait_for_input()


def remote_submenu():
    """Submenu for Remote Deployment."""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}REMOTE DEPLOYMENT{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}================={COLORS['RESET']}")
        print(f"1) Deploy Umbra Suite to Remote Machine")
        print(f"2) Deploy Red Team Tools to Remote Machine")
        print(f"3) Deploy All Tools to Remote Machine")
        print(f"4) SSH into Remote & Run Umbra")
        print(f"5) SSH into Remote & Run Tool")
        print(f"6) Check Remote Tool Status")
        print(f"99) Back")

        choice = input(f"\nSelect: ").strip()

        if choice == "99":
            return

        elif choice == "1":
            host, ssh_user, ssh_key = select_target_host()
            if host:
                deploy_umbra_remote(host, ssh_user, ssh_key)
            wait_for_input()

        elif choice == "2":
            host, ssh_user, ssh_key = select_target_host()
            if host:
                deploy_redteam_remote(host, ssh_user, ssh_key)
            wait_for_input()

        elif choice == "3":
            host, ssh_user, ssh_key = select_target_host()
            if host:
                deploy_umbra_remote(host, ssh_user, ssh_key)
                deploy_redteam_remote(host, ssh_user, ssh_key)
            wait_for_input()

        elif choice == "4":
            # SSH into remote and run Umbra launcher
            deployments = get_deployments()
            if not deployments:
                host, ssh_user, ssh_key = select_target_host()
            else:
                print(f"\n{COLORS['CYAN']}Known deployments:{COLORS['RESET']}")
                for i, d in enumerate(deployments, 1):
                    print(f"  {i}) {d['host']} ({d['ssh_user']}@) — deployed {d['timestamp']}")
                print(f"  {len(deployments) + 1}) Other host")

                sel = input(f"\n  Select: ").strip()
                try:
                    idx = int(sel) - 1
                    if 0 <= idx < len(deployments):
                        d = deployments[idx]
                        host = d["host"]
                        ssh_user = d["ssh_user"]
                        ssh_key = d["ssh_key"] if d["ssh_key"] != "default" else None
                    else:
                        host, ssh_user, ssh_key = select_target_host()
                except ValueError:
                    host, ssh_user, ssh_key = select_target_host()

            if host:
                ssh_run_tool(host, ssh_user, ssh_key, "/opt/umbra/umbra.py")
            wait_for_input()

        elif choice == "5":
            # SSH into remote and run a specific tool
            host, ssh_user, ssh_key = select_target_host()
            if not host:
                wait_for_input()
                continue

            print(f"\n{COLORS['CYAN']}Select tool to run:{COLORS['RESET']}")
            all_tools = list(TOOLS.keys())
            for i, name in enumerate(all_tools, 1):
                info = TOOLS[name]
                status = f"{COLORS['GREEN']}LOCAL{COLORS['RESET']}" if os.path.exists(info["path"]) else f"{COLORS['RED']}MISSING{COLORS['RESET']}"
                print(f"  {i:2d}) {name:16s} — {info['desc']}  [{status}]")

            sel = input(f"\n  Select tool #: ").strip()
            try:
                idx = int(sel) - 1
                if 0 <= idx < len(all_tools):
                    tool_name = all_tools[idx]
                    info = TOOLS[tool_name]
                    # Determine remote path
                    if tool_name in UMBRA_TOOLS:
                        remote_path = f"/opt/umbra/{os.path.basename(info['path'])}"
                    else:
                        remote_path = f"/opt/redteam/{tool_name}/{os.path.basename(info['path'])}"
                    ssh_run_tool(host, ssh_user, ssh_key, remote_path)
            except (ValueError, IndexError):
                print(f"{COLORS['RED']}Invalid selection{COLORS['RESET']}")
            wait_for_input()

        elif choice == "6":
            host, ssh_user, ssh_key = select_target_host()
            if host:
                check_remote_tools(host, ssh_user, ssh_key)
            wait_for_input()

        else:
            print(f"\n{COLORS['RED']}Invalid option{COLORS['RESET']}")
            wait_for_input()


def ops_submenu():
    """Submenu for Ops Dashboard & Engagement Management."""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}OPS & ENGAGEMENT MANAGEMENT{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}============================{COLORS['RESET']}")
        print(f"1)  Ops Dashboard      — Real-Time Engagement Monitor")
        print(f"2)  Ops Bridge         — Sync State from Remote Hosts")
        print(f"3)  Heartbeat Ingest   — Receive Host Check-Ins")
        print(f"4)  Umbra tmux         — Launch tmux Workspace")
        print(f"99) Back")

        choice = input(f"\nSelect: ").strip()

        if choice == "99":
            return
        elif choice == "1":
            launch_local_tool("ops-dashboard")
            wait_for_input()
        elif choice == "2":
            launch_local_tool("ops-bridge")
            wait_for_input()
        elif choice == "3":
            launch_local_tool("heartbeat-ingest")
            wait_for_input()
        elif choice == "4":
            _launch_umbra_tmux()
            wait_for_input()
        else:
            print(f"\n{COLORS['RED']}Invalid option{COLORS['RESET']}")
            wait_for_input()


def _launch_umbra_tmux():
    """Prompt for engagement and launch Umbra in tmux mode."""
    engagement = input(f"\n  Engagement name: ").strip()
    if not engagement:
        print(f"{COLORS['YELLOW']}No engagement specified.{COLORS['RESET']}")
        return
    umbra_script = os.path.join(UMBRA_PATH, "umbra.py")
    if not os.path.exists(umbra_script):
        print(f"{COLORS['RED']}Umbra launcher not found at {umbra_script}{COLORS['RESET']}")
        return
    try:
        subprocess.run([sys.executable, umbra_script, "-E", engagement, "--tmux", "--dashboard"])
    except KeyboardInterrupt:
        pass


def _forensics_submenu():
    """Submenu for Forensics & Malware Analysis tools."""
    # Delegate to the forensics module for full functionality
    forensics_module_path = os.path.join(
        os.path.dirname(__file__), '..', 'forensics', 'deploy_forensics.py'
    )
    if os.path.exists(forensics_module_path):
        import importlib.util
        spec = importlib.util.spec_from_file_location('deploy_forensics', forensics_module_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.forensics_menu()
    else:
        # Fallback: launch tools directly
        while True:
            clear_screen()
            print_banner()
            print(f"{COLORS['WHITE']}FORENSICS & MALWARE ANALYSIS{COLORS['RESET']}")
            print(f"{COLORS['WHITE']}============================={COLORS['RESET']}")
            print(f"1) IR-Sandbox (Interactive Menu)")
            print(f"2) Link-Sandbox (URL Analysis)")
            print(f"99) Back")

            choice = input(f"\nSelect: ").strip()
            if choice == "99":
                return
            elif choice == "1":
                launch_local_tool("ir-sandbox")
                wait_for_input()
            elif choice == "2":
                launch_local_tool("link-sandbox")
                wait_for_input()
            else:
                print(f"\n{COLORS['RED']}Invalid option{COLORS['RESET']}")
                wait_for_input()


def recon_tools_menu():
    """Main entry point — called from c2itall deploy.py tools_menu()."""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}RECON & RED TEAM TOOLS{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}======================{COLORS['RESET']}")

        # Show local tool status summary
        umbra_found = sum(1 for t in UMBRA_TOOLS if check_tool_status(t))
        redteam_found = sum(1 for t in REDTEAM_TOOLS if check_tool_status(t))
        ops_found = sum(1 for t in OPS_TOOLS if check_tool_status(t))
        print(f"  Local: Umbra {COLORS['GREEN']}{umbra_found}/{len(UMBRA_TOOLS)}{COLORS['RESET']} | "
              f"Red Team {COLORS['GREEN']}{redteam_found}/{len(REDTEAM_TOOLS)}{COLORS['RESET']} | "
              f"Ops {COLORS['CYAN']}{ops_found}/{len(OPS_TOOLS)}{COLORS['RESET']}")
        print()

        print(f"1) Umbra Reconnaissance Suite {COLORS['GREEN']}({umbra_found} tools){COLORS['RESET']}")
        print(f"2) Red Team Operations Tools {COLORS['GREEN']}({redteam_found} tools){COLORS['RESET']}")
        print(f"3) Remote Deployment & SSH")
        print(f"4) Ops & Engagement Management {COLORS['CYAN']}(Dashboard, Bridge, Heartbeat){COLORS['RESET']}")
        print(f"5) Forensics & Sandbox {COLORS['YELLOW']}(IR-Sandbox, Link-Sandbox){COLORS['RESET']}")
        print(f"99) Return to Tools Menu")

        choice = input(f"\nSelect: ").strip()

        if choice == "1":
            umbra_submenu()
        elif choice == "2":
            redteam_submenu()
        elif choice == "3":
            remote_submenu()
        elif choice == "4":
            ops_submenu()
        elif choice == "5":
            _forensics_submenu()
        elif choice == "99":
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option{COLORS['RESET']}")
            wait_for_input()
