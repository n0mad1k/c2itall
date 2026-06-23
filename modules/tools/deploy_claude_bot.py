#!/usr/bin/env python3
"""
Claude Bot — c2itall integration module
Deploy and manage the Matrix-Claude Code bridge bot locally or on a remote host.
"""

import os
import sys
import subprocess
import tempfile

# Add parent paths for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from utils.common import COLORS, clear_screen, print_banner, wait_for_input

# ─── Path Registry ───────────────────────────────────────────────────────────
C2ITALL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

# Look for claude-bot in the ghost_protocol submodule first, then standalone
_SUBMODULE_PATH = os.path.join(C2ITALL_ROOT, 'ghost_protocol', 'claude-bot')
_STANDALONE_PATH = os.path.expanduser('~/tools/ghost_protocol/claude-bot')

CLAUDE_BOT_PATH = _SUBMODULE_PATH if os.path.isdir(_SUBMODULE_PATH) else _STANDALONE_PATH
INSTALL_SH = os.path.join(CLAUDE_BOT_PATH, 'deploy', 'install.sh')
UNINSTALL_SH = os.path.join(CLAUDE_BOT_PATH, 'deploy', 'uninstall.sh')
SERVICE_NAME = 'claude-bot'


# ─── SSH helpers (mirrors recon_tools pattern) ───────────────────────────────

def _build_ssh_cmd(host, ssh_user, ssh_port, ssh_key, command=None, interactive=False):
    """Build an SSH command list."""
    cmd = ['ssh']
    if ssh_key:
        cmd.extend(['-i', ssh_key])
    cmd.extend(['-p', str(ssh_port)])
    known_hosts = os.path.expanduser('~/.ssh/c2deploy_claudebot_known_hosts')
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
    known_hosts = os.path.expanduser('~/.ssh/c2deploy_claudebot_known_hosts')
    cmd = [
        'scp',
        '-P', str(ssh_port),
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', f'UserKnownHostsFile={known_hosts}',
    ]
    if ssh_key:
        cmd.extend(['-i', ssh_key])
    return cmd


# ─── Config generation ───────────────────────────────────────────────────────

def _prompt_bot_config():
    """Prompt for all bot configuration values. Returns a dict."""
    print(f"\n{COLORS['CYAN']}Bot Configuration{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}================={COLORS['RESET']}")

    homeserver = input(f"  Matrix homeserver URL [{COLORS['CYAN']}https://matrix.example.com{COLORS['RESET']}]: ").strip()
    if not homeserver:
        homeserver = 'https://matrix.example.com'

    bot_user = input(f"  Bot Matrix user ID [{COLORS['CYAN']}@bot:matrix.example.com{COLORS['RESET']}]: ").strip()
    if not bot_user:
        bot_user = '@bot:matrix.example.com'

    bot_password = input(f"  Bot Matrix password: ").strip()

    allowed_raw = input(f"  Allowed Matrix user IDs (comma-separated): ").strip()
    allowed_users = [u.strip() for u in allowed_raw.split(',') if u.strip()] if allowed_raw else []

    print(f"\n  Claude backend:")
    print(f"    1) cli  (Claude Code CLI — uses Max plan, no extra cost)")
    print(f"    2) api  (Anthropic API — requires API key)")
    backend_choice = input(f"  Select [1]: ").strip() or '1'
    backend = 'api' if backend_choice == '2' else 'cli'

    api_key = ''
    if backend == 'api':
        api_key = input(f"  Anthropic API key: ").strip()

    return {
        'homeserver': homeserver,
        'bot_user': bot_user,
        'bot_password': bot_password,
        'allowed_users': allowed_users,
        'backend': backend,
        'api_key': api_key,
    }


def _generate_config_yaml(cfg):
    """Generate config.yaml content from a config dict.
    Credentials are NOT written here — they come from env vars at runtime."""
    allowed_block = '\n'.join(f'    - "{u}"' for u in cfg['allowed_users'])
    if not allowed_block:
        allowed_block = '    - "@yourusername:matrix.example.com"'

    return f"""matrix:
  homeserver: "{cfg['homeserver']}"
  user_id: "{cfg['bot_user']}"
  password: "${{MATRIX_PASSWORD}}"
  device_name: "claude-bot"
  store_path: "/opt/claude-bot/store"

claude:
  backend: "{cfg['backend']}"
  cli_path: "/usr/local/bin/claude"
  cli_model: "sonnet"
  cli_max_turns: 10
  api_key: "${{ANTHROPIC_API_KEY}}"
  api_model: "claude-sonnet-4-20250514"
  max_tokens: 4096
  temperature: 0.7
  system_prompt: |
    You are a helpful AI assistant in a Matrix chat room.
    Be concise. Use markdown formatting when helpful.
    You have full tool access: bash, file editing, web search, code analysis.
    The user is interacting from a mobile phone, so keep responses focused
    and avoid unnecessarily long output.

sessions:
  mode: "per_room"
  max_history: 50
  ttl_hours: 24

security:
  allowed_users:
{allowed_block}
  allowed_rooms: []
  rate_limit:
    messages_per_minute: 10
    tokens_per_hour: 100000
  max_monthly_cost_usd: 50.0

logging:
  level: "INFO"
  file: "/opt/claude-bot/claude-bot.log"
"""


# ─── Local actions ───────────────────────────────────────────────────────────

def _deploy_local():
    """Run install.sh locally, interactively."""
    if not os.path.exists(INSTALL_SH):
        print(f"\n{COLORS['RED']}install.sh not found at {INSTALL_SH}{COLORS['RESET']}")
        print(f"{COLORS['YELLOW']}Clone ghost_protocol first: ~/tools/ghost_protocol/claude-bot{COLORS['RESET']}")
        wait_for_input()
        return

    print(f"\n{COLORS['CYAN']}Deploying claude-bot locally...{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}Note: script requires sudo — you may be prompted for your password.{COLORS['RESET']}")
    print()
    try:
        subprocess.run(['sudo', 'bash', INSTALL_SH], cwd=os.path.dirname(INSTALL_SH))
    except KeyboardInterrupt:
        print(f"\n{COLORS['YELLOW']}Installation interrupted{COLORS['RESET']}")
    wait_for_input()


def _status_local():
    """Show systemctl status for claude-bot locally."""
    print(f"\n{COLORS['CYAN']}Local claude-bot status:{COLORS['RESET']}\n")
    try:
        subprocess.run(['systemctl', 'status', SERVICE_NAME, '--no-pager'])
    except FileNotFoundError:
        print(f"{COLORS['RED']}systemctl not found — is this a systemd system?{COLORS['RESET']}")
    wait_for_input()


def _uninstall_local():
    """Run uninstall.sh locally."""
    if not os.path.exists(UNINSTALL_SH):
        print(f"\n{COLORS['RED']}uninstall.sh not found at {UNINSTALL_SH}{COLORS['RESET']}")
        wait_for_input()
        return

    confirm = input(f"\n{COLORS['YELLOW']}Uninstall claude-bot locally? (y/N): {COLORS['RESET']}").strip().lower()
    if confirm != 'y':
        print(f"{COLORS['GREEN']}Cancelled{COLORS['RESET']}")
        wait_for_input()
        return

    print(f"\n{COLORS['CYAN']}Uninstalling claude-bot...{COLORS['RESET']}")
    try:
        subprocess.run(['sudo', 'bash', UNINSTALL_SH], cwd=os.path.dirname(UNINSTALL_SH))
    except KeyboardInterrupt:
        print(f"\n{COLORS['YELLOW']}Uninstall interrupted{COLORS['RESET']}")
    wait_for_input()


# ─── Remote actions ──────────────────────────────────────────────────────────

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


def _deploy_remote():
    """Copy claude-bot directory to remote, generate config.yaml, run install.sh over SSH."""
    if not os.path.isdir(CLAUDE_BOT_PATH):
        print(f"\n{COLORS['RED']}claude-bot source not found at {CLAUDE_BOT_PATH}{COLORS['RESET']}")
        wait_for_input()
        return

    host, ssh_user, ssh_port, ssh_key = _prompt_remote_target()
    if not host:
        wait_for_input()
        return

    cfg = _prompt_bot_config()
    config_yaml = _generate_config_yaml(cfg)

    remote_staging = '/tmp/claude-bot-deploy'

    print(f"\n{COLORS['CYAN']}Copying claude-bot to {ssh_user}@{host}:{remote_staging}...{COLORS['RESET']}")

    # Create remote staging dir
    mkdir_cmd = _build_ssh_cmd(host, ssh_user, ssh_port, ssh_key,
                                f'rm -rf {remote_staging} && mkdir -p {remote_staging}')
    result = subprocess.run(mkdir_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{COLORS['RED']}Failed to create remote staging dir: {result.stderr}{COLORS['RESET']}")
        wait_for_input()
        return

    # SCP the entire claude-bot directory
    scp_cmd = _build_scp_cmd(ssh_port, ssh_key)
    scp_cmd.extend(['-r', CLAUDE_BOT_PATH + '/'])
    scp_cmd.append(f'{ssh_user}@{host}:{remote_staging}/')
    result = subprocess.run(scp_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{COLORS['RED']}SCP failed: {result.stderr}{COLORS['RESET']}")
        wait_for_input()
        return
    print(f"  {COLORS['GREEN']}Files copied{COLORS['RESET']}")

    # Write config.yaml to a tempfile, then SCP it into the staging dir
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tf:
        tf.write(config_yaml)
        tmp_config = tf.name

    try:
        scp_cfg = _build_scp_cmd(ssh_port, ssh_key)
        scp_cfg.extend([tmp_config, f'{ssh_user}@{host}:{remote_staging}/config.yaml'])
        result = subprocess.run(scp_cfg, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{COLORS['RED']}Failed to copy config.yaml: {result.stderr}{COLORS['RESET']}")
            wait_for_input()
            return
        print(f"  {COLORS['GREEN']}config.yaml placed in staging directory{COLORS['RESET']}")
    finally:
        os.unlink(tmp_config)

    # Build env for sensitive credentials
    env_prefix = ''
    if cfg['bot_password']:
        env_prefix += f"MATRIX_PASSWORD={cfg['bot_password']!r} "
    if cfg['api_key']:
        env_prefix += f"ANTHROPIC_API_KEY={cfg['api_key']!r} "

    # Run install.sh on the remote host
    print(f"\n{COLORS['CYAN']}Running install.sh on {host}...{COLORS['RESET']}")
    install_cmd_str = (
        f'cd {remote_staging}/deploy && '
        f'{env_prefix}sudo --preserve-env=MATRIX_PASSWORD,ANTHROPIC_API_KEY '
        f'bash {remote_staging}/deploy/install.sh'
    )
    ssh_install = _build_ssh_cmd(host, ssh_user, ssh_port, ssh_key,
                                  install_cmd_str, interactive=True)
    try:
        subprocess.run(ssh_install)
    except KeyboardInterrupt:
        print(f"\n{COLORS['YELLOW']}Remote install interrupted{COLORS['RESET']}")

    wait_for_input()


def _status_remote():
    """SSH to a remote host and show systemctl status claude-bot."""
    host, ssh_user, ssh_port, ssh_key = _prompt_remote_target()
    if not host:
        wait_for_input()
        return

    print(f"\n{COLORS['CYAN']}Status on {ssh_user}@{host}:{COLORS['RESET']}\n")
    ssh_cmd = _build_ssh_cmd(host, ssh_user, ssh_port, ssh_key,
                              f'systemctl status {SERVICE_NAME} --no-pager',
                              interactive=True)
    try:
        subprocess.run(ssh_cmd)
    except KeyboardInterrupt:
        pass
    wait_for_input()


# ─── Main menu ───────────────────────────────────────────────────────────────

def claude_bot_menu():
    """Main entry point — called from c2itall deploy.py tools_menu()."""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}CLAUDE BOT{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}=========={COLORS['RESET']}")
        print(f"  Matrix-Claude Code bridge bot")

        # Show whether source is available
        if os.path.isdir(CLAUDE_BOT_PATH):
            print(f"  Source: {COLORS['GREEN']}{CLAUDE_BOT_PATH}{COLORS['RESET']}")
        else:
            print(f"  Source: {COLORS['RED']}NOT FOUND — {CLAUDE_BOT_PATH}{COLORS['RESET']}")
        print()

        print(f"1) Deploy Locally")
        print(f"2) Deploy Remote {COLORS['CYAN']}(SSH — copy + config + install){COLORS['RESET']}")
        print(f"3) Status {COLORS['GRAY']}(local systemctl){COLORS['RESET']}")
        print(f"4) Status Remote {COLORS['GRAY']}(SSH systemctl){COLORS['RESET']}")
        print(f"5) Uninstall Local")
        print(f"99) Return to Tools Menu")

        choice = input(f"\nSelect an option: ").strip()

        if choice == '1':
            _deploy_local()
        elif choice == '2':
            _deploy_remote()
        elif choice == '3':
            _status_local()
        elif choice == '4':
            _status_remote()
        elif choice == '5':
            _uninstall_local()
        elif choice == '99':
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()
