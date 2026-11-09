#!/usr/bin/env python3
"""Team share drive: Phantom's Nextcloud on a host that only the tailnet can reach."""

import getpass
import importlib.util
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
PHANTOM_ROOT = ROOT / "ghost_protocol" / "phantom"
ADDONS_PLAYBOOK = Path(__file__).resolve().with_name("share_addons.yml")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.common import COLORS, clear_screen, generate_deployment_id, print_banner, wait_for_input
from utils.provider_utils import gather_provider_config, select_provider


def _load_phantom():
    os.environ["C2ITALL_INTEGRATED"] = "1"
    if str(PHANTOM_ROOT) not in sys.path:
        sys.path.insert(0, str(PHANTOM_ROOT))
    spec = importlib.util.spec_from_file_location("c2itall_phantom_share", PHANTOM_ROOT / "phantom.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gather_share_parameters():
    clear_screen()
    print_banner()
    print(f"{COLORS['WHITE']}TEAM SHARE DRIVE SETUP{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}======================{COLORS['RESET']}")
    provider = select_provider("share")
    if provider is None:
        return None
    provider_config = gather_provider_config(provider, "share")
    if provider_config is None:
        return None
    config = dict(provider_config)
    config.update(provider=provider, provider_workload="share",
                  deployment_id=generate_deployment_id(), deployment_type="share_drive",
                  server_type="cloud", ssh_after_deploy=False,
                  # A private name keeps Phantom on a self-signed certificate:
                  # nothing is published to DNS or certificate-transparency logs.
                  domain="share.internal")
    admin = input("Nextcloud admin user [admin]: ").strip() or "admin"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", admin):
        print(f"{COLORS['RED']}Invalid admin user name{COLORS['RESET']}")
        return None
    storage = input("Storage quota in GB [10]: ").strip() or "10"
    if not storage.isdigit() or not 1 <= int(storage) <= 1000:
        print(f"{COLORS['RED']}Storage must be 1-1000 GB{COLORS['RESET']}")
        return None
    config.update(cloud_admin_user=admin, cloud_storage_gb=storage)
    config["tailscale_auth_key"] = getpass.getpass(
        "Tailscale auth key (blank for manual authentication): ").strip()
    return config


def deploy_share(config):
    """Deploy Nextcloud through Phantom, then bind it to the tailnet only."""
    phantom = _load_phantom()
    if not phantom.deploy("cloud", config):
        return False
    if not phantom.run_playbook(ADDONS_PLAYBOOK, config):
        phantom.err("Share drive private-networking layer failed.")
        phantom.teardown_instance(config)
        return False
    phantom.save_deploy_info(config)
    return True


def share_menu():
    print("1) Deploy Team Share Drive (Nextcloud + Tailscale, no public web ports)")
    print("99) Return")
    choice = input("Select an option: ").strip()
    if choice == "99":
        return False
    if choice != "1":
        print("Invalid option.")
        wait_for_input()
        return False
    try:
        config = gather_share_parameters()
        return deploy_share(config) if config is not None else False
    finally:
        wait_for_input()


if __name__ == "__main__":
    sys.exit(0 if share_menu() else 1)
