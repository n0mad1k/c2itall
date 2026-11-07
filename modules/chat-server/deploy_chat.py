#!/usr/bin/env python3
"""Team chat: Phantom Matrix core plus Tailscale and optional bot support."""

import getpass
import importlib.util
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
PHANTOM_ROOT = ROOT / "ghost_protocol" / "phantom"
ADDONS_PLAYBOOK = Path(__file__).resolve().with_name("chat_addons.yml")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.common import clear_screen, generate_deployment_id, print_banner, wait_for_input
from utils.provider_utils import gather_provider_config, select_provider


def _load_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_phantom():
    os.environ["C2ITALL_INTEGRATED"] = "1"
    if str(PHANTOM_ROOT) not in sys.path:
        sys.path.insert(0, str(PHANTOM_ROOT))
    return _load_path("c2itall_phantom_chat", PHANTOM_ROOT / "phantom.py")


def _load_matrix_config():
    return _load_path("c2itall_phantom_matrix_config",
                      PHANTOM_ROOT / "modules" / "matrix.py")


def gather_chat_parameters():
    clear_screen()
    print_banner()
    provider = select_provider("chat", legacy_fallback=True)
    if provider is None:
        return None
    provider_config = gather_provider_config(provider, "chat", legacy_fallback=True)
    if provider_config is None:
        return None
    config = dict(provider_config)
    config.update(provider=provider, provider_workload="chat",
                  deployment_id=generate_deployment_id(),
                  deployment_type="phantom_matrix", chat_deployment=True,
                  ssh_after_deploy=False)
    config = _load_matrix_config().gather_config(config)
    if config is None:
        return None
    config["tailscale_auth_key"] = getpass.getpass(
        "Tailscale auth key (blank for manual authentication): ").strip()
    config["enable_bot_support"] = input(
        "Install Matrix bot runtime and systemd template? [y/N]: ").strip().lower() in (
            "y", "yes", "true")
    return config


def deploy_chat(config):
    """Deploy the shared Matrix core, then the chat-only networking/runtime layer."""
    config.update(provider_workload="chat", deployment_type="phantom_matrix",
                  chat_deployment=True)
    phantom = _load_phantom()
    if not phantom.deploy("matrix", config):
        return False
    if not phantom.run_playbook(ADDONS_PLAYBOOK, config):
        phantom.err("Chat networking/bot layer failed.")
        phantom.teardown_instance(config)
        return False
    phantom.save_deploy_info(config)
    return True


def chat_menu():
    print("1) Deploy Team Chat Server (Matrix + Element + Tailscale)")
    print("2) Deploy Team Chat + Bot Support")
    print("99) Return")
    choice = input("Select an option: ").strip()
    if choice == "99":
        return False
    if choice not in ("1", "2"):
        print("Invalid option.")
        wait_for_input()
        return False
    try:
        config = gather_chat_parameters()
        if config is not None:
            if choice == "2":
                config["enable_bot_support"] = True
            return deploy_chat(config)
        return False
    finally:
        wait_for_input()


if __name__ == "__main__":
    sys.exit(0 if chat_menu() else 1)
