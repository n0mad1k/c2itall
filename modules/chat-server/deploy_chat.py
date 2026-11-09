#!/usr/bin/env python3
"""Team chat: provider-routed Matrix or TAK Server deployments."""

import getpass
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import secrets
import sys


ROOT = Path(__file__).resolve().parents[2]
PHANTOM_ROOT = ROOT / "ghost_protocol" / "phantom"
ADDONS_PLAYBOOK = Path(__file__).resolve().with_name("chat_addons.yml")
TAK_PLAYBOOK = Path(__file__).resolve().with_name("tak_server.yml")
TAK_VERSION = "5.7-RELEASE14"
TAK_DEB_NAME = f"takserver_{TAK_VERSION}_all.deb"
TAK_DEFAULT_DEB = Path.home() / ".cache/c2itall/takserver" / TAK_VERSION / TAK_DEB_NAME
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


def _load_matrix_rotation():
    return _load_path("c2itall_matrix_rotation",
                      Path(__file__).resolve().with_name("rotate_matrix.py"))


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_tak_name(value, label):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", value or ""):
        raise ValueError(f"Invalid {label}")
    return value


def _validate_tak_config(config):
    package = Path(config["tak_deb_path"]).expanduser().resolve()
    if not package.is_file() or package.name != TAK_DEB_NAME:
        raise ValueError(f"TAK package must be the pinned {TAK_DEB_NAME}")
    expected = config.get("tak_deb_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or _sha256(package) != expected:
        raise ValueError("TAK package checksum mismatch")
    for key in ("tak_admin_name", "tak_client_name", "tak_ca_name"):
        _safe_tak_name(config[key], key)
    for key in ("tak_cert_password", "tak_ca_password"):
        if not isinstance(config.get(key), str) or len(config[key]) < 16:
            raise ValueError(f"{key} must contain at least 16 characters")
    config["tak_deb_path"] = str(package)
    return config


def _gather_tak_config(config):
    default_package = str(TAK_DEFAULT_DEB)
    package = input(f"TAK Server {TAK_VERSION} package [{default_package}]: ").strip()
    package = Path(package or default_package).expanduser().resolve()
    if not package.is_file():
        print(f"TAK package not found. Build it with: {ROOT / 'scripts/build_tak_server.py'}")
        return None
    config.update(
        server_type="tak",
        deployment_type="chat_tak",
        tak_deb_path=str(package),
        tak_deb_sha256=_sha256(package),
        tak_admin_name=input("TAK admin certificate name [admin]: ").strip() or "admin",
        tak_client_name=input("TAK client certificate name [operator]: ").strip() or "operator",
        tak_ca_name=f"c2itall-{config['deployment_id']}",
        tak_cert_password=secrets.token_urlsafe(24),
        tak_ca_password=secrets.token_urlsafe(24),
        tak_cert_state="Virginia",
        tak_cert_city="EastUS",
        tak_cert_organization="c2itall",
        tak_cert_unit="Chat",
        tak_federation=input("Expose TAK federation? [y/N]: ").strip().lower()
        in ("y", "yes", "true"),
    )
    return _validate_tak_config(config)


def gather_chat_parameters(server_type="matrix"):
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
                  deployment_type=f"chat_{server_type}", chat_deployment=True,
                  server_type=server_type,
                  ssh_after_deploy=False)
    if server_type == "matrix":
        config = _load_matrix_config().gather_config(config)
    elif server_type == "tak":
        config = _gather_tak_config(config)
    else:
        raise ValueError(f"Unsupported chat server type: {server_type}")
    if config is None:
        return None
    config["tailscale_auth_key"] = getpass.getpass(
        "Tailscale auth key (blank for manual authentication): ").strip()
    config["enable_bot_support"] = server_type == "matrix" and input(
        "Install Matrix bot runtime and systemd template? [y/N]: ").strip().lower() in (
        "y", "yes", "true")
    return config


def deploy_chat(config):
    """Deploy a chat service, then its shared private-networking layer."""
    server_type = config.get("server_type", "matrix")
    config.update(provider_workload="chat", deployment_type=f"chat_{server_type}",
                  chat_deployment=True)
    phantom = _load_phantom()
    if server_type == "tak":
        _validate_tak_config(config)
        artifact_dir = Path(config.get(
            "tak_artifact_dir", ROOT / "deployments/chat" / config["deployment_id"]
        )).expanduser().resolve()
        artifact_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        artifact_dir.chmod(0o700)
        config["tak_artifact_dir"] = str(artifact_dir)
        deployed = phantom.deploy("tak", config, service_playbook=TAK_PLAYBOOK)
    elif server_type == "matrix":
        deployed = phantom.deploy("matrix", config)
    else:
        raise ValueError(f"Unsupported chat server type: {server_type}")
    if not deployed:
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
    print("3) Deploy TAK Server + Tailscale")
    print("4) Configure rolling Matrix replacement")
    print("99) Return")
    choice = input("Select an option: ").strip()
    if choice == "99":
        return False
    if choice not in ("1", "2", "3", "4"):
        print("Invalid option.")
        wait_for_input()
        return False
    try:
        if choice == "4":
            return _load_matrix_rotation().interactive_setup()
        config = gather_chat_parameters("tak" if choice == "3" else "matrix")
        if config is not None:
            if choice == "2":
                config["enable_bot_support"] = True
            return deploy_chat(config)
        return False
    finally:
        wait_for_input()


if __name__ == "__main__":
    sys.exit(0 if chat_menu() else 1)
