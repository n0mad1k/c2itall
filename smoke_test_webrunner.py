#!/usr/bin/env python3
"""Fail-closed Linode WEBRUNNER lifecycle test.

The default invocation is a non-mutating preview. Add ``--activate`` and an
explicit public operator IPv4 address to create one test node. The activated
path inventories and deletes every test-owned Linode and profile SSH key before
it reports success, including after a playbook failure.
"""

import argparse
from contextlib import chdir
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib import error, request


ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.common import generate_deployment_id, setup_logging
from utils.deployment_engine import execute_playbook, set_provider_environment
from utils.ssh_utils import generate_ssh_key


LINODE_API = "https://api.linode.com/v4"
DEPLOYMENT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,31}$")


def public_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "operator IP must be a public IPv4 address") from exc
    if address.version != 4 or not address.is_global:
        raise argparse.ArgumentTypeError(
            "operator IP must be a public IPv4 address")
    return str(address)


def safe_deployment_id(value):
    if not DEPLOYMENT_ID.fullmatch(value or ""):
        raise argparse.ArgumentTypeError(
            "deployment ID must be 3-32 lowercase letters, digits or hyphens")
    return value


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--activate", action="store_true",
                        help="perform the real one-node lifecycle")
    parser.add_argument(
        "--operator-ip", type=public_ipv4,
        help="public IPv4 allowed through SSH and used as /32 target")
    parser.add_argument(
        "--deployment-id", type=safe_deployment_id,
        help="stable ID for recovery; generated when omitted")
    return parser.parse_args(argv)


def linode_request(token, path, method="GET"):
    call = request.Request(
        LINODE_API + path,
        method=method,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/json"},
    )
    try:
        with request.urlopen(call, timeout=30) as response:
            payload = response.read()
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(
            f"Linode API {method} {path} failed with HTTP "
            f"{exc.code}: {detail}") from exc
    return json.loads(payload) if payload else None


def linode_pages(token, path):
    page = 1
    while True:
        separator = "&" if "?" in path else "?"
        payload = linode_request(
            token, f"{path}{separator}page={page}&page_size=500")
        if (not isinstance(payload, dict) or
                not isinstance(payload.get("data"), list)):
            raise RuntimeError("Linode API returned an invalid inventory response")
        yield from payload["data"]
        if page >= int(payload.get("pages", 1)):
            return
        page += 1


def owned_linode_inventory(token, deployment_id, webrunner_name):
    instances = []
    for item in linode_pages(token, "/linode/instances"):
        tags = item.get("tags") or []
        if (item.get("label", "").startswith(webrunner_name + "-") or
                deployment_id in tags or webrunner_name in tags):
            instances.append(item)
    keys = [item for item in linode_pages(token, "/profile/sshkeys")
            if item.get("label") == webrunner_name]
    return instances, keys


def cleanup_linode(token, deployment_id, webrunner_name, timeout=180):
    """Delete only test-owned cloud objects and prove their absence."""
    instances, keys = owned_linode_inventory(
        token, deployment_id, webrunner_name)
    for item in instances:
        linode_request(
            token, f"/linode/instances/{int(item['id'])}", "DELETE")
    for item in keys:
        linode_request(
            token, f"/profile/sshkeys/{int(item['id'])}", "DELETE")

    deadline = time.monotonic() + timeout
    while True:
        instances, keys = owned_linode_inventory(
            token, deployment_id, webrunner_name)
        if not instances and not keys:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(5)


def build_config(deployment_id, operator_ip):
    webrunner_name = f"wr-smoke-{deployment_id}"
    return {
        "deployment_id": deployment_id,
        "engagement": "smoketest",
        "deployment_type": "webrunner",
        "provider_workload": "webrunner",
        "webrunner_deployment": True,
        "webrunner_name": webrunner_name,
        "providers": ["linode"],
        "provider": "linode",
        "linode_region": "us-east",
        "linode_instance_type": "g6-nanode-1",
        "linode_image": "linode/debian12",
        "scan_mode": "masscan-only",
        "ports": [22],
        "ports_str": "22",
        "masscan_rate": 1000,
        "use_tor": False,
        "targets_file": "",
        "total_ips": 1,
        "preset": "sprint",
        "chunk_size": 500_000,
        "operator_ip": operator_ip,
        "enhanced_opsec": False,
        "teardown_after_scan": True,
    }


def remove_local_inputs(private_key, chunks_file):
    for path in (
            private_key,
            Path(str(private_key) + ".pub") if private_key else None,
            chunks_file):
        if path is not None:
            Path(path).unlink(missing_ok=True)


def main(argv=None):
    args = parse_args(argv)
    deployment_id = args.deployment_id or generate_deployment_id()
    operator_ip = args.operator_ip
    config = build_config(deployment_id, operator_ip or "198.51.100.1")

    print("WEBRUNNER Linode lifecycle test")
    print(f"  Deployment ID: {deployment_id}")
    print("  Node: 1 x g6-nanode-1 in us-east")
    print("  Cleanup: required and independently verified")
    if not args.activate:
        print("  Mode: preview only; no key, file or cloud resource created")
        return 0
    if operator_ip is None:
        print(
            "Activation requires --operator-ip with the operator's public IPv4.",
            file=sys.stderr)
        return 2

    set_provider_environment(config)
    token = os.environ.get("LINODE_TOKEN", "")
    if not token:
        print("Linode credentials are unavailable; no resource was created.",
              file=sys.stderr)
        return 2
    existing_instances, existing_keys = owned_linode_inventory(
        token, deployment_id, config["webrunner_name"])
    if existing_instances or existing_keys:
        print(
            "The test identity already owns Linode resources; refusing to "
            "claim or delete them.", file=sys.stderr)
        return 2

    logs_dir = ROOT / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    private_key = None
    chunks_file = None
    cleanup_verified = False
    workflow_passed = False
    try:
        key = generate_ssh_key(config["webrunner_name"])
        if not key:
            raise RuntimeError("failed to generate the test SSH key")
        private_key = Path(key)
        config["ssh_key_path"] = str(private_key) + ".pub"
        config["ssh_key_name"] = private_key.name

        chunks_file = logs_dir / f"node_chunks_{deployment_id}.json"
        node_chunks = [{
            "idx": 0,
            "node_name": f"{config['webrunner_name']}-01",
            "provider": "linode",
            "region": "us-east",
            "cidrs": [operator_ip + "/32"],
            "ip_count": 1,
        }]
        chunks_file.write_text(json.dumps(node_chunks))
        chunks_file.chmod(0o600)
        config["node_chunks_file"] = str(chunks_file)
        config["scanner_ip_log"] = str(
            logs_dir / f"scanner_ips_{config['webrunner_name']}.txt")
        config["results_dir"] = str(logs_dir / f"webrunner_{deployment_id}")
        with chdir(ROOT):
            setup_logging(deployment_id, "webrunner_live_test")
            workflow_passed = execute_playbook(
                "providers/webrunner.yml", config)
    except Exception as exc:
        print(f"WEBRUNNER lifecycle failed: {exc}", file=sys.stderr)
    finally:
        try:
            cleanup_verified = cleanup_linode(
                token, deployment_id, config["webrunner_name"])
        except Exception as exc:
            print(f"Linode cleanup verification failed: {exc}", file=sys.stderr)
        if cleanup_verified:
            remove_local_inputs(private_key, chunks_file)
        else:
            print(
                "Cleanup is unverified; recovery key and node file were retained.",
                file=sys.stderr)

    if workflow_passed and cleanup_verified:
        print("WEBRUNNER lifecycle and verified cleanup passed.")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
