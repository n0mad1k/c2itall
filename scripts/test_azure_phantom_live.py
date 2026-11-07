#!/usr/bin/env python3
"""Real Azure Phantom test: deploy, repeat, verify WireGuard, and clean up."""

import argparse
import contextlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import time
from unittest import mock
import uuid

from deploy_azure_smoke import (IMAGE, LOCATION, SIZE, SUBSCRIPTION, Runner,
                                SmokeError, nonnegative_count, public_ipv4,
                                remaining)


ROOT = Path(__file__).resolve().parents[1]
PHANTOM_ROOT = ROOT / "ghost_protocol" / "phantom"
STATE_DIR = ROOT / "deployments" / "azure"


class LiveTestError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise LiveTestError(message)


def verify_committed_source(runner):
    parent_paths = (
        "README.md", "providers/Azure/templates/infrastructure.json.j2",
        "scripts/test_azure_phantom_live.py", "tests/test_azure_provider.py",
        "utils/azure_phantom_adapter.py", "utils/azure_utils.py",
        "utils/provider_registry.py",
    )
    for path in parent_paths:
        runner.run(["git", "diff", "--quiet", "HEAD", "--", path])
    for path in ("phantom/phantom.py", "phantom/test_phantom.py"):
        runner.run(["git", "-C", str(ROOT / "ghost_protocol"), "diff", "--quiet",
                    "HEAD", "--", path])
    return {
        "parent": runner.run(["git", "rev-parse", "HEAD"]),
        "ghost_protocol": runner.run(
            ["git", "-C", str(ROOT / "ghost_protocol"), "rev-parse", "HEAD"]),
    }


def preflight(runner):
    account = runner.az("account", "show")
    require(account.get("id", "").lower() == SUBSCRIPTION, "Wrong Azure subscription")
    require(account.get("state") == "Enabled", "Azure subscription is not enabled")
    runner.deadline = time.monotonic() + 600
    for namespace in ("Microsoft.Compute", "Microsoft.Network"):
        provider = runner.az("provider", "show", "--namespace", namespace)
        if provider.get("registrationState") != "Registered":
            runner.az("provider", "register", "--namespace", namespace)
        while runner.az("provider", "show", "--namespace", namespace).get(
                "registrationState") != "Registered":
            time.sleep(min(5, remaining(runner.deadline)))
    sku = runner.find_sku()
    require(not sku.get("restrictions"), "Approved Azure VM size is restricted")
    capabilities = {item["name"]: item["value"] for item in sku["capabilities"]}
    cores = nonnegative_count(capabilities.get("vCPUs"), "SKU vCPUs")
    require(cores > 0, "Approved Azure VM size has no vCPUs")
    quotas = runner.az("vm", "list-usage", "--location", LOCATION)
    names = {"cores", sku["family"].lower()}
    found = set()
    for quota in quotas:
        name = quota.get("name", {}).get("value", "").lower()
        if name in names:
            found.add(name)
            used = nonnegative_count(quota.get("currentValue"), f"{name} currentValue")
            limit = nonnegative_count(quota.get("limit"), f"{name} limit")
            require(used + cores <= limit, f"Insufficient Azure quota: {name}")
    require(found == names, "Could not verify Azure regional and family quota")
    runner.az("vm", "image", "show", "--location", LOCATION, "--urn", IMAGE)


def resource_snapshot(runner, config):
    group = config["azure_resource_group"]
    vms = runner.az("vm", "list", "--resource-group", group)
    require(len(vms) == 1, "Expected exactly one Phantom VM")
    vm = vms[0]
    image = vm["storageProfile"]["imageReference"]
    disk = vm["storageProfile"]["osDisk"]
    require(vm["hardwareProfile"]["vmSize"] == SIZE, "Unexpected Phantom VM size")
    require(image["publisher"].lower() == "canonical"
            and image["offer"] == "ubuntu-24_04-lts" and image["sku"] == "server",
            "Unexpected Phantom VM image")
    disk_sizes = [disk[key] for key in ("diskSizeGB", "diskSizeGb") if key in disk]
    require(disk_sizes and all(size == 32 for size in disk_sizes)
            and disk["managedDisk"]["storageAccountType"] == "StandardSSD_LRS",
            "Unexpected Phantom OS disk")
    require(vm["osProfile"]["linuxConfiguration"]["disablePasswordAuthentication"],
            "Phantom VM permits SSH passwords")

    ips = runner.az("network", "public-ip", "list", "--resource-group", group)
    require(len(ips) == 1 and ips[0]["sku"]["name"] == "Standard"
            and ips[0]["publicIPAllocationMethod"] == "Static",
            "Expected one Standard static public IPv4")
    address = public_ipv4(ips[0]["ipAddress"])
    require(address == config["target_host"], "Phantom target does not match Azure IP")

    nsgs = runner.az("network", "nsg", "list", "--resource-group", group)
    require(len(nsgs) == 1, "Expected one Phantom network security group")
    rules = nsgs[0]["securityRules"]
    allows = {(rule["protocol"].lower(), rule["destinationPortRange"],
               rule["sourceAddressPrefix"])
              for rule in rules
              if rule["direction"] == "Inbound" and rule["access"] == "Allow"}
    expected = {("tcp", "22", public_ipv4(config["operator_ip"]) + "/32"),
                ("udp", "51820", "*")}
    require(allows == expected, "Azure NSG does not match the Phantom VPN allowlist")
    require(any(rule["direction"] == "Inbound" and rule["access"] == "Deny"
                and rule.get("sourceAddressPrefix") == "*"
                and rule.get("destinationPortRange") == "*"
                and rule["priority"] > 110 for rule in rules),
            "Azure NSG lacks the final inbound deny")

    resources = runner.az("resource", "list", "--resource-group", group)
    return {"vm_id": vm["id"], "public_ip": address,
            "resource_ids": sorted(resource["id"].lower() for resource in resources),
            "allow_rules": sorted([list(rule) for rule in allows])}


def verify_wireguard(runner, config):
    address = config["target_host"]
    endpoint = f"Endpoint = {address}:51820"
    command = (
        "set -eu; "
        "test \"$(. /etc/os-release; printf '%s' \"$VERSION_ID\")\" = 24.04; "
        "test \"$(systemctl is-active wg-quick@wg0)\" = active; "
        "test \"$(systemctl is-enabled wg-quick@wg0)\" = enabled; "
        "test \"$(sudo -n wg show wg0 listen-port)\" = 51820; "
        "sudo -n test -s /etc/wireguard/clients/client1.conf; "
        f"sudo -n grep -Fxq {json.dumps(endpoint)} /etc/wireguard/clients/client1.conf; "
        "test \"$(sysctl -n net.ipv4.ip_forward)\" = 1; "
        "sudo -n ufw status | grep -q '^Status: active'; "
        "sudo -n ufw status | grep -Eq '^51820/udp[[:space:]]+ALLOW'; "
        "sudo -n /usr/sbin/sshd -T | grep -q '^passwordauthentication no$'"
    )
    ssh = [
        "ssh", "-F", "/dev/null", "-i", config["ssh_key"],
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"UserKnownHostsFile={runner.evidence / 'known_hosts'}",
        f"azureuser@{address}", command,
    ]
    runner.run(ssh, timeout=60)
    return {"wireguard_active": True, "wireguard_enabled": True,
            "listen_port": 51820, "client_config": True,
            "ipv4_forwarding": True, "ufw_active": True,
            "ssh_password_authentication": False}


def clean_phantom_files(phantom, deployment_id):
    work = phantom.WORK_DIR / deployment_id
    if work.exists():
        shutil.rmtree(work)
    names = (f"deployment_{deployment_id}.log",
             f"deployment_info_{deployment_id}.txt")
    for directory in (phantom.PHANTOM_LOGS, phantom.PHANTOM_LOGS / "archive"):
        for name in names:
            with contextlib.suppress(FileNotFoundError):
                (directory / name).unlink()
    for path in (phantom._ssh_key_path(deployment_id),
                 Path(str(phantom._ssh_key_path(deployment_id)) + ".pub"),
                 phantom._ssh_known_hosts_path(deployment_id)):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def activate(operator_ip=None):
    runner = Runner(ROOT)
    deployment_id = f"phaz-{uuid.uuid4().hex[:12]}"
    runner.evidence = ROOT / "logs" / "azure-phantom-live" / deployment_id
    runner.evidence.mkdir(parents=True, mode=0o700)
    group = f"c2itall-{deployment_id}"
    key = Path.home() / ".ssh" / f"c2deploy_{deployment_id}"
    config = {
        "provider": "azure", "provider_workload": "phantom",
        "deployment_id": deployment_id, "azure_resource_group": group,
        "azure_subscription_id": SUBSCRIPTION, "azure_location": LOCATION,
        "azure_vm_size": SIZE, "azure_state_dir": str(STATE_DIR),
        "operator_ip": "", "server_type": "vpn", "vpn_port": 51820,
        "vpn_client_count": 1, "vpn_dns": "1.1.1.1",
        "vpn_subnet": "10.66.66.0/24", "vpn_allowed_ips": "0.0.0.0/0",
        "ssh_after_deploy": False,
    }
    phantom = None
    live_passed = cleanup_passed = False
    failure = None
    previous = {sig: signal.signal(sig, runner.handle_signal)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for executable in ("az", "ansible-playbook", "ssh", "ssh-keygen", "curl"):
            require(shutil.which(executable), f"Required tool unavailable: {executable}")
        commits = verify_committed_source(runner)
        runner.record("source.json", commits)
        require(not key.exists() and not Path(str(key) + ".pub").exists(),
                "Refusing to reuse an existing live-test SSH key")
        require(runner.az("group", "exists", "--name", group) is False,
                "Live-test resource group already exists")
        runner.baseline(group)
        operator_ip = public_ipv4(operator_ip or runner.run([
            "curl", "-4", "--fail", "--silent", "--show-error", "--max-time", "15",
            "https://api.ipify.org",
        ]))
        config["operator_ip"] = operator_ip
        preflight(runner)

        os.environ["C2ITALL_INTEGRATED"] = "1"
        sys.path.insert(0, str(PHANTOM_ROOT))
        import phantom as phantom_module
        phantom = phantom_module

        config["azure_deadline"] = time.monotonic() + 1800
        with mock.patch("builtins.input", return_value="y"):
            require(phantom.deploy("vpn", config), "Initial Phantom deployment failed")
        first = resource_snapshot(runner, config)
        first_service = verify_wireguard(runner, config)
        runner.record("first-deployment.json", {"azure": first,
                                                 "service": first_service})

        config["azure_deadline"] = time.monotonic() + 1800
        with mock.patch("builtins.input", return_value="y"):
            require(phantom.deploy("vpn", config), "Repeated Phantom deployment failed")
        repeated = resource_snapshot(runner, config)
        repeated_service = verify_wireguard(runner, config)
        require(first["vm_id"].lower() == repeated["vm_id"].lower()
                and first["resource_ids"] == repeated["resource_ids"],
                "Repeated Phantom deployment changed Azure resource identity")
        runner.record("repeat-deployment.json", {"azure": repeated,
                                                  "service": repeated_service,
                                                  "resource_identity_preserved": True})
        live_passed = True
    except BaseException as error:
        failure = str(error)
        runner.record("failure.json", {"error": failure})
        print(f"Azure Phantom live test did not pass: {error}", file=sys.stderr)
    finally:
        runner.cleaning = True
        runner.deadline = time.monotonic() + 600
        config["azure_cleanup_deadline"] = runner.deadline
        try:
            active_state = STATE_DIR / f"{deployment_id}.json"
            group_exists = runner.az("group", "exists", "--name", group)
            if active_state.exists() or group_exists is not False:
                require(phantom is not None, "Phantom could not be loaded for cleanup")
                require(phantom.teardown_instance(config), "Phantom teardown failed")
            require(runner.az("group", "exists", "--name", group) is False,
                    "Phantom resource group remains after teardown")
            runner.cleanup_subscription()
            final_inventory = runner.inventory()
            require(final_inventory == runner.subscription_baseline,
                    "Azure subscription inventory was not restored")
            require(not active_state.exists(), "Active Azure recovery state remains")
            require(not key.exists() and not Path(str(key) + ".pub").exists(),
                    "Generated Azure SSH key remains")
            if phantom is not None:
                clean_phantom_files(phantom, deployment_id)
            runner.record("final-cleanup.json", {
                "resource_group_absent": True, "active_state_absent": True,
                "generated_key_absent": True, "inventory": final_inventory,
                "phantom_work_files_removed": phantom is not None,
            })
            cleanup_passed = True
        except BaseException as cleanup_error:
            runner.record("cleanup-failure.json", {"error": str(cleanup_error)})
            print(f"Azure Phantom cleanup failed: {cleanup_error}", file=sys.stderr)
        for sig, handler in previous.items():
            signal.signal(sig, handler)

    passed = live_passed and cleanup_passed and not runner.interrupted
    runner.record("result.json", {
        "passed": passed, "live_workflow_passed": live_passed,
        "cleanup_passed": cleanup_passed, "failure": failure,
        "deployment_id": deployment_id, "resource_group": group,
    })
    print(f"Evidence: {runner.evidence}")
    if passed:
        print("Azure Phantom live workflow passed; WireGuard was verified after initial "
              "and repeated deployment, and the subscription baseline was restored.")
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--activate", action="store_true",
                        help="create the temporary Azure VM and run the full workflow")
    parser.add_argument("--operator-ip",
                        help="workstation public IPv4; otherwise resolve with api.ipify.org")
    args = parser.parse_args(argv)
    if not args.activate:
        print(f"DRY RUN: no cloud mutations. Target: {SUBSCRIPTION} / {LOCATION} / {SIZE}")
        print("Activation performs real Phantom provisioning, hardening, WireGuard setup, "
              "repeat deployment, SSH/Azure validation, teardown, and inventory restoration.")
        return 0
    return activate(args.operator_ip)


if __name__ == "__main__":
    sys.exit(main())
