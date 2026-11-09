#!/usr/bin/env python3
"""Deploy, repeat, verify, and remove one real Azure infrastructure VM."""

import argparse
import json
from pathlib import Path
import shutil
import signal
import sys
import time
import uuid

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
for path in (SCRIPT_DIR, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from deploy_azure_smoke import LOCATION, SIZE, SUBSCRIPTION, Runner, public_ipv4
from test_azure_phantom_live import preflight, require


STATE_DIR = ROOT / "deployments" / "azure"

from utils import azure_utils
from utils.deployment_engine import deploy_infrastructure
from utils.provider_registry import infrastructure_adapter
import teardown as standalone_teardown


def verify_committed_source(runner):
    paths = (
        "providers/Azure/infrastructure.yml",
        "providers/Azure/templates/infrastructure.json.j2",
        "scripts/test_azure_infrastructure_live.py",
        "teardown.py",
        "tests/test_azure_provider.py",
        "utils/azure_cloud.py", "utils/azure_utils.py",
        "utils/cleanup_engine.py", "utils/deployment_engine.py",
        "utils/legacy_provider_adapter.py", "utils/provider_registry.py",
    )
    for path in paths:
        runner.run(["git", "diff", "--quiet", "HEAD", "--", path])
    return runner.run(["git", "rev-parse", "HEAD"])


def snapshot(runner, config):
    group = config["azure_resource_group"]
    vms = runner.az("vm", "list", "--resource-group", group)
    require(len(vms) == 1, "Expected exactly one infrastructure VM")
    vm = vms[0]
    image = vm["storageProfile"]["imageReference"]
    disk = vm["storageProfile"]["osDisk"]
    require(vm["hardwareProfile"]["vmSize"] == SIZE, "Unexpected VM size")
    require(image["publisher"].lower() == "canonical"
            and image["offer"] == "ubuntu-24_04-lts"
            and image["sku"] == "server", "Unexpected VM image")
    sizes = [disk[key] for key in ("diskSizeGB", "diskSizeGb") if key in disk]
    require(sizes and all(size == 32 for size in sizes), "Unexpected OS disk size")
    require(disk["managedDisk"]["storageAccountType"] == "StandardSSD_LRS",
            "Unexpected OS disk type")
    require(vm["osProfile"]["linuxConfiguration"]["disablePasswordAuthentication"],
            "VM permits SSH passwords")

    ips = runner.az("network", "public-ip", "list", "--resource-group", group)
    require(len(ips) == 1 and ips[0]["sku"]["name"] == "Standard"
            and ips[0]["publicIPAllocationMethod"] == "Static",
            "Expected one Standard static public IPv4")
    address = public_ipv4(ips[0]["ipAddress"])
    nsgs = runner.az("network", "nsg", "list", "--resource-group", group)
    require(len(nsgs) == 1, "Expected one network security group")
    rules = nsgs[0]["securityRules"]
    allows = {(rule["protocol"].lower(), rule["destinationPortRange"],
               rule["sourceAddressPrefix"])
              for rule in rules
              if rule["direction"] == "Inbound" and rule["access"] == "Allow"}
    expected = {("tcp", "22", public_ipv4(config["operator_ip"]) + "/32")}
    require(allows == expected, "Infrastructure NSG permits unexpected ingress")
    require(any(rule["direction"] == "Inbound" and rule["access"] == "Deny"
                and rule.get("sourceAddressPrefix") == "*"
                and rule.get("destinationPortRange") == "*" for rule in rules),
            "Infrastructure NSG lacks final inbound deny")
    resources = runner.az("resource", "list", "--resource-group", group)
    return {"vm_id": vm["id"], "public_ip": address,
            "resource_ids": sorted(r["id"].lower() for r in resources),
            "allow_rules": sorted([list(rule) for rule in allows])}


def verify_ssh(runner, config, address):
    command = (
        "set -eu; "
        "test \"$(. /etc/os-release; printf '%s' \"$VERSION_ID\")\" = 24.04; "
        "test \"$(uname -m)\" = x86_64; "
        "sudo -n /usr/sbin/sshd -T | grep -q '^passwordauthentication no$'"
    )
    runner.run([
        "ssh", "-F", "/dev/null", "-i", config["ssh_private_key_path"],
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"UserKnownHostsFile={runner.evidence / 'known_hosts'}",
        f"azureuser@{address}", command,
    ], timeout=60)
    return {"ubuntu_24_04": True, "ssh_password_authentication": False,
            "sudo_noninteractive": True}


def activate(operator_ip=None):
    runner = Runner(ROOT)
    deployment_id = f"azinfra-{uuid.uuid4().hex[:10]}"
    runner.evidence = ROOT / "logs" / "azure-infrastructure-live" / deployment_id
    runner.evidence.mkdir(parents=True, mode=0o700)
    group = f"c2itall-{deployment_id}"
    key = Path.home() / ".ssh" / f"c2deploy_{deployment_id}"
    config = {
        "provider": "azure", "provider_workload": "infrastructure",
        "deployment_id": deployment_id, "deployment_type": "infrastructure",
        "infrastructure_deployment": True,
        "azure_subscription_id": SUBSCRIPTION, "azure_location": LOCATION,
        "azure_vm_size": SIZE, "azure_os_disk_gb": 32,
        "azure_resource_group": group, "azure_state_dir": str(STATE_DIR),
        "operator_ip": "", "ssh_key_path": str(key) + ".pub",
        "ssh_private_key_path": str(key), "ssh_key_generated": True,
    }
    adapter = infrastructure_adapter("azure")
    live_passed = cleanup_passed = False
    failure = None
    previous = {sig: signal.signal(sig, runner.handle_signal)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for executable in ("az", "ansible-playbook", "ssh", "ssh-keygen", "curl"):
            require(shutil.which(executable), f"Required tool unavailable: {executable}")
        runner.record("source.json", {"parent": verify_committed_source(runner)})
        require(not key.exists() and not Path(str(key) + ".pub").exists(),
                "Refusing to reuse a live-test SSH key")
        require(runner.az("group", "exists", "--name", group) is False,
                "Live-test resource group already exists")
        runner.baseline(group)
        config["operator_ip"] = public_ipv4(operator_ip or runner.run([
            "curl", "-4", "--fail", "--silent", "--show-error",
            "--max-time", "15", "https://api.ipify.org",
        ]))
        preflight(runner, config)

        config["azure_deadline"] = time.monotonic() + 1800
        azure_utils.prepare_state(config)
        require(adapter.prepare_key(config), "Azure SSH key preparation failed")
        require(deploy_infrastructure(config),
                "Initial routed Azure infrastructure deployment failed")
        first = snapshot(runner, config)
        first_health = adapter.health(config)
        require(first_health.get("healthy") is True, "Initial VM health failed")
        runner.record("first-deployment.json", {
            "azure": first, "ssh": verify_ssh(runner, config, first["public_ip"]),
            "health": first_health})

        config["azure_deadline"] = time.monotonic() + 1800
        require(deploy_infrastructure(config),
                "Repeated routed Azure infrastructure deployment failed")
        repeated = snapshot(runner, config)
        repeated_health = adapter.health(config)
        require(repeated_health.get("healthy") is True, "Repeated VM health failed")
        require(first["vm_id"].lower() == repeated["vm_id"].lower()
                and first["resource_ids"] == repeated["resource_ids"],
                "Repeated deployment changed Azure resource identity")
        runner.record("repeat-deployment.json", {
            "azure": repeated, "health": repeated_health,
            "resource_identity_preserved": True})
        live_passed = True
    except BaseException as error:
        failure = str(error)
        runner.record("failure.json", {"error": failure})
        print(f"Azure infrastructure live test did not pass: {error}", file=sys.stderr)
    finally:
        runner.cleaning = True
        runner.deadline = time.monotonic() + 600
        config["azure_cleanup_deadline"] = runner.deadline
        try:
            state = STATE_DIR / f"{deployment_id}.json"
            if state.exists() or runner.az("group", "exists", "--name", group) is not False:
                require(standalone_teardown.teardown_deployment(
                    deployment_id, force=True),
                    "Routed standalone Azure infrastructure cleanup failed")
            require(runner.az("group", "exists", "--name", group) is False,
                    "Infrastructure resource group remains after cleanup")
            runner.cleanup_subscription()
            inventory = runner.inventory()
            require(inventory == runner.subscription_baseline,
                    "Azure subscription inventory was not restored")
            require(not state.exists(), "Active Azure recovery state remains")
            require(not key.exists() and not Path(str(key) + ".pub").exists(),
                    "Generated Azure SSH key remains")
            runner.record("final-cleanup.json", {
                "resource_group_absent": True, "active_state_absent": True,
                "generated_key_absent": True, "inventory": inventory})
            cleanup_passed = True
        except BaseException as cleanup_error:
            runner.record("cleanup-failure.json", {"error": str(cleanup_error)})
            print(f"Azure infrastructure cleanup failed: {cleanup_error}", file=sys.stderr)
        for sig, handler in previous.items():
            signal.signal(sig, handler)

    passed = live_passed and cleanup_passed and not runner.interrupted
    runner.record("result.json", {
        "passed": passed, "live_workflow_passed": live_passed,
        "cleanup_passed": cleanup_passed, "failure": failure,
        "deployment_id": deployment_id, "resource_group": group})
    print(f"Evidence: {runner.evidence}")
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--activate", action="store_true")
    parser.add_argument("--operator-ip")
    args = parser.parse_args(argv)
    if not args.activate:
        print(f"DRY RUN: no cloud mutations. Target: {SUBSCRIPTION} / {LOCATION} / {SIZE}")
        return 0
    return activate(args.operator_ip)


if __name__ == "__main__":
    raise SystemExit(main())
