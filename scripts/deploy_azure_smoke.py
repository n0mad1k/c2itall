#!/usr/bin/env python3
"""Reviewed Azure smoke: --dry-run (default), --prepare, or --activate.

Activation commits approved source through normal hooks, pushes public to
forgejo, and uses an archived commit. SSH uses accept-new trust on first use
with a dedicated known_hosts file; changed keys are rejected. SIGINT/SIGTERM
trigger ownership-checked cleanup. SIGKILL/workstation loss cannot guarantee
cleanup: recover using the ordinary teardown-by-ID command and persisted state.
Preparation performs commit/push, backup, registration and preflight, then
removes its local key/state after confirming the group is absent. It never
creates a resource group or VM. Activation repeats all required preconditions.
"""

import argparse
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
SUBSCRIPTION = "cc2a66d1-67c2-47ca-856f-19a4eae52cfe"
LOCATION = "eastus"
SIZE = "Standard_D2as_v4"
IMAGE = "Canonical:ubuntu-24_04-lts:server:latest"
APPROVED_PATHS = (
    ".gitignore", "README.md", "deploy.py", "utils/common.py",
    "utils/provider_utils.py", "utils/azure_utils.py", "utils/deployment_engine.py",
    "utils/cleanup_engine.py", "providers/Azure/infrastructure.yml",
    "providers/Azure/cleanup.yml", "providers/Azure/vars.example.yaml",
    "providers/Azure/templates/infrastructure.json.j2",
    "modules/infrastructure/deploy_infrastructure.py", "tests/test_azure_provider.py",
    "scripts/deploy_azure_smoke.py",
)
PHASES = (
    "Validate public branch, tools, account and pinned Azure parameters.",
    "Check approved paths; commit with normal hooks; push forgejo/public; verify SHA.",
    "Archive committed source and capture the absent-resource-group baseline.",
    "Register only Compute/Network; preflight quota, SKU, image and policy.",
    "Provision one Ubuntu 24.04 VM, 32-GiB StandardSSD_LRS disk and Standard IPv4.",
    "Verify SSH and configuration; repeat deployment and verify one unchanged VM.",
    "Cancel provisioning; ownership-check cleanup; confirm group deletion; retain evidence.",
)


class SmokeError(RuntimeError):
    pass


class SmokeInterrupted(SmokeError):
    pass


def public_ipv4(value):
    address = ipaddress.ip_address(value.removesuffix("/32"))
    if address.version != 4 or not address.is_global:
        raise SmokeError("Operator address must be a public IPv4 /32")
    return str(address)


def remaining(deadline, maximum=60):
    budget = maximum if deadline is None else min(maximum, deadline - time.monotonic())
    if budget <= 0:
        raise SmokeError("Monotonic lifecycle deadline exceeded")
    return budget


def nonnegative_count(value, field):
    """Azure CLI versions return quota counts as either JSON integers or strings."""
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        try:
            return int(value)
        except ValueError:
            pass
    raise SmokeError(f"Invalid {field}: expected a nonnegative decimal count")


def child_environment():
    return {key: value for key, value in os.environ.items()
            if not key.upper().startswith(("AWS_", "LINODE", "FLOKINET", "ANSIBLE_"))}


def stop_process(process):
    """Give the worker time to stop its own separately grouped CLI children."""
    if process.poll() is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=5)


class Runner:
    def __init__(self, root=ROOT):
        self.root = Path(root)
        self.deadline = None
        self.evidence = None
        self.counter = 0
        self.cleaning = False
        self.interrupted = False

    def handle_signal(self, signum, _frame):
        self.interrupted = True
        if not self.cleaning:
            raise SmokeInterrupted(f"Interrupted by signal {signum}")

    def run(self, argv, *, timeout=60, cwd=None):
        budget = remaining(self.deadline, timeout)
        process = subprocess.Popen(
            [str(arg) for arg in argv], cwd=cwd or self.root,
            env=child_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=budget)
        except BaseException:
            stop_process(process)
            raise
        if self.evidence:
            self.counter += 1
            self.record(f"command-{self.counter:03d}.json", {
                "command": list(map(str, argv)), "returncode": process.returncode,
                "stdout": stdout, "stderr": stderr,
            })
        if process.returncode:
            raise SmokeError(f"Command failed ({process.returncode}): {argv[0]}: {stderr[-3000:]}")
        return stdout.strip()

    def az(self, *argv):
        result = self.run(["az", *argv, "--subscription", SUBSCRIPTION,
                           "--only-show-errors", "--output", "json"])
        return json.loads(result) if result else None

    def git(self, *argv, timeout=60):
        return self.run(["git", *argv], timeout=timeout)

    def record(self, filename, content):
        path = self.evidence / filename
        with path.open("w") as stream:
            os.chmod(path, 0o600)
            json.dump(content, stream, indent=2)
        return path

    def validate(self):
        if self.git("rev-parse", "--show-toplevel") != str(self.root):
            raise SmokeError("Unexpected project root")
        if self.git("branch", "--show-current") != "public":
            raise SmokeError("Activation requires public branch, not detached HEAD")
        for executable in ("git", "az", "ansible-playbook", "ssh", "ssh-keygen", "curl"):
            if not shutil.which(executable):
                raise SmokeError(f"Required tool unavailable: {executable}")
        self.git("remote", "get-url", "forgejo")
        account = self.az("account", "show")
        if account.get("id", "").lower() != SUBSCRIPTION or account.get("state") != "Enabled":
            raise SmokeError("Approved subscription must be enabled and authenticated")

    def commit_and_push(self):
        staged = set(filter(None, self.git("diff", "--cached", "--name-only", "-z").split("\0")))
        if staged - set(APPROVED_PATHS):
            raise SmokeError(f"Unexpected staged paths: {sorted(staged - set(APPROVED_PATHS))}")
        self.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests",
                  "-p", "test_azure_provider.py"], timeout=180)
        for playbook in ("infrastructure", "cleanup"):
            self.run(["ansible-playbook", "--syntax-check", f"providers/Azure/{playbook}.yml"])
        self.git("add", "--", *APPROVED_PATHS)
        staged = set(filter(None, self.git("diff", "--cached", "--name-only", "-z").split("\0")))
        if staged - set(APPROVED_PATHS):
            raise SmokeError("Unexpected content staged during checks")
        if staged:
            self.git("commit", "-m", "Add recoverable Azure infrastructure provisioning and smoke validation", timeout=180)
        if self.git("diff", "--cached", "--name-only"):
            raise SmokeError("Commit left staged changes")
        if self.git("diff", "HEAD", "--name-only", "--", *APPROVED_PATHS):
            raise SmokeError("Approved source differs from committed revision")
        sha = self.git("rev-parse", "HEAD")
        self.git("push", "--set-upstream", "forgejo", "public", timeout=180)
        remote = self.git("ls-remote", "--exit-code", "forgejo", "refs/heads/public").split()
        if not remote or remote[0] != sha:
            raise SmokeError("forgejo/public is not the exact deployment commit")
        if self.git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}") != "forgejo/public":
            raise SmokeError("Unexpected upstream after push")
        return sha

    def archive(self, sha, deployment_id):
        self.evidence = self.root / "logs" / "azure-smoke" / deployment_id
        self.evidence.mkdir(parents=True, mode=0o700)
        archive = self.evidence / f"{sha}.tar"
        self.git("archive", "--format=tar", f"--output={archive}", sha)
        source = self.evidence / "source"
        source.mkdir(mode=0o700)
        with tarfile.open(archive) as bundle:
            bundle.extractall(source, filter="data")
        if (source / "scripts/deploy_azure_smoke.py").read_bytes() != Path(__file__).read_bytes():
            raise SmokeError("Running script differs from the archived commit")
        self.record("artifact.json", {"commit": sha, "archive": str(archive), "source": str(source)})
        return source

    def baseline(self, group):
        if self.az("group", "exists", "--name", group) is not False:
            raise SmokeError("Smoke requires a resource group that does not exist")
        self.record("baseline.json", {"subscription": SUBSCRIPTION, "resource_group": group, "exists": False})

    def worker(self, source, operation, config, timeout=60):
        config_path = self.record("config.json", config)
        return self.run([sys.executable, "-B", str(source / "scripts/deploy_azure_smoke.py"),
                         "--worker", operation, "--config", str(config_path)],
                        cwd=source, timeout=timeout)

    def register_and_preflight(self, source, config):
        self.deadline = time.monotonic() + 600
        for namespace in ("Microsoft.Compute", "Microsoft.Network"):
            current = self.az("provider", "show", "--namespace", namespace)
            if current.get("registrationState") != "Registered":
                self.az("provider", "register", "--namespace", namespace)
            while self.az("provider", "show", "--namespace", namespace).get("registrationState") != "Registered":
                time.sleep(min(5, remaining(self.deadline)))
        sku = self.find_sku()
        if sku.get("restrictions"):
            raise SmokeError("Approved VM size unavailable/restricted; no fallback permitted")
        capabilities = {item["name"]: item["value"] for item in sku["capabilities"]}
        cores = nonnegative_count(capabilities.get("vCPUs"), "SKU vCPUs")
        if cores == 0:
            raise SmokeError("Approved SKU must require at least one vCPU")
        usage = self.az("vm", "list-usage", "--location", LOCATION)
        quota_names = {"cores", sku["family"].lower()}
        found = set()
        for quota in usage:
            name = quota.get("name", {}).get("value", "").lower()
            if name in quota_names:
                found.add(name)
                current = nonnegative_count(quota.get("currentValue"), f"{name} currentValue")
                limit = nonnegative_count(quota.get("limit"), f"{name} limit")
                if current + cores > limit:
                    raise SmokeError(f"Insufficient quota: {name}")
        if found != quota_names:
            raise SmokeError("Could not verify regional and VM-family vCPU quotas")
        self.az("vm", "image", "show", "--location", LOCATION, "--urn", IMAGE)
        policies = self.az("policy", "assignment", "list", "--scope", f"/subscriptions/{SUBSCRIPTION}", "--disable-scope-strict-match")
        self.record("policy-assignments.json", policies)
        self.worker(source, "render", config)
        template = json.loads((self.evidence / "rendered-template.json").read_text())
        envelope = {
            "$schema": "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [
                {"type": "Microsoft.Resources/resourceGroups", "apiVersion": "2024-03-01",
                 "name": config["azure_resource_group"], "location": LOCATION,
                 "tags": template["resources"][0]["tags"]},
                {"type": "Microsoft.Resources/deployments", "apiVersion": "2022-09-01",
                 "name": config["deployment_id"], "resourceGroup": config["azure_resource_group"],
                 "dependsOn": [f"[subscriptionResourceId('Microsoft.Resources/resourceGroups', '{config['azure_resource_group']}')]"],
                 "properties": {"mode": "Incremental", "expressionEvaluationOptions": {"scope": "inner"}, "template": template}},
            ],
        }
        path = self.record("preflight-template.json", envelope)
        self.az("deployment", "sub", "validate", "--name", config["deployment_id"],
                "--location", LOCATION, "--template-file", str(path), "--validation-level", "Provider")

    def find_sku(self):
        # CLI list-skus eagerly retrieves the entire catalogue. Page the same API
        # and stop at the exact approved SKU, keeping each request below 60 seconds.
        prefix = f"https://management.azure.com/subscriptions/{SUBSCRIPTION}/"
        url = prefix + "providers/Microsoft.Compute/skus?api-version=2021-07-01&$filter=location%20eq%20%27eastus%27"
        while url:
            if not url.startswith(prefix):
                raise SmokeError("Unexpected Azure SKU pagination URL")
            page = self.az("rest", "--method", "get", "--url", url)
            matches = [sku for sku in page["value"] if sku.get("name") == SIZE
                       and sku.get("resourceType") == "virtualMachines"]
            if len(matches) == 1:
                return matches[0]
            if matches:
                raise SmokeError("Ambiguous approved Azure SKU")
            url = page.get("nextLink")
        raise SmokeError("Approved Azure SKU was not returned")

    def verify(self, config, source):
        group = config["azure_resource_group"]
        vms = self.az("vm", "list", "--resource-group", group)
        if len(vms) != 1:
            raise SmokeError("Expected exactly one VM")
        vm = vms[0]
        storage = vm["storageProfile"]
        image, disk = storage["imageReference"], storage["osDisk"]
        if (vm["hardwareProfile"]["vmSize"] != SIZE or image["publisher"].lower() != "canonical"
                or image["offer"] != "ubuntu-24_04-lts" or image["sku"] != "server"):
            raise SmokeError("VM differs from approved size/image")
        # Current CLI uses diskSizeGB; older serializers used diskSizeGb. Fail
        # closed if either present spelling conflicts or isn't an integer 32.
        disk_sizes = [disk[key] for key in ("diskSizeGB", "diskSizeGb") if key in disk]
        if (not disk_sizes or any(type(size) is not int or size != 32 for size in disk_sizes)
                or disk["managedDisk"]["storageAccountType"] != "StandardSSD_LRS"):
            raise SmokeError("OS disk differs from approved disk")
        if not vm["osProfile"]["linuxConfiguration"]["disablePasswordAuthentication"]:
            raise SmokeError("VM allows SSH password authentication")
        if not vm["diagnosticsProfile"]["bootDiagnostics"]["enabled"]:
            raise SmokeError("Boot diagnostics are disabled")
        ips = self.az("network", "public-ip", "list", "--resource-group", group)
        if len(ips) != 1 or ips[0]["sku"]["name"] != "Standard" or ips[0]["publicIPAllocationMethod"] != "Static":
            raise SmokeError("Expected one Standard static public IPv4")
        address = public_ipv4(ips[0]["ipAddress"])
        nsgs = self.az("network", "nsg", "list", "--resource-group", group)
        if len(nsgs) != 1:
            raise SmokeError("Expected one SSH-restricted network security group")
        rules = nsgs[0]["securityRules"]
        allows = [rule for rule in rules if rule["direction"] == "Inbound" and rule["access"] == "Allow"]
        if (len(allows) != 1 or allows[0]["sourceAddressPrefix"] != public_ipv4(config["operator_ip"]) + "/32"
                or allows[0]["destinationPortRange"] != "22" or allows[0]["protocol"].lower() != "tcp"):
            raise SmokeError("NSG does not restrict SSH to the operator /32")
        if not any(rule["direction"] == "Inbound" and rule["access"] == "Deny"
                   and rule.get("sourceAddressPrefix") == "*" and rule.get("destinationPortRange") == "*"
                   and rule["priority"] > allows[0]["priority"] for rule in rules):
            raise SmokeError("NSG lacks an explicit deny for other inbound traffic")
        ssh = ["ssh", "-F", "/dev/null", "-i", config["ssh_private_key_path"],
               "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10",
               "-o", "StrictHostKeyChecking=accept-new", "-o", "GlobalKnownHostsFile=/dev/null",
               "-o", f"UserKnownHostsFile={self.evidence / 'known_hosts'}",
               f"{vm['osProfile']['adminUsername']}@{address}",
               "test \"$(. /etc/os-release; printf '%s' \"$VERSION_ID\")\" = 24.04 && "
               "systemctl is-active systemd-journald && sudo -n /usr/sbin/sshd -T | grep -q '^passwordauthentication no$'"]
        while True:
            try:
                self.run(ssh, timeout=30)
                break
            except SmokeError as error:
                if not any(message in str(error).lower() for message in ("connection refused", "connection timed out", "connection reset")):
                    raise
                time.sleep(min(5, remaining(self.deadline)))
        before = sorted(resource["id"].lower() for resource in self.az("resource", "list", "--resource-group", group))
        self.worker(source, "deploy", config, timeout=remaining(self.deadline, 1800))
        repeated = self.az("vm", "list", "--resource-group", group)
        after = sorted(resource["id"].lower() for resource in self.az("resource", "list", "--resource-group", group))
        if len(repeated) != 1 or repeated[0]["id"] != vm["id"] or before != after:
            raise SmokeError("Repeat deployment changed resource identities or VM count")
        self.record("validation.json", {"vm_id": vm["id"], "resource_ids": after, "ssh": "passed", "repeat": "passed"})

    def cleanup(self, source, config):
        self.cleaning = True
        self.deadline = time.monotonic() + 600
        config["azure_deadline"] = self.deadline
        config["azure_cleanup_deadline"] = self.deadline
        config["azure_cleanup_timeout_seconds"] = 600
        try:
            # Preserve ARM failure details before deleting the temporary group.
            # Diagnostic failures never prevent ownership-checked cleanup.
            for args in (
                ("deployment", "group", "show", "--resource-group", config["azure_resource_group"], "--name", config["deployment_id"]),
                ("deployment", "operation", "group", "list", "--resource-group", config["azure_resource_group"], "--name", config["deployment_id"]),
            ):
                try:
                    self.az(*args)
                except Exception as diagnostic_error:
                    self.record("diagnostic-error.json", {"error": str(diagnostic_error)})
            self.worker(source, "cleanup", config, timeout=remaining(self.deadline, 600))
            if self.az("group", "exists", "--name", config["azure_resource_group"]) is not False:
                raise SmokeError("Cleanup returned without confirmed group deletion")
            self.record("cleanup.json", {"confirmed_absent": True, "resource_group": config["azure_resource_group"]})
            return True
        except BaseException as error:
            self.deadline = time.monotonic() + 60  # Bounded read-only diagnostics after cleanup.
            residual = [{"id": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{config['azure_resource_group']}", "status": "unknown"}]
            try:
                residual = self.az("resource", "list", "--resource-group", config["azure_resource_group"])
            except Exception:
                pass
            self.record("cleanup-failure.json", {"error": str(error), "residual_resources": residual})
            print(f"Cleanup failed; retained state and residual IDs: {json.dumps(residual)}", file=sys.stderr)
            return False


def worker_main(operation, config_file):
    """Internal worker runs the already verified source artifact, never the dirty tree."""
    sys.path.insert(0, str(ROOT))
    config_path = Path(config_file).resolve()
    artifact = json.loads(config_path.with_name("artifact.json").read_text())
    baseline = json.loads(config_path.with_name("baseline.json").read_text())
    if Path(artifact["source"]).resolve() != ROOT or baseline["exists"] is not False:
        raise SmokeError("Worker requires the committed artifact and absent-group baseline")
    config = json.loads(config_path.read_text())
    if (config["azure_subscription_id"] != SUBSCRIPTION or config["azure_location"] != LOCATION
            or config["azure_vm_size"] != SIZE or baseline["resource_group"] != config["azure_resource_group"]):
        raise SmokeError("Worker configuration differs from approved target")
    from utils import azure_utils
    if operation == "key":
        if not azure_utils.prepare_ssh_key(config):
            raise SmokeError("Could not generate deployment SSH key")
    elif operation == "render":
        state = azure_utils.load_state(config["deployment_id"], config["azure_state_dir"])
        template = azure_utils.render_template({**config, **state})
        config_path.with_name("rendered-template.json").write_text(json.dumps(template))
    elif operation == "deploy":
        from utils.deployment_engine import deploy_infrastructure
        if not deploy_infrastructure(config):
            raise SmokeError("Infrastructure deployment failed")
    elif operation == "cleanup":
        from utils.cleanup_engine import execute_teardown
        if not execute_teardown(config):
            raise SmokeError("Ownership-checked infrastructure cleanup failed")


def activate(operator_ip=None, prepare_only=False):
    runner = Runner()
    previous = {sig: signal.signal(sig, runner.handle_signal) for sig in (signal.SIGINT, signal.SIGTERM)}
    source = config = None
    state_started = passed = preflight_passed = False
    cleanup_ok = True
    try:
        runner.validate()
        operator_ip = public_ipv4(operator_ip or runner.run(["curl", "-4", "--fail", "--silent", "--show-error", "--max-time", "15", "https://api.ipify.org"]))
        sha = runner.commit_and_push()
        deployment_id = f"azsmoke-{uuid.uuid4().hex[:12]}"
        source = runner.archive(sha, deployment_id)
        key = Path.home() / ".ssh" / f"c2deploy_{deployment_id}"
        if key.exists() or Path(str(key) + ".pub").exists():
            raise SmokeError("Refusing to reuse an existing smoke SSH key")
        config = {
            "provider": "azure", "deployment_type": "infrastructure", "infrastructure_deployment": True,
            "deployment_id": deployment_id, "azure_resource_group": f"c2itall-{deployment_id}",
            "azure_subscription_id": SUBSCRIPTION, "azure_location": LOCATION, "azure_vm_size": SIZE,
            "operator_ip": operator_ip, "ssh_key_path": str(key) + ".pub",
            "ssh_private_key_path": str(key), "ssh_key_generated": True,
            "azure_state_dir": str(runner.root / "deployments" / "azure"),
            "azure_timeout_seconds": 1800, "azure_cleanup_timeout_seconds": 600,
        }
        runner.baseline(config["azure_resource_group"])
        state_started = True
        runner.worker(source, "key", config)
        runner.register_and_preflight(source, config)
        preflight_passed = True
        if not prepare_only:
            runner.deadline = time.monotonic() + 1800  # Before the first possible group mutation.
            config["azure_deadline"] = runner.deadline
            runner.worker(source, "deploy", config, timeout=remaining(runner.deadline, 1800))
            runner.verify(config, source)
        passed = True
    except BaseException as error:
        print(f"Azure smoke did not pass: {error}", file=sys.stderr)
        if runner.evidence:
            runner.record("failure.json", {"error": str(error)})
    finally:
        if state_started:
            cleanup_ok = runner.cleanup(source, config)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    result = passed and cleanup_ok and not runner.interrupted
    if runner.evidence:
        runner.record("result.json", {
            "mode": "prepare" if prepare_only else "activate",
            "prepared": result and prepare_only, "passed": result and not prepare_only,
            "preflight_passed": preflight_passed,
            "validation_passed": passed and not prepare_only, "cleanup_passed": cleanup_ok,
        })
        print(f"Evidence: {runner.evidence}")
    if result and prepare_only:
        print("Azure preparation passed (prepared=true); no resource group or VM created. Local test key removed; provider registrations remain enabled.")
    elif result:
        print("Azure smoke passed; temporary group and generated key removed. Provider registrations remain enabled.")
    return 0 if result else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--activate", action="store_true")
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    parser.add_argument("--operator-ip", help="Workstation public IPv4; otherwise resolve via api.ipify.org")
    parser.add_argument("--worker", choices=("key", "render", "deploy", "cleanup"), help=argparse.SUPPRESS)
    parser.add_argument("--config", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker:
        if args.activate or args.prepare or args.dry_run or not args.config:
            parser.error("Internal worker requires only its operation and configuration")
        worker_main(args.worker, args.config)
        return 0
    if not (args.activate or args.prepare):
        print(f"DRY RUN: no commands or mutations. Target: {SUBSCRIPTION} / {LOCATION} / {SIZE}")
        for index, phase in enumerate(PHASES, 1):
            print(f"{index}. {phase}")
        print("Activation includes two existing local public commits. SIGKILL/workstation loss requires fresh-process teardown.")
        return 0
    return activate(args.operator_ip, prepare_only=args.prepare)


if __name__ == "__main__":
    sys.exit(main())
