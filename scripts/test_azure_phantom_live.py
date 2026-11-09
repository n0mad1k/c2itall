#!/usr/bin/env python3
"""Real Azure Phantom/chat test: deploy, repeat, verify service, and clean up."""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import sys
import time
from unittest import mock
from urllib.parse import quote
import uuid
import zipfile

from deploy_azure_smoke import (IMAGE, LOCATION, SIZE, SUBSCRIPTION, Runner,
                                SmokeError, nonnegative_count, public_ipv4,
                                remaining)


ROOT = Path(__file__).resolve().parents[1]
PHANTOM_ROOT = ROOT / "ghost_protocol" / "phantom"
STATE_DIR = ROOT / "deployments" / "azure"
EMAIL_IMAGE = "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest"
SERVICES = ("vpn", "matrix", "matrix_rotation", "tak", "dns", "cloud", "vault",
            "media", "email", "all_in_one")


class LiveTestError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise LiveTestError(message)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_committed_source(runner):
    parent_paths = (
        "README.md", "providers/Azure/templates/infrastructure.json.j2",
        "modules/chat-server/deploy_chat.py",
        "modules/chat-server/rotate_matrix.py",
        "modules/chat-server/chat_addons.yml",
        "modules/chat-server/tak_server.yml",
        "modules/chat-server/templates",
        "scripts/test_azure_phantom_live.py", "tests/test_azure_provider.py",
        "utils/vm_workloads.py", "utils/azure_cloud.py", "modules/phantom/workload.py", "utils/azure_utils.py",
        "utils/provider_registry.py",
    )
    for path in parent_paths:
        runner.run(["git", "diff", "--quiet", "HEAD", "--", path])
    for path in ("phantom/phantom.py", "phantom/test_phantom.py",
                 "phantom/modules", "phantom/playbooks/common",
                 "phantom/playbooks/matrix", "phantom/playbooks/vpn",
                 "phantom/playbooks/dns", "phantom/playbooks/cloud",
                 "phantom/playbooks/vault", "phantom/playbooks/media",
                 "phantom/playbooks/email", "phantom/playbooks/all_in_one"):
        runner.run(["git", "-C", str(ROOT / "ghost_protocol"), "diff", "--quiet",
                    "HEAD", "--", path])
    return {
        "parent": runner.run(["git", "rev-parse", "HEAD"]),
        "ghost_protocol": runner.run(
            ["git", "-C", str(ROOT / "ghost_protocol"), "rev-parse", "HEAD"]),
    }


def preflight(runner, config):
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
    image = EMAIL_IMAGE if config["server_type"] == "email" else IMAGE
    runner.az("vm", "image", "show", "--location", LOCATION, "--urn", image)


def expected_allow_rules(config):
    operator = public_ipv4(config["operator_ip"]) + "/32"
    service = config["server_type"]
    if service == "all_in_one":
        rules = {("tcp", "22", operator)}
        for component in config["services"]:
            component_config = dict(config, server_type=component,
                                    provider_workload="phantom")
            rules.update(expected_allow_rules(component_config))
        return rules
    if service == "vpn":
        return {("tcp", "22", operator), ("udp", "51820", "*")}
    if service == "dns":
        return {("tcp", "22", operator), ("tcp", "53", operator),
                ("udp", "53", operator), ("tcp", "80", operator),
                ("tcp", "443", operator)}
    if service in ("matrix", "matrix_rotation"):
        rules = {("tcp", "22", operator), ("tcp", "80", "*"),
                 ("tcp", "443", "*"), ("tcp", "8448", "*")}
        if config.get("provider_workload") == "chat":
            rules.add(("udp", "41641", "*"))
        return rules
    if service == "tak":
        rules = {("tcp", "22", operator), ("tcp", "8089", "*"),
                 ("tcp", "8443", "*"), ("tcp", "8446", "*"),
                 ("udp", "41641", "*")}
        if config.get("tak_federation"):
            rules.add(("tcp", "8444", "*"))
        return rules
    if service == "email":
        return {("tcp", "22", operator), ("tcp", "80", "*"),
                ("tcp", "443", "*"), ("tcp", "25", "*"),
                ("tcp", "465", "*"), ("tcp", "587", "*"),
                ("tcp", "993", "*"), ("tcp", "4190", "*"),
                ("tcp", "53", "*"), ("udp", "53", "*")}
    if service in ("cloud", "vault", "media"):
        return {("tcp", "22", operator), ("tcp", "80", "*"),
                ("tcp", "443", "*")}
    raise LiveTestError(f"No expected Azure allowlist for {service}")


def resource_snapshot(runner, config):
    group = config["azure_resource_group"]
    vms = runner.az("vm", "list", "--resource-group", group)
    require(len(vms) == 1, "Expected exactly one Phantom VM")
    vm = vms[0]
    image = vm["storageProfile"]["imageReference"]
    disk = vm["storageProfile"]["osDisk"]
    require(vm["hardwareProfile"]["vmSize"] == SIZE, "Unexpected Phantom VM size")
    expected_image = ({
        "publisher": "canonical", "offer": "0001-com-ubuntu-server-jammy",
        "sku": "22_04-lts-gen2",
    } if config["server_type"] == "email" else {
        "publisher": "canonical", "offer": "ubuntu-24_04-lts", "sku": "server",
    })
    require(image["publisher"].lower() == expected_image["publisher"]
            and image["offer"] == expected_image["offer"]
            and image["sku"] == expected_image["sku"],
            "Unexpected Phantom VM image")
    disk_sizes = [disk[key] for key in ("diskSizeGB", "diskSizeGb") if key in disk]
    expected_disk_gb = int(config.get("azure_os_disk_gb", 32))
    require(disk_sizes and all(size == expected_disk_gb for size in disk_sizes)
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
    expected = expected_allow_rules(config)
    require(allows == expected, "Azure NSG does not match the Phantom service allowlist")
    require(any(rule["direction"] == "Inbound" and rule["access"] == "Deny"
                and rule.get("sourceAddressPrefix") == "*"
                and rule.get("destinationPortRange") == "*"
                and rule["priority"] > 110 for rule in rules),
            "Azure NSG lacks the final inbound deny")

    resources = runner.az("resource", "list", "--resource-group", group)
    return {"vm_id": vm["id"], "public_ip": address,
            "resource_ids": sorted(resource["id"].lower() for resource in resources),
            "allow_rules": sorted([list(rule) for rule in allows])}


def run_ssh(runner, config, command, timeout=120):
    return runner.run([
        "ssh", "-F", "/dev/null", "-i", config["ssh_key"],
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"UserKnownHostsFile={runner.evidence / 'known_hosts'}",
        f"azureuser@{config['target_host']}", command,
    ], timeout=timeout)


def service_domain(config, service):
    return config.get("service_domains", {}).get(service, config.get("domain", ""))


def https_get(runner, config, service, path):
    domain = service_domain(config, service)
    require(domain, f"{service} live verification requires a domain")
    return runner.run([
        "curl", "-k", "--fail", "--silent", "--show-error", "--max-time", "20",
        "--resolve", f"{domain}:443:{config['target_host']}",
        f"https://{domain}{path}",
    ])


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


def verify_matrix(runner, config):
    address = config["target_host"]
    domain = config["domain"]
    admin = f"@{config['matrix_admin_user']}:{config['matrix_server_name']}"
    python_check = (
        "import sqlite3,sys;"
        "db=sqlite3.connect('/var/lib/matrix-synapse/homeserver.db');"
        f"row=db.execute(\"select count(*) from users where name='{admin}'\").fetchone();"
        "sys.exit(0 if row and row[0] == 1 else 1)"
    )
    command = (
        "set -eu; "
        "test \"$(systemctl is-active matrix-synapse)\" = active; "
        "test \"$(systemctl is-enabled matrix-synapse)\" = enabled; "
        "test \"$(systemctl is-active nginx)\" = active; "
        "test \"$(systemctl is-active tailscaled)\" = active; "
        "test \"$(systemctl is-enabled tailscaled)\" = enabled; "
        "sudo -n test -s /var/www/element/index.html; "
        f"sudo -n test -s /etc/ssl/certs/{domain}-selfsigned.crt; "
        "sudo -n test -s /etc/systemd/system/matrix-bot@.service; "
        "sudo -n /opt/matrix-bots/venv/bin/python -c 'import nio'; "
        f"sudo -n python3 -c {json.dumps(python_check)}; "
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
    versions = runner.run([
        "curl", "-k", "--fail", "--silent", "--show-error", "--max-time", "15",
        "--resolve", f"{domain}:443:{address}",
        f"https://{domain}/_matrix/client/versions",
    ])
    parsed = json.loads(versions)
    require(isinstance(parsed.get("versions"), list) and parsed["versions"],
            "Matrix client versions endpoint returned invalid JSON")
    element_status = runner.run([
        "curl", "-k", "--silent", "--show-error", "--max-time", "15",
        "--output", "/dev/null", "--write-out", "%{http_code}",
        "--resolve", f"{domain}:443:{address}", f"https://{domain}/",
    ])
    require(element_status == "200", "Element Web did not return HTTP 200")
    federation = runner.run([
        "curl", "-k", "--fail", "--silent", "--show-error", "--max-time", "15",
        "--resolve", f"{domain}:8448:{address}",
        f"https://{domain}:8448/_matrix/federation/v1/version",
    ])
    require(isinstance(json.loads(federation).get("server"), dict),
            "Matrix federation endpoint returned invalid JSON")
    return {"synapse_active": True, "synapse_enabled": True,
            "nginx_active": True, "element_http_status": 200,
            "client_api": True, "federation_api": True,
            "admin_user": True, "self_signed_tls": True,
            "tailscaled_active": True, "tailscaled_enabled": True,
            "bot_runtime": True, "bot_unit_template": True,
            "ssh_password_authentication": False}


def verify_dns(runner, config):
    active = run_ssh(runner, config, "systemctl is-active pihole-FTL")
    require(active == "active", f"Pi-hole FTL is not active: {active}")
    enabled = run_ssh(runner, config, "systemctl is-enabled pihole-FTL")
    require(enabled == "enabled", f"Pi-hole FTL is not enabled: {enabled}")
    password_mode = run_ssh(
        runner, config,
        "sudo -n test -s /etc/pihole/.phantom_password && "
        "sudo -n stat -c %a /etc/pihole/.phantom_password")
    require(password_mode == "600",
            f"Pi-hole password mode is not owner-only: {password_mode}")
    run_ssh(runner, config, "sudo -n pihole status")
    sockets = run_ssh(runner, config, "sudo -n ss -lntuH")
    require(any(token.endswith(":53") for line in sockets.splitlines()
                for token in line.split()), "Pi-hole is not listening on port 53")
    ssh_password = run_ssh(
        runner, config,
        "sudo -n /usr/sbin/sshd -T | sed -n 's/^passwordauthentication //p'")
    require(ssh_password == "no", "SSH password authentication remains enabled")
    dns_probe = (
        "import socket,struct,sys;"
        "host=sys.argv[1];"
        "q=b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00'"
        "+b'\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01';"
        "s=socket.create_connection((host,53),10);"
        "s.sendall(struct.pack('!H',len(q))+q);"
        "n=struct.unpack('!H',s.recv(2))[0];"
        "data=b'';"
        "\nwhile len(data)<n:\n data+=s.recv(n-len(data))\n"
        "assert data[:2]==b'\\x12\\x34' and data[2]&128 and data[3]&15==0"
    )
    runner.run([sys.executable, "-c", dns_probe, config["target_host"]], timeout=30)
    return {"pihole_active": True, "pihole_enabled": True,
            "dns_tcp_public": True, "admin_password_owner_only": True,
            "ssh_password_authentication": False}


def verify_cloud(runner, config):
    command = (
        "set -eu; "
        "php_ver=$(php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;'); "
        "test \"$(systemctl is-active mariadb)\" = active; "
        "test \"$(systemctl is-enabled mariadb)\" = enabled; "
        "test \"$(systemctl is-active redis-server)\" = active; "
        "test \"$(systemctl is-enabled redis-server)\" = enabled; "
        "test \"$(systemctl is-active php${php_ver}-fpm)\" = active; "
        "test \"$(systemctl is-active nginx)\" = active; "
        "test \"$(systemctl is-active nextcloud-cron.timer)\" = active; "
        "test \"$(systemctl is-enabled nextcloud-cron.timer)\" = enabled; "
        "sudo -n test -s /var/www/nextcloud/.admin_password; "
        "test \"$(sudo -n stat -c %a /var/www/nextcloud/.admin_password)\" = 600; "
        "sudo -n -u www-data php /var/www/nextcloud/occ status --output=json "
        "| grep -Eq '\"installed\"[[:space:]]*:[[:space:]]*true'; "
        "sudo -n /usr/sbin/sshd -T | grep -q '^passwordauthentication no$'"
    )
    run_ssh(runner, config, command)
    status = json.loads(https_get(runner, config, "cloud", "/status.php"))
    require(status.get("installed") is True, "Nextcloud status endpoint is not installed")
    return {"nextcloud_installed": True, "mariadb_active": True,
            "redis_active": True, "php_fpm_active": True, "nginx_active": True,
            "cron_timer_active": True, "https_status": True,
            "ssh_password_authentication": False}


def verify_vault(runner, config):
    command = (
        "set -eu; "
        "test \"$(systemctl is-active vaultwarden)\" = active; "
        "test \"$(systemctl is-enabled vaultwarden)\" = enabled; "
        "test \"$(systemctl is-active nginx)\" = active; "
        "sudo -n test -s /opt/vaultwarden/.env; "
        "test \"$(sudo -n stat -c %a /opt/vaultwarden/.env)\" = 600; "
        "curl --fail --silent --show-error http://127.0.0.1:8081/alive >/dev/null; "
        "sudo -n /usr/sbin/sshd -T | grep -q '^passwordauthentication no$'"
    )
    run_ssh(runner, config, command)
    require(https_get(runner, config, "vault", "/alive"),
            "Vaultwarden HTTPS health endpoint returned no body")
    return {"vaultwarden_active": True, "vaultwarden_enabled": True,
            "nginx_active": True, "environment_owner_only": True,
            "https_health": True, "ssh_password_authentication": False}


def verify_media(runner, config):
    command = (
        "set -eu; "
        "test \"$(systemctl is-active jellyfin)\" = active; "
        "test \"$(systemctl is-enabled jellyfin)\" = enabled; "
        "test \"$(systemctl is-active nginx)\" = active; "
        "sudo -n test -d /srv/media; "
        "curl --fail --silent --show-error "
        "http://127.0.0.1:8096/System/Info/Public >/dev/null; "
        "sudo -n /usr/sbin/sshd -T | grep -q '^passwordauthentication no$'"
    )
    run_ssh(runner, config, command)
    status = json.loads(https_get(runner, config, "media", "/System/Info/Public"))
    require(status.get("Version"), "Jellyfin public status endpoint is invalid")
    return {"jellyfin_active": True, "jellyfin_enabled": True,
            "nginx_active": True, "media_library_present": True,
            "https_status": True, "ssh_password_authentication": False}


def verify_email(runner, config):
    command = (
        "set -eu; "
        "sudo -n test -s /etc/mailinabox.conf; "
        "sudo -n test -s /root/.miab_admin_password; "
        "test \"$(sudo -n stat -c %a /root/.miab_admin_password)\" = 600; "
        "test \"$(systemctl is-active postfix)\" = active; "
        "test \"$(systemctl is-active dovecot)\" = active; "
        "test \"$(systemctl is-active nginx)\" = active; "
        "sudo -n ss -lnt | grep -Eq '[:.]25[[:space:]]'; "
        "sudo -n ss -lnt | grep -Eq '[:.]993[[:space:]]'; "
        "sudo -n /usr/sbin/sshd -T | grep -q '^passwordauthentication no$'"
    )
    run_ssh(runner, config, command)
    tcp_probe = (
        "import socket,sys;"
        "host=sys.argv[1];"
        "ports=(25,443,993);"
        "\nfor port in ports:\n"
        " s=socket.create_connection((host,port),10); s.close()\n"
    )
    runner.run([sys.executable, "-c", tcp_probe, config["target_host"]], timeout=45)
    return {"mailinabox_configured": True, "postfix_active": True,
            "dovecot_active": True, "nginx_active": True,
            "public_mail_ports": True, "admin_password_owner_only": True,
            "ssh_password_authentication": False}


def verify_tak(runner, config):
    admin = config["tak_admin_name"]
    command = (
        "set -eu; "
        "test \"$(systemctl is-active takserver)\" = active; "
        "test \"$(systemctl is-enabled takserver)\" = enabled; "
        "test \"$(systemctl is-active tailscaled)\" = active; "
        "test \"$(systemctl is-enabled tailscaled)\" = enabled; "
        "test \"$(dpkg-query -W -f='${Version}' takserver)\" = 5.7-RELEASE14; "
        "sudo -n test -s /opt/tak/CoreConfig.xml; "
        "test \"$(sudo -n stat -c %a /opt/tak/CoreConfig.xml)\" = 600; "
        "sudo -n test -s /opt/tak/certs/files/" + admin + ".p12; "
        "for port in 8089 8443 8446; do ss -ltn | grep -q \":${port} \"; done; "
        "sudo -n sh -c '. /opt/tak/certs/cert-metadata.sh; "
        "curl --fail --silent --show-error --insecure --cert-type P12 "
        "--cert \"/opt/tak/certs/files/" + admin + ".p12:${PASS}\" "
        "https://127.0.0.1:8443/Marti/api/version'; "
        "sudo -n /usr/sbin/sshd -T | grep -q '^passwordauthentication no$'"
    )
    version = run_ssh(runner, config, command, timeout=180)
    require(version.strip(), "TAK administration API returned no version data")
    tcp_probe = (
        "import socket,sys;"
        "host=sys.argv[1];"
        "ports=(8089,8443,8446);"
        "\nfor port in ports:\n"
        " s=socket.create_connection((host,port),10); s.close()\n"
    )
    runner.run([sys.executable, "-c", tcp_probe, config["target_host"]], timeout=45)
    artifact_dir = Path(config["tak_artifact_dir"])
    expected = {
        f"tak-connection-{config['deployment_id']}.zip",
        f"tak-admin-{config['deployment_id']}.p12",
        f"tak-ca-{config['deployment_id']}.pem",
    }
    require({path.name for path in artifact_dir.iterdir()} == expected,
            "TAK fetched artifact set is incomplete or unexpected")
    require(all((path.stat().st_mode & 0o777) == 0o600
                for path in artifact_dir.iterdir()),
            "TAK fetched artifacts are not owner-only")
    connection = artifact_dir / f"tak-connection-{config['deployment_id']}.zip"
    with zipfile.ZipFile(connection) as archive:
        require({"MANIFEST/manifest.xml", "config.pref", "client.p12", "caCert.p12"}
                <= set(archive.namelist()),
                "TAK connection package is missing required entries")
    return {"takserver_active": True, "takserver_enabled": True,
            "tailscaled_active": True, "public_tls_ports": [8089, 8443, 8446],
            "admin_api": True, "connection_package": True,
            "artifacts_owner_only": True, "ssh_password_authentication": False}


def verify_service(runner, config):
    if config["server_type"] == "vpn":
        return verify_wireguard(runner, config)
    if config["server_type"] == "matrix":
        return verify_matrix(runner, config)
    if config["server_type"] == "tak":
        return verify_tak(runner, config)
    if config["server_type"] == "dns":
        return verify_dns(runner, config)
    if config["server_type"] == "cloud":
        return verify_cloud(runner, config)
    if config["server_type"] == "vault":
        return verify_vault(runner, config)
    if config["server_type"] == "media":
        return verify_media(runner, config)
    if config["server_type"] == "email":
        return verify_email(runner, config)
    if config["server_type"] == "all_in_one":
        return {"wireguard": verify_wireguard(runner, config),
                "vaultwarden": verify_vault(runner, config)}
    raise LiveTestError(f"No live service verifier for {config['server_type']}")


def verify_service_log_redaction(phantom, deployment_id, config):
    log = phantom.PHANTOM_LOGS / f"deployment_{deployment_id}.log"
    require(log.is_file(), "Phantom deployment log is missing")
    content = log.read_text(errors="replace")
    forbidden = ["PrivateKey =", "PresharedKey ="]
    for key in ("matrix_admin_password", "matrix_signing_key",
                "matrix_form_secret", "matrix_macaroon_secret",
                "tailscale_auth_key", "vault_admin_token",
                "tak_cert_password", "tak_ca_password"):
        if config.get(key):
            forbidden.append(str(config[key]))
    require(not any(value in content for value in forbidden),
            "Phantom deployment log contains service key material")
    return {"service_key_material_absent": True}


def service_config(service):
    if service == "vpn":
        return {
            "provider_workload": "phantom", "vpn_port": 51820,
            "vpn_client_count": 1, "vpn_dns": "1.1.1.1",
            "vpn_subnet": "10.66.66.0/24", "vpn_allowed_ips": "0.0.0.0/0",
        }
    if service == "matrix":
        return {
            "provider_workload": "chat", "domain": "matrix.test",
            "matrix_server_name": "matrix.test", "matrix_admin_user": "liveadmin",
            "matrix_admin_password": secrets.token_urlsafe(24),
            "matrix_registration": False, "matrix_element_web": True,
            "matrix_signing_key": secrets.token_hex(32),
            "matrix_form_secret": secrets.token_hex(32),
            "matrix_macaroon_secret": secrets.token_hex(32),
            "tailscale_auth_key": "", "enable_bot_support": True,
        }
    if service == "matrix_rotation":
        config = service_config("matrix")
        config.update(domain="matrix-1.test", matrix_server_name="matrix-1.test",
                      matrix_registration_requires_token=False)
        return config
    if service == "tak":
        chat = load_chat_module()
        return {
            "provider_workload": "chat", "tak_deb_path": str(chat.TAK_DEFAULT_DEB),
            "tak_admin_name": "admin", "tak_client_name": "operator",
            "tak_ca_name": "c2itall-live", "tak_cert_password": secrets.token_urlsafe(24),
            "tak_ca_password": secrets.token_urlsafe(24), "tak_cert_state": "Virginia",
            "tak_cert_city": "EastUS", "tak_cert_organization": "c2itall",
            "tak_cert_unit": "Chat", "tak_federation": False,
            "tailscale_auth_key": "", "enable_bot_support": False,
        }
    if service == "dns":
        return {
            "provider_workload": "phantom", "dns_upstream": "9.9.9.9;149.112.112.112",
            "dns_upstream_name": "Quad9", "dns_domain": "",
            "dns_blocklist": "minimal",
        }
    if service == "cloud":
        return {
            "provider_workload": "phantom", "domain": "cloud.test",
            "cloud_admin_user": "liveadmin", "cloud_storage_gb": "10",
        }
    if service == "vault":
        return {
            "provider_workload": "phantom", "domain": "vault.test",
            "vault_admin_token": secrets.token_urlsafe(32),
            "vault_signups_allowed": False,
        }
    if service == "media":
        return {
            "provider_workload": "phantom", "domain": "media.test",
            "media_library_path": "/srv/media",
        }
    if service == "email":
        return {
            "provider_workload": "phantom", "domain": "box.example.com",
            "email_first_user": "admin@example.com",
            "email_skip_network_checks": True,
        }
    if service == "all_in_one":
        return {
            "provider_workload": "phantom", "domain": "all.test",
            "services": ["vpn", "vault"],
            "service_domains": {"vpn": "all.test", "vault": "vault.all.test"},
            "all_in_one": True, "certbot_email": "", "certbot_enabled": False,
            "vpn_port": 51820, "vpn_client_count": 1,
            "vpn_dns": "1.1.1.1", "vpn_subnet": "10.66.66.0/24",
            "vpn_allowed_ips": "0.0.0.0/0",
            "vault_admin_token": secrets.token_urlsafe(32),
            "vault_signups_allowed": False,
        }
    raise LiveTestError(f"Unsupported live service: {service}")


def load_chat_module():
    path = ROOT / "modules" / "chat-server" / "deploy_chat.py"
    spec = importlib.util.spec_from_file_location("azure_live_chat", path)
    require(spec is not None and spec.loader is not None, "Could not load chat module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def deploy_service(service, phantom, config):
    if service in ("matrix", "matrix_rotation", "tak"):
        return load_chat_module().deploy_chat(config)
    return phantom.deploy(service, config)


def load_rotation_module():
    path = ROOT / "modules" / "chat-server" / "rotate_matrix.py"
    spec = importlib.util.spec_from_file_location("azure_live_matrix_rotation", path)
    require(spec is not None and spec.loader is not None,
            "Could not load Matrix rotation module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_matrix_rotation_live(runner, config, context):
    rotation = load_rotation_module()
    context["module"] = rotation
    access = rotation._login(config)
    created = rotation._matrix_request(
        config, "POST", "/_matrix/client/v3/createRoom",
        {"preset": "private_chat", "visibility": "private",
         "name": "c2itall live rotation"}, access)
    room_id = created.get("room_id")
    require(isinstance(room_id, str) and room_id.startswith("!"),
            "Matrix announcement room was not created")
    now = time.time()
    state_path, _ = rotation.initialise(
        "live-" + config["deployment_id"], config["deployment_id"], room_id,
        "matrix-{generation}.test", interval_days=1, grace_hours=1,
        uses_allowed=5, now=now - 86401)
    context["state_path"] = state_path
    with mock.patch("builtins.input", return_value="y"):
        require(rotation.run_once(state_path, now=now) == "replacement announced",
                "Matrix replacement was not announced")
    state = rotation._load_state(state_path)
    replacement = state.get("replacement")
    require(state.get("phase") == "grace" and replacement,
            "Matrix rotation did not enter the grace phase")
    context["replacement"] = replacement
    azure = resource_snapshot(runner, replacement)
    service = verify_matrix(runner, replacement)
    run_ssh(
        runner, replacement,
        "sudo -n grep -Fxq 'registration_requires_token: true' "
        "/etc/matrix-synapse/homeserver.yaml")
    messages = rotation._matrix_request(
        config, "GET",
        f"/_matrix/client/v3/rooms/{quote(room_id, safe='')}/messages?dir=b&limit=10",
        token=access)
    bodies = [event.get("content", {}).get("body", "")
              for event in messages.get("chunk", [])
              if event.get("type") == "m.room.message"]
    require(any(replacement["domain"] in body and "Registration token:" in body
                for body in bodies),
            "Old Matrix server does not contain the replacement announcement")
    require("Registration token:" not in state_path.read_text(),
            "Rotation state persisted the posted registration token")
    require(rotation.run_once(
        state_path, now=float(state["teardown_at"])) == "old deployment retired",
        "Matrix rotation did not retire the old deployment")
    final_state = rotation._load_state(state_path)
    require(final_state["phase"] == "active"
            and final_state["active"]["deployment_id"] == replacement["deployment_id"],
            "Replacement Matrix server was not promoted")
    require(runner.az("group", "exists", "--name",
                      config["azure_resource_group"]) is False,
            "Old Matrix resource group remains after rotation")
    return {
        "replacement_azure": azure, "replacement_service": service,
        "announcement_posted": True, "registration_token_required": True,
        "posted_token_absent_from_state": True, "old_server_retired": True,
        "replacement_promoted": True,
    }


def clean_phantom_files(phantom, deployment_id, config=None):
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
    if config and config.get("tak_artifact_dir"):
        artifact_dir = Path(config["tak_artifact_dir"])
        if artifact_dir.exists():
            shutil.rmtree(artifact_dir)


def activate(service="vpn", operator_ip=None):
    runner = Runner(ROOT)
    deployment_id = f"phaz-{service}-{uuid.uuid4().hex[:8]}"
    runner.evidence = ROOT / "logs" / "azure-phantom-live" / deployment_id
    runner.evidence.mkdir(parents=True, mode=0o700)
    group = f"c2itall-{deployment_id}"
    key = Path.home() / ".ssh" / f"c2deploy_{deployment_id}"
    config = {
        "provider": "azure", "provider_workload": "phantom",
        "deployment_id": deployment_id, "azure_resource_group": group,
        "azure_subscription_id": SUBSCRIPTION, "azure_location": LOCATION,
        "azure_vm_size": SIZE, "azure_state_dir": str(STATE_DIR),
        "operator_ip": "",
        "server_type": "matrix" if service == "matrix_rotation" else service,
        "ssh_after_deploy": False,
    }
    config.update(service_config(service))
    if service == "tak":
        package = Path(config["tak_deb_path"])
        require(package.is_file(), f"Pinned TAK package is missing: {package}")
        config["tak_deb_sha256"] = sha256(package)
        config["tak_ca_name"] = f"c2itall-{deployment_id}"
        config["tak_artifact_dir"] = str(
            ROOT / "deployments" / "chat" / deployment_id)
    phantom = None
    rotation_context = {}
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
        preflight(runner, config)

        os.environ["C2ITALL_INTEGRATED"] = "1"
        sys.path.insert(0, str(PHANTOM_ROOT))
        import phantom as phantom_module
        phantom = phantom_module

        config["azure_deadline"] = time.monotonic() + 1800
        with mock.patch("builtins.input", return_value="y"):
            require(deploy_service(service, phantom, config),
                    f"Initial Phantom {service} deployment failed")
        runner.deadline = time.monotonic() + 600
        first = resource_snapshot(runner, config)
        first_service = verify_service(runner, config)
        runner.record("first-deployment.json", {"azure": first,
                                                 "service": first_service})

        config["azure_deadline"] = time.monotonic() + 1800
        with mock.patch("builtins.input", return_value="y"):
            require(deploy_service(service, phantom, config),
                    f"Repeated Phantom {service} deployment failed")
        runner.deadline = time.monotonic() + 600
        repeated = resource_snapshot(runner, config)
        repeated_service = verify_service(runner, config)
        redaction = verify_service_log_redaction(phantom, deployment_id, config)
        require(first["vm_id"].lower() == repeated["vm_id"].lower()
                and first["resource_ids"] == repeated["resource_ids"],
                "Repeated Phantom deployment changed Azure resource identity")
        runner.record("repeat-deployment.json", {"azure": repeated,
                                                  "service": repeated_service,
                                                  "log_redaction": redaction,
                                                  "resource_identity_preserved": True})
        if service == "matrix_rotation":
            runner.deadline = time.monotonic() + 1800
            rotation_result = verify_matrix_rotation_live(
                runner, config, rotation_context)
            runner.record("matrix-rotation.json", rotation_result)
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
            cleanup_configs = {config["deployment_id"]: config}
            rotation_state_path = rotation_context.get("state_path")
            rotation = rotation_context.get("module")
            if rotation_state_path and Path(rotation_state_path).exists() and rotation:
                rotation_state = rotation._load_state(rotation_state_path)
                for candidate in (rotation_state.get("active"),
                                  rotation_state.get("replacement")):
                    if candidate and candidate.get("deployment_id"):
                        cleanup_configs[candidate["deployment_id"]] = candidate
            if rotation_context.get("replacement"):
                candidate = rotation_context["replacement"]
                cleanup_configs[candidate["deployment_id"]] = candidate
            require(phantom is not None or not cleanup_configs,
                    "Phantom could not be loaded for cleanup")
            cleaned_groups = []
            for candidate in reversed(list(cleanup_configs.values())):
                candidate_id = candidate["deployment_id"]
                candidate_group = candidate.get(
                    "azure_resource_group", f"c2itall-{candidate_id}")
                active_state = STATE_DIR / f"{candidate_id}.json"
                group_exists = runner.az(
                    "group", "exists", "--name", candidate_group)
                if active_state.exists() or group_exists is not False:
                    candidate["azure_cleanup_deadline"] = runner.deadline
                    require(phantom.teardown_instance(candidate),
                            f"Phantom teardown failed for {candidate_id}")
                require(runner.az("group", "exists", "--name",
                                  candidate_group) is False,
                        f"Phantom resource group remains: {candidate_group}")
                require(not active_state.exists(),
                        f"Active Azure recovery state remains: {candidate_id}")
                clean_phantom_files(phantom, candidate_id, candidate)
                candidate_key = phantom._ssh_key_path(candidate_id)
                require(not candidate_key.exists()
                        and not Path(str(candidate_key) + ".pub").exists(),
                        f"Generated Azure SSH key remains: {candidate_id}")
                cleaned_groups.append(candidate_group)
            if rotation_state_path:
                Path(rotation_state_path).unlink(missing_ok=True)
                with contextlib.suppress(OSError):
                    Path(rotation_state_path).parent.rmdir()
            runner.cleanup_subscription()
            final_inventory = runner.inventory()
            require(final_inventory == runner.subscription_baseline,
                    "Azure subscription inventory was not restored")
            require(not key.exists() and not Path(str(key) + ".pub").exists(),
                    "Generated Azure SSH key remains")
            if config.get("tak_artifact_dir"):
                require(not Path(config["tak_artifact_dir"]).exists(),
                        "Fetched TAK artifacts remain after cleanup")
            runner.record("final-cleanup.json", {
                "resource_group_absent": True, "active_state_absent": True,
                "generated_key_absent": True, "inventory": final_inventory,
                "phantom_work_files_removed": phantom is not None,
                "cleaned_groups": cleaned_groups,
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
        "deployment_id": deployment_id, "resource_group": group, "service": service,
    })
    print(f"Evidence: {runner.evidence}")
    if passed:
        print(f"Azure Phantom {service} live workflow passed after initial and repeated "
              "deployment; the subscription baseline was restored.")
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--activate", action="store_true",
                        help="create the temporary Azure VM and run the full workflow")
    parser.add_argument("--service", choices=SERVICES, default="vpn",
                        help="safe Phantom service/top-level entry point to validate")
    parser.add_argument("--operator-ip",
                        help="workstation public IPv4; otherwise resolve with api.ipify.org")
    args = parser.parse_args(argv)
    if not args.activate:
        print(f"DRY RUN: no cloud mutations. Target: {SUBSCRIPTION} / {LOCATION} / {SIZE}")
        print(f"Service: {args.service}")
        print("Activation performs real Phantom provisioning, hardening, service setup, "
              "repeat deployment, SSH/Azure validation, teardown, and inventory restoration.")
        return 0
    return activate(args.service, args.operator_ip)


if __name__ == "__main__":
    sys.exit(main())
