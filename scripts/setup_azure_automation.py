#!/usr/bin/env python3
"""Create and verify Infisical-backed Azure service-principal authentication."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUBSCRIPTION = "cc2a66d1-67c2-47ca-856f-19a4eae52cfe"
DISPLAY_NAME = "c2itall-automation"
INFISICAL_FOLDER = "homelab"
CREDS = Path.home() / ".local" / "bin" / "creds"
SECRET_KEYS = (
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_CERTIFICATE",
    "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
)


class SetupError(RuntimeError):
    pass


def run(argv, *, input_text=None, timeout=90, sensitive=False, cwd=ROOT,
        failure="Credential setup command"):
    try:
        result = subprocess.run(
            [str(value) for value in argv],
            cwd=cwd,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SetupError(f"{failure} could not run") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        if sensitive:
            detail = f"{failure} failed; sensitive output suppressed"
        raise SetupError(detail or f"{failure} failed")
    return result.stdout.strip()


def az(*args, input_text=None, sensitive=False, cwd=ROOT,
       failure="Azure command"):
    return run(
        ["az", *args, "--only-show-errors"],
        input_text=input_text,
        sensitive=sensitive,
        cwd=cwd,
        failure=failure,
    )


def infisical_get(key):
    return run(
        [CREDS, "get", key, INFISICAL_FOLDER], sensitive=True,
        failure=f"Infisical read for {key}")


def infisical_set(key, value):
    output = run(
        [CREDS, "set", key, value, INFISICAL_FOLDER], sensitive=True,
        failure=f"Infisical write for {key}")
    if any(marker in output.lower() for marker in ("not found", "failed", "error")):
        raise SetupError(f"Infisical write for {key} was rejected")


def existing_service_principal():
    payload = az(
        "ad", "sp", "list", "--display-name", DISPLAY_NAME,
        "--query", "[].{appId:appId,id:id}", "--output", "json",
    )
    matches = json.loads(payload)
    if len(matches) > 1:
        raise SetupError(f"More than one {DISPLAY_NAME} service principal exists")
    return matches[0] if matches else None


def _certificate_credentials(payload, temporary, subscription_id, tenant_id=None):
    values = json.loads(payload)
    certificate = Path(values.get("fileWithCertAndPrivateKey", ""))
    if not certificate.is_absolute():
        certificate = Path(temporary) / certificate
    try:
        certificate_text = certificate.read_text().strip()
    except (OSError, UnicodeError) as exc:
        raise SetupError("Azure did not create a readable private certificate") from exc
    if (not re.search(r"-----BEGIN [^-]*PRIVATE KEY-----", certificate_text)
            or "-----BEGIN CERTIFICATE-----" not in certificate_text):
        raise SetupError("Azure returned an invalid private certificate")
    credentials = {
        "AZURE_CLIENT_ID": values.get("appId", ""),
        "AZURE_CLIENT_CERTIFICATE": certificate_text,
        "AZURE_TENANT_ID": values.get("tenant", "") or tenant_id or "",
        "AZURE_SUBSCRIPTION_ID": subscription_id,
    }
    if not all(credentials.values()):
        raise SetupError("Azure returned an incomplete service-principal credential")
    return credentials


def create_service_principal(subscription_id):
    scope = f"/subscriptions/{subscription_id}"
    with tempfile.TemporaryDirectory(prefix="c2itall-azure-cert-") as temporary:
        payload = az(
            "ad", "sp", "create-for-rbac",
            "--name", DISPLAY_NAME,
            "--role", "Contributor",
            "--scopes", scope,
            "--create-cert",
            "--years", "1",
            "--output", "json",
            sensitive=True,
            cwd=temporary,
            failure="Azure service-principal creation",
        )
        return _certificate_credentials(payload, temporary, subscription_id)


def rotate_service_principal_certificate(app_id, subscription_id):
    account = json.loads(az(
        "account", "show", "--subscription", subscription_id,
        "--output", "json"))
    tenant_id = account.get("tenantId", "")
    with tempfile.TemporaryDirectory(prefix="c2itall-azure-cert-") as temporary:
        payload = az(
            "ad", "app", "credential", "reset",
            "--id", app_id,
            "--create-cert",
            "--years", "1",
            "--output", "json",
            sensitive=True,
            cwd=temporary,
            failure="Azure certificate rotation",
        )
        return _certificate_credentials(
            payload, temporary, subscription_id, tenant_id=tenant_id)


def stored_credentials(subscription_id):
    values = {}
    for key in SECRET_KEYS:
        try:
            values[key] = infisical_get(key)
        except SetupError:
            return None
    if not all(values.values()) or values["AZURE_SUBSCRIPTION_ID"] != subscription_id:
        return None
    return values


def store_and_verify(credentials):
    for key in SECRET_KEYS:
        infisical_set(key, credentials[key])
    for key in SECRET_KEYS:
        if infisical_get(key) != credentials[key]:
            raise SetupError(f"Infisical round-trip verification failed for {key}")


def login_and_verify(credentials):
    subscription_id = credentials["AZURE_SUBSCRIPTION_ID"]
    with tempfile.TemporaryDirectory(prefix="c2itall-azure-login-") as temporary:
        certificate = Path(temporary) / "service-principal.pem"
        certificate.write_text(credentials["AZURE_CLIENT_CERTIFICATE"])
        certificate.chmod(0o600)
        az(
            "login", "--service-principal",
            "--username", credentials["AZURE_CLIENT_ID"],
            "--tenant", credentials["AZURE_TENANT_ID"],
            "--subscription", subscription_id,
            "--skip-subscription-discovery",
            "--output", "none",
            "--certificate", str(certificate),
            sensitive=True,
        )
        try:
            account = json.loads(az(
                "account", "show", "--subscription", subscription_id,
                "--output", "json"))
            if account.get("id", "").lower() != subscription_id.lower():
                raise SetupError("Azure CLI selected a different subscription")
            if (account.get("state") != "Enabled"
                    or account.get("user", {}).get("type") != "servicePrincipal"):
                raise SetupError(
                    "Azure CLI did not establish a valid service-principal session")
            count = json.loads(az(
                "group", "list", "--subscription", subscription_id,
                "--query", "length(@)", "--output", "json"))
            if type(count) is not int or count < 0:
                raise SetupError(
                    "Azure resource-group verification returned an invalid result")
            return count
        finally:
            try:
                az("logout", "--username", credentials["AZURE_CLIENT_ID"])
            except SetupError:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subscription", default=DEFAULT_SUBSCRIPTION)
    parser.add_argument("--activate", action="store_true")
    args = parser.parse_args(argv)
    try:
        subscription_id = str(uuid.UUID(args.subscription))
        if not CREDS.is_file():
            raise SetupError(f"Infisical helper is unavailable: {CREDS}")
        stored = stored_credentials(subscription_id)
        if args.activate and stored:
            group_count = login_and_verify(stored)
            print(
                f"Azure noninteractive authentication verified for {DISPLAY_NAME}; "
                f"resource_groups={group_count}")
            return 0
        existing = existing_service_principal()
        if not args.activate:
            state = "existing" if existing else "absent"
            secret_state = "complete" if stored else "absent-or-incomplete"
            print(f"Plan: {DISPLAY_NAME}={state}; Infisical/{INFISICAL_FOLDER}={secret_state}")
            return 0
        if existing:
            if stored and stored["AZURE_CLIENT_ID"] == existing["appId"]:
                credentials = stored
            else:
                credentials = rotate_service_principal_certificate(
                    existing["appId"], subscription_id)
                store_and_verify(credentials)
        else:
            credentials = create_service_principal(subscription_id)
            store_and_verify(credentials)
        group_count = login_and_verify(credentials)
        print(
            f"Azure noninteractive authentication verified for {DISPLAY_NAME}; "
            f"resource_groups={group_count}")
        return 0
    except (SetupError, ValueError, json.JSONDecodeError) as exc:
        print(f"Azure automation setup failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
