#!/usr/bin/env python3
"""Controller-side rolling replacement for provider-routed Matrix servers."""

import argparse
import contextlib
import copy
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[2]
PHANTOM_ROOT = ROOT / "ghost_protocol" / "phantom"
DEFAULT_STATE_DIR = Path.home() / ".local/state/c2itall/matrix-rotation"
STATE_VERSION = 1
_SAFE_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
_DYNAMIC_KEYS = {
    "target_host", "ssh_key", "timestamp", "ownership_marker",
    "planned_resource_ids", "outputs", "status", "error", "verified_disk",
    "deletion_started", "azure_resource_group", "ssh_private_key_path",
    "ssh_key_path", "ssh_key_generated", "ssh_known_hosts_path", "azure_deadline",
    "azure_cleanup_deadline", "_host_output_file",
}


class RotationError(RuntimeError):
    pass


def _load_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _chat():
    return _load_path("c2itall_matrix_rotation_chat",
                      Path(__file__).resolve().with_name("deploy_chat.py"))


def _phantom():
    os.environ["C2ITALL_INTEGRATED"] = "1"
    if str(PHANTOM_ROOT) not in sys.path:
        sys.path.insert(0, str(PHANTOM_ROOT))
    return _load_path("c2itall_matrix_rotation_phantom", PHANTOM_ROOT / "phantom.py")


def _state_path(name):
    if not _SAFE_NAME.fullmatch(name):
        raise ValueError("Rotation name must be lowercase letters, numbers, or hyphens")
    return DEFAULT_STATE_DIR / (name + ".json")


def _write_state(path, state):
    path = Path(path).expanduser().absolute()
    if path.is_symlink():
        raise RotationError("Refusing symlinked rotation state")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(state, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def _load_state(path):
    path = Path(path).expanduser().absolute()
    if path.is_symlink() or not path.is_file():
        raise RotationError("Rotation state is missing or unsafe")
    if path.stat().st_mode & 0o077:
        raise RotationError("Rotation state must be owner-only")
    state = json.loads(path.read_text())
    if (state.get("version") != STATE_VERSION or state.get("phase") not in
            ("active", "provisioning", "grace")):
        raise RotationError("Rotation state is invalid")
    return state


def _active_config(deployment_id):
    path = PHANTOM_ROOT / "logs" / deployment_id / "deploy_info.json"
    if not path.is_file() or path.is_symlink():
        raise RotationError(f"Matrix deployment config is unavailable: {path}")
    config = json.loads(path.read_text())
    if config.get("server_type") != "matrix" or config.get("deployment_id") != deployment_id:
        raise RotationError("Active deployment is not a Matrix server")
    for key in ("provider", "domain", "matrix_server_name", "matrix_admin_user",
                "matrix_admin_password", "target_host"):
        if not config.get(key):
            raise RotationError("Active Matrix config is missing " + key)
    return config


def _validate_room_id(room_id):
    """Accept opaque Matrix room IDs, including domainless room v12 IDs."""
    if not isinstance(room_id, str) or not room_id.startswith("!"):
        return False
    try:
        encoded = room_id.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return len(encoded) > 1 and len(encoded) <= 255 and b"\x00" not in encoded


def initialise(name, active_deployment, room_id, domain_template,
               interval_days=7, grace_hours=24, uses_allowed=100, now=None):
    if not _validate_room_id(room_id):
        raise ValueError("Announcement room must be a Matrix room ID")
    if "{id}" not in domain_template and "{generation}" not in domain_template:
        raise ValueError("Domain template must contain {id} or {generation}")
    if interval_days < 1 or grace_hours < 1 or uses_allowed < 1:
        raise ValueError("Rotation interval, grace window, and token uses must be positive")
    active = _active_config(active_deployment)
    preview = domain_template.format(id="preview", generation=2)
    if not re.fullmatch(r"[A-Za-z0-9.-]+", preview) or "." not in preview:
        raise ValueError("Domain template must produce a hostname")
    now = time.time() if now is None else float(now)
    state = {
        "version": STATE_VERSION, "name": name, "phase": "active",
        "generation": 1, "active": active, "replacement": None,
        "room_id": room_id, "domain_template": domain_template,
        "interval_seconds": int(interval_days * 86400),
        "grace_seconds": int(grace_hours * 3600),
        "uses_allowed": int(uses_allowed),
        "next_rotation_at": now + int(interval_days * 86400),
        "teardown_at": None, "last_announcement": None,
    }
    path = _state_path(name)
    _write_state(path, state)
    return path, state


def _replacement_config(state):
    config = copy.deepcopy(state["active"])
    for key in _DYNAMIC_KEYS:
        config.pop(key, None)
    deployment_id = "matrix-rot-" + secrets.token_hex(4)
    generation = int(state["generation"]) + 1
    domain = state["domain_template"].format(
        id=deployment_id, generation=generation).lower()
    if domain == state["active"]["domain"]:
        raise RotationError("Replacement domain must differ from the active domain")
    config.update(
        deployment_id=deployment_id, deployment_type="chat_matrix",
        provider_workload="chat", server_type="matrix", chat_deployment=True,
        domain=domain, matrix_server_name=domain,
        matrix_admin_password=secrets.token_urlsafe(24),
        matrix_signing_key=secrets.token_hex(32),
        matrix_form_secret=secrets.token_hex(32),
        matrix_macaroon_secret=secrets.token_hex(32),
        matrix_registration=True, matrix_registration_requires_token=True,
        ssh_after_deploy=False,
    )
    return config


def _matrix_request(config, method, path, payload=None, token=None):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(
        config["target_host"], 443, timeout=30, context=context)
    headers = {"Host": config["domain"], "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = None if payload is None else json.dumps(payload)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        content = response.read()
    finally:
        connection.close()
    if response.status < 200 or response.status >= 300:
        raise RotationError(f"Matrix API {path} returned HTTP {response.status}")
    return json.loads(content or b"{}")


_REMOTE_ADMIN_REQUEST = """\
import http.client
import json
import sys

request = json.load(sys.stdin)
connection = http.client.HTTPConnection("127.0.0.1", 8008, timeout=30)
headers = {"Content-Type": "application/json",
           "Authorization": "Bearer " + request["token"]}
body = None if request["payload"] is None else json.dumps(request["payload"])
try:
    connection.request(request["method"], request["path"], body, headers)
    response = connection.getresponse()
    content = response.read().decode("utf-8", "replace")
finally:
    connection.close()
print(json.dumps({"status": response.status, "body": content}))
"""


def _matrix_admin_request(config, method, path, payload, token):
    """Call Synapse's loopback-only admin API without exposing credentials."""
    key = Path(config.get("ssh_private_key_path") or config.get("ssh_key", ""))
    known_hosts_value = config.get("ssh_known_hosts_path")
    known_hosts = (Path(known_hosts_value) if known_hosts_value else
                   _phantom()._ssh_known_hosts_path(config["deployment_id"]))
    if (not key.is_file() or key.is_symlink() or not known_hosts.is_file()
            or known_hosts.is_symlink()):
        raise RotationError("Secure SSH material is unavailable for Matrix admin API")
    command = [
        "ssh", "-F", "/dev/null", "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"UserKnownHostsFile={known_hosts}", "-i", str(key),
        "--", f"{config.get('ssh_user', 'root')}@{config['target_host']}",
        "python3 -c " + shlex.quote(_REMOTE_ADMIN_REQUEST),
    ]
    request = json.dumps({
        "method": method, "path": path, "payload": payload, "token": token})
    try:
        result = subprocess.run(
            command, input=request, text=True, capture_output=True,
            timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RotationError("Matrix admin API SSH request failed") from error
    if result.returncode:
        raise RotationError("Matrix admin API SSH request failed")
    try:
        envelope = json.loads(result.stdout)
        status = int(envelope["status"])
    except (KeyError, TypeError, ValueError) as error:
        raise RotationError("Matrix admin API returned an invalid response") from error
    if status < 200 or status >= 300:
        raise RotationError(f"Matrix admin API {path} returned HTTP {status}")
    try:
        return json.loads(envelope["body"] or "{}")
    except (TypeError, ValueError) as error:
        raise RotationError("Matrix admin API returned an invalid response") from error


def _login(config):
    response = _matrix_request(config, "POST", "/_matrix/client/v3/login", {
        "type": "m.login.password",
        "identifier": {"type": "m.id.user", "user": config["matrix_admin_user"]},
        "password": config["matrix_admin_password"],
    })
    token = response.get("access_token")
    if not token:
        raise RotationError("Matrix admin login returned no access token")
    return token


def _create_registration_token(config, access_token, uses, expiry):
    response = _matrix_admin_request(
        config, "POST", "/_synapse/admin/v1/registration_tokens/new",
        {"length": 24, "uses_allowed": uses, "expiry_time": int(expiry * 1000)},
        access_token)
    token = response.get("token")
    if not token:
        raise RotationError("Synapse returned no registration token")
    return token


def _announce(config, access_token, room_id, replacement, registration_token,
              teardown_at):
    txn = secrets.token_hex(8)
    room = quote(room_id, safe="")
    deadline = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(teardown_at))
    body = (
        "Matrix server rotation is ready.\n"
        f"New server: https://{replacement['domain']}\n"
        f"Registration token: {registration_token}\n"
        f"The current server will be retired after {deadline}."
    )
    _matrix_request(
        config, "PUT",
        f"/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}",
        {"msgtype": "m.text", "body": body}, access_token)
    return body


def _retire(config):
    if not _phantom().teardown_instance(config):
        raise RotationError("Verified teardown failed for " + config["deployment_id"])


def run_once(path, now=None, deploy=None, retire=None, api=None):
    path = Path(path).expanduser().absolute()
    state = _load_state(path)
    now = time.time() if now is None else float(now)
    deploy = deploy or _chat().deploy_chat
    retire = retire or _retire
    api = api or {
        "login": _login,
        "create_token": _create_registration_token,
        "announce": _announce,
    }

    if state["phase"] == "provisioning":
        retire(state["replacement"])
        state.update(phase="active", replacement=None)
        _write_state(path, state)
        return "recovered incomplete replacement"

    if state["phase"] == "grace":
        if now < state["teardown_at"]:
            return "grace window active"
        retire(state["active"])
        state.update(
            phase="active", generation=int(state["generation"]) + 1,
            active=state["replacement"], replacement=None,
            next_rotation_at=now + int(state["interval_seconds"]),
            teardown_at=None, last_announcement=None,
        )
        _write_state(path, state)
        return "old deployment retired"

    if now < state["next_rotation_at"]:
        return "rotation not due"

    replacement = _replacement_config(state)
    state.update(phase="provisioning", replacement=replacement)
    _write_state(path, state)
    try:
        deployed = deploy(replacement)
    except BaseException as deployment_error:
        try:
            retire(replacement)
        except Exception as cleanup_error:
            _write_state(path, state)
            raise RotationError(
                "Replacement raised an error and verified cleanup also failed; "
                "recovery state was preserved"
            ) from cleanup_error
        state.update(phase="active", replacement=None)
        _write_state(path, state)
        raise deployment_error
    if not deployed:
        # deploy_chat owns rollback for every normal False result. Calling
        # teardown again would fail after its durable state has been retired.
        state.update(phase="active", replacement=None)
        _write_state(path, state)
        raise RotationError("Replacement Matrix deployment failed")
    try:
        teardown_at = now + int(state["grace_seconds"])
        new_access = api["login"](replacement)
        registration = api["create_token"](
            replacement, new_access, int(state["uses_allowed"]), teardown_at)
        old_access = api["login"](state["active"])
        announcement = api["announce"](
            state["active"], old_access, state["room_id"], replacement,
            registration, teardown_at)
    except BaseException as service_error:
        try:
            retire(replacement)
        except Exception as cleanup_error:
            # Keep the provisioning record intact so the next timer run can
            # recover the replacement instead of losing track of a resource.
            _write_state(path, state)
            raise RotationError(
                "Replacement failed and verified cleanup also failed; "
                "recovery state was preserved"
            ) from cleanup_error
        state.update(phase="active", replacement=None)
        _write_state(path, state)
        raise service_error
    state.update(phase="grace", teardown_at=teardown_at,
                 last_announcement={"at": now, "teardown_at": teardown_at})
    _write_state(path, state)
    return "replacement announced"


def install_timer(name, state_path, interval_minutes=15):
    if not _SAFE_NAME.fullmatch(name):
        raise ValueError("Invalid timer name")
    if interval_minutes < 5:
        raise ValueError("Timer interval must be at least five minutes")
    state_path = Path(state_path).expanduser().absolute()
    _load_state(state_path)
    user_dir = Path.home() / ".config/systemd/user"
    user_dir.mkdir(parents=True, exist_ok=True)
    unit = "c2itall-matrix-rotation-" + name
    service = user_dir / (unit + ".service")
    timer = user_dir / (unit + ".timer")
    command = " ".join(shlex.quote(value) for value in (
        sys.executable, str(Path(__file__).resolve()), "run", "--state", str(state_path)))
    service.write_text(
        "[Unit]\nDescription=c2itall Matrix rolling replacement\n\n"
        "[Service]\nType=oneshot\nUMask=0077\n"
        f"WorkingDirectory={ROOT}\nExecStart={command}\n")
    timer.write_text(
        "[Unit]\nDescription=Check c2itall Matrix rotation state\n\n"
        "[Timer]\nOnBootSec=5m\n"
        f"OnUnitActiveSec={int(interval_minutes)}m\nPersistent=true\n\n"
        "[Install]\nWantedBy=timers.target\n")
    service.chmod(0o600)
    timer.chmod(0o600)
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "--user", "enable", "--now", timer.name], check=True)
    return timer


def uninstall_timer(name):
    if not _SAFE_NAME.fullmatch(name):
        raise ValueError("Invalid timer name")
    unit = "c2itall-matrix-rotation-" + name
    user_dir = Path.home() / ".config/systemd/user"
    subprocess.run(["systemctl", "--user", "disable", "--now", unit + ".timer"],
                   check=False)
    for suffix in (".timer", ".service"):
        with contextlib.suppress(FileNotFoundError):
            (user_dir / (unit + suffix)).unlink()
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)


def _status(state):
    return {
        "name": state["name"], "phase": state["phase"],
        "generation": state["generation"],
        "active_deployment": state["active"]["deployment_id"],
        "active_domain": state["active"]["domain"],
        "replacement_deployment": ((state.get("replacement") or {}).get("deployment_id")),
        "replacement_domain": ((state.get("replacement") or {}).get("domain")),
        "next_rotation_at": state.get("next_rotation_at"),
        "teardown_at": state.get("teardown_at"),
    }


def interactive_setup():
    name = input("Rotation name [team-chat]: ").strip() or "team-chat"
    active = input("Active Matrix deployment ID: ").strip()
    room = input("Announcement room ID (!room:server): ").strip()
    template = input("Replacement domain template (example: matrix-{generation}.example.com): ").strip()
    days = int(input("Rotate every N days [7]: ").strip() or "7")
    grace = int(input("Grace period in hours [24]: ").strip() or "24")
    uses = int(input("Registration token uses [100]: ").strip() or "100")
    path, _ = initialise(name, active, room, template, days, grace, uses)
    install_timer(name, path)
    print("Matrix rolling rotation enabled: " + str(path))
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("init")
    create.add_argument("--name", required=True)
    create.add_argument("--active-deployment", required=True)
    create.add_argument("--room-id", required=True)
    create.add_argument("--domain-template", required=True)
    create.add_argument("--interval-days", type=int, default=7)
    create.add_argument("--grace-hours", type=int, default=24)
    create.add_argument("--uses-allowed", type=int, default=100)
    run = sub.add_parser("run")
    run.add_argument("--state", type=Path, required=True)
    status = sub.add_parser("status")
    status.add_argument("--state", type=Path, required=True)
    install = sub.add_parser("install-timer")
    install.add_argument("--name", required=True)
    install.add_argument("--state", type=Path, required=True)
    install.add_argument("--interval-minutes", type=int, default=15)
    remove = sub.add_parser("uninstall-timer")
    remove.add_argument("--name", required=True)
    args = parser.parse_args(argv)
    if args.command == "init":
        path, state = initialise(
            args.name, args.active_deployment, args.room_id, args.domain_template,
            args.interval_days, args.grace_hours, args.uses_allowed)
        print(json.dumps(dict(_status(state), state_path=str(path)), indent=2))
    elif args.command == "run":
        print(run_once(args.state))
    elif args.command == "status":
        print(json.dumps(_status(_load_state(args.state)), indent=2))
    elif args.command == "install-timer":
        print(install_timer(args.name, args.state, args.interval_minutes))
    else:
        uninstall_timer(args.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
