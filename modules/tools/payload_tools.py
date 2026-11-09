#!/usr/bin/env python3
"""Payload generation tools: drive the generator on a deployed C2 server."""

import os
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.common import COLORS, clear_screen, print_banner, wait_for_input
from utils.naming_utils import get_existing_deployments
from utils.provider_registry import PROVIDER_SPECS

GENERATOR = '/root/Tools/generate_havoc_payloads.sh'
SYNC = '/root/Tools/secure_payload_sync.sh'
PAYLOAD_DIR = '/root/Tools/Havoc/payloads'


def c2_deployments():
    """Deployment records that describe a C2 server."""
    return [record for record in get_existing_deployments()
            if record.get('provider_workload') == 'c2'
            or str(record.get('deployment_type', '')).startswith('c2')]


def ssh_target(record):
    """Return (user@host, private key path) for a recorded deployment."""
    provider = record.get('provider', '')
    spec = PROVIDER_SPECS.get(provider)
    if spec is None:
        raise ValueError('Unknown provider in deployment record: ' + provider)
    host = record.get('c2_ip') or input('C2 public IP (not in the record): ').strip()
    key = record.get('ssh_key_path') or str(
        Path.home() / '.ssh' / ('c2deploy_' + record['deployment_id']))
    key = key.removesuffix('.pub')
    if not Path(key).is_file():
        raise ValueError('SSH private key not found: ' + key)
    return spec.ssh_user + '@' + host, key


def ssh_argv(target, key, command):
    return ['ssh', '-i', key, '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=accept-new', target, command]


def run_remote(target, key, command):
    return subprocess.run(ssh_argv(target, key, command), check=False).returncode == 0


def pull_payloads(target, key, deployment_id):
    """Copy the generated payloads to payloads/<deployment>/ as an archive stream."""
    destination = ROOT / 'payloads' / deployment_id
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    archive = destination / 'payloads.tgz'
    with open(archive, 'wb') as stream:
        result = subprocess.run(
            ssh_argv(target, key, 'sudo -n tar -C ' + PAYLOAD_DIR + ' -czf - .'),
            stdout=stream, check=False)
    if result.returncode:
        archive.unlink(missing_ok=True)
        return None
    with tarfile.open(archive) as bundle:
        bundle.extractall(destination, filter='data')
    archive.unlink()
    os.chmod(destination, 0o700)
    return destination


def select_c2():
    records = c2_deployments()
    if not records:
        print(f"{COLORS['YELLOW']}No C2 deployment records found in logs/.{COLORS['RESET']}")
        return None
    print(f"\n{COLORS['BLUE']}Deployed C2 servers:{COLORS['RESET']}")
    for index, record in enumerate(records, 1):
        print(f"  {index}. {record['deployment_id']} ({record.get('provider', '?')}, "
              f"{record.get('c2_framework', 'havoc')}, {record.get('c2_ip', 'IP not recorded')})")
    choice = input(f"\nSelect a C2 server (1-{len(records)} or 99 to cancel): ").strip()
    if not choice.isdigit() or not 1 <= int(choice) <= len(records):
        return None
    return records[int(choice) - 1]


def payload_tools_menu():
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}PAYLOAD GENERATION TOOLS{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}========================{COLORS['RESET']}")
        print("1) Generate Havoc payloads on a deployed C2")
        print("2) Pull generated payloads to this machine")
        print("3) Sync payloads from the C2 to its redirector")
        print("99) Return")
        choice = input("\nSelect an option: ").strip()
        if choice == '99':
            return
        if choice not in ('1', '2', '3'):
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()
            continue
        record = select_c2()
        if record is None:
            continue
        try:
            target, key = ssh_target(record)
        except ValueError as exc:
            print(f"{COLORS['RED']}{exc}{COLORS['RESET']}")
            wait_for_input()
            continue
        if choice == '1':
            ok = run_remote(target, key, 'sudo -n ' + GENERATOR)
            print(f"{COLORS['GREEN' if ok else 'RED']}Payload generation "
                  f"{'finished' if ok else 'failed'} on {target}.{COLORS['RESET']}")
        elif choice == '2':
            destination = pull_payloads(target, key, record['deployment_id'])
            if destination:
                print(f"{COLORS['GREEN']}Payloads saved under {destination}{COLORS['RESET']}")
            else:
                print(f"{COLORS['RED']}Could not pull payloads from {target}.{COLORS['RESET']}")
        else:
            ok = run_remote(target, key, 'sudo -n ' + SYNC)
            print(f"{COLORS['GREEN' if ok else 'RED']}Payload sync "
                  f"{'finished' if ok else 'failed'} on {target}.{COLORS['RESET']}")
        wait_for_input()


if __name__ == '__main__':
    payload_tools_menu()
