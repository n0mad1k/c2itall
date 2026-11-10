#!/usr/bin/env python3
"""Exfil receiver: MinIO, SFTP and an authenticated HTTP drop, reachable only inside the lab."""

import os
import secrets
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils import lab as lab_mod
from utils.common import COLORS, clear_screen, confirm_action, generate_deployment_id, print_banner, wait_for_input
from utils.provider_utils import gather_provider_config, select_provider


def _credentials(lab):
    """Reuse the lab's exfil credentials, or generate and persist them once."""
    saved = lab_mod.read_secret(lab, 'exfil.json')
    if saved:
        return saved
    creds = {
        'minio_user': 'exfil', 'minio_password': secrets.token_urlsafe(24),
        'http_user': 'exfil', 'http_password': secrets.token_urlsafe(24),
        'sftp_user': 'drop', 'sftp_password': secrets.token_urlsafe(24),
    }
    lab_mod.write_secret(lab, 'exfil.json', creds)
    return creds


def _ready_receiver(lab):
    """The deployment_id of the lab's ready exfil receiver, or None."""
    for deployment_id, member in lab['members'].items():
        if member.get('workload') == 'exfil_receiver' and member.get('status') == 'ready':
            return deployment_id
    return None


def gather_exfil_parameters(lab_name):
    """Collect the inputs for the lab's exfil receiver."""
    lab = lab_mod.load(lab_name)
    config = {'deployment_id': generate_deployment_id(), 'lab': lab_name}
    print(f"Deployment ID: {COLORS['CYAN']}{config['deployment_id']}{COLORS['RESET']}")
    provider = select_provider('exfil_receiver')
    if not provider:
        return None
    provider_config = gather_provider_config(provider, 'exfil_receiver')
    if not provider_config:
        return None
    config.update(provider_config)
    config.update(provider=provider, provider_workload='exfil_receiver',
                  deployment_type='exfil_receiver', exfil_name='exfil-' + config['deployment_id'])
    creds = _credentials(lab)
    config.update(exfil_minio_user=creds['minio_user'], exfil_minio_password=creds['minio_password'],
                  exfil_http_user=creds['http_user'], exfil_http_password=creds['http_password'],
                  exfil_sftp_password=creds['sftp_password'])
    config['ssh_key_path'] = lab['ssh_key_path']
    return config


def execute_exfil_deployment(config):
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    print(f"Deployment ID: {config['deployment_id']}")
    print(f"Lab: {config['lab']}")
    print(f"Provider: {config['provider']}")
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with exfil receiver deployment?{COLORS['RESET']}", default=False):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return False
    from utils.deployment_engine import deploy_infrastructure
    success = deploy_infrastructure(config)
    if success:
        lab = lab_mod.load(config['lab'])
        ip = config['exfil_ip']
        print(f"\n{COLORS['GREEN']}Exfil receiver deployed inside lab {config['lab']}.{COLORS['RESET']}")
        print(f"S3 (MinIO): {ip}:9000")
        print(f"HTTPS upload: https://{ip}:8443/upload/<name>")
        print(f"SFTP: sftp -P 2222 drop@{ip}")
        print(f"Credentials: {lab_mod.secret_dir(lab) / 'exfil.json'}")
    else:
        print(f"\n{COLORS['RED']}Exfil receiver deployment failed.{COLORS['RESET']}")
    return success


def _show_ledger(name):
    lab = lab_mod.load(name)
    deployment_id = _ready_receiver(lab)
    if not deployment_id:
        print(f"{COLORS['RED']}No ready exfil receiver in lab {name}{COLORS['RESET']}")
        return
    result = lab_mod.member_command(name, deployment_id, ['sudo', 'tail', '-n', '50', '/var/log/exfil/ledger.jsonl'])
    print(result.stdout)
    if result.stderr:
        print(f"{COLORS['RED']}{result.stderr}{COLORS['RESET']}")


def _verify_manifest(name):
    lab = lab_mod.load(name)
    deployment_id = _ready_receiver(lab)
    if not deployment_id:
        print(f"{COLORS['RED']}No ready exfil receiver in lab {name}{COLORS['RESET']}")
        return
    manifest_src = input('Manifest JSON path: ').strip()
    if not manifest_src or not os.path.isfile(manifest_src):
        print(f"{COLORS['RED']}Manifest not found{COLORS['RESET']}")
        return
    if not lab_mod.run_member_playbook(name, deployment_id, 'modules/exfil/push_manifest.yml',
                                        {'manifest_src': manifest_src}, 'exfil-verify', 300):
        print(f"{COLORS['RED']}Could not push the manifest to the receiver{COLORS['RESET']}")
        return
    remote_path = '/var/lib/exfil/manifests/' + os.path.basename(manifest_src)
    result = lab_mod.member_command(name, deployment_id, ['sudo', 'exfil-receiver', 'verify', remote_path])
    print(result.stdout)
    print(f"Exit status: {result.returncode}")


def _clean_receiver(name):
    lab = lab_mod.load(name)
    deployment_id = _ready_receiver(lab)
    if not deployment_id:
        print(f"{COLORS['RED']}No ready exfil receiver in lab {name}{COLORS['RESET']}")
        return
    if not confirm_action(f"{COLORS['YELLOW']}Clean the receiver (removes uploads, rotates the ledger)?{COLORS['RESET']}",
                           default=False):
        return
    result = lab_mod.member_command(name, deployment_id, ['sudo', 'exfil-receiver', 'clean'])
    print(result.stdout)


def exfil_menu():
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}EXFIL RECEIVER MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}==================={COLORS['RESET']}")
        print("1) Deploy the exfil receiver into a lab")
        print("2) Show ledger")
        print("3) Verify a manifest")
        print("4) Clean the receiver")
        print("99) Return to Main Menu")
        choice = input("\nSelect an option: ").strip()
        if choice == '1':
            name = input('Lab name [lab]: ').strip() or 'lab'
            try:
                lab_mod.load(name)
            except FileNotFoundError:
                print(f"{COLORS['RED']}No lab named {name}; deploy its gateway first{COLORS['RESET']}")
                wait_for_input()
                continue
            config = gather_exfil_parameters(name)
            if config:
                execute_exfil_deployment(config)
            wait_for_input()
        elif choice in ('2', '3', '4'):
            name = input('Lab name [lab]: ').strip() or 'lab'
            try:
                lab_mod.load(name)
            except FileNotFoundError:
                print(f"{COLORS['RED']}No lab named {name}{COLORS['RESET']}")
                wait_for_input()
                continue
            {'2': _show_ledger, '3': _verify_manifest, '4': _clean_receiver}[choice](name)
            wait_for_input()
        elif choice == '99':
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()


if __name__ == '__main__':
    exfil_menu()
