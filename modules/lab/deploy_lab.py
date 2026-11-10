#!/usr/bin/env python3
"""Lab menu: a private purple-team lab built from lab-aware workloads on any provider."""

import importlib.util
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils import lab as lab_mod
from utils.common import COLORS, clear_screen, confirm_action, print_banner, wait_for_input
from utils.controller_io import ROOT


def _module(directory, filename):
    path = ROOT / 'modules' / directory / filename
    spec = importlib.util.spec_from_file_location(filename.removesuffix('.py'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pick_lab():
    labs = lab_mod.list_labs()
    if not labs:
        print(f"{COLORS['RED']}No lab yet; create one with option 1{COLORS['RESET']}")
        return None
    name = input('Lab name [' + labs[0] + ']: ').strip() or labs[0]
    try:
        return lab_mod.load(name)
    except FileNotFoundError:
        print(f"{COLORS['RED']}No lab named {name}{COLORS['RESET']}")
        return None


def status(lab):
    gateway = lab.get('gateway') or {}
    print(f"Lab {lab['name']}: overlay {lab['cidr']}, ranges {', '.join(lab['range_cidrs']) or 'none'}, "
          f"blocked {', '.join(lab['blocked_cidrs']) or 'none'}")
    print(f"Gateway: {gateway.get('status', 'missing')} {gateway.get('public_ip', '')} "
          f"({gateway.get('provider', '')})")
    for deployment_id, member in lab['members'].items():
        print(f"  {member['lab_ip']:<14} {member['workload']:<16} {member['provider']:<9} "
              f"{member['status']:<8} {deployment_id}")
    for provider, network in lab['networks'].items():
        print(f"  network {provider}: {network.get('cidr')} {network.get('status')}")
    journal = lab_mod.secret_dir(lab) / 'journal.jsonl'
    if journal.is_file():
        print('Journal:')
        print(journal.read_text().rstrip())
    print('Operator WireGuard config: ' + str(lab_mod.secret_dir(lab) / 'operator.conf'))


def payload_manifest(lab):
    for deployment_id, member in lab['members'].items():
        if member.get('workload') == 'c2' and member.get('status') == 'ready':
            result = lab_mod.member_command(lab['name'], deployment_id,
                                            ['sudo', '-n', 'cat', '/root/Tools/Havoc/payloads/manifest.json'])
            print(result.stdout or result.stderr)
            return
    print('No ready C2 in this lab')


def teardown(lab):
    if not confirm_action('Tear down every member, the gateway and the shared networks of '
                          + lab['name'] + '?', default=False):
        return
    if lab_mod.teardown(lab['name']):
        print(f"{COLORS['GREEN']}Lab {lab['name']} torn down{COLORS['RESET']}")
    else:
        print(f"{COLORS['RED']}Teardown stopped at the first failure; run it again to continue{COLORS['RESET']}")


def lab_menu():
    gateway = _module('gateway', 'deploy_gateway.py')
    red = _module('lab', 'red.py')
    actions = {'4': red.c2, '5': red.payload_server, '6': red.attack_box,
               '7': red.logging_server, '8': red.chat, '9': status,
               '10': payload_manifest, '11': teardown}
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}LAB MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}========{COLORS['RESET']}")
        print("1) Create lab + deploy its gateway (WireGuard hub, logged NAT egress)")
        print("2) LUDUS host and AD range")
        print("3) Exfil receiver (MinIO, SFTP, HTTPS drop)")
        print("4) C2 server (Havoc, lab mode)")
        print("5) Payload server (lab mode)")
        print("6) Attack box (lab mode)")
        print("7) Logging server (lab mode)")
        print("8) Chat server (lab mode)")
        print("9) Lab status and journal")
        print("10) C2 payload manifest (hashes for implant staging)")
        print("11) Teardown lab")
        print("99) Return to Main Menu")
        choice = input("\nSelect an option: ").strip()
        if choice == '1':
            lab = gateway.ensure_lab()
            config = gateway.gather_gateway_parameters(lab['name'])
            if config:
                gateway.execute_gateway_deployment(config)
        elif choice == '2':
            _module('ludus', 'deploy_ludus.py').ludus_menu()
            continue
        elif choice == '3':
            _module('exfil', 'deploy_exfil.py').exfil_menu()
            continue
        elif choice in actions:
            lab = pick_lab()
            if lab:
                actions[choice](lab)
        elif choice == '99':
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
        wait_for_input()


if __name__ == '__main__':
    lab_menu()
