#!/usr/bin/env python3
"""Build or remove a Debian VirtualBox VM the `local` provider can adopt.

    venv/bin/python scripts/local_vm.py create lab-gw --ip 192.168.56.10
    venv/bin/python scripts/local_vm.py create lab-ludus --ip 192.168.56.12 --cpus 8 --ram 20480 --disk 150 --nested
    venv/bin/python scripts/local_vm.py destroy lab-gw

The VM gets a NAT adapter for egress and a host-only adapter (vboxnet0, the
host is 192.168.56.1) with the static address given; Debian installs
unattended from the netinst ISO, root logs in with ~/.ssh/c2deploy_local only.
`create` returns once root answers over SSH. Test tooling only: nothing here
is part of a deployment.
"""

import argparse
import secrets
import subprocess
import sys
import time
from pathlib import Path

ISO = next(iter(sorted(Path.home().glob('Downloads/debian-1[23]*-amd64-netinst.iso'))), None)
KEY = Path.home() / '.ssh' / 'c2deploy_local'
HOST_ONLY = 'vboxnet0'


def vbox(*args, check=True):
    return subprocess.run(['VBoxManage', *args], check=check, text=True, capture_output=True)


def bootstrap_key():
    if not KEY.is_file():
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', str(KEY)], check=True)
    return Path(str(KEY) + '.pub').read_text().strip()


def ssh_ready(ip):
    return subprocess.run(['ssh', '-F', '/dev/null', '-i', str(KEY), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                           '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                           '-o', 'ConnectTimeout=5', 'root@' + ip, 'true'],
                          capture_output=True).returncode == 0


def create(args):
    if ISO is None:
        sys.exit('No Debian netinst ISO under ~/Downloads')
    public_key = bootstrap_key()
    folder = Path.home() / 'VirtualBox VMs' / args.name
    disk = folder / (args.name + '.vdi')
    vbox('createvm', '--name', args.name, '--ostype', 'Debian_64', '--register')
    vbox('modifyvm', args.name, '--cpus', str(args.cpus), '--memory', str(args.ram), '--vram', '16',
         '--graphicscontroller', 'vmsvga', '--audio-driver', 'none', '--boot1', 'disk', '--boot2', 'dvd',
         '--nic1', 'nat', '--nic2', 'hostonly', '--hostonlyadapter2', HOST_ONLY,
         '--nested-hw-virt', 'on' if args.nested else 'off', '--rtc-use-utc', 'on')
    vbox('createmedium', 'disk', '--filename', str(disk), '--size', str(args.disk * 1024))
    vbox('storagectl', args.name, '--name', 'SATA', '--add', 'sata', '--controller', 'IntelAhci')
    vbox('storageattach', args.name, '--storagectl', 'SATA', '--port', '0', '--device', '0', '--type', 'hdd',
         '--medium', str(disk))
    # Runs inside the installed system at the end of the Debian install.
    post_install = (
        "apt-get install -y openssh-server sudo >/dev/null 2>&1; "
        "printf 'auto enp0s8\\niface enp0s8 inet static\\n address " + args.ip + "/24\\n' > /etc/network/interfaces.d/lab; "
        "install -d -m 700 /root/.ssh; printf '%s\\n' '" + public_key + "' > /root/.ssh/authorized_keys; "
        "chmod 600 /root/.ssh/authorized_keys; "
        "printf 'PermitRootLogin prohibit-password\\nPasswordAuthentication no\\n' > /etc/ssh/sshd_config.d/lab.conf")
    vbox('unattended', 'install', args.name, '--iso=' + str(ISO), '--user=lab',
         '--user-password=' + secrets.token_urlsafe(16), '--hostname=' + args.name + '.lab',
         '--package-selection-adjustment=minimal', '--no-install-additions', '--time-zone=UTC',
         '--locale=en_US', '--country=US', '--post-install-command=' + post_install, '--start-vm=headless')
    deadline = time.monotonic() + args.timeout
    while not ssh_ready(args.ip):
        if time.monotonic() >= deadline:
            sys.exit(args.name + ' did not answer on ' + args.ip + ' in time')
        time.sleep(20)
    print(args.name + ' ready: root@' + args.ip + ' with ' + str(KEY))


def destroy(args):
    vbox('controlvm', args.name, 'poweroff', check=False)
    time.sleep(3)
    vbox('unregistervm', args.name, '--delete')
    print(args.name + ' removed')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='action', required=True)
    make = sub.add_parser('create')
    make.add_argument('name')
    make.add_argument('--ip', required=True)
    make.add_argument('--cpus', type=int, default=2)
    make.add_argument('--ram', type=int, default=2048)
    make.add_argument('--disk', type=int, default=16)
    make.add_argument('--nested', action='store_true')
    make.add_argument('--timeout', type=int, default=2400)
    make.set_defaults(run=create)
    remove = sub.add_parser('destroy')
    remove.add_argument('name')
    remove.set_defaults(run=destroy)
    args = parser.parse_args()
    args.run(args)


if __name__ == '__main__':
    main()
