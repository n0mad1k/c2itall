#!/usr/bin/env python3
"""Prove a lab end to end on one provider: gateway, members, overlay, logged egress, teardown.

    venv/bin/python scripts/test_lab_live.py --provider azure --members exfil_receiver --activate
    venv/bin/python scripts/test_lab_live.py --provider linode --members exfil_receiver,c2 --activate
    venv/bin/python scripts/test_lab_live.py --provider flokinet --activate
        (an Azure stand-in host joins an Azure gateway as an overlay member, like test_flokinet_live.py)
    venv/bin/python scripts/test_lab_live.py --provider local --gateway-host 192.168.56.10 \
        --member-hosts 192.168.56.11 --members exfil_receiver --activate
        (VMs from scripts/local_vm.py; the operator address is the host-only interface)

Each check is one step in logs/lab-live/<lab>/result.json. The lab is removed
with `teardown.py --lab` from a fresh process that holds no provider credential,
and the provider's account totals must return to their baseline.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts')]

from live_clouds import build_cloud, live_config, public_ipv4  # noqa: E402
from utils import lab as lab_mod  # noqa: E402
from utils.cloud_driver import ProvisionRequest  # noqa: E402
from utils.common import setup_logging  # noqa: E402
from utils.deployment_engine import deploy_infrastructure  # noqa: E402
from utils.provider_registry import PROVIDER_SPECS, prepare_provider_environment, provider_driver  # noqa: E402
from utils.ssh_utils import ssh_options  # noqa: E402

CREDENTIALS = tuple(env for spec in PROVIDER_SPECS.values() for _, env in spec.credential_environment)
HOST_KEYS = {'flokinet': ('flokinet_host', 'flokinet_bootstrap_key'), 'local': ('local_host', 'local_bootstrap_key')}
SOURCE_PATHS = ('utils', 'teardown.py', 'scripts', 'modules/lab', 'modules/gateway', 'modules/exfil',
                'modules/ludus', 'modules/c2', 'providers')


class Live:
    def __init__(self, args):
        self.args = args
        self.name = 'lt' + uuid.uuid4().hex[:6]
        self.evidence = ROOT / 'logs' / 'lab-live' / self.name
        self.evidence.mkdir(parents=True, mode=0o700)
        self.report = {'lab': self.name, 'provider': args.provider, 'members': args.members, 'steps': {}}
        self.failed = False

    def step(self, name, ok, detail=''):
        self.report['steps'][name] = {'ok': bool(ok), 'detail': str(detail)[-800:]}
        (self.evidence / 'result.json').write_text(json.dumps(self.report, indent=2))
        print('STEP', name, 'OK' if ok else 'FAIL', str(detail)[-300:], flush=True)
        if not ok:
            self.failed = True
        return bool(ok)

    def record(self, name, data):
        (self.evidence / name).write_text(json.dumps(data, indent=2, default=str))

    # --- reaching hosts ----------------------------------------------------
    def gateway_ssh(self, command, timeout=120):
        lab = lab_mod.load(self.name)
        target = lab_mod.gateway_target(lab)
        argv = ['ssh', *ssh_options(target['known_hosts'], target['key']),
                target['user'] + '@' + target['host'], command]
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)

    def member_ssh(self, deployment_id, command, timeout=120):
        return lab_mod.member_command(self.name, deployment_id, ['sh', '-c', command], timeout=timeout)

    # --- configs -----------------------------------------------------------
    def account(self, provider, host=None):
        config = live_config(provider)
        config.pop('azure_os_disk_gb', None)
        if provider in HOST_KEYS:
            host_key, key_key = HOST_KEYS[provider]
            config.update({host_key: host, key_key: str(self.args.bootstrap_key), 'provider_manages_ssh_key': True})
        return config

    def gateway_config(self, lab):
        provider = self.args.gateway_provider
        deployment_id = 'lt-gw-' + uuid.uuid4().hex[:6]
        return {'provider': provider, 'provider_workload': 'lab_gateway', 'deployment_type': 'lab_gateway',
                'deployment_id': deployment_id, 'lab': lab['name'], 'lab_gateway_name': 'gw-' + deployment_id,
                'operator_ip': self.operator, 'ssh_key_path': lab['ssh_key_path'], 'ssh_after_deploy': False,
                **self.account(provider, self.args.gateway_host)}

    def deploy_member(self, workload, host):
        """Run the same builder the lab menu uses, with its prompts answered."""
        lab = lab_mod.load(self.name)
        before = set(lab['members'])
        provider = self.args.provider
        answers = {'operator names': 'red1', 'Lab name': self.name, 'range': self.args.ludus_range}
        patches = [mock.patch('builtins.input', lambda prompt='': next(
            (value for key, value in answers.items() if key.lower() in prompt.lower()), ''))]
        if workload in ('c2', 'payload_server', 'attack_box', 'logging_server', 'chat'):
            red = load_module('modules/lab/red.py')
            patches += [mock.patch.object(red, 'select_provider', return_value=provider),
                        mock.patch.object(red, 'gather_provider_config',
                                          return_value=dict(self.account(provider, host), operator_ip=self.operator)),
                        mock.patch.object(red, 'confirm_action', return_value=True)]
            run = lambda: getattr(red, workload)(lab)  # noqa: E731
        else:
            directory, stem = {'exfil_receiver': ('exfil', 'exfil'), 'ludus_host': ('ludus', 'ludus')}[workload]
            module = load_module('modules/{0}/deploy_{1}.py'.format(directory, stem))
            patches += [mock.patch.object(module, 'select_provider', return_value=provider),
                        mock.patch.object(module, 'gather_provider_config',
                                          return_value=dict(self.account(provider, host), operator_ip=self.operator))]
            if hasattr(module, 'prepare_module_ssh_key'):
                patches.append(mock.patch.object(module, 'prepare_module_ssh_key', return_value=(True, None)))

            def run():
                config = getattr(module, 'gather_{0}_parameters'.format(stem))(self.name)
                if config is None:
                    return False
                config['ssh_after_deploy'] = False
                self.record(workload + '-config.json', {k: v for k, v in config.items()
                                                        if not any(s in k for s in ('password', 'key', 'secret'))})
                self.member_configs[workload] = config
                return deploy_infrastructure(config)
        for patch in patches:
            patch.start()
        try:
            ok = run()
        finally:
            for patch in reversed(patches):
                patch.stop()
        lab = lab_mod.load(self.name)
        new = [deployment_id for deployment_id in lab['members'] if deployment_id not in before]
        return ok, (new[0] if new else None)

    # --- checks ------------------------------------------------------------
    def check_gateway(self):
        lab = lab_mod.load(self.name)
        gateway = lab['gateway']
        self.step('gateway_registered', gateway and gateway['status'] == 'ready', gateway)
        result = self.gateway_ssh(
            "set -e; sudo -n wg show wg0 peers | grep -c . ; sudo -n sysctl -n net.ipv4.ip_forward; "
            "systemctl is-active wg-quick@wg0 lab-hub-fw rsyslog; sudo -n iptables -t nat -S LAB_NAT | grep -c MASQUERADE; "
            "sudo -n test -f /var/log/lab/flows.log && echo flows; sudo -n ufw status | head -1")
        lines = result.stdout.split()
        self.step('gateway_hub_up', result.returncode == 0 and lines[:1] >= ['1'] and lines[1:2] == ['1']
                  and lines[2:5] == ['active'] * 3 and 'flows' in lines and 'active' in result.stdout.split('\n')[-2],
                  result.stdout + result.stderr)
        operator = lab_mod.secret_dir(lab) / 'operator.conf'
        self.step('operator_config_private', operator.is_file() and (operator.stat().st_mode & 0o777) == 0o600,
                  str(operator))

    def check_member(self, workload, deployment_id):
        lab = lab_mod.load(self.name)
        member = lab['members'][deployment_id]
        network = lab['networks'].get(member['provider'])
        native = network is not None
        prefix = workload + '.'
        self.step(prefix + 'registered', member['status'] == 'ready', member)
        result = self.member_ssh(deployment_id, "sudo -n wg show wg0 latest-handshakes | awk '{print $2}' | grep -vqx 0 && "
                                 "ip -4 addr show wg0 | grep -q ' " + member['lab_ip'] + "/32' && echo overlay")
        self.step(prefix + 'overlay_joined', 'overlay' in result.stdout, result.stdout + result.stderr)
        hub = self.gateway_ssh('sudo -n wg show wg0 allowed-ips')
        self.step(prefix + 'hub_routes_member', member['lab_ip'] + '/32' in hub.stdout, hub.stdout)
        ping = self.gateway_ssh('ping -c 2 -W 3 ' + member['lab_ip'])
        self.step(prefix + 'reachable_over_overlay', ping.returncode == 0, ping.stdout[-200:])
        egress = self.member_ssh(deployment_id, 'curl -4 -s --max-time 25 https://api.ipify.org')
        expected = network['nat_ip'] if native else lab['gateway']['public_ip']
        self.step(prefix + 'egress_through_' + ('nat_gateway' if native else 'hub'),
                  egress.stdout.strip() == expected, egress.stdout.strip() + ' expected ' + str(expected))
        if native:
            inventory = self.cloud.inventory({'deployment_id': deployment_id})
            instances = inventory.get('instances', [])
            self.step(prefix + 'no_public_ip', instances and all(not item.get('public_ip') for item in instances),
                      instances)
        else:
            flows = self.gateway_ssh('sudo -n grep -c LABFLOW /var/log/lab/flows.log')
            self.step(prefix + 'hub_logged_flows', flows.stdout.strip().isdigit() and int(flows.stdout.strip()) > 0,
                      flows.stdout.strip())
        getattr(self, 'verify_' + workload, lambda d: None)(deployment_id)

    def verify_exfil_receiver(self, deployment_id):
        lab = lab_mod.load(self.name)
        member = lab['members'][deployment_id]
        creds = lab_mod.read_secret(lab, 'exfil.json') or {}
        ip = member['lab_ip']
        listening = self.member_ssh(deployment_id, "ss -ltn | grep -c -E ':(9000|8443|2222) '")
        self.step('exfil.listening', listening.stdout.strip() == '3', listening.stdout + listening.stderr)
        env = ' '.join('{0}={1}'.format(key, json.dumps(str(value))) for key, value in creds.items())
        upload = self.gateway_ssh(
            'set -e; export ' + env + '; cd /tmp; for f in http s3 sftp; do head -c 200000 /dev/urandom > lab-$f.bin; done; '
            'curl -ks --fail -u "$exfil_http_user:$exfil_http_password" -T lab-http.bin https://' + ip + ':8443/upload/lab-http.bin; '
            'rclone --s3-provider Minio --s3-endpoint http://' + ip + ':9000 --s3-access-key-id "$exfil_minio_user" '
            '--s3-secret-access-key "$exfil_minio_password" copyto lab-s3.bin :s3:drop/lab-s3.bin; '
            'curl -ks --fail -u "drop:$exfil_sftp_password" -T lab-sftp.bin sftp://' + ip + ':2222/upload/lab-sftp.bin; '
            'sha256sum lab-http.bin lab-s3.bin lab-sftp.bin', timeout=300)
        self.step('exfil.uploads_from_gateway', upload.returncode == 0, upload.stdout + upload.stderr)
        hashes = dict(line.split()[::-1] for line in upload.stdout.splitlines() if line.strip().endswith('.bin'))
        ledger = ''
        for _ in range(24):
            time.sleep(10)
            ledger = self.member_ssh(deployment_id, 'sudo -n cat /var/log/exfil/ledger.jsonl 2>/dev/null').stdout
            if ledger.count('\n') >= 3:
                break
        entries = [json.loads(line) for line in ledger.splitlines() if line.strip()]
        self.record('exfil-ledger.json', entries)
        self.step('exfil.ledger_records_every_channel', {e.get('channel') for e in entries} >= {'http', 's3', 'sftp'},
                  ledger[-600:])
        self.step('exfil.ledger_hashes_match', {e.get('sha256') for e in entries} >= set(hashes.values()), hashes)
        self.step('exfil.ledger_attributes_gateway', all(e.get('src') == lab['gateway']['lab_ip'] for e in entries),
                  [e.get('src') for e in entries])
        manifest = self.evidence / 'manifest.json'
        manifest.write_text(json.dumps({'set': 'live', 'generated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                                        'canary_token': 'none', 'total_bytes': 600000,
                                        'files': [{'path': name, 'size': 200000, 'sha256': digest}
                                                  for name, digest in hashes.items()]}))
        pushed = lab_mod.run_member_playbook(self.name, deployment_id, 'modules/exfil/push_manifest.yml',
                                             {'manifest_src': str(manifest)}, 'exfil-verify', 300)
        verify = self.member_ssh(deployment_id, 'sudo -n exfil-receiver verify /var/lib/exfil/manifests/manifest.json')
        self.step('exfil.manifest_verified', pushed and verify.returncode == 0, verify.stdout + verify.stderr)
        before = self.member_ssh(deployment_id, 'sudo -n sha256sum /etc/exfil/minio.env').stdout
        self.step('exfil.repeat_deploy', deploy_infrastructure(self.member_configs['exfil_receiver']))
        after = self.member_ssh(deployment_id, 'sudo -n sha256sum /etc/exfil/minio.env').stdout
        self.step('exfil.credentials_stable_on_repeat', before and before == after, before + after)
        clean = self.member_ssh(deployment_id, 'sudo -n exfil-receiver clean && ls -A /srv/exfil/http /srv/exfil/sftp/upload | grep -c . || true')
        self.step('exfil.clean_empties_channels', clean.returncode == 0 and clean.stdout.strip().splitlines()[-1:] in ([], ['0']),
                  clean.stdout[-400:] + clean.stderr[-200:])

    def verify_c2(self, deployment_id):
        lab = lab_mod.load(self.name)
        ip = lab['members'][deployment_id]['lab_ip']
        result = self.member_ssh(deployment_id, "systemctl is-active havoc; ss -ltn | grep -c -E ':(40056|9443|8443) '; "
                                 "sudo -n grep -c '\"" + ip + "\"' /root/Tools/Havoc/data/havoc.yaotl; "
                                 "sudo -n grep -c 'Cert {' /root/Tools/Havoc/data/havoc.yaotl; "
                                 "sudo -n grep -c 'user \"red1\"' /root/Tools/Havoc/data/havoc.yaotl; "
                                 "sudo -n jq -r .windows_exe_sha256 /root/Tools/Havoc/payloads/manifest.json", timeout=180)
        lines = result.stdout.split()
        self.step('c2.teamserver_on_lab_address', lines[:5] == ['active', '3', '1', '0', '1'] and len(lines) > 5
                  and len(lines[5]) == 64, result.stdout + result.stderr)
        manifest = self.member_ssh(deployment_id, 'sudo -n jq -r .windows_exe /root/Tools/Havoc/payloads/manifest.json').stdout.strip()
        fetched = self.gateway_ssh('curl -ks -o /dev/null -w "%{http_code}" --max-time 20 https://' + ip + ':8443/content/windows/' + manifest)
        self.step('c2.payload_served_inside_lab', fetched.stdout.strip() == '200', fetched.stdout + manifest)
        killed = self.member_ssh(deployment_id, 'sudo -n /root/Tools/havoc_killall.sh; systemctl is-active havoc || true')
        self.step('c2.killall_stops_teamserver', 'inactive' in killed.stdout, killed.stdout[-300:])

    def verify_payload_server(self, deployment_id):
        ip = lab_mod.load(self.name)['members'][deployment_id]['lab_ip']
        result = self.gateway_ssh('curl -ks -o /dev/null -w "%{http_code}" --max-time 20 https://' + ip + '/')
        self.step('payload_server.answers_lab_clients', result.stdout.strip() not in ('', '403', '000'), result.stdout)

    def verify_attack_box(self, deployment_id):
        result = self.member_ssh(deployment_id, 'which nmap && ! ss -lun | grep -q :1194 && echo plain')
        self.step('attack_box.tools_without_vpn', 'plain' in result.stdout, result.stdout + result.stderr)

    def verify_logging_server(self, deployment_id):
        result = self.member_ssh(deployment_id, "sudo -n docker ps --format '{{.Names}}' | grep -c redelk; ss -ltn | grep -c ':5044 '")
        self.step('logging_server.redelk_up', result.stdout.split()[:2] >= ['4', '1'], result.stdout + result.stderr)

    def verify_chat(self, deployment_id):
        ip = lab_mod.load(self.name)['members'][deployment_id]['lab_ip']
        result = self.gateway_ssh('curl -ks -o /dev/null -w "%{http_code}" --max-time 20 https://' + ip + '/_matrix/client/versions')
        self.step('chat.matrix_answers_inside_lab', result.stdout.strip() == '200', result.stdout)

    def verify_ludus_host(self, deployment_id):
        result = self.member_ssh(deployment_id, "sudo -n ludus-install-status 2>&1 | tail -1; sudo -n stat -c %a /root/.ludus-lab.env; "
                                 "systemctl is-active lab-datasets lab-routing; sudo -n iptables -S LAB_API | grep -c 8080; "
                                 "ls /srv/lab-datasets | grep -c manifest", timeout=300)
        self.step('ludus_host.installed', result.returncode == 0 and '600' in result.stdout.split()
                  and 'active' in result.stdout, result.stdout + result.stderr)

    # --- flow ----------------------------------------------------------------
    def standin(self):
        """An Azure VM with root login for the deployment key, as test_flokinet_live.py builds."""
        prepare_provider_environment({'provider': 'azure'})
        azure = provider_driver('azure')
        az_id = 'lt-standin-' + uuid.uuid4().hex[:6]
        config = {'provider': 'azure', 'deployment_id': az_id, 'operator_ip': self.operator, **live_config('azure')}
        config.pop('azure_os_disk_gb', None)
        key = Path.home() / '.ssh' / ('c2deploy_' + az_id)
        plan = azure.plan(config, ProvisionRequest(az_id, 'tracker', [], 'ubuntu', 32, str(key) + '.pub', str(key), True))
        azure.prepare_state(plan)
        azure.prepare_ssh_key(plan)
        self.step('standin_deployed', azure.deploy(plan))
        ip = azure.public_address(az_id, config)
        argv = ['ssh', *ssh_options(self.evidence / 'standin-known-hosts', key), 'azureuser@' + ip,
                "sudo install -d -m 700 /root/.ssh && sudo cp /home/azureuser/.ssh/authorized_keys /root/.ssh/authorized_keys"
                " && sudo chmod 600 /root/.ssh/authorized_keys && printf 'PermitRootLogin prohibit-password\\n' | sudo tee"
                " /etc/ssh/sshd_config.d/00-root.conf >/dev/null && sudo systemctl reload ssh && echo root-ready"]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        self.step('standin_root_login', 'root-ready' in result.stdout, result.stderr)
        self.standin_cleanup = lambda: azure.cleanup(azure.cleanup_request(config))
        self.args.bootstrap_key = key
        return ip

    def run(self):
        args = self.args
        for executable in ('ansible-playbook', 'ssh', 'ssh-keygen', 'curl', 'git'):
            if not shutil.which(executable):
                return self.step('tools_present', False, executable)
        dirty = [path for path in SOURCE_PATHS
                 if subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--', path]).returncode]
        if not self.step('source_committed', not dirty, dirty):
            return False
        self.report['commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        self.operator = args.operator_ip or public_ipv4(subprocess.check_output(
            ['curl', '-4', '--fail', '--silent', '--max-time', '15', 'https://api.ipify.org'], text=True).strip())
        cloud_provider = 'azure' if args.provider == 'flokinet' else args.provider
        prepare_provider_environment({'provider': cloud_provider})
        self.cloud = build_cloud(cloud_provider, self.evidence)
        self.member_configs = {}
        self.standin_cleanup = None
        member_hosts = list(args.member_hosts)
        baseline = self.cloud.totals()
        self.record('baseline.json', baseline)
        lab = lab_mod.create(self.name)
        self.step('lab_created', (lab_mod.LAB_ROOT / (self.name + '.json')).is_file(), lab_mod.LAB_ROOT / self.name)
        try:
            setup_logging('lab-' + self.name, 'live_test')
            if args.provider == 'flokinet':
                member_hosts = [self.standin()]
            gateway = self.gateway_config(lab)
            self.record('gateway-config.json', {k: v for k, v in gateway.items() if 'key' not in k})
            if not self.step('gateway_deployed', deploy_infrastructure(gateway)):
                return False
            self.check_gateway()
            for index, workload in enumerate(args.members):
                host = member_hosts[index] if index < len(member_hosts) else None
                ok, deployment_id = self.deploy_member(workload, host)
                if not self.step(workload + '.deployed', ok and deployment_id, deployment_id):
                    continue
                self.check_member(workload, deployment_id)
            self.record('lab-record.json', lab_mod.load(self.name))
            return not self.failed
        finally:
            if args.keep:
                print('Keeping lab ' + self.name + ' as requested')
            else:
                self.teardown(baseline)
            if self.standin_cleanup:
                self.step('standin_cleanup', self.standin_cleanup())
            self.report['passed'] = not self.failed and not args.keep
            (self.evidence / 'result.json').write_text(json.dumps(self.report, indent=2))
            print('RESULT', 'PASS' if self.report['passed'] else 'FAIL', self.evidence, flush=True)

    def teardown(self, baseline):
        env = {key: value for key, value in os.environ.items() if key not in CREDENTIALS}
        result = subprocess.run([sys.executable, 'teardown.py', '--lab', self.name, '--force'], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=3600)
        (self.evidence / 'standalone-teardown.txt').write_text(result.stdout[-30000:] + '\n--- stderr ---\n' + result.stderr[-5000:])
        self.step('standalone_teardown', result.returncode == 0, 'exit ' + str(result.returncode) + ' ' + result.stdout[-300:])
        gone = not (lab_mod.LAB_ROOT / (self.name + '.json')).exists() and not (lab_mod.LAB_ROOT / self.name).exists()
        self.step('lab_record_and_secrets_removed', gone, str(lab_mod.LAB_ROOT))
        getattr(self.cloud, 'settle', lambda: None)()
        deadline = time.monotonic() + 600
        totals = self.cloud.totals()
        while totals != baseline and time.monotonic() < deadline:
            time.sleep(20)
            totals = self.cloud.totals()
        self.step('account_totals_restored', totals == baseline, {'before': baseline, 'after': totals})


def load_module(relative):
    import importlib.util
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--provider', choices=['azure', 'aws', 'linode', 'flokinet', 'local'], required=True)
    parser.add_argument('--gateway-provider', help='where the hub runs (default: --provider; azure for flokinet)')
    parser.add_argument('--members', default='exfil_receiver', help='comma-separated workloads to join as members')
    parser.add_argument('--gateway-host', help='local/flokinet: the gateway host to adopt')
    parser.add_argument('--member-hosts', default='', help='local/flokinet: hosts to adopt, one per member')
    parser.add_argument('--bootstrap-key', type=Path, default=Path.home() / '.ssh' / 'c2deploy_local')
    parser.add_argument('--ludus-range', default='mini')
    parser.add_argument('--operator-ip')
    parser.add_argument('--keep', action='store_true', help='leave the lab running (the run then does not pass)')
    parser.add_argument('--activate', action='store_true')
    args = parser.parse_args(argv)
    args.members = [item.strip() for item in args.members.split(',') if item.strip()]
    args.member_hosts = [item.strip() for item in args.member_hosts.split(',') if item.strip()]
    args.gateway_provider = args.gateway_provider or ('azure' if args.provider == 'flokinet' else args.provider)
    if args.provider == 'local' and not args.operator_ip:
        args.operator_ip = '192.168.56.1'
    if not args.activate:
        print('DRY RUN: pass --activate to build lab on {0} with members {1}'.format(args.provider, args.members))
        return 0
    return 0 if Live(args).run() else 1


if __name__ == '__main__':
    sys.exit(main())
