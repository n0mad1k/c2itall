"""Prove the FlokiNET driver against a stand-in host.

FlokiNET has no API, so the live harness cannot order a server. This test
creates one Azure VM through the Azure driver, enables root login on it with
the Azure deployment key (the "key that currently opens root@host"), and then
runs the FlokiNET route end to end against it: adopt, deploy the tracker,
verify as root with the deployment key, repeat, standalone teardown, confirm
only the deployment key was revoked, remove the stand-in. Evidence lands under
logs/flokinet-tracker-live/<deployment_id>/result.json.

    venv/bin/python scripts/test_flokinet_live.py --activate
"""
import json, os, shutil, subprocess, sys, uuid
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
if '--activate' not in sys.argv[1:]:
    print('DRY RUN: pass --activate to create one Azure stand-in VM and run the FlokiNET route against it')
    raise SystemExit(0)
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts')]
from live_clouds import live_config, public_ipv4
from utils.provider_registry import prepare_provider_environment, provider_driver
from utils.cloud_driver import ProvisionRequest
from utils.deployment_engine import deploy_infrastructure
from utils.common import setup_logging

op = public_ipv4(subprocess.check_output(['curl', '-4', '--fail', '--silent', 'https://api.ipify.org'], text=True).strip())
az_id = 'lt-standin-' + uuid.uuid4().hex[:6]
fl_id = 'lt-flokinet-tracke-' + uuid.uuid4().hex[:6]
evidence = ROOT / 'logs' / 'flokinet-tracker-live' / fl_id
evidence.mkdir(parents=True, mode=0o700)
report = {'provider': 'flokinet', 'workload': 'tracker', 'deployment_id': fl_id, 'stand_in': 'azure/' + az_id,
          'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(), 'steps': {}}

def step(name, ok, detail=''):
    report['steps'][name] = {'ok': bool(ok), 'detail': str(detail)[-500:]}
    (evidence / 'result.json').write_text(json.dumps(report, indent=2))
    print('STEP', name, 'OK' if ok else 'FAIL', str(detail)[-300:], flush=True)
    return bool(ok)

def ssh(user, keypath, command, ip):
    return subprocess.run(['ssh', '-F', '/dev/null', '-i', str(keypath), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                           '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=' + str(evidence / 'known_hosts'),
                           '-o', 'ConnectTimeout=10', user + '@' + ip, command], capture_output=True, text=True, timeout=180)

prepare_provider_environment({'provider': 'azure'})
azure = provider_driver('azure')
az_config = {'provider': 'azure', 'deployment_id': az_id, 'operator_ip': op, **live_config('azure')}
az_config.pop('azure_os_disk_gb', None)
key = Path.home() / '.ssh' / ('c2deploy_' + az_id)
rules = [{'name': 'http', 'protocol': 'Tcp', 'port': 80, 'source': '*'},
         {'name': 'https', 'protocol': 'Tcp', 'port': 443, 'source': '*'}]
ip = None
try:
    plan = azure.plan(az_config, ProvisionRequest(az_id, 'tracker', rules, 'ubuntu', 32, str(key) + '.pub', str(key), True))
    azure.prepare_state(plan)
    azure.prepare_ssh_key(plan)
    if not step('azure_standin_deployed', azure.deploy(plan)):
        raise SystemExit(1)
    ip = azure.public_address(az_id, az_config)
    step('azure_standin_ip', ip, ip)
    r = ssh('azureuser', key, "sudo install -d -m 700 /root/.ssh && sudo cp /home/azureuser/.ssh/authorized_keys /root/.ssh/authorized_keys"
            " && sudo chmod 600 /root/.ssh/authorized_keys && printf 'PermitRootLogin prohibit-password\\n' | sudo tee /etc/ssh/sshd_config.d/00-root.conf >/dev/null"
            " && sudo systemctl reload ssh && echo root-ready", ip)
    if not step('root_login_enabled', 'root-ready' in r.stdout, r.stderr):
        raise SystemExit(1)
    r = ssh('root', key, 'id -u', ip)
    if not step('root_ssh_with_bootstrap_key', r.stdout.strip() == '0', r.stderr):
        raise SystemExit(1)

    fl_config = {'provider': 'flokinet', 'provider_workload': 'tracker', 'deployment_type': 'email_tracker',
                 'deployment_id': fl_id, 'flokinet_host': ip, 'flokinet_bootstrap_key': str(key), 'operator_ip': op,
                 'tracker_name': 't-' + fl_id, 'domain': 'tracker-lab.test', 'tracker_subdomain': 'track',
                 'letsencrypt_email': 'admin@tracker-lab.test', 'zero_logs': True, 'ssh_after_deploy': False,
                 'provider_manages_ssh_key': True}
    (evidence / 'config.json').write_text(json.dumps(fl_config, indent=2))
    setup_logging(fl_id, 'live_test')
    deployed = deploy_infrastructure(fl_config)
    step('flokinet_tracker_deployed', deployed)
    flkey = Path.home() / '.ssh' / ('c2deploy_' + fl_id)
    saved = evidence / 'deployment-key'
    if deployed and flkey.is_file():
        shutil.copy(flkey, saved); os.chmod(saved, 0o600)
        pub = (Path(str(flkey) + '.pub')).read_text().strip()
        checks = ("set -u; test \"$(systemctl is-active tracker)\" = active && test \"$(systemctl is-active nginx)\" = active"
                  " && ss -ltn | grep -q ':443 '"
                  " && test \"$(curl -ks -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: track.tracker-lab.test' https://127.0.0.1/pixel/local.png)\" = 200"
                  " && /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"
                  " && ufw status | grep -q '22/tcp.*ALLOW.*" + op + "' && ufw status | grep -Eq '^443/tcp +ALLOW +Anywhere'"
                  " && ufw status | grep -Eq '^80/tcp +ALLOW +Anywhere' && ufw status | grep -q 'Status: active' && echo verified")
        r = ssh('root', flkey, checks, ip)
        step('tracker_verified_as_root_with_deployment_key', 'verified' in r.stdout, r.stdout + r.stderr)
        pixel = subprocess.run(['curl', '-ks', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20',
                                'https://' + ip + '/pixel/live.png'], capture_output=True, text=True).stdout
        step('pixel_public', pixel == '200', pixel)
        step('repeat_deploy_idempotent', deploy_infrastructure(fl_config))
        r = subprocess.run([sys.executable, 'teardown.py', '--deployment-id', fl_id, '--force'],
                           capture_output=True, text=True, timeout=900)
        (evidence / 'standalone-teardown.txt').write_text(r.stdout[-30000:] + '\n--- stderr ---\n' + r.stderr[-5000:])
        step('standalone_teardown_exit', r.returncode == 0, 'exit ' + str(r.returncode) + ' ' + r.stdout[-300:])
        r = ssh('root', saved, 'id -u', ip)
        step('deployment_key_revoked', r.returncode != 0, r.stderr)
        r = ssh('root', key, 'grep -cF ' + json.dumps(pub) + ' /root/.ssh/authorized_keys; echo bootstrap-still-works', ip)
        step('bootstrap_key_still_works_and_deployment_key_absent', 'bootstrap-still-works' in r.stdout and r.stdout.strip().startswith('0'), r.stdout + r.stderr)
        leftovers = [str(p) for p in (flkey, Path(str(flkey) + '.pub'), ROOT / 'logs' / ('deployment_info_' + fl_id + '.txt'),
                                      ROOT / 'deployments' / 'flokinet' / (fl_id + '.json')) if p.exists()]
        step('local_artifacts_absent', not leftovers, leftovers)
finally:
    if ip is not None or (ROOT / 'deployments' / 'azure' / (az_id + '.json')).exists():
        step('azure_standin_cleanup', azure.cleanup(azure.cleanup_request(az_config)))
    report['passed'] = all(item['ok'] for item in report['steps'].values())
    (evidence / 'result.json').write_text(json.dumps(report, indent=2))
    print('RESULT', 'PASS' if report['passed'] else 'FAIL', evidence, flush=True)
