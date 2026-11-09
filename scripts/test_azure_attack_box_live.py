#!/usr/bin/env python3
"""Deploy, repeat, verify, and remove one real Azure quick-recon box."""

import argparse
import json
from pathlib import Path
import shutil
import signal
import sys
import time
import uuid

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
for path in (SCRIPT_DIR, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from deploy_azure_smoke import LOCATION, SIZE, SUBSCRIPTION, Runner, public_ipv4
from test_azure_infrastructure_live import snapshot
from test_azure_phantom_live import preflight, require

import teardown as standalone_teardown
from utils.deployment_engine import deploy_infrastructure
from utils.provider_registry import infrastructure_adapter, workload_route


STATE_DIR = ROOT / 'deployments' / 'azure'


def verify_committed_source(runner):
    paths = (
        'modules/attack-box/deploy_attack_box.py',
        'modules/attack-box/tasks/configure_quick_recon.yml',
        'modules/attack-box/service.yml',
        'providers/Azure/infrastructure.yml',
        'providers/Azure/templates/infrastructure.json.j2',
        'scripts/test_azure_attack_box_live.py',
        'teardown.py', 'tests/test_azure_provider.py',
        'utils/azure_cloud.py', 'utils/azure_utils.py',
        'utils/azure_runtime.py', 'utils/vm_workloads.py', 'modules/attack-box/workload.py',
        'utils/cleanup_engine.py',
        'utils/deployment_engine.py', 'utils/provider_registry.py',
    )
    for path in paths:
        runner.run(['git', 'diff', '--quiet', 'HEAD', '--', path])
    return runner.run(['git', 'rev-parse', 'HEAD'])


def verify_quick_recon(runner, config):
    command = (
        'set -eu; '
        'test "$(. /etc/os-release; printf %s "$VERSION_ID")" = 24.04; '
        'sudo -n test -d /root/' + config['deployment_id'] + '/scans; '
        'sudo -n test -s /root/QUICK_RECON_GUIDE.txt; '
        'command -v nmap >/dev/null; command -v dig >/dev/null; '
        'command -v tor >/dev/null; command -v torsocks >/dev/null; '
        'command -v proxychains4 >/dev/null; '
        'test "$(systemctl is-enabled tor)" = enabled; '
        'systemctl is-active tor >/dev/null; '
        "sudo -n grep -Fq \"alias qr='cd /root/" + config['deployment_id'] +
        "'\" /root/.bashrc; "
        "sudo -n /usr/sbin/sshd -T | grep -q '^passwordauthentication no$'"
    )
    runner.run([
        'ssh', '-F', '/dev/null', '-i', config['ssh_private_key_path'],
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'UserKnownHostsFile=' + str(runner.evidence / 'known_hosts'),
        'azureuser@' + config['attack_box_ip'], command,
    ], timeout=90)
    return {
        'ubuntu_24_04': True, 'workspace': True, 'quick_guide': True,
        'nmap': True, 'dnsutils': True, 'tor': True, 'torsocks': True,
        'proxychains': True, 'tor_enabled': True, 'tor_active': True,
        'ssh_password_authentication': False,
    }


def activate(operator_ip=None):
    runner = Runner(ROOT)
    deployment_id = 'azattack-' + uuid.uuid4().hex[:10]
    runner.evidence = ROOT / 'logs' / 'azure-attack-box-live' / deployment_id
    runner.evidence.mkdir(parents=True, mode=0o700)
    group = 'c2itall-' + deployment_id
    key = Path.home() / '.ssh' / ('c2deploy_' + deployment_id)
    config = {
        'provider': 'azure', 'provider_workload': 'attack_box',
        'deployment_id': deployment_id, 'deployment_type': 'quick_recon_box',
        'attack_box_type': 'quick_recon', 'attack_box_deployment': True,
        'attack_box_name': 'qr-' + deployment_id,
        'setup_vpn': False, 'setup_tor': True, 'setup_domain': False,
        'enhanced_opsec': True, 'work_dir': '/root/' + deployment_id,
        'tool_name': 'toolkit', 'project_name': deployment_id,
        'azure_subscription_id': SUBSCRIPTION, 'azure_location': LOCATION,
        'azure_vm_size': SIZE, 'azure_os_disk_gb': 32,
        'azure_resource_group': group, 'azure_state_dir': str(STATE_DIR),
        'operator_ip': '',
    }
    adapter = workload_route(config)
    live_passed = cleanup_passed = False
    failure = None
    previous = {sig: signal.signal(sig, runner.handle_signal)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for executable in ('az', 'ansible-playbook', 'ssh', 'ssh-keygen', 'curl'):
            require(shutil.which(executable), 'Required tool unavailable: ' + executable)
        require(adapter is not None, 'Azure attack-box route is unavailable')
        runner.record('source.json', {'parent': verify_committed_source(runner)})
        require(not key.exists() and not Path(str(key) + '.pub').exists(),
                'Refusing to reuse a live-test SSH key')
        require(runner.az('group', 'exists', '--name', group) is False,
                'Live-test resource group already exists')
        runner.baseline(group)
        config['operator_ip'] = public_ipv4(operator_ip or runner.run([
            'curl', '-4', '--fail', '--silent', '--show-error',
            '--max-time', '15', 'https://api.ipify.org',
        ]))
        preflight(runner, config)

        config['azure_deadline'] = time.monotonic() + 1800
        config['azure_service_deadline'] = time.monotonic() + 1800
        require(deploy_infrastructure(config),
                'Initial routed Azure attack-box deployment failed')
        first = snapshot(runner, config)
        health = infrastructure_adapter('azure').health(config)
        require(health.get('healthy') is True, 'Initial attack-box VM health failed')
        runner.record('first-deployment.json', {
            'azure': first, 'service': verify_quick_recon(runner, config),
            'health': health,
        })

        config['azure_deadline'] = time.monotonic() + 1800
        config['azure_service_deadline'] = time.monotonic() + 1800
        require(deploy_infrastructure(config),
                'Repeated routed Azure attack-box deployment failed')
        repeated = snapshot(runner, config)
        repeated_health = infrastructure_adapter('azure').health(config)
        require(repeated_health.get('healthy') is True,
                'Repeated attack-box VM health failed')
        require(first['vm_id'].lower() == repeated['vm_id'].lower()
                and first['resource_ids'] == repeated['resource_ids'],
                'Repeated attack-box deployment changed Azure resource identity')
        runner.record('repeat-deployment.json', {
            'azure': repeated, 'service': verify_quick_recon(runner, config),
            'health': repeated_health, 'resource_identity_preserved': True,
        })
        live_passed = True
    except BaseException as error:
        failure = str(error)
        runner.record('failure.json', {'error': failure})
        print('Azure attack-box live test did not pass: ' + failure, file=sys.stderr)
    finally:
        runner.cleaning = True
        runner.deadline = time.monotonic() + 600
        config['azure_cleanup_deadline'] = runner.deadline
        try:
            state = STATE_DIR / (deployment_id + '.json')
            if state.exists() or runner.az('group', 'exists', '--name', group) is not False:
                require(standalone_teardown.teardown_deployment(
                    deployment_id, force=True),
                    'Routed standalone Azure attack-box cleanup failed')
            require(runner.az('group', 'exists', '--name', group) is False,
                    'Attack-box resource group remains after cleanup')
            runner.cleanup_subscription()
            inventory = runner.inventory()
            require(inventory == runner.subscription_baseline,
                    'Azure subscription inventory was not restored')
            require(not state.exists(), 'Active Azure recovery state remains')
            require(not key.exists() and not Path(str(key) + '.pub').exists(),
                    'Generated Azure attack-box key remains')
            require(not (ROOT / 'logs' / ('deployment_info_' + deployment_id + '.txt')).exists(),
                    'Active deployment-info record remains')
            runner.record('final-cleanup.json', {
                'resource_group_absent': True, 'active_state_absent': True,
                'generated_key_absent': True, 'active_deployment_info_absent': True,
                'inventory': inventory,
            })
            cleanup_passed = True
        except BaseException as cleanup_error:
            runner.record('cleanup-failure.json', {'error': str(cleanup_error)})
            print('Azure attack-box cleanup failed: ' + str(cleanup_error),
                  file=sys.stderr)
        for sig, handler in previous.items():
            signal.signal(sig, handler)

    passed = live_passed and cleanup_passed and not runner.interrupted
    runner.record('result.json', {
        'passed': passed, 'live_workflow_passed': live_passed,
        'cleanup_passed': cleanup_passed, 'failure': failure,
        'deployment_id': deployment_id, 'resource_group': group,
    })
    print('Evidence: ' + str(runner.evidence))
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--activate', action='store_true')
    parser.add_argument('--operator-ip')
    args = parser.parse_args(argv)
    if not args.activate:
        print('DRY RUN: no cloud mutations. Target: {0} / {1} / {2}'.format(
            SUBSCRIPTION, LOCATION, SIZE))
        return 0
    return activate(args.operator_ip)


if __name__ == '__main__':
    sys.exit(main())
