#!/usr/bin/env python3
"""Deploy, verify, repeat and remove one real AWS or Linode offensive workload.

The default invocation is a dry run. ``--activate`` performs the lifecycle
through the shared provider registry exactly as the interactive modules do,
then removes every cloud and local artifact through standalone teardown in a
fresh process and proves the provider inventory returned to its baseline.
Nothing is scanned or attacked: verification only inspects the deployed host.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time
from urllib import error, request
import uuid

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
for path in (SCRIPT_DIR, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from utils.common import load_vars_file, setup_logging
from utils.deployment_engine import deploy_infrastructure
from utils.provider_registry import prepare_provider_environment
from utils.provider_utils import apply_provider_profile, prepare_module_ssh_key

REGIONS = {'aws': 'us-east-1', 'linode': 'us-east'}
PROVIDER_DIRS = {'aws': 'AWS', 'linode': 'Linode'}
CREDENTIAL_ENVIRONMENT = ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                          'AWS_DEFAULT_REGION', 'LINODE_TOKEN')
SECRET_FRAGMENTS = ('token', 'secret', 'pass', 'access_key')
LINODE_API = 'https://api.linode.com/v4'
SSH_DIR = Path.home() / '.ssh'


class LiveError(RuntimeError):
    pass


class LiveInterrupted(LiveError):
    pass


def require(condition, message):
    if not condition:
        raise LiveError(message)


def public_ipv4(value):
    address = ipaddress.ip_address(str(value).strip().removesuffix('/32'))
    if address.version != 4 or not address.is_global:
        raise LiveError('Operator address must be a public IPv4 address')
    return str(address)


def redacted(config):
    return {key: ('<redacted>' if any(fragment in key.lower()
                                      for fragment in SECRET_FRAGMENTS) else value)
            for key, value in config.items()}


class Runner:
    def __init__(self, evidence):
        self.evidence = evidence
        self.counter = 0
        self.cleaning = False
        self.interrupted = False

    def handle_signal(self, signum, _frame):
        self.interrupted = True
        if not self.cleaning:
            raise LiveInterrupted('Interrupted by signal ' + str(signum))

    def record(self, name, content):
        path = self.evidence / name
        with path.open('w') as stream:
            os.chmod(path, 0o600)
            json.dump(content, stream, indent=2, default=str)

    def run(self, argv, timeout=60, env=None, check=True):
        process = subprocess.run(
            [str(arg) for arg in argv], cwd=ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=timeout)
        self.counter += 1
        self.record('command-{0:03d}.json'.format(self.counter), {
            'command': [str(arg) for arg in argv],
            'returncode': process.returncode,
            'stdout': process.stdout[-20000:], 'stderr': process.stderr[-20000:],
        })
        if check and process.returncode:
            raise LiveError('Command failed ({0}): {1}: {2}'.format(
                process.returncode, argv[0], process.stderr[-3000:]))
        return process.stdout.strip()


class AwsCloud:
    provider = 'aws'

    def __init__(self, region):
        import boto3
        self.region = region
        self.ec2 = boto3.client('ec2', region_name=region)

    def _instances(self, filters):
        found = {}
        for reservation in self.ec2.describe_instances(Filters=filters)['Reservations']:
            for instance in reservation['Instances']:
                if instance['State']['Name'] == 'terminated':
                    continue
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                found[instance['InstanceId']] = {
                    'id': instance['InstanceId'], 'state': instance['State']['Name'],
                    'name': tags.get('Name', ''), 'public_ip': instance.get('PublicIpAddress', ''),
                    'instance_type': instance['InstanceType'], 'image_id': instance['ImageId'],
                }
        return found

    def inventory(self, identity):
        deployment_id = identity['deployment_id']
        tag_filters = [[{'Name': 'tag:deployment_id', 'Values': [deployment_id]}],
                       [{'Name': 'tag:DeploymentID', 'Values': [deployment_id]}],
                       [{'Name': 'tag:Name', 'Values': identity['names']}]]
        instances = {}
        for filters in tag_filters:
            instances.update(self._instances(filters))
        groups = {}
        for filters in tag_filters[:2] + [[{'Name': 'group-name', 'Values': identity['sg_names']}]]:
            for group in self.ec2.describe_security_groups(Filters=filters)['SecurityGroups']:
                groups[group['GroupId']] = {'id': group['GroupId'], 'name': group['GroupName'],
                                            'vpc_id': group.get('VpcId', '')}
        vpcs = {}
        for filters in tag_filters[:2]:
            for vpc in self.ec2.describe_vpcs(Filters=filters)['Vpcs']:
                vpcs[vpc['VpcId']] = {'id': vpc['VpcId']}
        interfaces = {}
        for filters in tag_filters[:2]:
            for eni in self.ec2.describe_network_interfaces(Filters=filters)['NetworkInterfaces']:
                interfaces[eni['NetworkInterfaceId']] = {'id': eni['NetworkInterfaceId']}
        keys = [pair['KeyName'] for pair in self.ec2.describe_key_pairs(
            Filters=[{'Name': 'key-name', 'Values': identity['key_names']}])['KeyPairs']]
        return {
            'instances': sorted(instances.values(), key=lambda item: item['id']),
            'security_groups': sorted(groups.values(), key=lambda item: item['id']),
            'vpcs': sorted(vpcs.values(), key=lambda item: item['id']),
            'network_interfaces': sorted(interfaces.values(), key=lambda item: item['id']),
            'key_pairs': sorted(keys),
        }

    def totals(self):
        instances = len(self._instances([]))
        groups = sum(1 for group in self.ec2.describe_security_groups()['SecurityGroups']
                     if group['GroupName'] != 'default')
        vpcs = sum(1 for vpc in self.ec2.describe_vpcs()['Vpcs'] if not vpc.get('IsDefault'))
        keys = len(self.ec2.describe_key_pairs()['KeyPairs'])
        return {'region': self.region, 'instances': instances, 'security_groups': groups,
                'vpcs': vpcs, 'key_pairs': keys}

    def address(self, identity, name):
        for instance in self.inventory(identity)['instances']:
            if instance['name'] == name and instance['state'] == 'running':
                return public_ipv4(instance['public_ip'])
        raise LiveError('No running AWS instance named ' + name)

    def inbound_rules(self, sg_name):
        rules = []
        for group in self.ec2.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': [sg_name]}])['SecurityGroups']:
            for permission in group['IpPermissions']:
                for cidr in permission.get('IpRanges', []):
                    rules.append((permission.get('IpProtocol'), permission.get('FromPort'),
                                  permission.get('ToPort'), cidr['CidrIp']))
        return sorted(rules, key=str)


class LinodeCloud:
    provider = 'linode'

    def __init__(self, token):
        self.token = token
        self.region = REGIONS['linode']

    def _pages(self, path):
        page = 1
        while True:
            separator = '&' if '?' in path else '?'
            call = request.Request(
                LINODE_API + path + separator + 'page={0}&page_size=500'.format(page),
                headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json'})
            try:
                with request.urlopen(call, timeout=30) as response:
                    payload = json.loads(response.read())
            except error.HTTPError as exc:
                raise LiveError('Linode API {0} failed with HTTP {1}'.format(path, exc.code)) from exc
            if not isinstance(payload.get('data'), list):
                raise LiveError('Linode API returned an invalid inventory')
            yield from payload['data']
            if page >= int(payload.get('pages', 1)):
                return
            page += 1

    def inventory(self, identity):
        deployment_id = identity['deployment_id']
        instances = []
        for item in self._pages('/linode/instances'):
            if deployment_id in (item.get('tags') or []) or item.get('label') in identity['names']:
                instances.append({'id': item['id'], 'name': item['label'], 'state': item['status'],
                                  'public_ip': (item.get('ipv4') or [''])[0],
                                  'instance_type': item.get('type'), 'image_id': item.get('image')})
        keys = [item['label'] for item in self._pages('/profile/sshkeys')
                if item.get('label') in identity['key_names']]
        return {'instances': sorted(instances, key=lambda item: item['id']),
                'key_pairs': sorted(keys)}

    def totals(self):
        return {'region': self.region,
                'instances': sum(1 for _ in self._pages('/linode/instances')),
                'key_pairs': sum(1 for _ in self._pages('/profile/sshkeys'))}

    def address(self, identity, name):
        for instance in self.inventory(identity)['instances']:
            if instance['name'] == name and instance['state'] == 'running':
                return public_ipv4(instance['public_ip'])
        raise LiveError('No running Linode named ' + name)


def provider_config(provider):
    values = load_vars_file(provider)
    if provider == 'aws':
        return {
            'aws_access_key': os.environ['AWS_ACCESS_KEY_ID'],
            'aws_secret_key': os.environ['AWS_SECRET_ACCESS_KEY'],
            'aws_regions': [REGIONS['aws']], 'aws_region': REGIONS['aws'],
            'ami_map': values.get('ami_map', {}),
            'aws_instance_type': values.get('aws_instance_type', 't3.micro'),
            'aws_volume_size': values.get('aws_volume_size', 20),
        }
    return {
        'linode_token': os.environ['LINODE_TOKEN'],
        'linode_regions': [REGIONS['linode']], 'linode_region': REGIONS['linode'],
        'linode_instance_type': values.get('linode_instance_type', 'g6-nanode-1'),
        'linode_image': values.get('linode_image', 'linode/debian12'),
    }


def key_files(stem):
    return [SSH_DIR / stem, SSH_DIR / (stem + '.pub'), SSH_DIR / (stem + '.pem')]


class AttackBox:
    name = 'attack_box'
    repeat = {'aws': True, 'linode': False}
    source_paths = ('modules/attack-box', 'providers/{dir}/attack_box.yml')

    def config(self, provider, deployment_id, operator_ip):
        box = 'qr-' + deployment_id
        config = {
            'deployment_id': deployment_id, 'provider': provider,
            'provider_workload': 'attack_box', 'deployment_type': 'quick_recon_box',
            'attack_box_type': 'quick_recon', 'attack_box_name': box,
            'instance_size': 'small', 'setup_tor': True, 'setup_vpn': False,
            'setup_domain': False, 'operator_ip': operator_ip,
            'ssh_after_deploy': False, 'enhanced_opsec': True,
            'work_dir': '/root/' + deployment_id, 'tool_name': 'toolkit',
            'project_name': deployment_id, 'auto_teardown_on_fail': False,
            'default_user': 'root', 'attack_box_deployment': True,
            'ssh_user': 'root', 'attack_box_image': 'linode/kali',
            'quick_deployment': True,
        }
        config.update(provider_config(provider))
        apply_provider_profile(config, 'instance_size', 'small')
        ready, _ = prepare_module_ssh_key(config, box)
        require(ready, 'Could not generate the module SSH key')
        return config

    def identity(self, config):
        deployment_id = config['deployment_id']
        return {'deployment_id': deployment_id, 'names': [config['attack_box_name']],
                'key_names': ['attack-box-' + deployment_id, 'c2deploy_' + config['attack_box_name']],
                'sg_names': ['attack-box-sg-' + deployment_id]}

    def target(self, provider, config):
        if provider == 'aws':
            return config['attack_box_name'], 'kali', SSH_DIR / ('attack-box-' + config['deployment_id'])
        return config['attack_box_name'], 'root', SSH_DIR / ('c2deploy_' + config['attack_box_name'])

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_' + config['attack_box_name']) + [
            SSH_DIR / ('attack-box-' + deployment_id),
            ROOT / 'logs' / ('attack_box_' + deployment_id + '_info.txt'),
            ROOT / 'providers' / 'Linode' / 'logs' / ('deployment_info_' + deployment_id + '.txt'),
            ROOT / 'providers' / 'Linode' / 'logs' / ('attack_box_' + deployment_id + '.env'),
        ]

    def verify(self, context, config):
        deployment_id = config['deployment_id']
        command = (
            "set -eu; grep -q '^ID=kali' /etc/os-release; "
            "sudo -n test -d /root/" + deployment_id + "/scans; "
            "sudo -n test -s /root/QUICK_RECON_GUIDE.txt; "
            "command -v nmap >/dev/null; command -v dig >/dev/null; "
            "command -v tor >/dev/null; command -v torsocks >/dev/null; "
            "command -v proxychains4 >/dev/null; "
            "test \"$(systemctl is-enabled tor)\" = enabled; "
            "systemctl is-active tor >/dev/null; "
            "sudo -n grep -Fq \"alias qr='cd /root/" + deployment_id + "'\" /root/.bashrc; "
            "sudo -n /usr/sbin/sshd -T | grep -q '^passwordauthentication no$'"
        )
        context.ssh(command)
        report = {'kali': True, 'workspace': True, 'quick_guide': True, 'nmap': True,
                  'dnsutils': True, 'tor': True, 'torsocks': True, 'proxychains': True,
                  'tor_enabled': True, 'tor_active': True, 'ssh_password_authentication': False}
        if context.provider == 'aws':
            rules = context.cloud.inbound_rules('attack-box-sg-' + deployment_id)
            require(('tcp', 22, 22, config['operator_ip'] + '/32') in rules,
                    'AWS attack box does not restrict SSH to the operator /32')
            require(all(cidr == config['operator_ip'] + '/32' for proto, low, high, cidr in rules
                        if low <= 22 <= high), 'AWS attack box exposes SSH beyond the operator')
            report['security_group_rules'] = rules
        return report


class Redirector:
    name = 'redirector'
    repeat = {'aws': True, 'linode': True}
    source_paths = ('modules/redirectors', 'providers/{dir}/redirector.yml', 'common')

    def config(self, provider, deployment_id, operator_ip):
        config = {
            'deployment_id': deployment_id, 'provider': provider,
            'provider_workload': 'redirector', 'domain': 'redirector-lab.test',
            'redirector_subdomain': 'cdn', 'backend_type': 'c2',
            'backend_ip': operator_ip, 'backend_port': '443',
            'redirector_type': 'https', 'letsencrypt_email': 'admin@redirector-lab.test',
            'operator_ip': operator_ip, 'ssh_after_deploy': False,
            'deployment_type': 'c2_redirector', 'redirector_only': True,
            'c2_only': False,
        }
        config.update(provider_config(provider))
        ready, _ = prepare_module_ssh_key(config, deployment_id)
        require(ready, 'Could not generate the module SSH key')
        return config

    def identity(self, config):
        deployment_id = config['deployment_id']
        return {'deployment_id': deployment_id, 'names': ['r-' + deployment_id],
                'key_names': ['c2deploy_' + deployment_id],
                'sg_names': ['r-' + deployment_id + '-sg']}

    def target(self, provider, config):
        deployment_id = config['deployment_id']
        if provider == 'aws':
            return 'r-' + deployment_id, 'ubuntu', SSH_DIR / ('c2deploy_' + deployment_id + '.pem')
        return 'r-' + deployment_id, 'root', SSH_DIR / ('c2deploy_' + deployment_id)

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_' + deployment_id) + [
            ROOT / ('infrastructure_state_' + deployment_id + '.json')]

    def verify(self, context, config):
        command = (
            "set -eu; "
            "test \"$(systemctl is-active nginx)\" = active; "
            "test \"$(systemctl is-enabled nginx)\" = enabled; "
            "test \"$(systemctl is-enabled shell-handler)\" = enabled; "
            "ss -ltn | grep -q ':80 '; ss -ltn | grep -q ':443 '; "
            "test \"$(curl -ks -o /dev/null -w '%{http_code}' https://127.0.0.1/)\" = 200; "
            "sudo -n test -x /root/Tools/post_install_redirector.sh; "
            "sudo -n /usr/sbin/sshd -T | grep -q '^passwordauthentication no$'"
        )
        context.ssh(command)
        status = context.run([
            'curl', '-ks', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20',
            'https://' + context.address + '/'])
        require(status == '200', 'Redirector HTTPS front page is not public: ' + status)
        report = {'nginx_active': True, 'nginx_enabled': True, 'shell_handler_enabled': True,
                  'http_listening': True, 'https_listening': True, 'local_https': True,
                  'public_https': True, 'ssh_password_authentication': False}
        if context.provider == 'aws':
            rules = context.cloud.inbound_rules('r-' + config['deployment_id'] + '-sg')
            require(('tcp', 22, 22, config['operator_ip'] + '/32') in rules,
                    'AWS redirector does not restrict SSH to the operator /32')
            report['security_group_rules'] = rules
        return report


class C2:
    name = 'c2'
    repeat = {'aws': False, 'linode': False}
    source_paths = ('modules/c2', 'providers/{dir}/c2.yml', 'common')

    def config(self, provider, deployment_id, operator_ip):
        config = {
            'deployment_id': deployment_id, 'provider': provider,
            'provider_workload': 'c2', 'domain': 'c2-lab.test', 'c2_subdomain': 'mail',
            'redirector_name': 'r-' + deployment_id, 'c2_name': 's-' + deployment_id,
            'c2_framework': 'havoc', 'letsencrypt_email': 'admin@c2-lab.test',
            'operator_ip': operator_ip, 'smtp_auth_user': 'admin',
            'smtp_auth_pass': secrets.token_urlsafe(12), 'zero_logs': True,
            'ssh_after_deploy': False, 'deployment_type': 'c2_only', 'c2_only': True,
            'gophish_admin_port': '2222',
        }
        config.update(provider_config(provider))
        # Havoc is compiled on the host; the vars.yaml defaults are sized for
        # redirectors and starve the build. Match the playbook's own defaults.
        if provider == 'aws':
            config['aws_instance_type'] = 't3.medium'
        else:
            config['linode_instance_type'] = 'g6-standard-2'
        ready, _ = prepare_module_ssh_key(config, deployment_id)
        require(ready, 'Could not generate the module SSH key')
        return config

    def identity(self, config):
        deployment_id = config['deployment_id']
        return {'deployment_id': deployment_id, 'names': [config['c2_name']],
                'key_names': ['c2deploy_' + deployment_id],
                'sg_names': [config['c2_name'] + '-sg']}

    def target(self, provider, config):
        deployment_id = config['deployment_id']
        if provider == 'aws':
            return config['c2_name'], 'kali', SSH_DIR / ('c2deploy_' + deployment_id + '.pem')
        return config['c2_name'], 'root', SSH_DIR / ('c2deploy_' + deployment_id)

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_' + deployment_id) + [
            ROOT / ('infrastructure_state_' + deployment_id + '.json')]

    def verify(self, context, config):
        command = (
            "set -eu; grep -q '^ID=kali' /etc/os-release; "
            "sudo -n test -x /root/Tools/Havoc/havoc; "
            "sudo -n test -s /root/Tools/Havoc/data/havoc.yaotl; "
            "sudo -n test -s /root/havoc-guide.txt; "
            "sudo -n test -x /root/Tools/havoc_installer.sh; "
            "test \"$(systemctl is-active postfix)\" = active; "
            "test \"$(systemctl is-active dovecot)\" = active; "
            "test \"$(systemctl is-active opendkim)\" = active; "
            "sudo -n /usr/sbin/sshd -T | grep -q '^passwordauthentication no$'"
        )
        context.ssh(command, timeout=120)
        report = {'kali': True, 'havoc_teamserver': True, 'havoc_config': True,
                  'havoc_guide': True, 'postfix_active': True, 'dovecot_active': True,
                  'opendkim_active': True, 'ssh_password_authentication': False}
        if context.provider == 'aws':
            rules = context.cloud.inbound_rules(config['c2_name'] + '-sg')
            require(('tcp', 22, 22, config['operator_ip'] + '/32') in rules,
                    'AWS C2 does not restrict SSH to the operator /32')
            report['security_group_rules'] = rules
        return report


WORKLOADS = {cls.name: cls for cls in (AttackBox, Redirector, C2)}


class Context:
    def __init__(self, runner, cloud, provider, address, user, key):
        self.runner = runner
        self.cloud = cloud
        self.provider = provider
        self.address = address
        self.user = user
        self.key = key

    def run(self, argv, timeout=60):
        return self.runner.run(argv, timeout=timeout)

    def ssh(self, command, timeout=90):
        argv = ['ssh', '-F', '/dev/null', '-i', str(self.key),
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new',
                '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'UserKnownHostsFile=' + str(self.runner.evidence / 'known_hosts'),
                self.user + '@' + self.address, command]
        deadline = time.monotonic() + 300
        while True:
            try:
                return self.runner.run(argv, timeout=timeout)
            except LiveError as exc:
                transient = any(marker in str(exc).lower() for marker in (
                    'connection refused', 'connection timed out', 'connection reset',
                    'kex_exchange_identification', 'connection closed by'))
                if not transient or time.monotonic() >= deadline:
                    raise
                time.sleep(10)


def verify_committed_source(runner, provider, workload):
    paths = ['utils', 'teardown.py', 'scripts/test_provider_workload_live.py',
             'providers/{0}/cleanup.yml'.format(PROVIDER_DIRS[provider])]
    paths += [path.format(dir=PROVIDER_DIRS[provider]) for path in workload.source_paths]
    for path in paths:
        runner.run(['git', 'diff', '--quiet', 'HEAD', '--', path])
    return runner.run(['git', 'rev-parse', 'HEAD'])


def build_cloud(provider):
    if provider == 'aws':
        return AwsCloud(REGIONS['aws'])
    return LinodeCloud(os.environ['LINODE_TOKEN'])


def empty(inventory):
    return not any(inventory.values())


def activate(provider, workload_name, operator_ip=None, repeat=None):
    workload = WORKLOADS[workload_name]()
    os.chdir(ROOT)
    deployment_id = 'lt-{0}-{1}-{2}'.format(
        provider, workload_name.replace('_', '')[:6], uuid.uuid4().hex[:6])
    evidence = ROOT / 'logs' / '{0}-{1}-live'.format(provider, workload_name.replace('_', '-')) / deployment_id
    evidence.mkdir(parents=True, mode=0o700)
    runner = Runner(evidence)
    previous = {sig: signal.signal(sig, runner.handle_signal)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    config = cloud = identity = None
    live_passed = cleanup_passed = deployed = False
    failure = None
    try:
        for executable in ('ansible-playbook', 'ssh', 'ssh-keygen', 'curl', 'git'):
            require(shutil.which(executable), 'Required tool unavailable: ' + executable)
        runner.record('source.json', {'commit': verify_committed_source(runner, provider, workload)})
        prepare_provider_environment({'provider': provider})
        cloud = build_cloud(provider)
        operator_ip = public_ipv4(operator_ip or runner.run([
            'curl', '-4', '--fail', '--silent', '--show-error', '--max-time', '15',
            'https://api.ipify.org']))
        config = workload.config(provider, deployment_id, operator_ip)
        identity = workload.identity(config)
        require(empty(cloud.inventory(identity)), 'Live-test identity already owns cloud resources')
        generated = [path for path in workload.local_artifacts(provider, config) if path.exists()]
        expected_key = Path(config['ssh_key_path']).with_suffix('')
        require(set(generated) <= {expected_key, Path(str(expected_key) + '.pub')},
                'Unexpected local artifacts exist for the live-test identity')
        baseline = cloud.totals()
        runner.record('baseline.json', {'identity': identity, 'totals': baseline,
                                        'operator_ip': operator_ip})
        runner.record('config.json', redacted(config))
        setup_logging(deployment_id, 'live_test')

        deployed = True
        require(deploy_infrastructure(config), 'Initial routed deployment failed')
        first = cloud.inventory(identity)
        require(len(first['instances']) == 1 and first['instances'][0]['state'] == 'running',
                'Expected exactly one running instance after deployment')
        name, user, key = workload.target(provider, config)
        require(key.is_file(), 'Expected SSH key is missing: ' + str(key))
        address = cloud.address(identity, name)
        context = Context(runner, cloud, provider, address, user, key)
        service = workload.verify(context, config)
        runner.record('first-deployment.json', {'cloud': first, 'address': address, 'service': service})

        do_repeat = workload.repeat[provider] if repeat is None else repeat
        if do_repeat:
            require(deploy_infrastructure(config), 'Repeated routed deployment failed')
            repeated = cloud.inventory(identity)
            require(repeated == first, 'Repeated deployment changed cloud resource identities')
            require(cloud.address(identity, name) == address, 'Repeated deployment changed the public address')
            runner.record('repeat-deployment.json', {
                'cloud': repeated, 'service': workload.verify(context, config),
                'resource_identity_preserved': True})
        else:
            runner.record('repeat-deployment.json', {'skipped': True,
                                                     'reason': 'provider playbook creates instances non-idempotently'})
        live_passed = True
    except BaseException as exc:
        failure = str(exc)
        runner.record('failure.json', {'error': failure})
        print('{0} {1} live test did not pass: {2}'.format(provider, workload_name, failure), file=sys.stderr)
    finally:
        runner.cleaning = True
        try:
            if config is not None and cloud is not None:
                cleanup_passed = cleanup(runner, cloud, provider, workload, config, identity, deployed)
            elif config is None:
                cleanup_passed = True
        except BaseException as exc:
            runner.record('cleanup-failure.json', {'error': str(exc)})
            print('{0} {1} cleanup failed: {2}'.format(provider, workload_name, exc), file=sys.stderr)
        for sig, handler in previous.items():
            signal.signal(sig, handler)

    passed = live_passed and cleanup_passed and not runner.interrupted
    runner.record('result.json', {
        'passed': passed, 'live_workflow_passed': live_passed,
        'cleanup_passed': cleanup_passed, 'failure': failure,
        'deployment_id': deployment_id, 'provider': provider, 'workload': workload_name,
    })
    print('Evidence: ' + str(evidence))
    return 0 if passed else 1


def cleanup(runner, cloud, provider, workload, config, identity, deployed):
    deployment_id = config['deployment_id']
    info = ROOT / 'logs' / ('deployment_info_' + deployment_id + '.txt')
    report = {'standalone_teardown': None}
    if info.exists():
        # Prove recovery from a fresh process that holds no provider credential.
        env = {key: value for key, value in os.environ.items() if key not in CREDENTIAL_ENVIRONMENT}
        result = subprocess.run(
            [sys.executable, 'teardown.py', '--deployment-id', deployment_id, '--force'],
            cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1800)
        runner.record('standalone-teardown.json', {'returncode': result.returncode,
                                                   'output': result.stdout[-30000:]})
        report['standalone_teardown'] = result.returncode == 0
        require(result.returncode == 0, 'Standalone routed teardown failed')
    elif deployed:
        report['standalone_teardown'] = 'not-recorded'
    deadline = time.monotonic() + 600
    while True:
        remaining = cloud.inventory(identity)
        if empty(remaining):
            break
        if time.monotonic() >= deadline:
            runner.record('residual-cloud.json', remaining)
            raise LiveError('Cloud resources remain after teardown: ' + json.dumps(remaining))
        time.sleep(10)
    baseline = json.loads((runner.evidence / 'baseline.json').read_text())['totals']
    totals = cloud.totals()
    require(totals == baseline, 'Provider inventory was not restored: {0} != {1}'.format(totals, baseline))
    leftovers = [str(path) for path in workload.local_artifacts(provider, config) if path.exists()]
    for path in (ROOT / 'logs' / ('deployment_' + deployment_id + '.log'), info):
        if path.exists():
            leftovers.append(str(path))
    require(not leftovers, 'Local artifacts remain after teardown: ' + ', '.join(leftovers))
    report.update({'cloud_absent': True, 'inventory_restored': True, 'local_artifacts_absent': True,
                   'totals': totals})
    runner.record('final-cleanup.json', report)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=sorted(REGIONS), required=True)
    parser.add_argument('--workload', choices=sorted(WORKLOADS), required=True)
    parser.add_argument('--activate', action='store_true')
    parser.add_argument('--operator-ip')
    parser.add_argument('--repeat', dest='repeat', action='store_true', default=None)
    parser.add_argument('--no-repeat', dest='repeat', action='store_false')
    args = parser.parse_args(argv)
    if not args.activate:
        print('DRY RUN: no cloud mutations. Target: {0} / {1} / {2}'.format(
            args.provider, REGIONS[args.provider], args.workload))
        return 0
    return activate(args.provider, args.workload, args.operator_ip, args.repeat)


if __name__ == '__main__':
    sys.exit(main())
