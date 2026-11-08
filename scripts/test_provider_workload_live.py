#!/usr/bin/env python3
"""Deploy, verify, repeat and remove one real AWS or Linode offensive workload.

The default invocation is a dry run. ``--activate`` performs the lifecycle
through the shared provider registry exactly as the interactive modules do,
then removes every cloud and local artifact through standalone teardown in a
fresh process and proves the provider inventory returned to its baseline.
Nothing is scanned or attacked: verification only inspects the deployed host.
"""

import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
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
from utils.deployment_engine import deploy_infrastructure, dispatch_composite_workload
from utils.provider_registry import prepare_provider_environment
from utils.provider_utils import apply_provider_profile, prepare_module_ssh_key

REGIONS = {'aws': 'us-east-1', 'linode': 'us-east', 'azure': 'eastus'}
PROVIDER_DIRS = {'aws': 'AWS', 'linode': 'Linode', 'azure': 'Azure'}
AZURE_SUBSCRIPTION = 'cc2a66d1-67c2-47ca-856f-19a4eae52cfe'
AZURE_SIZE = 'Standard_D2as_v4'
AZURE_STATE_DIR = ROOT / 'deployments' / 'azure'
CREDENTIAL_ENVIRONMENT = ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                          'AWS_DEFAULT_REGION', 'LINODE_TOKEN')
SECRET_FRAGMENTS = ('token', 'secret', 'pass', 'access_key')
LINODE_API = 'https://api.linode.com/v4'
SSH_DIR = Path.home() / '.ssh'
# Never fails; records why an sshd check could fail without a second deployment.
SSHD_DIAGNOSTICS = (
    "sudo -n /usr/sbin/sshd -T 2>&1 | grep -i '^passwordauthentication'; "
    "grep -n -i 'passwordauthentication\\|^include' /etc/ssh/sshd_config; "
    "ls -la /etc/ssh/sshd_config.d/ 2>&1; "
    "sudo -n sh -c 'head -20 /etc/ssh/sshd_config.d/*.conf' 2>&1; true")


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


class AzureCloud:
    provider = 'azure'

    def __init__(self, evidence):
        import deploy_azure_smoke as smoke
        from utils import azure_utils
        self.region = REGIONS['azure']
        self.smoke = smoke.Runner(ROOT)
        self.smoke.evidence = evidence / 'azure'
        self.smoke.evidence.mkdir(mode=0o700)
        azure_utils.ensure_azure_auth(AZURE_SUBSCRIPTION, force=True)

    def inventory(self, identity):
        group = 'c2itall-' + identity['deployment_id']
        if self.smoke.az('group', 'exists', '--name', group) is not True:
            return {'instances': [], 'resources': []}
        instances = []
        for vm in self.smoke.az('vm', 'list', '--resource-group', group, '--show-details') or []:
            instances.append({
                'id': vm['id'].lower(), 'name': vm['name'],
                'state': 'running' if vm.get('powerState') == 'VM running' else str(vm.get('powerState', '')),
                'public_ip': vm.get('publicIps', ''), 'instance_type': vm['hardwareProfile']['vmSize'],
                'image_id': json.dumps(vm['storageProfile']['imageReference'], sort_keys=True)})
        resources = sorted(item['id'].lower() for item in
                           self.smoke.az('resource', 'list', '--resource-group', group) or [])
        return {'instances': sorted(instances, key=lambda item: item['id']), 'resources': resources}

    def totals(self):
        inventory = self.smoke.inventory()
        if self.smoke.subscription_baseline is None:
            self.smoke.subscription_baseline = inventory
        return inventory

    def settle(self):
        # Azure adds a NetworkWatcher to an empty lab; the smoke runner removes only that.
        self.smoke.cleanup_subscription()

    def address(self, identity, name):
        for instance in self.inventory(identity)['instances']:
            if instance['state'] == 'running':
                return public_ipv4(instance['public_ip'])
        raise LiveError('No running Azure VM for ' + name)

    def inbound_rules(self, deployment_id):
        rules = []
        for nsg in self.smoke.az('network', 'nsg', 'list', '--resource-group',
                                 'c2itall-' + deployment_id) or []:
            for rule in nsg.get('securityRules', []):
                if rule.get('direction') == 'Inbound' and rule.get('access') == 'Allow':
                    rules.append((str(rule.get('protocol', '')).lower(), str(rule.get('destinationPortRange')),
                                  str(rule.get('sourceAddressPrefix'))))
        return sorted(rules)


def provider_config(provider):
    if provider == 'azure':
        return {
            'azure_subscription_id': AZURE_SUBSCRIPTION, 'azure_location': REGIONS['azure'],
            'azure_vm_size': AZURE_SIZE, 'azure_os_disk_gb': 32,
            'provider_manages_ssh_key': True,
        }
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


def checks(context, items, timeout=90):
    """Run named host checks; the first failure names itself on stderr."""
    script = 'set -u; ' + ' '.join(
        '{ ' + command + '; } || { echo "FAILED CHECK: ' + label + '" >&2; exit 1; };'
        for label, command in items)
    context.ssh(script, timeout=timeout)
    return {label: True for label, _ in items}


def key_files(stem):
    return [SSH_DIR / stem, SSH_DIR / (stem + '.pub'), SSH_DIR / (stem + '.pem')]


def azure_artifacts(deployment_id):
    return key_files('c2deploy_' + deployment_id) + [AZURE_STATE_DIR / (deployment_id + '.json')]


class AttackBox:
    name = 'attack_box'
    repeat = {'aws': True, 'linode': False, 'azure': True}
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
        if provider != 'azure':
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
        if provider == 'azure':
            return config['attack_box_name'], 'azureuser', SSH_DIR / ('c2deploy_' + config['deployment_id'])
        return config['attack_box_name'], 'root', SSH_DIR / ('c2deploy_' + config['attack_box_name'])

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_' + config['attack_box_name']) + azure_artifacts(deployment_id) + [
            SSH_DIR / ('attack-box-' + deployment_id),
            ROOT / 'logs' / ('attack_box_' + deployment_id + '_info.txt'),
            ROOT / 'providers' / 'Linode' / 'logs' / ('deployment_info_' + deployment_id + '.txt'),
            ROOT / 'providers' / 'Linode' / 'logs' / ('attack_box_' + deployment_id + '.env'),
        ]

    def verify(self, context, config):
        deployment_id = config['deployment_id']
        report = checks(context, [
            ('os', "grep -Eq '^ID=(kali|ubuntu)' /etc/os-release"),
            ('workspace', 'sudo -n test -d /root/' + deployment_id + '/scans'),
            ('quick_guide', 'sudo -n test -s /root/QUICK_RECON_GUIDE.txt'),
            ('nmap', 'command -v nmap >/dev/null'), ('dig', 'command -v dig >/dev/null'),
            ('tor', 'command -v tor >/dev/null'), ('torsocks', 'command -v torsocks >/dev/null'),
            ('proxychains', 'command -v proxychains4 >/dev/null'),
            ('tor_enabled', 'test "$(systemctl is-enabled tor)" = enabled'),
            ('tor_active', 'systemctl is-active tor >/dev/null'),
            ('alias', "sudo -n grep -Fq \"alias qr='cd /root/" + deployment_id + "'\" /root/.bashrc"),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ])
        if context.provider == 'azure':
            rules = context.cloud.inbound_rules(deployment_id)
            require(rules == [('tcp', '22', config['operator_ip'] + '/32')],
                    'Azure attack box exposes more than operator SSH: ' + str(rules))
            report['security_group_rules'] = rules
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
    repeat = {'aws': True, 'linode': True, 'azure': True}
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
        if provider == 'azure':
            return 'r-' + deployment_id, 'azureuser', SSH_DIR / ('c2deploy_' + deployment_id)
        return 'r-' + deployment_id, 'root', SSH_DIR / ('c2deploy_' + deployment_id)

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_' + deployment_id) + azure_artifacts(deployment_id) + [
            ROOT / ('infrastructure_state_' + deployment_id + '.json'),
            ROOT / 'providers' / PROVIDER_DIRS[provider] / ('infrastructure_state_' + deployment_id + '.json')]

    def verify(self, context, config):
        # The site answers only its own hostname; the catch-all vhost bounces every other Host.
        host = config['redirector_subdomain'] + '.' + config['domain']
        report = checks(context, [
            ('nginx_active', 'test "$(systemctl is-active nginx)" = active'),
            ('nginx_enabled', 'test "$(systemctl is-enabled nginx)" = enabled'),
            ('shell_handler_enabled', 'test "$(systemctl is-enabled shell-handler)" = enabled'),
            ('http_listening', "ss -ltn | grep -q ':80 '"),
            ('https_listening', "ss -ltn | grep -q ':443 '"),
            ('local_https', 'test "$(curl -ks -o /dev/null -w \'%{http_code}\' -H \'Host: ' + host +
             '\' https://127.0.0.1/)" = 200'),
            ('post_install_script', 'sudo -n test -x /root/Tools/post_install_redirector.sh'),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ])
        base = ['curl', '-ks', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20']
        url = 'https://' + context.address + '/'
        status = context.run(base + ['-H', 'Host: ' + host, url])
        require(status == '200', 'Redirector HTTPS front page is not public: ' + status)
        unknown = context.run(base + [url])
        require(unknown == '301', 'Redirector answered an unknown Host instead of bouncing it: ' + unknown)
        report['unknown_host_bounced'] = True
        if context.provider == 'azure':
            rules = context.cloud.inbound_rules(config['deployment_id'])
            require(('tcp', '22', config['operator_ip'] + '/32') in rules and
                    all(source == '*' for proto, port, source in rules if port != '22'),
                    'Azure redirector rules are not operator-SSH plus public web: ' + str(rules))
            report['security_group_rules'] = rules
        if context.provider == 'aws':
            rules = context.cloud.inbound_rules('r-' + config['deployment_id'] + '-sg')
            require(('tcp', 22, 22, config['operator_ip'] + '/32') in rules,
                    'AWS redirector does not restrict SSH to the operator /32')
            report['security_group_rules'] = rules
        return report


class C2:
    name = 'c2'
    repeat = {'aws': False, 'linode': False, 'azure': True}
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
        elif provider == 'linode':
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
        if provider == 'azure':
            return config['c2_name'], 'azureuser', SSH_DIR / ('c2deploy_' + deployment_id)
        return config['c2_name'], 'root', SSH_DIR / ('c2deploy_' + deployment_id)

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_' + deployment_id) + azure_artifacts(deployment_id) + [
            ROOT / ('infrastructure_state_' + deployment_id + '.json'),
            ROOT / 'providers' / PROVIDER_DIRS[provider] / ('infrastructure_state_' + deployment_id + '.json')]

    def verify(self, context, config):
        report = checks(context, [
            ('kali', "grep -q '^ID=kali' /etc/os-release"),
            ('havoc_teamserver', 'sudo -n test -x /root/Tools/Havoc/havoc'),
            ('havoc_config', 'sudo -n test -s /root/Tools/Havoc/data/havoc.yaotl'),
            ('havoc_guide', 'sudo -n test -s /root/havoc-guide.txt'),
            ('havoc_installer', 'sudo -n test -x /root/Tools/havoc_installer.sh'),
            ('postfix_active', 'test "$(systemctl is-active postfix)" = active'),
            ('dovecot_active', 'test "$(systemctl is-active dovecot)" = active'),
            ('opendkim_active', 'test "$(systemctl is-active opendkim)" = active'),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ], timeout=120)
        if context.provider == 'aws':
            rules = context.cloud.inbound_rules(config['c2_name'] + '-sg')
            require(('tcp', 22, 22, config['operator_ip'] + '/32') in rules,
                    'AWS C2 does not restrict SSH to the operator /32')
            report['security_group_rules'] = rules
        return report


class PayloadServer:
    name = 'payload_server'
    repeat = {'aws': True, 'linode': True, 'azure': True}
    source_paths = ('modules/payload-server', 'providers/{dir}/payload_server.yml')

    def config(self, provider, deployment_id, operator_ip):
        config = {
            'deployment_id': deployment_id, 'provider': provider,
            'provider_workload': 'payload_server', 'deployment_type': 'secure_payload_server',
            'payload_server_name': 'ps-' + deployment_id, 'domain': 'payload-lab.test',
            'payload_subdomain': 'cdn', 'host_executables': True, 'host_scripts': True,
            'host_documents': False, 'host_mobile': False, 'enable_basic_auth': True,
            'enable_ip_filtering': True, 'enable_user_agent_filtering': True,
            'enable_rate_limiting': True, 'auto_generate_payloads': False,
            'auth_username': 'operator', 'auth_password': None,
            'letsencrypt_email': 'admin@payload-lab.test', 'operator_ip': operator_ip,
            'ssh_after_deploy': False,
        }
        config.update(provider_config(provider))
        ready, _ = prepare_module_ssh_key(config, deployment_id)
        require(ready, 'Could not generate the module SSH key')
        return config

    def identity(self, config):
        deployment_id = config['deployment_id']
        return {'deployment_id': deployment_id, 'names': ['ps-' + deployment_id],
                'key_names': ['c2deploy_' + deployment_id],
                'sg_names': ['ps-' + deployment_id + '-sg']}

    def target(self, provider, config):
        deployment_id = config['deployment_id']
        user = {'aws': 'ubuntu', 'azure': 'azureuser'}.get(provider, 'root')
        return 'ps-' + deployment_id, user, SSH_DIR / ('c2deploy_' + deployment_id)

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_' + deployment_id) + azure_artifacts(deployment_id)

    def verify(self, context, config):
        report = checks(context, [
            ('nginx_active', 'test "$(systemctl is-active nginx)" = active'),
            ('nginx_enabled', 'test "$(systemctl is-enabled nginx)" = enabled'),
            ('https_listening', "ss -ltn | grep -q ':443 '"),
            ('local_denied_by_allowlist',
             'test "$(curl -ks -o /dev/null -w \'%{http_code}\' -A Mozilla/5.0 https://127.0.0.1/)" = 403'),
            ('payload_dirs', 'sudo -n test -d /var/www/payloads/windows -a -d /var/www/payloads/scripts'),
            ('go_donut_built', 'sudo -n test -x /root/Tools/go-donut/go-donut'),
            ('guide', 'sudo -n test -s /root/PAYLOAD_SERVER_GUIDE.txt'),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ])
        credentials = context.ssh("sudo -n sed -n 's/^Basic auth: //p' /root/PAYLOAD_SERVER_GUIDE.txt")
        user, password = credentials.split(' / ')
        base = ['curl', '-ks', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20']
        url = 'https://' + context.address + '/'
        anonymous = context.run(base + ['-A', 'Mozilla/5.0', url])
        require(anonymous == '401', 'Payload server did not demand basic auth: ' + anonymous)
        authorized = context.run(base + ['-A', 'Mozilla/5.0', '-u', user + ':' + password, url])
        require(authorized == '200', 'Payload server refused valid credentials: ' + authorized)
        scanner = context.runner.run(base + [url], check=False)
        require(scanner == '000', 'Payload server answered a tool user agent: ' + scanner)
        report.update({'public_basic_auth': True, 'public_authorized': True,
                       'tool_user_agent_dropped': True})
        if context.provider == 'azure':
            rules = context.cloud.inbound_rules(config['deployment_id'])
            require(('tcp', '22', config['operator_ip'] + '/32') in rules and
                    all(source == '*' for proto, port, source in rules if port != '22'),
                    'Azure payload server rules are not operator-SSH plus public web: ' + str(rules))
            report['security_group_rules'] = rules
        if context.provider == 'aws':
            rules = context.cloud.inbound_rules('ps-' + config['deployment_id'] + '-sg')
            require(('tcp', 22, 22, config['operator_ip'] + '/32') in rules,
                    'AWS payload server does not restrict SSH to the operator /32')
            report['security_group_rules'] = rules
        return report


WORKLOADS = {cls.name: cls for cls in (AttackBox, Redirector, C2, PayloadServer)}


class Webrunner:
    """One composite scan node per provider, scanning only the operator's own /32."""
    name = 'webrunner'
    source_paths = ('modules/webrunner', 'providers/webrunner.yml', 'providers/{dir}')

    def config(self, provider, deployment_id, operator_ip, keep_nodes):
        name = 'wr-' + deployment_id
        config = {
            'deployment_id': deployment_id, 'engagement': 'livetest',
            'deployment_type': 'webrunner', 'provider_workload': 'webrunner',
            'webrunner_deployment': True, 'webrunner_name': name, 'providers': [provider],
            'scan_mode': 'masscan-only', 'ports': [22], 'ports_str': '22', 'masscan_rate': 1000,
            'use_tor': False, 'targets_file': '', 'total_ips': 1, 'preset': 'sprint',
            'chunk_size': 500000, 'operator_ip': operator_ip, 'enhanced_opsec': False,
            'teardown_after_scan': not keep_nodes,
        }
        config.update(provider_config(provider))
        # Every provider's scan nodes share the module key, so Azure must not own one.
        config.pop('provider_manages_ssh_key', None)
        ready, private = prepare_module_ssh_key(config, name)
        require(ready and private, 'Could not generate the module SSH key')
        config['ssh_key_name'] = Path(private).name
        logs = ROOT / 'logs'
        chunks = logs / ('node_chunks_' + deployment_id + '.json')
        chunks.write_text(json.dumps([{
            'idx': 0, 'node_name': name + '-01', 'provider': provider,
            'region': REGIONS[provider], 'cidrs': [operator_ip + '/32'], 'ip_count': 1}]))
        chunks.chmod(0o600)
        config['node_chunks_file'] = str(chunks)
        config['scanner_ip_log'] = str(logs / ('scanner_ips_' + name + '.txt'))
        config['results_dir'] = str(logs / ('webrunner_' + deployment_id))
        return config

    def identity(self, provider, deployment_id):
        name = 'wr-' + deployment_id
        if provider == 'azure':
            return {'deployment_id': deployment_id + '-n01', 'names': [name + '-01']}
        return {'deployment_id': deployment_id, 'names': [name + '-01'],
                'key_names': [name], 'sg_names': ['webrunner-' + name]}

    def target(self, provider, config):
        user = {'aws': 'admin', 'azure': 'azureuser'}.get(provider, 'root')
        return config['webrunner_name'] + '-01', user, SSH_DIR / ('c2deploy_' + config['webrunner_name'])

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return (key_files('c2deploy_wr-' + deployment_id) +
                [AZURE_STATE_DIR / (deployment_id + '-n01.json')])

    def verify(self, runner, cloud, provider, config, identity, keep_nodes):
        node, user, key = self.target(provider, config)
        merged = json.loads((Path(config['results_dir']) / 'merged_results.json').read_text())
        require([item['node_name'] for item in merged['nodes']] == [node] and
                merged['nodes'][0]['scan_mode'] == 'masscan-only',
                'Merged results do not describe the single scan node: ' + json.dumps(merged['nodes']))
        logged = re.search('^' + re.escape(node) + r': (\S+)$',
                           Path(config['scanner_ip_log']).read_text(), re.MULTILINE)
        require(logged, 'Scanner IP log does not list the node')
        address = public_ipv4(logged.group(1))
        report = {'nodes': merged['nodes'], 'total_results': merged['total_results'],
                  'scanner_ip': address, 'target': config['operator_ip'] + '/32 tcp/22'}
        inventory = cloud.inventory(identity)
        if keep_nodes:
            require(len(inventory['instances']) == 1 and inventory['instances'][0]['state'] == 'running',
                    'Expected exactly one running scan node')
            require(cloud.address(identity, node) == address, 'Scanner IP log disagrees with the cloud inventory')
            require(key.is_file(), 'Module SSH key is missing: ' + str(key))
            context = Context(runner, cloud, provider, address, user, key)
            report['host'] = checks(context, [
                ('masscan_installed', 'command -v masscan'),
                ('scanner_present', 'sudo -n test -s /root/webrunner/node_scanner.py'),
                ('results_present', 'sudo -n test -s /root/webrunner/results.json'),
                ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
            ])
            if provider == 'azure':
                rules = cloud.inbound_rules(identity['deployment_id'])
                require(rules == [('tcp', '22', config['operator_ip'] + '/32')],
                        'Azure scan node allows more than operator SSH: ' + str(rules))
                report['security_group_rules'] = rules
            if provider == 'aws':
                rules = cloud.inbound_rules('webrunner-' + config['webrunner_name'])
                require(rules == [('tcp', 22, 22, config['operator_ip'] + '/32')],
                        'AWS scan node allows more than operator SSH: ' + str(rules))
                report['security_group_rules'] = rules
        else:
            require(empty(inventory), 'Scan node remains after the in-play teardown')
            require(not key.exists(), 'Module key remains after the in-play teardown')
            report['in_play_teardown'] = True
        report['cloud'] = inventory
        return report

    def collect(self, runner, config, label):
        for source in (Path(config['results_dir']), Path(config['scanner_ip_log']),
                       Path(config['node_chunks_file'])):
            if source.exists():
                shutil.move(str(source), str(runner.evidence / (label + '-' + source.name)))


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


def build_cloud(provider, evidence):
    if provider == 'aws':
        return AwsCloud(REGIONS['aws'])
    if provider == 'azure':
        return AzureCloud(evidence)
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
        # The project venv carries Ansible plus the AWS and Linode SDKs its
        # controller lookups import; prefer it over a system ansible-playbook.
        venv_bin = Path(sys.executable).parent
        if (venv_bin / 'ansible-playbook').is_file():
            os.environ['PATH'] = str(venv_bin) + os.pathsep + os.environ.get('PATH', '')
        for executable in ('ansible-playbook', 'ssh', 'ssh-keygen', 'curl', 'git'):
            require(shutil.which(executable), 'Required tool unavailable: ' + executable)
        runner.record('source.json', {'commit': verify_committed_source(runner, provider, workload)})
        prepare_provider_environment({'provider': provider})
        cloud = build_cloud(provider, evidence)
        operator_ip = public_ipv4(operator_ip or runner.run([
            'curl', '-4', '--fail', '--silent', '--show-error', '--max-time', '15',
            'https://api.ipify.org']))
        config = workload.config(provider, deployment_id, operator_ip)
        identity = workload.identity(config)
        require(empty(cloud.inventory(identity)), 'Live-test identity already owns cloud resources')
        generated = [path for path in workload.local_artifacts(provider, config) if path.exists()]
        expected_key = Path(config.get('ssh_key_path') or
                            SSH_DIR / ('c2deploy_' + deployment_id + '.pub')).with_suffix('')
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
        runner.record('host-diagnostics.json', {'sshd': context.ssh(SSHD_DIAGNOSTICS)})
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
    getattr(cloud, 'settle', lambda: None)()
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


def activate_webrunner(provider, operator_ip=None):
    """Keep the first run's node for inspection and routed teardown; the second
    run exercises the module's own in-play teardown. Both scan only the
    operator's /32 on tcp/22."""
    workload = Webrunner()
    os.chdir(ROOT)
    deployment_id = 'lt-{0}-webrun-{1}'.format(provider, uuid.uuid4().hex[:6])
    evidence = ROOT / 'logs' / (provider + '-webrunner-live') / deployment_id
    evidence.mkdir(parents=True, mode=0o700)
    runner = Runner(evidence)
    previous = {sig: signal.signal(sig, runner.handle_signal)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    cloud = None
    pending = []
    live_passed = cleanup_passed = False
    failure = None
    try:
        venv_bin = Path(sys.executable).parent
        if (venv_bin / 'ansible-playbook').is_file():
            os.environ['PATH'] = str(venv_bin) + os.pathsep + os.environ.get('PATH', '')
        for executable in ('ansible-playbook', 'ssh', 'ssh-keygen', 'curl', 'git'):
            require(shutil.which(executable), 'Required tool unavailable: ' + executable)
        runner.record('source.json', {'commit': verify_committed_source(runner, provider, workload)})
        prepare_provider_environment({'provider': provider})
        cloud = build_cloud(provider, evidence)
        operator_ip = public_ipv4(operator_ip or runner.run([
            'curl', '-4', '--fail', '--silent', '--show-error', '--max-time', '15',
            'https://api.ipify.org']))
        spec = importlib.util.spec_from_file_location(
            'deploy_webrunner_live', ROOT / 'modules/webrunner/deploy_webrunner.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        baseline = None
        for label, run_id, keep in (('kept', deployment_id, True),
                                    ('self-teardown', deployment_id + '-r', False)):
            identity = workload.identity(provider, run_id)
            require(empty(cloud.inventory(identity)), 'Live-test identity already owns cloud resources')
            require(not [path for path in workload.local_artifacts(provider, {'deployment_id': run_id})
                         if path.exists()], 'Unexpected local artifacts exist for the live-test identity')
            if baseline is None:
                baseline = cloud.totals()
                runner.record('baseline.json', {'identity': identity, 'totals': baseline,
                                                'operator_ip': operator_ip})
            config = workload.config(provider, run_id, operator_ip, keep)
            runner.record(label + '-config.json', redacted(config))
            setup_logging(run_id, 'live_test')
            pending.append((label, config, identity))
            require(dispatch_composite_workload(config, module._execute_webrunner_legacy),
                    'Routed WEBRUNNER deployment failed (' + label + ')')
            report = workload.verify(runner, cloud, provider, config, identity, keep)
            runner.record(label + '-deployment.json', report)
            workload.collect(runner, config, label)
            runner.cleaning = True
            require(cleanup(runner, cloud, provider, workload, config, identity, True),
                    'Cleanup did not verify (' + label + ')')
            for name in ('final-cleanup.json', 'standalone-teardown.json'):
                if (runner.evidence / name).exists():
                    (runner.evidence / name).rename(runner.evidence / (label + '-' + name))
            runner.cleaning = False
            pending.pop()
        live_passed = True
    except BaseException as exc:
        failure = str(exc)
        runner.record('failure.json', {'error': failure})
        print('{0} webrunner live test did not pass: {1}'.format(provider, failure), file=sys.stderr)
    finally:
        runner.cleaning = True
        cleanup_passed = True
        for label, config, identity in pending:
            try:
                workload.collect(runner, config, label)
                node_state = AZURE_STATE_DIR / (config['deployment_id'] + '-n01.json')
                if node_state.exists() and not (
                        ROOT / 'logs' / ('deployment_info_' + config['deployment_id'] + '.txt')).exists():
                    # Provisioning failed before the playbook recorded the run.
                    runner.run([sys.executable, 'teardown.py', '--deployment-id',
                                config['deployment_id'] + '-n01', '--force'], timeout=1800)
                cleanup_passed = cleanup(runner, cloud, provider, workload, config, identity, True) and cleanup_passed
            except BaseException as exc:
                cleanup_passed = False
                runner.record('cleanup-failure.json', {'error': str(exc)})
                print('{0} webrunner cleanup failed: {1}'.format(provider, exc), file=sys.stderr)
        for sig, handler in previous.items():
            signal.signal(sig, handler)

    passed = live_passed and cleanup_passed and not runner.interrupted
    runner.record('result.json', {
        'passed': passed, 'live_workflow_passed': live_passed,
        'cleanup_passed': cleanup_passed, 'failure': failure,
        'deployment_id': deployment_id, 'provider': provider, 'workload': 'webrunner',
    })
    print('Evidence: ' + str(evidence))
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=sorted(REGIONS), required=True)
    parser.add_argument('--workload', choices=sorted(WORKLOADS) + ['webrunner'], required=True)
    parser.add_argument('--activate', action='store_true')
    parser.add_argument('--operator-ip')
    parser.add_argument('--repeat', dest='repeat', action='store_true', default=None)
    parser.add_argument('--no-repeat', dest='repeat', action='store_false')
    args = parser.parse_args(argv)
    if not args.activate:
        print('DRY RUN: no cloud mutations. Target: {0} / {1} / {2}'.format(
            args.provider, REGIONS[args.provider], args.workload))
        return 0
    if args.workload == 'webrunner':
        return activate_webrunner(args.provider, args.operator_ip)
    return activate(args.provider, args.workload, args.operator_ip, args.repeat)


if __name__ == '__main__':
    sys.exit(main())
