#!/usr/bin/env python3
"""Cloud inventories and account inputs for the live workload harness.

One class per provider answers the harness's inventory, totals, address and
inbound-rule questions, and live_config supplies the non-secret account
inputs a live run uses. Adding a provider to the harness is one cloud class
plus one entry each in CLOUDS, REGIONS and _account_inputs; the workload
classes in test_provider_workload_live.py never name a provider. Clouds for
driver-backed providers report inbound rules as (protocol, port, source)
tuples with lower-case protocol names and string ports, and resolve the
harness's neutral component IDs to their own resource names.
"""

import ipaddress
import json
import os
from pathlib import Path
import sys
from urllib import error, request

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
for path in (SCRIPT_DIR, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from utils.common import load_vars_file

REGIONS = {'aws': 'us-east-1', 'linode': 'us-east', 'azure': 'eastus'}
AZURE_SUBSCRIPTION = 'cc2a66d1-67c2-47ca-856f-19a4eae52cfe'
AZURE_SIZE = 'Standard_D2as_v4'
LINODE_API = 'https://api.linode.com/v4'
SECRET_FRAGMENTS = ('token', 'secret', 'pass', 'access_key')
# Workload sizing a transition provider needs beyond its vars.yaml defaults.
LIVE_SIZING = {
    # Havoc is compiled on the host; the vars.yaml defaults are sized for
    # redirectors and starve the build. Match the playbook's own defaults.
    'aws': {'c2': {'aws_instance_type': 't3.medium'}},
    'linode': {'c2': {'linode_instance_type': 'g6-standard-2'}},
}


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
                                  'instance_type': item.get('type'), 'image_id': item.get('image'),
                                  'region': item.get('region')})
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

    @staticmethod
    def _groups(identity):
        ids = list((identity.get('components') or {}).values()) or [identity['deployment_id']]
        return ['c2itall-' + deployment_id for deployment_id in ids]

    def inventory(self, identity):
        groups = self._groups(identity)
        instances, resources = [], []
        for group in groups:
            if self.smoke.az('group', 'exists', '--name', group) is not True:
                continue
            for vm in self.smoke.az('vm', 'list', '--resource-group', group, '--show-details') or []:
                instances.append({
                    'id': vm['id'].lower(), 'name': vm['name'],
                    'state': 'running' if vm.get('powerState') == 'VM running' else str(vm.get('powerState', '')),
                    'public_ip': vm.get('publicIps', ''), 'instance_type': vm['hardwareProfile']['vmSize'],
                    'image_id': json.dumps(vm['storageProfile']['imageReference'], sort_keys=True)})
            resources.extend(item['id'].lower() for item in
                             self.smoke.az('resource', 'list', '--resource-group', group) or [])
        return {'instances': sorted(instances, key=lambda item: item['id']), 'resources': sorted(resources)}

    def totals(self):
        inventory = self.smoke.inventory()
        if self.smoke.subscription_baseline is None:
            self.smoke.subscription_baseline = inventory
        return inventory

    def settle(self):
        # Azure adds a NetworkWatcher to an empty lab; the smoke runner removes only that.
        self.smoke.cleanup_subscription()

    def address(self, identity, name):
        component = (identity.get('components') or {}).get(name)
        wanted = None if component is None else 'c2itall-' + component + '-vm'
        for instance in self.inventory(identity)['instances']:
            if instance['state'] == 'running' and wanted in (None, instance['name']):
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


def _account_inputs(provider):
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


def live_config(provider, workload=None):
    """Non-secret account inputs plus any workload sizing for one live run."""
    config = _account_inputs(provider)
    config.update(LIVE_SIZING.get(provider, {}).get(workload, {}))
    return config


CLOUDS = {
    'aws': lambda evidence: AwsCloud(REGIONS['aws']),
    'linode': lambda evidence: LinodeCloud(os.environ['LINODE_TOKEN']),
    'azure': AzureCloud,
}


def build_cloud(provider, evidence):
    return CLOUDS[provider](evidence)
