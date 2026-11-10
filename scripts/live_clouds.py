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

REGIONS = {'aws': 'us-east-1', 'linode': 'us-east', 'azure': 'eastus', 'local': 'localhost'}
AZURE_SUBSCRIPTION = 'cc2a66d1-67c2-47ca-856f-19a4eae52cfe'
AZURE_SIZE = 'Standard_D2as_v4'
LINODE_API = 'https://api.linode.com/v4'
SECRET_FRAGMENTS = ('token', 'secret', 'pass', 'access_key')
# Workload sizing beyond a provider's default instance.
LIVE_SIZING = {
    # RedELK runs Elasticsearch, Logstash and Kibana together; 8 GB keeps them up.
    'aws': {'logging_server': {'aws_instance_type': 't3.large'}},
    'linode': {'logging_server': {'linode_instance_type': 'g6-standard-4'}},
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
    TAG = 'c2itall-deployment'

    def __init__(self, region):
        import boto3
        self.region = region
        self.ec2 = boto3.client('ec2', region_name=region)
        self.cloudfront = boto3.client('cloudfront', region_name='us-east-1')

    @staticmethod
    def _ids(identity):
        return list((identity.get('components') or {}).values()) or [identity['deployment_id']]

    def _filters(self, ids):
        return [{'Name': 'tag:' + self.TAG, 'Values': list(ids)}]

    def _instances(self, filters):
        found = []
        for reservation in self.ec2.describe_instances(Filters=filters)['Reservations']:
            for instance in reservation['Instances']:
                if instance['State']['Name'] == 'terminated':
                    continue
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                found.append({
                    'id': instance['InstanceId'], 'state': instance['State']['Name'],
                    'name': tags.get(self.TAG, ''), 'public_ip': instance.get('PublicIpAddress', ''),
                    'instance_type': instance['InstanceType'], 'image_id': instance['ImageId'],
                })
        return sorted(found, key=lambda item: item['id'])

    def _distributions(self):
        items = []
        for page in self.cloudfront.get_paginator('list_distributions').paginate():
            for distribution in page['DistributionList'].get('Items', []):
                tags = {tag['Key']: tag['Value'] for tag in self.cloudfront.list_tags_for_resource(
                    Resource=distribution['ARN'])['Tags']['Items']}
                items.append({'id': distribution['Id'], 'domain': distribution['DomainName'],
                              'status': distribution['Status'], 'name': tags.get(self.TAG, '')})
        return sorted(items, key=lambda item: item['id'])

    def inventory(self, identity):
        ids = self._ids(identity)
        filters = self._filters(ids)
        return {
            'instances': self._instances(filters),
            'security_groups': sorted(
                [{'id': group['GroupId'], 'name': group['GroupName']}
                 for group in self.ec2.describe_security_groups(Filters=filters)['SecurityGroups']],
                key=lambda item: item['id']),
            'subnets': sorted(item['SubnetId'] for item in self.ec2.describe_subnets(Filters=filters)['Subnets']),
            'internet_gateways': sorted(item['InternetGatewayId'] for item in
                                        self.ec2.describe_internet_gateways(Filters=filters)['InternetGateways']),
            'vpcs': sorted(item['VpcId'] for item in self.ec2.describe_vpcs(Filters=filters)['Vpcs']),
            'edges': [item for item in self._distributions() if item['name'] in ids],
        }

    def totals(self):
        groups = sum(1 for group in self.ec2.describe_security_groups()['SecurityGroups']
                     if group['GroupName'] != 'default')
        vpcs = sum(1 for vpc in self.ec2.describe_vpcs()['Vpcs'] if not vpc.get('IsDefault'))
        return {'region': self.region, 'instances': len(self._instances([])), 'security_groups': groups,
                'vpcs': vpcs, 'distributions': len(self._distributions())}

    def address(self, identity, name):
        wanted = (identity.get('components') or {}).get(name, identity['deployment_id'])
        for instance in self._instances(self._filters([wanted])):
            if instance['state'] == 'running':
                return public_ipv4(instance['public_ip'])
        raise LiveError('No running AWS instance for ' + name)

    def inbound_rules(self, deployment_id):
        rules = []
        for group in self.ec2.describe_security_groups(Filters=self._filters([deployment_id]))['SecurityGroups']:
            for permission in group['IpPermissions']:
                port = str(permission.get('FromPort'))
                if permission.get('ToPort') not in (None, permission.get('FromPort')):
                    port += '-' + str(permission['ToPort'])
                for cidr in permission.get('IpRanges', []):
                    rules.append((permission['IpProtocol'], port,
                                  '*' if cidr['CidrIp'] == '0.0.0.0/0' else cidr['CidrIp']))
                for _prefix in permission.get('PrefixListIds', []):
                    rules.append((permission['IpProtocol'], port, 'cloudfront'))
        return sorted(rules)


class LinodeCloud:
    provider = 'linode'
    TAG = 'c2itall-deployment-'

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

    @staticmethod
    def _ids(identity):
        return list((identity.get('components') or {}).values()) or [identity['deployment_id']]

    def _owner(self, item):
        for tag in item.get('tags') or []:
            if tag.startswith(self.TAG):
                return tag[len(self.TAG):]
        return ''

    def inventory(self, identity):
        ids = set(self._ids(identity))
        instances = [{'id': item['id'], 'name': self._owner(item), 'state': item['status'],
                      'public_ip': (item.get('ipv4') or [''])[0], 'instance_type': item.get('type'),
                      'image_id': item.get('image'), 'region': item.get('region')}
                     for item in self._pages('/linode/instances') if self._owner(item) in ids]
        firewalls = [{'id': item['id'], 'name': self._owner(item)}
                     for item in self._pages('/networking/firewalls') if self._owner(item) in ids]
        return {'instances': sorted(instances, key=lambda item: item['id']),
                'firewalls': sorted(firewalls, key=lambda item: item['id'])}

    def totals(self):
        return {'region': self.region,
                'instances': sum(1 for _ in self._pages('/linode/instances')),
                'firewalls': sum(1 for _ in self._pages('/networking/firewalls'))}

    def address(self, identity, name):
        wanted = (identity.get('components') or {}).get(name, identity['deployment_id'])
        for instance in self.inventory({'deployment_id': wanted})['instances']:
            if instance['state'] == 'running':
                return public_ipv4(instance['public_ip'])
        raise LiveError('No running Linode for ' + name)

    def inbound_rules(self, deployment_id):
        rules = []
        for firewall in self._pages('/networking/firewalls'):
            if self._owner(firewall) != deployment_id:
                continue
            for rule in firewall.get('rules', {}).get('inbound', []):
                if rule.get('action') != 'ACCEPT':
                    continue
                for cidr in rule.get('addresses', {}).get('ipv4', []):
                    rules.append((rule['protocol'].lower(), str(rule['ports']),
                                  '*' if cidr == '0.0.0.0/0' else cidr))
        return sorted(rules)


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


class LocalCloud:
    """Hosts the operator built themselves: nothing to count, nothing to restore."""
    provider = 'local'

    def __init__(self, evidence):
        pass

    def inventory(self, identity):
        return {}

    def totals(self):
        return {}


def _account_inputs(provider):
    if provider == 'local':
        return {'provider_manages_ssh_key': True}
    if provider == 'azure':
        return {
            'azure_subscription_id': AZURE_SUBSCRIPTION, 'azure_location': REGIONS['azure'],
            'azure_vm_size': AZURE_SIZE, 'azure_os_disk_gb': 32,
            'provider_manages_ssh_key': True,
        }
    if provider == 'aws':
        return {
            'aws_region': REGIONS['aws'], 'aws_regions': [REGIONS['aws']],
            'aws_instance_type': 't3.medium', 'provider_manages_ssh_key': True,
        }
    return {
        'linode_region': REGIONS['linode'], 'linode_regions': [REGIONS['linode']],
        'linode_instance_type': 'g6-standard-2', 'provider_manages_ssh_key': True,
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
    'local': LocalCloud,
}


def build_cloud(provider, evidence):
    return CLOUDS[provider](evidence)
