"""The AWS, Linode and FlokiNET drivers against in-memory provider APIs.

Each driver plans, creates, resumes, inspects and removes its resources
through the shared recoverable lifecycle; cleanup refuses anything the
deployment does not own. Every provider is registered and serves every
profiled workload.
"""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils import aws_cloud, flokinet_cloud, linode_cloud, local_cloud
from utils import provider_registry as registry
from utils.cloud_driver import ProvisionRequest
from utils.driver_base import StatefulDriver
from utils.workloads import load_profile

OPERATOR = '8.8.8.8'
RULES = [
    {'name': 'http', 'protocol': 'Tcp', 'port': 80, 'source': 'edge'},
    {'name': 'https', 'protocol': 'Tcp', 'port': 443, 'source': 'edge'},
    {'name': 'shell-handler', 'protocol': 'Tcp', 'port': 4488, 'source': '*'},
    {'name': 'peer', 'protocol': 'Udp', 'port': 5044, 'source': '9.9.9.9'},
]
EDGE = {'host_header': 'cdn.lab.test', 'forwarding': 'HttpOnly', 'name': 'cdn-x'}


def tags(state):
    return {'c2itall-deployment': state['deployment_id'], 'c2itall-owner': state['ownership_marker']}


class FakeEc2:
    """The EC2 subset the driver uses, keyed by the tags it must honour."""

    def __init__(self):
        self.vpcs, self.gateways, self.subnets, self.groups, self.instances = {}, {}, {}, {}, {}
        self.routes = []
        self.calls = []
        self.counter = 0

    def _id(self, prefix):
        self.counter += 1
        return prefix + '-' + str(self.counter)

    @staticmethod
    def _tags(specs, kind):
        return [dict(tag) for spec in specs for tag in spec['Tags'] if spec['ResourceType'] == kind]

    @staticmethod
    def _match(item, filters):
        for condition in filters or []:
            name, values = condition['Name'], condition['Values']
            if name.startswith('tag:'):
                if {tag['Key']: tag['Value'] for tag in item.get('Tags', [])}.get(name[4:]) not in values:
                    return False
            elif name == 'instance-state-name':
                if item['State']['Name'] not in values:
                    return False
            elif name == 'vpc-id':
                if item.get('VpcId') not in values:
                    return False
            elif name not in ('association.main', 'prefix-list-name'):
                raise AssertionError('unexpected filter ' + name)
        return True

    def _select(self, store, filters=None, ids=None):
        if ids is not None:
            missing = [item for item in ids if item not in store]
            if missing:
                raise RuntimeError('InvalidID.NotFound: ' + ','.join(missing))
            items = [store[item] for item in ids]
        else:
            items = list(store.values())
        return [item for item in items if self._match(item, filters)]

    # VPC
    def create_vpc(self, CidrBlock, TagSpecifications):
        vpc = {'VpcId': self._id('vpc'), 'CidrBlock': CidrBlock, 'IsDefault': False,
               'Tags': self._tags(TagSpecifications, 'vpc')}
        self.vpcs[vpc['VpcId']] = vpc
        return {'Vpc': vpc}

    def describe_vpcs(self, Filters=None, VpcIds=None):
        return {'Vpcs': self._select(self.vpcs, Filters, VpcIds)}

    def modify_vpc_attribute(self, **kwargs):
        self.calls.append(('modify_vpc_attribute', kwargs))

    def delete_vpc(self, VpcId):
        del self.vpcs[VpcId]

    # Internet gateway
    def create_internet_gateway(self, TagSpecifications):
        gateway = {'InternetGatewayId': self._id('igw'), 'Attachments': [],
                   'Tags': self._tags(TagSpecifications, 'internet-gateway')}
        self.gateways[gateway['InternetGatewayId']] = gateway
        return {'InternetGateway': gateway}

    def describe_internet_gateways(self, Filters=None, InternetGatewayIds=None):
        return {'InternetGateways': self._select(self.gateways, Filters, InternetGatewayIds)}

    def attach_internet_gateway(self, InternetGatewayId, VpcId):
        self.gateways[InternetGatewayId]['Attachments'].append({'VpcId': VpcId, 'State': 'available'})

    def detach_internet_gateway(self, InternetGatewayId, VpcId):
        self.gateways[InternetGatewayId]['Attachments'] = []

    def delete_internet_gateway(self, InternetGatewayId):
        del self.gateways[InternetGatewayId]

    # Subnet and routes
    def describe_instance_type_offerings(self, LocationType, Filters):
        self.calls.append(('describe_instance_type_offerings', Filters[0]['Values'][0]))
        return {'InstanceTypeOfferings': [{'Location': 'us-east-1e'}, {'Location': 'us-east-1a'}]}

    def create_subnet(self, VpcId, CidrBlock, AvailabilityZone, TagSpecifications):
        self.calls.append(('create_subnet', AvailabilityZone))
        subnet = {'SubnetId': self._id('subnet'), 'VpcId': VpcId, 'CidrBlock': CidrBlock,
                  'Tags': self._tags(TagSpecifications, 'subnet')}
        self.subnets[subnet['SubnetId']] = subnet
        return {'Subnet': subnet}

    def describe_subnets(self, Filters=None, SubnetIds=None):
        return {'Subnets': self._select(self.subnets, Filters, SubnetIds)}

    def modify_subnet_attribute(self, **kwargs):
        self.calls.append(('modify_subnet_attribute', kwargs))

    def delete_subnet(self, SubnetId):
        del self.subnets[SubnetId]

    def describe_route_tables(self, Filters):
        return {'RouteTables': [{'RouteTableId': 'rtb-main', 'Routes': list(self.routes)}]}

    def create_route(self, RouteTableId, DestinationCidrBlock, GatewayId):
        self.routes.append({'DestinationCidrBlock': DestinationCidrBlock, 'GatewayId': GatewayId})

    # Security group
    def create_security_group(self, GroupName, Description, VpcId, TagSpecifications):
        group = {'GroupId': self._id('sg'), 'GroupName': GroupName, 'VpcId': VpcId,
                 'IpPermissions': [], 'Tags': self._tags(TagSpecifications, 'security-group')}
        self.groups[group['GroupId']] = group
        return {'GroupId': group['GroupId']}

    def describe_security_groups(self, Filters=None, GroupIds=None):
        return {'SecurityGroups': self._select(self.groups, Filters, GroupIds)}

    def authorize_security_group_ingress(self, GroupId, IpPermissions):
        self.groups[GroupId]['IpPermissions'].extend(IpPermissions)

    def delete_security_group(self, GroupId):
        del self.groups[GroupId]

    def describe_managed_prefix_lists(self, Filters):
        return {'PrefixLists': [{'PrefixListId': 'pl-cloudfront'}]}

    # Instances
    def run_instances(self, **kwargs):
        instance = {'InstanceId': self._id('i'), 'State': {'Name': 'running'},
                    'PublicIpAddress': '8.8.8.20', 'PublicDnsName': 'ec2-8-8-8-20.compute-1.amazonaws.com',
                    'Tags': self._tags(kwargs['TagSpecifications'], 'instance'), 'Launch': kwargs}
        self.instances[instance['InstanceId']] = instance
        return {'Instances': [instance]}

    def describe_instances(self, Filters=None, InstanceIds=None):
        return {'Reservations': [{'Instances': self._select(self.instances, Filters, InstanceIds)}]}

    def describe_instance_status(self, InstanceIds, IncludeAllInstances):
        return {'InstanceStatuses': [{'InstanceState': self.instances[item]['State'],
                                      'InstanceStatus': {'Status': 'ok'}} for item in InstanceIds]}

    def terminate_instances(self, InstanceIds):
        for item in InstanceIds:
            self.instances[item]['State'] = {'Name': 'terminated'}

    def get_waiter(self, name):
        calls = self.calls

        class Waiter:
            def wait(self, **kwargs):
                calls.append(('wait', name, kwargs))
        return Waiter()


class FakeCloudFront:
    class exceptions:
        class NoSuchDistribution(Exception):
            pass

        class NoSuchResource(Exception):
            pass

    def __init__(self):
        self.distributions = {}
        self.calls = []

    def create_distribution_with_tags(self, DistributionConfigWithTags):
        identifier = 'E' + str(len(self.distributions) + 1)
        arn = 'arn:aws:cloudfront::123456789012:distribution/' + identifier
        self.distributions[identifier] = {
            'config': DistributionConfigWithTags['DistributionConfig'], 'arn': arn,
            'tags': DistributionConfigWithTags['Tags']['Items']}
        return {'Distribution': {'Id': identifier, 'ARN': arn, 'DomainName': identifier.lower() + '.cloudfront.test'}}

    def get_waiter(self, name):
        calls = self.calls

        class Waiter:
            def wait(self, **kwargs):
                calls.append(('wait', name, kwargs))
        return Waiter()

    def list_tags_for_resource(self, Resource):
        for item in self.distributions.values():
            if item['arn'] == Resource:
                return {'Tags': {'Items': item['tags']}}
        raise self.exceptions.NoSuchResource()

    def get_distribution_config(self, Id):
        if Id not in self.distributions:
            raise self.exceptions.NoSuchDistribution()
        return {'DistributionConfig': dict(self.distributions[Id]['config']), 'ETag': 'etag-' + Id}

    def update_distribution(self, Id, IfMatch, DistributionConfig):
        self.calls.append(('update', Id, DistributionConfig['Enabled']))
        self.distributions[Id]['config'] = DistributionConfig

    def delete_distribution(self, Id, IfMatch):
        assert not self.distributions[Id]['config']['Enabled'], 'delete before disable'
        self.calls.append(('delete', Id))
        del self.distributions[Id]

    def get_distribution(self, Id):
        if Id not in self.distributions:
            raise self.exceptions.NoSuchDistribution()
        return {'Distribution': {'Id': Id}}


class FakeLinodeApi:
    def __init__(self):
        self.linodes, self.firewalls = {}, {}
        self.calls = []
        self.types = [
            {'id': 'g6-nanode-1', 'class': 'nanode', 'disk': 25600, 'price': {'hourly': 0.0075}},
            {'id': 'g6-standard-2', 'class': 'standard', 'disk': 81920, 'price': {'hourly': 0.018}},
            {'id': 'g6-standard-4', 'class': 'standard', 'disk': 163840, 'price': {'hourly': 0.036}},
        ]

    def __call__(self, method, path, body=None, ok=(200,)):
        self.calls.append((method, path.split('?')[0]))
        clean = path.split('?')[0]
        if method == 'GET' and clean == '/linode/types':
            return {'data': self.types, 'pages': 1}
        if method == 'GET' and clean == '/linode/instances':
            return {'data': list(self.linodes.values()), 'pages': 1, 'results': len(self.linodes)}
        if method == 'GET' and clean == '/networking/firewalls':
            return {'data': list(self.firewalls.values()), 'pages': 1}
        if method == 'GET' and clean == '/profile':
            return {'username': 'operator'}
        if method == 'POST' and clean == '/networking/firewalls':
            firewall = dict(body, id=len(self.firewalls) + 100)
            self.firewalls[firewall['id']] = firewall
            return firewall
        if method == 'POST' and clean == '/linode/instances':
            linode = dict(body, id=len(self.linodes) + 500, status='running', ipv4=['8.8.8.30'])
            self.linodes[linode['id']] = linode
            return linode
        for prefix, store in (('/linode/instances/', self.linodes), ('/networking/firewalls/', self.firewalls)):
            if clean.startswith(prefix):
                identifier = int(clean[len(prefix):])
                if method == 'GET':
                    return dict(store[identifier]) if identifier in store else {}
                if method == 'DELETE':
                    store.pop(identifier, None)
                    return {}
        raise AssertionError('unexpected call ' + method + ' ' + path)


class DriverCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp.name) / 'state'
        self.private = Path(self.temp.name) / 'c2deploy_unit'
        self.public = Path(str(self.private) + '.pub')
        self.private.write_text('fake private key\n')
        self.public.write_text('ssh-ed25519 AAAAC3unit unit@test\n')
        self.ssh_wait = mock.patch.object(StatefulDriver, 'wait_for_ssh')
        self.ssh_wait.start()

    def tearDown(self):
        self.ssh_wait.stop()
        self.temp.cleanup()

    def request(self, deployment_id, rules=RULES, edge=EDGE):
        return ProvisionRequest(deployment_id, 'redirector', rules, 'ubuntu', 32,
                                str(self.public), str(self.private), False, edge=edge)

    def config(self, provider, **extra):
        return {'provider': provider, 'operator_ip': OPERATOR,
                provider + '_state_dir': str(self.state_dir), **extra}


class RegistryTests(unittest.TestCase):
    def test_every_provider_serves_every_workload_through_its_driver(self):
        summary = registry.validate_provider_registry(load_references=True)
        self.assertEqual(summary['routes'], 0)
        self.assertEqual(summary['counts']['native'] + summary['counts']['gated'], summary['pairs'])
        for provider in ('aws', 'linode', 'flokinet', 'azure', 'local'):
            for workload in registry.CANONICAL_WORKLOADS:
                profile = load_profile(workload)
                served = profile is None or profile.requires <= registry.provider_driver(provider).capabilities
                self.assertEqual(registry.provider_route_kind(provider, workload),
                                 'native' if served else 'gated', (provider, workload))
        self.assertEqual(registry.provider_driver('aws').ssh_user, 'ec2-user')
        self.assertEqual(registry.provider_driver('linode').ssh_user, 'root')
        self.assertEqual(registry.provider_driver('flokinet').ssh_user, 'root')
        self.assertEqual(registry.provider_driver('local').ssh_user, 'root')
        self.assertTrue(registry.provider_driver('local').private_addresses)
        self.assertTrue(registry.provider_driver('aws').supports_edge)
        self.assertFalse(registry.provider_driver('linode').supports_edge)
        self.assertFalse(registry.provider_driver('flokinet').supports_edge)
        self.assertEqual(registry.provider_driver('aws').regions({'aws_regions': ['us-east-1', 'eu-west-1']}),
                         ['us-east-1', 'eu-west-1'])


class SharedValidationTests(DriverCase):
    def test_rules_and_identity_are_validated_the_same_on_every_driver(self):
        driver = linode_cloud.LinodeDriver()
        config = self.config('linode', linode_region='us-east')
        plain = [{'name': 'http', 'protocol': 'Tcp', 'port': 80, 'source': '*'}]
        plan = driver.plan(config, self.request('lt-unit', plain, edge=None))
        self.assertEqual(driver.validate_config(plan)['linode_inbound_rules'],
                         [{'name': 'http', 'protocol': 'Tcp', 'port': '80', 'source': '*'}])
        with self.assertRaisesRegex(ValueError, 'edge'):
            driver.plan(config, self.request('lt-unit'))
        for bad in ([{'name': 'ssh', 'protocol': 'Tcp', 'port': 22, 'source': '*'}],
                    [{'name': 'doc', 'protocol': 'Tcp', 'port': 80, 'source': '192.0.2.1'}],
                    [{'name': 'r' + str(i), 'protocol': 'Tcp', 'port': 1000 + i, 'source': '*'}
                     for i in range(17)]):
            with self.subTest(bad=bad[0]['name']), self.assertRaises(ValueError):
                driver.validate_config(driver.plan(config, self.request('lt-unit', bad, edge=None)))
        with self.assertRaisesRegex(ValueError, 'operator_ip'):
            driver.validate_config(driver.plan(dict(config, operator_ip='10.0.0.1'),
                                               self.request('lt-unit', plain, edge=None)))
        with self.assertRaisesRegex(ValueError, 'linode_region'):
            driver.validate_config(driver.plan(dict(config, linode_region='Bad Region'),
                                               self.request('lt-unit', plain, edge=None)))

    def test_lab_members_admit_ssh_from_the_gateway_and_connect_through_it(self):
        driver = linode_cloud.LinodeDriver()
        config = self.config('linode', linode_region='us-east')
        proxy = {'user': 'root', 'host': '9.9.9.9', 'key': str(self.private),
                 'known_hosts': str(self.state_dir / 'gateway-known-hosts')}
        placement = {'name': 'lab', 'role': 'member', 'lab_ip': '198.18.0.10', 'public_ip': False,
                     'ssh_source': '9.9.9.9/32', 'ssh_proxy': proxy, 'cidrs': ['198.18.0.0/16']}
        request = ProvisionRequest('lt-lab-unit', 'exfil_receiver', [], 'debian12', 64,
                                   str(self.public), str(self.private), False, lab=placement)
        plan = driver.validate_config(driver.plan(config, request))
        self.assertEqual(plan['operator_ip'], '9.9.9.9/32')
        self.assertEqual(plan['linode_image_role'], 'debian12')
        self.assertEqual(plan['linode_lab']['lab_ip'], '198.18.0.10')
        argv = driver.ssh_argv(plan, '198.18.16.5', self.state_dir / 'kh')
        hop = [part for part in argv if part.startswith('ProxyCommand=')][0]
        self.assertIn('-W %h:%p root@9.9.9.9', hop)
        self.assertIn('-i ' + str(self.private), hop)
        self.assertEqual(argv[-1], 'root@198.18.16.5')
        self.assertNotIn('ProxyCommand', ' '.join(driver.ssh_argv(
            dict(plan, ssh_proxy=None), '8.8.4.4', self.state_dir / 'kh')))
        with self.assertRaisesRegex(ValueError, 'lab placement'):
            driver.validate_config(dict(plan, linode_lab={'role': 'member'}))
        with self.assertRaisesRegex(ValueError, 'ssh_proxy'):
            driver.validate_config(dict(plan, ssh_proxy={'host': '9.9.9.9'}))


class AwsDriverTests(DriverCase):
    def setUp(self):
        super().setUp()
        self.ec2 = FakeEc2()
        self.cloudfront = FakeCloudFront()
        self.driver = aws_cloud.AwsDriver()
        self.driver.client = lambda service, region='us-east-1': {'ec2': self.ec2, 'cloudfront': self.cloudfront}[service]
        self.driver.resolve_image = lambda role, region: {'id': 'ami-' + role, 'root_device': '/dev/sda1'}

    def test_lifecycle_creates_tagged_resources_and_retires_them(self):
        config = self.config('aws', aws_region='us-east-1', aws_instance_type='t3.small')
        plan = self.driver.plan(config, self.request('lt-aws-unit'))
        self.assertEqual([rule['source'] for rule in self.driver.validate_config(plan)['aws_inbound_rules']],
                         ['cloudfront', 'cloudfront', '*', '9.9.9.9/32'])
        self.assertEqual(self.driver.planned_ids(plan)['edge'], 'c2itall-lt-aws-unit')
        self.driver.prepare_state(plan)
        self.assertEqual(self.driver.prepare_ssh_key(plan), str(self.private))
        self.assertTrue(self.driver.deploy(plan))
        state = self.driver.store.load('lt-aws-unit', self.state_dir)
        self.assertEqual(state['status'], 'ready')
        resources = state['resources']
        self.assertEqual(set(resources), {'vpc', 'internet_gateway', 'subnet', 'security_group', 'image',
                                          'instance', 'edge', 'edge_arn', 'edge_hostname', 'edge_secret'})
        self.assertEqual(self.driver.public_address('lt-aws-unit', config), '8.8.8.20')
        group = self.ec2.groups[resources['security_group']]
        self.assertEqual(group['IpPermissions'][0], {
            'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': OPERATOR + '/32'}]})
        self.assertEqual(group['IpPermissions'][1]['IpRanges'], [{'CidrIp': '0.0.0.0/0'}])
        self.assertEqual((group['IpPermissions'][2]['IpProtocol'], group['IpPermissions'][2]['FromPort']),
                         ('udp', 5044))
        # Both edge ports share one prefix-list reference: it counts as 55 of the 60-rule quota.
        self.assertEqual(group['IpPermissions'][3], {
            'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 443,
            'PrefixListIds': [{'PrefixListId': 'pl-cloudfront'}]})
        launch = self.ec2.instances[resources['instance']]['Launch']
        self.assertIn('name: ec2-user', launch['UserData'])
        self.assertIn('ssh_pwauth: false', launch['UserData'])
        self.assertIn(self.public.read_text().strip(), launch['UserData'])
        self.assertEqual(launch['ImageId'], 'ami-ubuntu')
        self.assertEqual(launch['BlockDeviceMappings'][0]['Ebs']['VolumeSize'], 32)
        self.assertEqual(launch['MetadataOptions']['HttpTokens'], 'required')
        self.assertEqual({tag['Key'] for tag in launch['TagSpecifications'][0]['Tags']},
                         {'Name', 'c2itall-deployment', 'c2itall-owner'})
        self.assertEqual(self.ec2.routes, [{'DestinationCidrBlock': '0.0.0.0/0',
                                            'GatewayId': resources['internet_gateway']}])
        distribution = self.cloudfront.distributions[resources['edge']]['config']
        origin = distribution['Origins']['Items'][0]
        self.assertEqual(origin['DomainName'], 'ec2-8-8-8-20.compute-1.amazonaws.com')
        self.assertEqual(origin['CustomOriginConfig']['OriginProtocolPolicy'], 'http-only')
        self.assertEqual(origin['CustomHeaders']['Items'][0],
                         {'HeaderName': 'X-Origin-Verify', 'HeaderValue': resources['edge_secret']})
        self.assertEqual(self.driver.edge_endpoint('lt-aws-unit', config), {
            'edge_id': resources['edge_secret'], 'edge_hostname': 'e1.cloudfront.test',
            'edge_header': 'X-Origin-Verify'})
        self.assertTrue(self.driver.health({'deployment_id': 'lt-aws-unit', 'aws_state_dir': str(self.state_dir)})['healthy'])

        # A repeated deployment resumes the same resources instead of adding more.
        self.assertTrue(self.driver.deploy(plan))
        self.assertEqual(self.driver.store.load('lt-aws-unit', self.state_dir)['resources'], resources)
        self.assertEqual((len(self.ec2.vpcs), len(self.ec2.instances), len(self.cloudfront.distributions)), (1, 1, 1))

        # A recorded ID that no longer carries the ownership tags is never deleted.
        instance = self.ec2.instances[resources['instance']]
        original = instance['Tags']
        instance['Tags'] = [{'Key': 'c2itall-owner', 'Value': 'someone-else'}]
        self.assertFalse(self.driver.cleanup({'deployment_id': 'lt-aws-unit', 'aws_state_dir': str(self.state_dir)}))
        self.assertEqual(self.driver.store.load('lt-aws-unit', self.state_dir)['status'], 'cleanup_failed')
        self.assertIn(resources['instance'], self.ec2.instances)
        instance['Tags'] = original

        self.cloudfront.calls.clear()
        self.assertTrue(self.driver.cleanup({'deployment_id': 'lt-aws-unit', 'aws_state_dir': str(self.state_dir)}))
        self.assertEqual([call[:2] for call in self.cloudfront.calls],
                         [('update', 'E1'), ('wait', 'distribution_deployed'), ('delete', 'E1')])
        self.assertFalse(self.cloudfront.calls[0][2], 'the distribution is disabled before deletion')
        self.assertEqual((self.ec2.vpcs, self.ec2.gateways, self.ec2.subnets, self.ec2.groups), ({}, {}, {}, {}))
        self.assertEqual(self.ec2.instances[resources['instance']]['State']['Name'], 'terminated')
        self.assertFalse((self.state_dir / 'lt-aws-unit.json').exists())
        self.assertEqual(json.loads((self.state_dir / 'archive' / 'lt-aws-unit.json').read_text())['status'], 'deleted')
        self.assertTrue(self.private.exists(), 'a module-owned key is never deleted by the driver')


class LinodeDriverTests(DriverCase):
    def setUp(self):
        super().setUp()
        self.api = FakeLinodeApi()
        self.driver = linode_cloud.LinodeDriver()
        self.driver.request = self.api
        self.commands = []
        self.driver.run_command = lambda argv, **kw: self.commands.append(argv)

    def test_lifecycle_creates_firewall_then_linode_and_retires_both(self):
        config = self.config('linode', linode_region='us-east', linode_instance_type='g6-nanode-1')
        rules = [{'name': 'https', 'protocol': 'Tcp', 'port': 443, 'source': '*'},
                 {'name': 'beats', 'protocol': 'Tcp', 'port': 5044, 'source': '9.9.9.9'}]
        # A component ID pushes the prefixed label past Linode's 32-character firewall limit.
        request = ProvisionRequest('lt-linode-unit-phishing-mta', 'logging_server', rules, 'kali', 64,
                                   str(self.public), str(self.private), False)
        plan = self.driver.plan(config, request)
        self.driver.prepare_state(plan)
        self.assertTrue(self.driver.deploy(plan))
        state = self.driver.store.load('lt-linode-unit-phishing-mta', self.state_dir)
        self.assertEqual(state['status'], 'ready')
        self.assertEqual(self.api.calls[:4], [('GET', '/linode/instances'), ('GET', '/networking/firewalls'),
                                              ('POST', '/networking/firewalls'), ('GET', '/linode/types')])
        firewall = self.api.firewalls[state['resources']['firewall']]
        self.assertEqual(firewall['label'], 'lt-linode-unit-phishing-mta')
        self.assertLessEqual(len(firewall['label']), 32)
        self.assertEqual(firewall['rules']['inbound_policy'], 'DROP')
        self.assertEqual([(rule['protocol'], rule['ports'], rule['addresses']) for rule in firewall['rules']['inbound']], [
            ('TCP', '22', {'ipv4': [OPERATOR + '/32']}),
            ('TCP', '443', {'ipv4': ['0.0.0.0/0'], 'ipv6': ['::/0']}),
            ('TCP', '5044', {'ipv4': ['9.9.9.9/32']})])
        linode = self.api.linodes[state['resources']['linode']]
        # A nanode cannot hold a 64 GB workload disk; the cheapest fitting standard plan is used.
        self.assertEqual(linode['type'], 'g6-standard-2')
        self.assertEqual(linode['image'], 'linode/kali')
        self.assertEqual(linode['firewall_id'], firewall['id'])
        self.assertEqual(linode['authorized_keys'], [self.public.read_text().strip()])
        self.assertEqual(set(linode['tags']), set(firewall['tags']))
        self.assertTrue(all(len(tag) <= 50 for tag in linode['tags']))
        self.assertEqual(self.driver.public_address('lt-linode-unit-phishing-mta', config), '8.8.8.30')
        # The image enables password login; the driver turns it off once the key works.
        self.assertEqual(self.commands[0][-2], 'root@8.8.8.30')
        self.assertIn('PasswordAuthentication no', self.commands[0][-1])
        self.assertTrue(self.driver.deploy(plan))
        self.assertEqual((len(self.api.linodes), len(self.api.firewalls)), (1, 1))
        self.assertTrue(self.driver.health({'deployment_id': 'lt-linode-unit-phishing-mta',
                                            'linode_state_dir': str(self.state_dir)})['healthy'])
        self.assertTrue(self.driver.cleanup({'deployment_id': 'lt-linode-unit-phishing-mta',
                                             'linode_state_dir': str(self.state_dir)}))
        self.assertEqual((self.api.linodes, self.api.firewalls), ({}, {}))
        self.assertFalse((self.state_dir / 'lt-linode-unit.json').exists())


class FlokinetDriverTests(DriverCase):
    def setUp(self):
        super().setUp()
        self.driver = flokinet_cloud.FlokinetDriver()
        self.scripts = []
        self.driver._run_stdin = lambda argv, script, deadline: self.scripts.append((argv, script))

    def test_adopts_a_host_by_key_and_firewall_then_revokes_the_key(self):
        config = self.config('flokinet', flokinet_host='8.8.4.4', flokinet_bootstrap_key='~/.ssh/id_ed25519')
        rules = [{'name': 'https', 'protocol': 'Tcp', 'port': 443, 'source': '*'},
                 {'name': 'tailscale', 'protocol': 'Udp', 'port': 41641, 'source': '*'}]
        request = ProvisionRequest('lt-floki-unit', 'share', rules, 'ubuntu', 64,
                                   str(self.public), str(self.private), False)
        plan = self.driver.plan(config, request)
        self.assertEqual(plan['flokinet_host'], '8.8.4.4')
        with self.assertRaisesRegex(ValueError, 'edge'):
            self.driver.plan(config, self.request('lt-floki-unit'))
        self.driver.prepare_state(plan)
        self.assertTrue(self.driver.deploy(plan))
        argv, script = self.scripts[0]
        self.assertEqual(argv[-3:], ['root@8.8.4.4', 'bash', '-s'])
        self.assertIn('-i', argv)
        self.assertIn(self.public.read_text().strip(), script)
        self.assertIn('>> /root/.ssh/authorized_keys', script)
        self.assertIn('ufw allow from 8.8.8.8/32 to any port 22 proto tcp', script)
        self.assertIn('ufw allow to any port 443 proto tcp', script)
        self.assertIn('ufw allow to any port 41641 proto udp', script)
        self.assertIn('ufw --force enable', script)
        self.assertIn('PasswordAuthentication no', script)
        self.assertEqual(self.driver.public_address('lt-floki-unit', config), '8.8.4.4')
        self.assertTrue(self.driver.cleanup({'deployment_id': 'lt-floki-unit',
                                             'flokinet_state_dir': str(self.state_dir)}))
        argv, script = self.scripts[1]
        self.assertIn(str(self.private), argv)
        self.assertIn('grep -vxF', script)
        self.assertNotIn('ufw', script)
        self.assertFalse((self.state_dir / 'lt-floki-unit.json').exists())


class LocalDriverTests(DriverCase):
    def test_adopts_private_hosts_that_flokinet_refuses(self):
        driver = local_cloud.LocalDriver()
        driver._run_stdin = lambda argv, script, deadline: None
        config = self.config('local', local_host='192.168.56.20', operator_ip='192.168.56.1')
        request = ProvisionRequest('lt-local-unit', 'exfil_receiver', [], 'debian12', 64,
                                   str(self.public), str(self.private), False)
        plan = driver.validate_config(driver.plan(config, request))
        self.assertEqual((plan['local_host'], plan['operator_ip']), ('192.168.56.20', '192.168.56.1/32'))
        driver.prepare_state(plan)
        self.assertTrue(driver.deploy(plan))
        self.assertEqual(driver.public_address('lt-local-unit', config), '192.168.56.20')
        self.assertIn('nested_virtualization', driver.capabilities)
        with self.assertRaisesRegex(ValueError, 'flokinet_host'):
            flokinet_cloud.FlokinetDriver().validate_config(flokinet_cloud.FlokinetDriver().plan(
                self.config('flokinet', flokinet_host='192.168.56.20'), request))

    def test_profiles_that_require_a_capability_are_gated_per_driver(self):
        baseline = registry.validate_provider_registry(load_references=True)['counts']['gated']
        lacking = [provider for provider in registry.PROVIDER_SPECS
                   if 'nested_virtualization' not in registry.provider_driver(provider).capabilities]
        self.assertIn('linode', lacking)
        with mock.patch.object(load_profile('tracker'), 'requires', frozenset({'nested_virtualization'})):
            self.assertEqual(registry.provider_route_kind('linode', 'tracker'), 'gated')
            self.assertEqual(registry.provider_route_kind('local', 'tracker'), 'native')
            self.assertNotIn('linode', registry.providers_for('tracker'))
            self.assertIsNone(registry.provider_dispatcher('linode').route('tracker'))
            self.assertEqual(registry.validate_provider_registry(load_references=True)['counts']['gated'],
                             baseline + len(lacking))
        self.assertEqual(registry.provider_route_kind('linode', 'tracker'), 'native')


if __name__ == '__main__':
    unittest.main()
