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
        self.route_tables, self.addresses, self.nat_gateways, self.flow_logs = {}, {}, {}, {}
        self.routes = []
        self.calls = []
        self.counter = 0
        # Per-instance-type AZ offerings a lab test can seed; unseeded types
        # fall back to the two legacy zones every other test relies on.
        self.instance_type_zones = {}

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
            elif name == 'state':
                if item.get('State') not in values:
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
        instance_type = Filters[0]['Values'][0]
        self.calls.append(('describe_instance_type_offerings', instance_type))
        zones = self.instance_type_zones.get(instance_type, ['us-east-1e', 'us-east-1a'])
        return {'InstanceTypeOfferings': [{'Location': zone} for zone in zones]}

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

    def describe_route_tables(self, Filters=None):
        if any(condition['Name'] == 'association.main' for condition in Filters or []):
            # The one legacy per-VM VPC's main table; never tagged, never in self.route_tables.
            return {'RouteTables': [{'RouteTableId': 'rtb-main', 'Routes': list(self.routes),
                                     'Associations': [{'Main': True}]}]}
        return {'RouteTables': self._select(self.route_tables, Filters)}

    def create_route(self, RouteTableId, DestinationCidrBlock, GatewayId=None, NatGatewayId=None):
        route = {'DestinationCidrBlock': DestinationCidrBlock}
        if GatewayId:
            route['GatewayId'] = GatewayId
        if NatGatewayId:
            route['NatGatewayId'] = NatGatewayId
        if RouteTableId in self.route_tables:
            self.route_tables[RouteTableId]['Routes'].append(route)
        else:
            self.routes.append(route)

    def create_route_table(self, VpcId, TagSpecifications):
        table = {'RouteTableId': self._id('rtb'), 'VpcId': VpcId, 'Routes': [], 'Associations': [],
                 'Tags': self._tags(TagSpecifications, 'route-table')}
        self.route_tables[table['RouteTableId']] = table
        return {'RouteTable': table}

    def associate_route_table(self, RouteTableId, SubnetId):
        association_id = self._id('rtbassoc')
        self.route_tables[RouteTableId]['Associations'].append(
            {'RouteTableAssociationId': association_id, 'SubnetId': SubnetId, 'Main': False})
        return {'AssociationId': association_id}

    def disassociate_route_table(self, AssociationId):
        for table in self.route_tables.values():
            table['Associations'] = [assoc for assoc in table['Associations']
                                     if assoc['RouteTableAssociationId'] != AssociationId]

    def delete_route_table(self, RouteTableId):
        del self.route_tables[RouteTableId]

    # Elastic IPs
    def allocate_address(self, Domain, TagSpecifications):
        allocation_id = self._id('eipalloc')
        address = {'AllocationId': allocation_id, 'PublicIp': '8.8.9.' + str(10 + len(self.addresses)),
                   'Tags': self._tags(TagSpecifications, 'elastic-ip')}
        self.addresses[allocation_id] = address
        return address

    def describe_addresses(self, Filters=None):
        return {'Addresses': self._select(self.addresses, Filters)}

    def release_address(self, AllocationId):
        del self.addresses[AllocationId]

    # NAT gateways
    def create_nat_gateway(self, SubnetId, AllocationId, TagSpecifications):
        nat_id = self._id('nat')
        nat = {'NatGatewayId': nat_id, 'SubnetId': SubnetId, 'State': 'available',
               'NatGatewayAddresses': [{'AllocationId': AllocationId,
                                       'PublicIp': self.addresses[AllocationId]['PublicIp']}],
               'Tags': self._tags(TagSpecifications, 'natgateway')}
        self.nat_gateways[nat_id] = nat
        return {'NatGateway': nat}

    def describe_nat_gateways(self, Filters=None, NatGatewayIds=None):
        return {'NatGateways': self._select(self.nat_gateways, Filters, NatGatewayIds)}

    def delete_nat_gateway(self, NatGatewayId):
        self.nat_gateways[NatGatewayId]['State'] = 'deleted'

    # VPC flow logs
    def create_flow_logs(self, ResourceType, ResourceIds, TrafficType, LogDestinationType,
                         LogDestination, TagSpecifications):
        flow_id = self._id('fl')
        self.flow_logs[flow_id] = {
            'FlowLogId': flow_id, 'ResourceId': ResourceIds[0], 'TrafficType': TrafficType,
            'LogDestinationType': LogDestinationType, 'LogDestination': LogDestination,
            'Tags': self._tags(TagSpecifications, 'vpc-flow-log')}
        return {'FlowLogIds': [flow_id], 'Unsuccessful': []}

    def describe_flow_logs(self, Filters=None):
        return {'FlowLogs': self._select(self.flow_logs, Filters)}

    def delete_flow_logs(self, FlowLogIds):
        for flow_id in FlowLogIds:
            self.flow_logs.pop(flow_id, None)

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
        if 'NetworkInterfaces' in kwargs:
            interface = kwargs['NetworkInterfaces'][0]
            subnet_id = interface['SubnetId']
            public = bool(interface.get('AssociatePublicIpAddress'))
        else:
            subnet_id = kwargs.get('SubnetId')
            public = True
        vpc_id = self.subnets[subnet_id]['VpcId'] if subnet_id in self.subnets else None
        instance = {'InstanceId': self._id('i'), 'State': {'Name': 'running'}, 'VpcId': vpc_id,
                    'SubnetId': subnet_id, 'PrivateIpAddress': '10.0.1.' + str(20 + len(self.instances)),
                    'Tags': self._tags(kwargs['TagSpecifications'], 'instance'), 'Launch': kwargs}
        if public:
            instance.update(PublicIpAddress='8.8.8.20', PublicDnsName='ec2-8-8-8-20.compute-1.amazonaws.com')
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


class FakeS3:
    """The bucket subset the lab network uses: create, lock down, empty, delete."""

    def __init__(self):
        self.buckets = {}

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise Exception('404 Not Found')
        return {}

    def create_bucket(self, Bucket, CreateBucketConfiguration=None):
        self.buckets[Bucket] = {'objects': {}, 'public_access_block': None,
                                'location': (CreateBucketConfiguration or {}).get('LocationConstraint')}

    def put_public_access_block(self, Bucket, PublicAccessBlockConfiguration):
        self.buckets[Bucket]['public_access_block'] = PublicAccessBlockConfiguration

    def put_object(self, Bucket, Key, Body=b''):
        self.buckets[Bucket]['objects'][Key] = Body

    def get_paginator(self, name):
        assert name == 'list_objects_v2'
        buckets = self.buckets

        class Paginator:
            def paginate(self, Bucket):
                yield {'Contents': [{'Key': key} for key in buckets[Bucket]['objects']]}
        return Paginator()

    def delete_objects(self, Bucket, Delete):
        for item in Delete['Objects']:
            self.buckets[Bucket]['objects'].pop(item['Key'], None)

    def delete_bucket(self, Bucket):
        del self.buckets[Bucket]


class FakeSts:
    def get_caller_identity(self):
        return {'Account': '123456789012'}


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
        self.s3 = FakeS3()
        self.sts = FakeSts()
        self.driver = aws_cloud.AwsDriver()
        self.driver.client = lambda service, region='us-east-1': {
            'ec2': self.ec2, 'cloudfront': self.cloudfront, 's3': self.s3, 'sts': self.sts}[service]
        self.driver.resolve_image = lambda role, region: {'id': 'ami-' + role, 'root_device': '/dev/sda1'}

    def _lab_network(self, instance_type='t3.small'):
        """A ready lab network a lab VM test can place its instance into."""
        self.ec2.instance_type_zones = {instance_type: ['us-east-1a', 'us-east-1e'], 'c5.metal': ['us-east-1a']}
        lab = {'name': 'redteam', 'ownership_marker': 'marker-1', 'blocks': {'aws': '198.18.16.0/20'}}
        config = self.config('aws', aws_region='us-east-1', aws_instance_type=instance_type)
        return lab, config, self.driver.lab_network(lab, config)

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

    def test_lab_network_creates_every_tagged_resource_and_is_idempotent(self):
        lab, config, network = self._lab_network()
        self.assertEqual(network['region'], 'us-east-1')
        self.assertEqual(network['availability_zone'], 'us-east-1a')
        vpc = self.ec2.vpcs[network['vpc']]
        self.assertEqual(vpc['CidrBlock'], '198.18.16.0/20')
        self.assertEqual({tag['Key']: tag['Value'] for tag in vpc['Tags']},
                         {'Name': 'c2itall-lab-redteam', 'c2itall-deployment': 'lab-redteam',
                          'c2itall-owner': 'marker-1'})
        self.assertTrue(any(item.get('VpcId') == network['vpc']
                            for item in self.ec2.gateways[network['internet_gateway']]['Attachments']))
        self.assertEqual(self.ec2.subnets[network['public_subnet']]['CidrBlock'], '198.18.16.0/24')
        self.assertEqual(self.ec2.subnets[network['private_subnet']]['CidrBlock'], '198.18.17.0/24')
        public_rt = self.ec2.route_tables[network['public_route_table']]
        self.assertEqual(public_rt['Routes'],
                         [{'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': network['internet_gateway']}])
        self.assertEqual([assoc['SubnetId'] for assoc in public_rt['Associations']], [network['public_subnet']])
        private_rt = self.ec2.route_tables[network['private_route_table']]
        self.assertEqual(private_rt['Routes'],
                         [{'DestinationCidrBlock': '0.0.0.0/0', 'NatGatewayId': network['nat_gateway']}])
        self.assertEqual([assoc['SubnetId'] for assoc in private_rt['Associations']], [network['private_subnet']])
        self.assertEqual(network['nat_ip'], self.ec2.addresses[network['eip_allocation']]['PublicIp'])
        self.assertTrue(any(call[0] == 'wait' and call[1] == 'nat_gateway_available'
                            and call[2]['NatGatewayIds'] == [network['nat_gateway']]
                            for call in self.ec2.calls))
        self.assertEqual(network['bucket'], 'c2itall-lab-redteam-123456789012')
        self.assertIn(network['bucket'], self.s3.buckets)
        self.assertEqual(self.s3.buckets[network['bucket']]['public_access_block'], {
            'BlockPublicAcls': True, 'IgnorePublicAcls': True,
            'BlockPublicPolicy': True, 'RestrictPublicBuckets': True})
        flow_log = self.ec2.flow_logs[network['flow_log']]
        self.assertEqual(flow_log['LogDestination'], 'arn:aws:s3:::' + network['bucket'])
        self.assertEqual((flow_log['TrafficType'], flow_log['LogDestinationType']), ('ALL', 's3'))

        counts_before = (len(self.ec2.vpcs), len(self.ec2.subnets), len(self.ec2.route_tables),
                         len(self.ec2.addresses), len(self.ec2.nat_gateways), len(self.ec2.flow_logs),
                         len(self.s3.buckets))
        again = self.driver.lab_network(lab, config)
        self.assertEqual(again, network)
        self.assertEqual((len(self.ec2.vpcs), len(self.ec2.subnets), len(self.ec2.route_tables),
                          len(self.ec2.addresses), len(self.ec2.nat_gateways), len(self.ec2.flow_logs),
                          len(self.s3.buckets)), counts_before)

    def test_lab_member_launches_in_the_private_subnet_without_a_public_ip(self):
        lab, config, network = self._lab_network()
        placement = {'name': 'redteam', 'role': 'member', 'lab_ip': '198.18.0.10', 'public_ip': False,
                     'cidrs': ['198.18.0.0/16'], 'range_cidrs': [], 'network': network,
                     'ssh_source': '9.9.9.9/32', 'ssh_proxy': None, 'egress_via_hub': True}
        request = ProvisionRequest('lt-aws-lab-member', 'exfil_receiver', [], 'debian12', 64,
                                   str(self.public), str(self.private), False, lab=placement)
        plan = self.driver.validate_config(self.driver.plan(config, request))
        self.assertEqual(plan['operator_ip'], '9.9.9.9/32')
        self.driver.prepare_state(plan)
        self.assertTrue(self.driver.deploy(plan))
        state = self.driver.store.load('lt-aws-lab-member', self.state_dir)
        self.assertEqual(set(state['resources']), {'image', 'security_group', 'instance'})
        instance = self.ec2.instances[state['resources']['instance']]
        self.assertEqual(instance['SubnetId'], network['private_subnet'])
        self.assertFalse(instance['Launch']['NetworkInterfaces'][0]['AssociatePublicIpAddress'])
        self.assertNotIn('PublicIpAddress', instance)
        self.assertEqual(self.driver.public_address('lt-aws-lab-member', config), instance['PrivateIpAddress'])
        group = self.ec2.groups[state['resources']['security_group']]
        self.assertEqual(group['IpPermissions'], [
            {'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '198.18.0.0/16'}]},
            {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '9.9.9.9/32'}]}])
        self.assertEqual(self.driver.planned_ids(plan),
                         {'security_group': 'c2itall-lt-aws-lab-member', 'instance': 'c2itall-lt-aws-lab-member'})
        self.assertNotIn('vpc', self.driver.planned_ids(plan))

    def test_lab_gateway_launches_in_the_public_subnet(self):
        lab, config, network = self._lab_network()
        placement = {'name': 'redteam', 'role': 'gateway', 'lab_ip': '198.18.0.1', 'public_ip': True,
                     'cidrs': ['198.18.0.0/16'], 'range_cidrs': [], 'network': network,
                     'ssh_source': OPERATOR + '/32', 'ssh_proxy': None, 'egress_via_hub': False}
        rules = [{'name': 'wireguard', 'protocol': 'Udp', 'port': 51820, 'source': '*'}]
        request = ProvisionRequest('lt-aws-lab-gateway', 'lab_gateway', rules, 'debian12', 32,
                                   str(self.public), str(self.private), False, lab=placement)
        plan = self.driver.validate_config(self.driver.plan(config, request))
        self.driver.prepare_state(plan)
        self.assertTrue(self.driver.deploy(plan))
        state = self.driver.store.load('lt-aws-lab-gateway', self.state_dir)
        instance = self.ec2.instances[state['resources']['instance']]
        self.assertEqual(instance['SubnetId'], network['public_subnet'])
        self.assertTrue(instance['Launch']['NetworkInterfaces'][0]['AssociatePublicIpAddress'])
        self.assertEqual(self.driver.public_address('lt-aws-lab-gateway', config), instance['PublicIpAddress'])
        group = self.ec2.groups[state['resources']['security_group']]
        self.assertEqual(group['IpPermissions'][-1], {
            'IpProtocol': 'udp', 'FromPort': 51820, 'ToPort': 51820, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]})

    def test_lab_member_delete_leaves_the_lab_vpc_in_place(self):
        lab, config, network = self._lab_network()
        placement = {'name': 'redteam', 'role': 'member', 'lab_ip': '198.18.0.12', 'public_ip': False,
                     'cidrs': ['198.18.0.0/16'], 'range_cidrs': [], 'network': network,
                     'ssh_source': '9.9.9.9/32', 'ssh_proxy': None, 'egress_via_hub': True}
        request = ProvisionRequest('lt-aws-lab-del', 'exfil_receiver', [], 'debian12', 64,
                                   str(self.public), str(self.private), False, lab=placement)
        plan = self.driver.validate_config(self.driver.plan(config, request))
        self.driver.prepare_state(plan)
        self.assertTrue(self.driver.deploy(plan))
        state = self.driver.store.load('lt-aws-lab-del', self.state_dir)
        instance_id = state['resources']['instance']
        group_id = state['resources']['security_group']
        self.assertTrue(self.driver.cleanup({'deployment_id': 'lt-aws-lab-del', 'aws_state_dir': str(self.state_dir)}))
        self.assertEqual(self.ec2.instances[instance_id]['State']['Name'], 'terminated')
        self.assertNotIn(group_id, self.ec2.groups)
        self.assertIn(network['vpc'], self.ec2.vpcs)
        self.assertIn(network['public_subnet'], self.ec2.subnets)
        self.assertIn(network['private_subnet'], self.ec2.subnets)
        self.assertIn(network['nat_gateway'], self.ec2.nat_gateways)

    def test_delete_lab_network_refuses_with_a_live_instance_then_removes_everything(self):
        lab, config, network = self._lab_network()
        placement = {'name': 'redteam', 'role': 'member', 'lab_ip': '198.18.0.13', 'public_ip': False,
                     'cidrs': ['198.18.0.0/16'], 'range_cidrs': [], 'network': network,
                     'ssh_source': '9.9.9.9/32', 'ssh_proxy': None, 'egress_via_hub': True}
        request = ProvisionRequest('lt-aws-lab-net', 'exfil_receiver', [], 'debian12', 64,
                                   str(self.public), str(self.private), False, lab=placement)
        plan = self.driver.validate_config(self.driver.plan(config, request))
        self.driver.prepare_state(plan)
        self.assertTrue(self.driver.deploy(plan))
        with self.assertRaisesRegex(RuntimeError, 'instance'):
            self.driver.delete_lab_network(lab, network)
        self.assertTrue(self.driver.cleanup({'deployment_id': 'lt-aws-lab-net', 'aws_state_dir': str(self.state_dir)}))

        self.assertTrue(self.driver.delete_lab_network(lab, network))
        self.assertEqual((self.ec2.vpcs, self.ec2.gateways, self.ec2.subnets, self.ec2.route_tables,
                          self.ec2.addresses, self.ec2.flow_logs), ({}, {}, {}, {}, {}, {}))
        # A deleted NAT gateway lingers in describe output with State 'deleted', as AWS itself does.
        self.assertTrue(all(nat['State'] == 'deleted' for nat in self.ec2.nat_gateways.values()))
        self.assertNotIn(network['bucket'], self.s3.buckets)
        with self.assertRaises(Exception):
            self.s3.head_bucket(Bucket=network['bucket'])
        # Re-running after everything is already gone stays re-runnable.
        self.assertTrue(self.driver.delete_lab_network(lab, network))


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
