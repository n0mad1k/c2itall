"""AWS cloud driver: one VPC, one instance and optionally one CloudFront edge per deployment.

Every resource carries the deployment and ownership tags; discovery, resume
and cleanup go through those tags, never through names alone. The instance
gets a uniform login user through cloud-init so Kali and Ubuntu images
behave the same; no EC2 key pair is ever registered.
"""

import re
import secrets
import time
from pathlib import Path

from . import aws_utils
from .driver_base import STATE_ROOT, StatefulDriver, ownership_tags, wait_until

EDGE_SOURCE = 'cloudfront'
EDGE_HEADER = 'X-Origin-Verify'
PREFIX_LIST = 'com.amazonaws.global.cloudfront.origin-facing'
# AWS managed policies: no caching, forward every viewer header, cookie and query.
CACHING_DISABLED = '4135ea2d-6df8-44a3-9df3-4b5a84be39ad'
ALL_VIEWER_EXCEPT_HOST = 'b689b0a8-53d0-40ab-baf2-68738e2966ac'
ORIGIN_POLICY = {'HttpsOnly': 'https-only', 'HttpOnly': 'http-only', 'MatchRequest': 'match-viewer'}
UBUNTU_PARAMETERS = {
    'ubuntu': '/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id',
    'ubuntu2204': '/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id',
}
KALI_PRODUCT_CODE = '7lgvy7mt78lgoi4lant0znp5h'
ATTACK_BOX_SIZES = {'small': 't3.small', 'medium': 't3.medium', 'large': 't3.large', 'xlarge': 't3.xlarge'}
LIVE_STATES = ['pending', 'running', 'stopping', 'stopped', 'shutting-down']
REGION = re.compile(r'[a-z]{2}(-[a-z]+)+-\d')
INSTANCE_TYPE = re.compile(r'[a-z0-9-]+\.[a-z0-9]+')


def cloud_config(user, public_key):
    return ('#cloud-config\n'
            'users:\n'
            '  - name: ' + user + '\n'
            '    sudo: ALL=(ALL) NOPASSWD:ALL\n'
            '    shell: /bin/bash\n'
            '    lock_passwd: true\n'
            '    ssh_authorized_keys:\n'
            '      - ' + public_key + '\n'
            'ssh_pwauth: false\n')


class AwsDriver(StatefulDriver):
    provider = 'aws'
    ssh_user = 'ec2-user'
    prefix = 'aws_'
    identity_keys = ('aws_region',)
    option_keys = ('aws_state_dir', 'aws_cleanup_deadline')
    provider_keys = ('region', 'instance_type')
    state_root = STATE_ROOT / 'aws'
    edge_source = EDGE_SOURCE
    supports_edge = True
    # Every node owns a VPC; the default VPC quota is five per region.
    node_quota = 4

    def __init__(self):
        super().__init__()
        self._session = None

    # --- configuration -----------------------------------------------------
    def gather_config(self):
        regions = [region.strip() for region in input(
            'AWS region(s), comma-separated; pools spread across them [us-east-1]: ').split(',')
            if region.strip()] or ['us-east-1']
        return {
            'aws_region': regions[0], 'aws_regions': regions,
            'aws_instance_type': input('AWS instance type [t3.medium]: ').strip() or 't3.medium',
            'operator_ip': input('Operator public IPv4 (SSH /32): ').strip(),
        }

    def validate_provider(self, result):
        if not REGION.fullmatch(str(result.get('aws_region', ''))):
            raise ValueError('Invalid aws_region')
        result.setdefault('aws_instance_type', 't3.medium')
        if not INSTANCE_TYPE.fullmatch(str(result['aws_instance_type'])):
            raise ValueError('Invalid aws_instance_type')

    region_key = 'aws_region'

    def region(self, config):
        return config.get('aws_region', 'us-east-1')

    def regions(self, config):
        return list(config.get('aws_regions') or [self.region(config)])

    def apply_profile(self, config, workload, profile, value):
        if workload != 'attack_box' or profile != 'instance_size':
            return config
        if value not in ATTACK_BOX_SIZES:
            raise ValueError('Unsupported AWS attack-box instance size')
        config['aws_instance_type'] = ATTACK_BOX_SIZES[value]
        return config

    def plan(self, config, request):
        result = self.base_plan(config, request)
        result.update(aws_region=self.region(config),
                      aws_instance_type=config.get('aws_instance_type', 't3.medium'))
        return result

    def planned_ids(self, state):
        name = 'c2itall-' + state['deployment_id']
        kinds = ['vpc', 'internet_gateway', 'subnet', 'security_group', 'instance']
        if state.get('aws_edge'):
            kinds.append('edge')
        return {kind: name for kind in kinds}

    def lock_target(self, state):
        return state['aws_region'] + '/c2itall-' + state['deployment_id']

    def cleanup_timeout(self, state):
        # Disabling then deleting a CloudFront distribution takes minutes.
        return 1800 if state.get('aws_edge') else 900

    # --- clients -----------------------------------------------------------
    def session(self):
        if self._session is None:
            import boto3
            credentials = aws_utils.load_aws_credentials()
            if not (credentials['aws_access_key'] and credentials['aws_secret_key']):
                raise RuntimeError('AWS credentials are unavailable: set Infisical aws/AWS_ACCESS_KEY '
                                   'and AWS_SECRET_KEY or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY')
            self._session = boto3.session.Session(
                aws_access_key_id=credentials['aws_access_key'],
                aws_secret_access_key=credentials['aws_secret_key'])
        return self._session

    def client(self, service, region='us-east-1'):
        return self.session().client(service, region_name=region)

    def check_connection(self):
        identity = self.client('sts').get_caller_identity()
        vpcs = self.client('ec2').describe_vpcs()['Vpcs']
        return {'account': identity['Account'], 'vpcs': len(vpcs)}

    # --- images ------------------------------------------------------------
    def image(self, role):
        return UBUNTU_PARAMETERS.get(role, 'marketplace:' + KALI_PRODUCT_CODE)

    def resolve_image(self, role, region):
        """Return {'id', 'root_device'} for the newest image of a role in a region."""
        ec2 = self.client('ec2', region)
        if role == 'kali':
            images = ec2.describe_images(Owners=['aws-marketplace'], Filters=[
                {'Name': 'product-code', 'Values': [KALI_PRODUCT_CODE]},
                {'Name': 'architecture', 'Values': ['x86_64']},
                {'Name': 'state', 'Values': ['available']}])['Images']
            if not images:
                raise RuntimeError('No Kali marketplace image is available in ' + region)
            image = max(images, key=lambda item: item['CreationDate'])
        else:
            image_id = self.client('ssm', region).get_parameter(
                Name=UBUNTU_PARAMETERS[role])['Parameter']['Value']
            image = ec2.describe_images(ImageIds=[image_id])['Images'][0]
        return {'id': image['ImageId'], 'root_device': image['RootDeviceName']}

    # --- resources ---------------------------------------------------------
    @staticmethod
    def _filters(state):
        return [{'Name': 'tag:' + key, 'Values': [value]} for key, value in ownership_tags(state).items()]

    @staticmethod
    def _tag_specifications(state, *types):
        tags = [{'Key': 'Name', 'Value': 'c2itall-' + state['deployment_id']}]
        tags += [{'Key': key, 'Value': value} for key, value in ownership_tags(state).items()]
        return [{'ResourceType': kind, 'Tags': tags} for kind in types]

    def owned(self, ec2, state):
        """Every live resource carrying this deployment's ownership tags."""
        filters = self._filters(state)
        instances = [instance['InstanceId']
                     for reservation in ec2.describe_instances(
                         Filters=filters + [{'Name': 'instance-state-name', 'Values': LIVE_STATES}])['Reservations']
                     for instance in reservation['Instances']]
        return {
            'vpc': [item['VpcId'] for item in ec2.describe_vpcs(Filters=filters)['Vpcs']],
            'internet_gateway': [item['InternetGatewayId']
                                 for item in ec2.describe_internet_gateways(Filters=filters)['InternetGateways']],
            'subnet': [item['SubnetId'] for item in ec2.describe_subnets(Filters=filters)['Subnets']],
            'security_group': [item['GroupId']
                               for item in ec2.describe_security_groups(Filters=filters)['SecurityGroups']],
            'instance': instances,
        }

    def _prefix_list(self, ec2):
        lists = ec2.describe_managed_prefix_lists(
            Filters=[{'Name': 'prefix-list-name', 'Values': [PREFIX_LIST]}])['PrefixLists']
        if not lists:
            raise RuntimeError('The CloudFront origin-facing prefix list is unavailable in this region')
        return lists[0]['PrefixListId']

    def _permissions(self, ec2, state):
        permissions = [{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
                        'IpRanges': [{'CidrIp': state['operator_ip']}]}]
        edge = sorted(int(rule['port']) for rule in state['aws_inbound_rules'] if rule['source'] == EDGE_SOURCE)
        for rule in state['aws_inbound_rules']:
            if rule['source'] == EDGE_SOURCE:
                continue
            permissions.append({'IpProtocol': rule['protocol'].lower(),
                                'FromPort': int(rule['port']), 'ToPort': int(rule['port']),
                                'IpRanges': [{'CidrIp': '0.0.0.0/0' if rule['source'] == '*' else rule['source']}]})
        if edge:
            # The CloudFront prefix list counts as 55 of the 60 rules a group may
            # hold, so every edge port shares one reference as a port range.
            permissions.append({'IpProtocol': 'tcp', 'FromPort': edge[0], 'ToPort': edge[-1],
                                'PrefixListIds': [{'PrefixListId': self._prefix_list(ec2)}]})
        return permissions

    def create(self, state, deadline):
        region = state['aws_region']
        ec2 = self.client('ec2', region)
        resources = state.setdefault('resources', {})
        owned = self.owned(ec2, state)
        for kind, ids in owned.items():
            if len(ids) > 1:
                raise RuntimeError('More than one owned {0} exists for this deployment'.format(kind))
            if ids and resources.get(kind) not in (None, ids[0]):
                raise RuntimeError('Recorded {0} differs from the owned one'.format(kind))
            if ids:
                resources[kind] = ids[0]
        name = 'c2itall-' + state['deployment_id']

        if 'vpc' not in resources:
            resources['vpc'] = ec2.create_vpc(
                CidrBlock='10.0.0.0/16',
                TagSpecifications=self._tag_specifications(state, 'vpc'))['Vpc']['VpcId']
            self.save(state)
        vpc = resources['vpc']
        ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={'Value': True})
        ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={'Value': True})

        if 'internet_gateway' not in resources:
            resources['internet_gateway'] = ec2.create_internet_gateway(
                TagSpecifications=self._tag_specifications(state, 'internet-gateway'))['InternetGateway']['InternetGatewayId']
            self.save(state)
        gateway = ec2.describe_internet_gateways(
            InternetGatewayIds=[resources['internet_gateway']])['InternetGateways'][0]
        if not any(item.get('VpcId') == vpc for item in gateway.get('Attachments', [])):
            ec2.attach_internet_gateway(InternetGatewayId=resources['internet_gateway'], VpcId=vpc)

        if 'subnet' not in resources:
            # Not every zone offers every instance type (us-east-1e has no t3); pick one that does.
            zones = sorted(item['Location'] for item in ec2.describe_instance_type_offerings(
                LocationType='availability-zone',
                Filters=[{'Name': 'instance-type', 'Values': [state['aws_instance_type']]}])['InstanceTypeOfferings'])
            if not zones:
                raise RuntimeError(state['aws_instance_type'] + ' is not offered in ' + state['aws_region'])
            resources['subnet'] = ec2.create_subnet(
                VpcId=vpc, CidrBlock='10.0.1.0/24', AvailabilityZone=zones[0],
                TagSpecifications=self._tag_specifications(state, 'subnet'))['Subnet']['SubnetId']
            self.save(state)
        ec2.modify_subnet_attribute(SubnetId=resources['subnet'], MapPublicIpOnLaunch={'Value': True})
        table = ec2.describe_route_tables(Filters=[
            {'Name': 'vpc-id', 'Values': [vpc]},
            {'Name': 'association.main', 'Values': ['true']}])['RouteTables'][0]
        if not any(route.get('DestinationCidrBlock') == '0.0.0.0/0' for route in table['Routes']):
            ec2.create_route(RouteTableId=table['RouteTableId'], DestinationCidrBlock='0.0.0.0/0',
                             GatewayId=resources['internet_gateway'])

        if 'security_group' not in resources:
            resources['security_group'] = ec2.create_security_group(
                GroupName=name, Description=name, VpcId=vpc,
                TagSpecifications=self._tag_specifications(state, 'security-group'))['GroupId']
            self.save(state)
        group = ec2.describe_security_groups(GroupIds=[resources['security_group']])['SecurityGroups'][0]
        wanted = self._permissions(ec2, state)
        if not group['IpPermissions']:
            ec2.authorize_security_group_ingress(GroupId=resources['security_group'], IpPermissions=wanted)

        if 'instance' not in resources:
            image = self.resolve_image(state['aws_image_role'], region)
            resources['image'] = image['id']
            instance = ec2.run_instances(
                ImageId=image['id'], InstanceType=state['aws_instance_type'], MinCount=1, MaxCount=1,
                SubnetId=resources['subnet'], SecurityGroupIds=[resources['security_group']],
                UserData=cloud_config(self.ssh_user, Path(state['ssh_key_path']).read_text().strip()),
                BlockDeviceMappings=[{'DeviceName': image['root_device'],
                                      'Ebs': {'VolumeSize': state['aws_disk_gb'], 'VolumeType': 'gp3',
                                              'DeleteOnTermination': True, 'Encrypted': True}}],
                MetadataOptions={'HttpTokens': 'required', 'HttpEndpoint': 'enabled'},
                TagSpecifications=self._tag_specifications(state, 'instance', 'volume'))
            resources['instance'] = instance['Instances'][0]['InstanceId']
            self.save(state)
        self._wait(ec2, 'instance_running', deadline, InstanceIds=[resources['instance']])
        instance = ec2.describe_instances(InstanceIds=[resources['instance']])['Reservations'][0]['Instances'][0]
        outputs = {'public_ip': instance.get('PublicIpAddress', ''),
                   'public_dns': instance.get('PublicDnsName', '')}
        if state.get('aws_edge'):
            outputs.update(self._create_edge(state, outputs['public_dns'], deadline))
        return outputs

    def _wait(self, client, waiter, deadline, delay=15, **kwargs):
        attempts = max(1, int((deadline - time.monotonic()) / delay))
        client.get_waiter(waiter).wait(WaiterConfig={'Delay': delay, 'MaxAttempts': attempts}, **kwargs)

    # --- edge --------------------------------------------------------------
    def _create_edge(self, state, origin, deadline):
        if not origin:
            raise RuntimeError('The instance has no public DNS name for the edge origin')
        cloudfront = self.client('cloudfront')
        resources = state['resources']
        if 'edge' not in resources:
            resources['edge_secret'] = secrets.token_hex(16)
            config = {
                'CallerReference': 'c2itall-' + state['deployment_id'] + '-' + state['ownership_marker'],
                'Comment': '', 'Enabled': True,
                'Origins': {'Quantity': 1, 'Items': [{
                    'Id': 'origin', 'DomainName': origin,
                    'CustomHeaders': {'Quantity': 1, 'Items': [
                        {'HeaderName': EDGE_HEADER, 'HeaderValue': resources['edge_secret']}]},
                    'CustomOriginConfig': {
                        'HTTPPort': 80, 'HTTPSPort': 443,
                        'OriginProtocolPolicy': ORIGIN_POLICY[state['aws_edge']['forwarding']],
                        'OriginSslProtocols': {'Quantity': 1, 'Items': ['TLSv1.2']},
                        'OriginReadTimeout': 60, 'OriginKeepaliveTimeout': 5}}]},
                'DefaultCacheBehavior': {
                    'TargetOriginId': 'origin', 'ViewerProtocolPolicy': 'allow-all',
                    'AllowedMethods': {'Quantity': 7,
                                       'Items': ['GET', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'POST', 'DELETE'],
                                       'CachedMethods': {'Quantity': 2, 'Items': ['GET', 'HEAD']}},
                    'Compress': False, 'CachePolicyId': CACHING_DISABLED,
                    'OriginRequestPolicyId': ALL_VIEWER_EXCEPT_HOST},
                'HttpVersion': 'http2', 'IsIPV6Enabled': True, 'PriceClass': 'PriceClass_All',
            }
            tags = [{'Key': key, 'Value': value} for key, value in ownership_tags(state).items()]
            created = cloudfront.create_distribution_with_tags(DistributionConfigWithTags={
                'DistributionConfig': config, 'Tags': {'Items': tags}})['Distribution']
            resources.update(edge=created['Id'], edge_arn=created['ARN'], edge_hostname=created['DomainName'])
            self.save(state)
        self._wait(cloudfront, 'distribution_deployed', deadline, delay=30, Id=resources['edge'])
        return {'edge_hostname': resources['edge_hostname']}

    def edge_endpoint(self, deployment_id, config):
        resources = self.store.load(deployment_id, self.state_dir(config))['resources']
        return {'edge_id': resources['edge_secret'], 'edge_hostname': resources['edge_hostname'],
                'edge_header': EDGE_HEADER}

    def _delete_edge(self, state, deadline):
        resources = state['resources']
        cloudfront = self.client('cloudfront')
        try:
            tags = cloudfront.list_tags_for_resource(Resource=resources['edge_arn'])['Tags']['Items']
        except cloudfront.exceptions.NoSuchResource:
            return
        if {item['Key']: item['Value'] for item in tags} != ownership_tags(state):
            raise ValueError('Refusing to delete a foreign CloudFront distribution')
        current = cloudfront.get_distribution_config(Id=resources['edge'])
        if current['DistributionConfig']['Enabled']:
            current['DistributionConfig']['Enabled'] = False
            cloudfront.update_distribution(Id=resources['edge'], IfMatch=current['ETag'],
                                           DistributionConfig=current['DistributionConfig'])
        self._wait(cloudfront, 'distribution_deployed', deadline, delay=30, Id=resources['edge'])
        etag = cloudfront.get_distribution_config(Id=resources['edge'])['ETag']
        cloudfront.delete_distribution(Id=resources['edge'], IfMatch=etag)
        try:
            cloudfront.get_distribution(Id=resources['edge'])
        except cloudfront.exceptions.NoSuchDistribution:
            return
        raise RuntimeError('CloudFront distribution still exists after deletion')

    # --- cleanup -----------------------------------------------------------
    def delete(self, state, deadline):
        ec2 = self.client('ec2', state['aws_region'])
        resources = state.get('resources', {})
        owned = self.owned(ec2, state)
        for kind, ids in owned.items():
            recorded = resources.get(kind)
            if recorded and recorded not in ids and self._exists(ec2, kind, recorded):
                raise ValueError('Refusing to delete a foreign {0}: {1}'.format(kind, recorded))
        if resources.get('edge'):
            self._delete_edge(state, deadline)
        if owned['instance']:
            ec2.terminate_instances(InstanceIds=owned['instance'])
            self._wait(ec2, 'instance_terminated', deadline, InstanceIds=owned['instance'])
        for group in owned['security_group']:
            self._retry(deadline, lambda: ec2.delete_security_group(GroupId=group))
        for subnet in owned['subnet']:
            self._retry(deadline, lambda: ec2.delete_subnet(SubnetId=subnet))
        for gateway in owned['internet_gateway']:
            attachments = ec2.describe_internet_gateways(
                InternetGatewayIds=[gateway])['InternetGateways'][0].get('Attachments', [])
            for attachment in attachments:
                self._retry(deadline, lambda: ec2.detach_internet_gateway(
                    InternetGatewayId=gateway, VpcId=attachment['VpcId']))
            self._retry(deadline, lambda: ec2.delete_internet_gateway(InternetGatewayId=gateway))
        for vpc in owned['vpc']:
            self._retry(deadline, lambda: ec2.delete_vpc(VpcId=vpc))
        remaining = {kind: ids for kind, ids in self.owned(ec2, state).items() if ids}
        if remaining:
            raise RuntimeError('Owned resources remain after deletion: ' + str(remaining))

    def _exists(self, ec2, kind, resource_id):
        describe = {
            'vpc': (ec2.describe_vpcs, 'VpcIds', 'Vpcs'),
            'internet_gateway': (ec2.describe_internet_gateways, 'InternetGatewayIds', 'InternetGateways'),
            'subnet': (ec2.describe_subnets, 'SubnetIds', 'Subnets'),
            'security_group': (ec2.describe_security_groups, 'GroupIds', 'SecurityGroups'),
            'instance': (ec2.describe_instances, 'InstanceIds', 'Reservations'),
        }[kind]
        try:
            items = describe[0](**{describe[1]: [resource_id]})[describe[2]]
        except Exception as exc:  # botocore ClientError for a vanished ID
            if 'NotFound' in str(exc) or 'Malformed' in str(exc):
                return False
            raise
        if kind == 'instance':
            return any(instance['State']['Name'] != 'terminated'
                       for reservation in items for instance in reservation['Instances'])
        return bool(items)

    @staticmethod
    def _retry(deadline, action):
        def attempt():
            try:
                action()
                return True
            except Exception as exc:
                if 'DependencyViolation' in str(exc) or 'InvalidParameterValue' in str(exc):
                    return False
                if 'NotFound' in str(exc):
                    return True
                raise
        wait_until(deadline, attempt, interval=10, what='AWS dependency release')

    # --- health ------------------------------------------------------------
    def inspect(self, state, deadline):
        instance_id = (state.get('resources') or {}).get('instance')
        if not instance_id:
            return {'healthy': False, 'detail': 'No instance was recorded'}
        ec2 = self.client('ec2', state['aws_region'])
        if instance_id not in self.owned(ec2, state)['instance']:
            return {'healthy': False, 'detail': 'Instance is absent'}
        status = ec2.describe_instance_status(InstanceIds=[instance_id], IncludeAllInstances=True)['InstanceStatuses']
        power = status[0]['InstanceState']['Name'] if status else 'unknown'
        checks = status[0]['InstanceStatus']['Status'] if status else 'unknown'
        return {'healthy': power == 'running' and checks in ('ok', 'initializing'),
                'power_state': power, 'status_checks': checks,
                'detail': 'Instance {0}; status checks {1}'.format(power, checks)}


def aws_driver():
    return AwsDriver()


def gather_aws_config():
    return AwsDriver().gather_config()
