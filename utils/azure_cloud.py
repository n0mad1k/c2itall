"""Azure cloud driver: the only Azure-aware code outside azure_utils."""

import re
from pathlib import Path

from . import azure_utils
from .cloud_driver import CloudDriver

KALI_IMAGE = {'publisher': 'kali-linux', 'offer': 'kali', 'sku': 'kali-2026-2',
              'version': 'latest', 'plan': True}
UBUNTU_2204_IMAGE = {
    'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy',
    'sku': '22_04-lts-gen2', 'version': 'latest', 'plan': False,
}
DEBIAN_12_IMAGE = {'publisher': 'Debian', 'offer': 'debian-12', 'sku': '12-gen2',
                   'version': 'latest', 'plan': False}


class AzureDriver(CloudDriver):
    capabilities = frozenset({'lab_network', 'nested_virtualization'})
    provider = 'azure'
    ssh_user = 'azureuser'
    prefix = 'azure_'
    identity_keys = ('azure_subscription_id', 'azure_resource_group')
    option_keys = ('azure_state_dir', 'azure_cleanup_deadline')
    supports_edge = True

    def gather_config(self):
        return azure_utils.gather_azure_config()

    def validate_config(self, config, require_key=True):
        return azure_utils.validate_config(config, require_key=require_key)

    def image(self, role):
        if role == 'kali':
            return KALI_IMAGE
        if role == 'ubuntu2204':
            return UBUNTU_2204_IMAGE
        if role == 'debian12':
            return DEBIAN_12_IMAGE
        return None

    def apply_profile(self, config, workload, profile, value):
        if (workload, profile, value) == ('ludus_host', 'instance_size', 'nested'):
            config['azure_vm_size'] = 'Standard_D8s_v5'
        return config

    region_key = 'azure_location'

    def region(self, config):
        return config.get('azure_location', 'eastus')

    def plan(self, config, request):
        default_group = 'c2itall-' + request.deployment_id
        # A derived ID (component or node) always owns its own group.
        group = (config.get('azure_resource_group', default_group)
                 if request.deployment_id == config['deployment_id'] else default_group)
        result = {
            'provider': 'azure', 'provider_workload': request.workload,
            'deployment_id': request.deployment_id,
            'deployment_type': 'infrastructure',
            'infrastructure_deployment': True,
            'azure_subscription_id': config['azure_subscription_id'],
            'azure_location': config.get('azure_location', 'eastus'),
            'azure_vm_size': config.get('azure_vm_size', 'Standard_D2as_v4'),
            'azure_os_disk_gb': config.get('azure_os_disk_gb', request.disk_gb),
            'azure_resource_group': group,
            'azure_inbound_rules': [
                dict(rule, source=azure_utils.EDGE_SOURCE) if rule['source'] == 'edge'
                else dict(rule) for rule in request.inbound_rules],
            'operator_ip': config['operator_ip'],
            'ssh_private_key_path': request.ssh_private,
            'ssh_key_path': request.ssh_public,
            'ssh_key_generated': request.ssh_generated,
        }
        for name in ('azure_state_dir', 'azure_deadline', 'azure_cleanup_deadline'):
            if name in config:
                result[name] = config[name]
        image = config.get('azure_image') or self.image(request.image_role)
        if image:
            result['azure_image'] = image
        if request.edge:
            result['azure_edge'] = dict(request.edge)
        if request.lab:
            result['azure_lab'] = dict(request.lab)
            if request.lab['role'] == 'member':
                result['operator_ip'] = request.lab['ssh_source']
            if request.lab.get('ssh_proxy'):
                result['ssh_proxy'] = dict(request.lab['ssh_proxy'])
        return result

    def prepare_state(self, infrastructure):
        return azure_utils.prepare_state(infrastructure)

    def prepare_ssh_key(self, infrastructure):
        return azure_utils.prepare_ssh_key(infrastructure)

    def deploy(self, infrastructure):
        return azure_utils.deploy_azure(infrastructure)

    def public_address(self, deployment_id, config):
        return azure_utils.vm_address(azure_utils.load_state(deployment_id, config.get('azure_state_dir')))

    def lab_network(self, lab, config):
        return azure_utils.create_lab_network(lab, config)

    def delete_lab_network(self, lab, network):
        return azure_utils.delete_lab_network(lab, network)

    def edge_endpoint(self, deployment_id, config):
        outputs = azure_utils.load_state(deployment_id, config.get('azure_state_dir')).get('outputs', {})
        return {'edge_id': outputs['edge_id']['value'],
                'edge_hostname': outputs['edge_hostname']['value'],
                'edge_header': azure_utils.EDGE_HEADER}

    def cleanup(self, request):
        return azure_utils.cleanup_azure(request)

    def health(self, state):
        return azure_utils.health_azure(state)

    def load_state(self, deployment_id):
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', deployment_id):
            return None
        try:
            return azure_utils.load_state(deployment_id)
        except FileNotFoundError:
            return None

    def list_states(self, config=None):
        return azure_utils.list_states((config or {}).get('azure_state_dir'))

    def infrastructure_playbook(self, config):
        if azure_utils.supports_infrastructure(config):
            return str(azure_utils.ROOT / 'providers' / 'Azure' / 'infrastructure.yml')
        return None

    def local_artifacts(self, deployment_id, config=None):
        return [azure_utils._state_path(deployment_id, (config or {}).get('azure_state_dir'))]

    def log_dir(self, config):
        return Path(config.get('azure_state_dir') or azure_utils.STATE_DIR) / 'logs'

    def run_command(self, argv, timeout=60, deadline=None, check=True):
        return azure_utils.run_command(argv, timeout=timeout, deadline=deadline, check=check)

    def check_connection(self):
        return azure_utils.check_connection()


def azure_driver():
    return AzureDriver()
