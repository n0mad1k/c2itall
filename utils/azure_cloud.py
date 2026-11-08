"""Azure cloud driver: the only Azure-aware code outside azure_utils."""

import re
from pathlib import Path

from . import azure_utils
from .cloud_driver import CloudDriver

KALI_IMAGE = {'publisher': 'kali-linux', 'offer': 'kali', 'sku': 'kali-2026-2',
              'version': 'latest', 'plan': True}


class AzureDriver(CloudDriver):
    provider = 'azure'
    ssh_user = 'azureuser'
    prefix = 'azure_'
    identity_keys = ('azure_subscription_id', 'azure_resource_group')
    option_keys = ('azure_state_dir', 'azure_cleanup_deadline')

    def gather_config(self):
        return azure_utils.gather_azure_config()

    def validate_config(self, config, require_key=True):
        return azure_utils.validate_config(config, require_key=require_key)

    def image(self, role):
        return KALI_IMAGE if role == 'kali' else None

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
            'azure_inbound_rules': request.inbound_rules,
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
        return result

    def prepare_state(self, infrastructure):
        return azure_utils.prepare_state(infrastructure)

    def prepare_ssh_key(self, infrastructure):
        return azure_utils.prepare_ssh_key(infrastructure)

    def deploy(self, infrastructure):
        return azure_utils.deploy_azure(infrastructure)

    def public_address(self, deployment_id, config):
        state = azure_utils.load_state(deployment_id, config.get('azure_state_dir'))
        return state.get('outputs', {}).get('public_ip', {}).get('value', '')

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
