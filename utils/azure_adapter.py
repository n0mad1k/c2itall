"""Azure implementation of the neutral infrastructure lifecycle contract."""

import re
from . import azure_utils
from .provider_registry import InfrastructureAdapter


class AzureInfrastructureAdapter(InfrastructureAdapter):
    def gather_config(self):
        return azure_utils.gather_azure_config()

    def validate_config(self, config, require_key=True):
        return azure_utils.validate_config(config, require_key=require_key)

    def prepare_key(self, config):
        return azure_utils.prepare_ssh_key(config)

    def playbook(self, config):
        if azure_utils.supports_infrastructure(config):
            return str(azure_utils.ROOT / 'providers' / 'Azure' / 'infrastructure.yml')
        return None

    def deploy(self, config):
        return azure_utils.deploy_azure(config)

    def cleanup(self, config):
        return azure_utils.cleanup_azure(config)

    def health(self, config):
        return azure_utils.health_azure(config)

    def load_state(self, deployment_id):
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', deployment_id):
            return None
        try:
            return azure_utils.load_state(deployment_id)
        except FileNotFoundError:
            return None

    def list_states(self):
        return azure_utils.list_states()
