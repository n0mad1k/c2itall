"""Azure basic phishing: an MTA front and a GoPhish server as two recoverable VMs.

Each component reuses the single-VM lifecycle under its own deployment ID
(``<id>-mta``, ``<id>-gophish``) and the module's shared SSH key, so a lost
controller recovers either VM alone or the whole deployment from its record.
"""

import logging
from pathlib import Path
import secrets

from . import azure_utils
from .azure_workload_adapter import AzureSingleVmWorkloadAdapter
from .provider_registry import WorkloadAdapter

COMPONENTS = ('mta', 'gophish')


class AzurePhishingComponent(AzureSingleVmWorkloadAdapter):
    workload = 'phishing'
    manages_ssh_key = False
    component = None

    def _validate_workload(self, config):
        if not config.get('domain'):
            raise ValueError('Azure phishing requires a domain')
        if config.get('deploy_phishing_redirector') or config.get('deploy_phishing_webserver'):
            raise ValueError('Azure phishing supports the MTA front and GoPhish components only')

    def _infrastructure_config(self, config):
        result = super()._infrastructure_config(config)
        public = Path(config['ssh_key_path']).expanduser()
        deployment_id = config['deployment_id'] + '-' + self.component
        result.update(deployment_id=deployment_id,
                      azure_resource_group='c2itall-' + deployment_id,
                      ssh_key_path=str(public),
                      ssh_private_key_path=str(public).removesuffix('.pub'),
                      ssh_key_generated=False)
        return result


class AzureMtaFront(AzurePhishingComponent):
    component = 'mta'
    address_key = 'mta_ip'
    playbook_name = 'mta.yml'
    service_log_suffix = 'phishing-mta'
    inventory_group = 'mta_fronts'
    service_config_keys = (
        'domain', 'phishing_domain', 'mta_hostname', 'mta_name', 'operator_ip',
        'smtp_auth_user', 'smtp_auth_pass', 'zero_logs', 'mta_ip',
    )

    def _inbound_rules(self, config):
        return [{'name': 'smtp', 'protocol': 'Tcp', 'port': 25, 'source': '*'},
                {'name': 'submission', 'protocol': 'Tcp', 'port': 587, 'source': '*'}]


class AzureGophishServer(AzurePhishingComponent):
    component = 'gophish'
    address_key = 'gophish_ip'
    playbook_name = 'gophish.yml'
    service_log_suffix = 'phishing-gophish'
    inventory_group = 'gophish_servers'
    service_config_keys = (
        'domain', 'phishing_domain', 'phishing_hostname', 'gophish_name',
        'gophish_admin_port', 'gophish_phish_port', 'mta_ip', 'operator_ip',
        'smtp_auth_user', 'smtp_auth_pass', 'zero_logs', 'gophish_ip',
    )

    def _inbound_rules(self, config):
        return [{'name': 'phish', 'protocol': 'Tcp',
                 'port': int(config.get('gophish_phish_port') or 80), 'source': '*'},
                {'name': 'gophish-admin', 'protocol': 'Tcp',
                 'port': int(config.get('gophish_admin_port') or 3333),
                 'source': config['operator_ip']}]


class AzurePhishingAdapter(WorkloadAdapter):
    """Deploy the enabled components in order and retire them together."""

    manages_ssh_key = False
    recovers_from_log = True
    components = (('deploy_mta_front', AzureMtaFront),
                  ('deploy_gophish', AzureGophishServer))

    def gather_config(self):
        return azure_utils.gather_azure_config()

    def deploy(self, config):
        enabled = [factory() for flag, factory in self.components if config.get(flag)]
        if not enabled:
            logging.error('Azure phishing requires the MTA front or GoPhish component')
            return False
        if not config.get('smtp_auth_pass'):
            # Both hosts must agree on the relay credential.
            config['smtp_auth_pass'] = secrets.token_urlsafe(16)
        for component in enabled:
            if not component.deploy(config):
                logging.error('Azure phishing component failed; entering verified cleanup')
                self.cleanup(dict(config, preserve_local_keys=True))
                return False
        return True

    def cleanup(self, config):
        wanted = config['deployment_id']
        # A component state cleans itself; the deployment record retires every component.
        ids = {wanted} if 'azure_resource_group' in config else {
            wanted + '-' + component for component in COMPONENTS}
        verified = True
        for state in azure_utils.list_states(config.get('azure_state_dir')):
            if state['deployment_id'] not in ids or state.get('provider_workload') != 'phishing':
                continue
            cleanup = {'deployment_id': state['deployment_id']}
            for key in ('azure_state_dir', 'azure_cleanup_deadline'):
                if key in config:
                    cleanup[key] = config[key]
            verified = azure_utils.cleanup_azure(cleanup) and verified
        if not verified:
            return False
        from .cleanup_engine import archive_deployment_logs, cleanup_ssh_keys_for_deployment
        if not config.get('preserve_local_keys') and 'azure_resource_group' not in config:
            cleanup_ssh_keys_for_deployment(wanted, config.get('ssh_key_path'))
        archive_deployment_logs(wanted)
        return True


def azure_phishing_adapter():
    return AzurePhishingAdapter()
