"""Azure provisioning bridge for Phantom's privacy-service lifecycle."""

import ipaddress
from pathlib import Path

from . import azure_utils
from .provider_registry import WorkloadAdapter


_WEB_RULES = (
    {'name': 'public-http', 'protocol': 'Tcp', 'port': 80, 'source': '*'},
    {'name': 'public-https', 'protocol': 'Tcp', 'port': 443, 'source': '*'},
)


def _service_rules(config):
    service = config.get('server_type')
    if service == 'vpn':
        return [{'name': 'wireguard', 'protocol': 'Udp',
                 'port': int(config.get('vpn_port', 51820)), 'source': '*'}]
    if service == 'dns':
        return [
            {'name': 'public-dns-tcp', 'protocol': 'Tcp', 'port': 53, 'source': '*'},
            {'name': 'public-dns-udp', 'protocol': 'Udp', 'port': 53, 'source': '*'},
            *_WEB_RULES,
        ]
    if service == 'matrix':
        rules = [*_WEB_RULES, {'name': 'matrix-federation', 'protocol': 'Tcp',
                               'port': 8448, 'source': '*'}]
        if config.get('provider_workload') == 'chat':
            rules.append({'name': 'tailscale-direct', 'protocol': 'Udp',
                          'port': 41641, 'source': '*'})
        return rules
    if service == 'email':
        return [
            *_WEB_RULES,
            *[{'name': 'mail-' + str(port), 'protocol': 'Tcp', 'port': port,
               'source': '*'} for port in (25, 465, 587, 993, 4190)],
            {'name': 'mail-dns-tcp', 'protocol': 'Tcp', 'port': 53, 'source': '*'},
            {'name': 'mail-dns-udp', 'protocol': 'Udp', 'port': 53, 'source': '*'},
        ]
    if service in ('cloud', 'vault', 'media', 'all_in_one'):
        return list(_WEB_RULES)
    raise ValueError('Unsupported Phantom service for Azure')


class AzurePhantomAdapter(WorkloadAdapter):
    def gather_config(self):
        return azure_utils.gather_azure_config()

    def _infrastructure_config(self, config):
        deployment_id = config['deployment_id']
        key = Path.home() / '.ssh' / ('c2deploy_' + deployment_id)
        result = {
            'provider': 'azure', 'deployment_id': deployment_id,
            'deployment_type': 'infrastructure', 'infrastructure_deployment': True,
            'azure_subscription_id': config['azure_subscription_id'],
            'azure_location': config.get('azure_location', 'eastus'),
            'azure_vm_size': config.get('azure_vm_size', 'Standard_D2as_v4'),
            'azure_resource_group': config.get('azure_resource_group',
                                                'c2itall-' + deployment_id),
            'operator_ip': config['operator_ip'],
            'ssh_private_key_path': str(key), 'ssh_key_path': str(key) + '.pub',
            'ssh_key_generated': True, 'azure_inbound_rules': _service_rules(config),
        }
        for key_name in ('azure_state_dir', 'azure_deadline', 'azure_cleanup_deadline'):
            if key_name in config:
                result[key_name] = config[key_name]
        return result

    def deploy(self, config):
        infrastructure = self._infrastructure_config(config)
        azure_utils.prepare_state(infrastructure)
        azure_utils.prepare_ssh_key(infrastructure)
        if not azure_utils.deploy_azure(infrastructure):
            return False
        state = azure_utils.load_state(config['deployment_id'],
                                       config.get('azure_state_dir'))
        address = state.get('outputs', {}).get('public_ip', {}).get('value', '')
        parsed = ipaddress.ip_address(address)
        if parsed.version != 4 or not parsed.is_global:
            raise ValueError('Azure Phantom deployment returned an invalid public IP')
        config.update({key: value for key, value in infrastructure.items()
                       if key.startswith('azure_') or key == 'operator_ip'})
        config.update(target_host=str(parsed), ssh_user='azureuser',
                      ssh_key=infrastructure['ssh_private_key_path'],
                      provider_workload='phantom')
        return True

    def cleanup(self, config):
        cleanup = {'deployment_id': config['deployment_id']}
        for key in ('azure_state_dir', 'azure_subscription_id',
                    'azure_resource_group', 'azure_cleanup_deadline'):
            if key in config:
                cleanup[key] = config[key]
        return azure_utils.cleanup_azure(cleanup)
