"""Azure provider implementations for non-Phantom single-VM workloads."""

import ipaddress
import json
import logging
import os
from pathlib import Path
import tempfile
import time

from . import azure_utils
from .provider_registry import WorkloadAdapter


class AzureAttackBoxAdapter(WorkloadAdapter):
    """Provision and configure the supported Azure attack-box workload."""

    workload = 'attack_box'

    def gather_config(self):
        config = azure_utils.gather_azure_config()
        # The adapter persists intent before creating its canonical deployment
        # key, so the module must not create an unrelated legacy key first.
        config['provider_manages_ssh_key'] = True
        return config

    def playbook(self, config):
        return str(azure_utils.ROOT / 'providers' / 'Azure' / 'attack_box.yml')

    def _infrastructure_config(self, config):
        if config.get('provider') != 'azure' or config.get('provider_workload') != self.workload:
            raise ValueError('Azure attack-box route does not match its provider workload')
        if config.get('attack_box_type') != 'quick_recon' or config.get('deployment_type') != 'quick_recon_box':
            raise ValueError('Azure currently supports only the quick-recon attack-box subtype')
        deployment_id = config['deployment_id']
        key = Path.home() / '.ssh' / ('c2deploy_' + deployment_id)
        rules = []
        if config.get('setup_vpn'):
            rules.append({'name': 'openvpn', 'protocol': 'Udp',
                          'port': 1194, 'source': '*'})
        result = {
            'provider': 'azure', 'provider_workload': self.workload,
            'deployment_id': deployment_id,
            'deployment_type': 'infrastructure',
            'infrastructure_deployment': True,
            'azure_subscription_id': config['azure_subscription_id'],
            'azure_location': config.get('azure_location', 'eastus'),
            'azure_vm_size': config.get('azure_vm_size', 'Standard_D2as_v4'),
            'azure_os_disk_gb': config.get('azure_os_disk_gb', 32),
            'azure_resource_group': config.get(
                'azure_resource_group', 'c2itall-' + deployment_id),
            'azure_inbound_rules': rules,
            'operator_ip': config['operator_ip'],
            'ssh_private_key_path': str(key),
            'ssh_key_path': str(key) + '.pub',
            'ssh_key_generated': True,
        }
        for name in ('azure_state_dir', 'azure_deadline',
                     'azure_cleanup_deadline'):
            if name in config:
                result[name] = config[name]
        return result

    def _run_service_playbook(self, config):
        address = ipaddress.ip_address(config['attack_box_ip'])
        if address.version != 4 or not address.is_global:
            raise ValueError('Azure attack-box deployment returned an invalid public IP')
        private_key = Path(config['ssh_private_key_path'])
        if not private_key.is_file() or private_key.is_symlink():
            raise ValueError('Azure attack-box private key is unavailable')
        state_root = Path(config.get('azure_state_dir') or azure_utils.STATE_DIR)
        log_dir = state_root / 'logs'
        known_hosts = log_dir / (config['deployment_id'] + '-known-hosts')
        service_vars = dict(config)
        service_vars.update(
            ansible_python_interpreter='/usr/bin/python3',
            ansible_ssh_common_args=(
                '-o BatchMode=yes -o IdentitiesOnly=yes '
                '-o StrictHostKeyChecking=accept-new '
                '-o GlobalKnownHostsFile=/dev/null '
                '-o UserKnownHostsFile=' + str(known_hosts)),
        )
        deadline = config.get('azure_service_deadline', time.monotonic() + 1800)
        with azure_utils.secure_directory(log_dir, create=True):
            pass
        with tempfile.TemporaryDirectory(prefix='c2itall-azure-service-') as temporary:
            variables = Path(temporary) / 'variables.json'
            variables.write_text(json.dumps(service_vars))
            variables.chmod(0o600)
            result = azure_utils.run_command([
                'ansible-playbook', self.playbook(config),
                '-i', str(address) + ',', '-u', 'azureuser',
                '--private-key', str(private_key),
                '--extra-vars', '@' + str(variables),
            ], timeout=1800, deadline=deadline)
        log_path = log_dir / (config['deployment_id'] + '-attack-box.log')
        with azure_utils.secure_directory(log_dir) as directory:
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, 'O_NOFOLLOW'):
                flags |= os.O_NOFOLLOW
            fd = os.open(log_path.name, flags, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'a') as stream:
                azure_utils._regular_file(stream.fileno())
                stream.write(result.stdout)
                stream.write(result.stderr)
        return True

    def deploy(self, config):
        try:
            infrastructure = self._infrastructure_config(config)
            azure_utils.prepare_state(infrastructure)
            azure_utils.prepare_ssh_key(infrastructure)
            if not azure_utils.deploy_azure(infrastructure):
                return False
            state = azure_utils.load_state(
                config['deployment_id'], config.get('azure_state_dir'))
            address = state.get('outputs', {}).get('public_ip', {}).get('value', '')
            parsed = ipaddress.ip_address(address)
            if parsed.version != 4 or not parsed.is_global:
                raise ValueError('Azure attack-box deployment returned an invalid public IP')
            config.update({key: value for key, value in infrastructure.items()
                           if key.startswith('azure_') or key in (
                               'operator_ip', 'ssh_key_path',
                               'ssh_private_key_path', 'ssh_key_generated')})
            config.update(attack_box_ip=str(parsed), ssh_user='azureuser',
                          ssh_key=infrastructure['ssh_private_key_path'])
            if not self._run_service_playbook(config):
                return False
            from .deployment_engine import save_deployment_info
            save_deployment_info(config)
            return True
        except (Exception, KeyboardInterrupt) as exc:
            logging.error('Azure attack-box deployment failed: %s', exc)
            return False

    def cleanup(self, config):
        cleanup = {'deployment_id': config['deployment_id']}
        for key in ('azure_state_dir', 'azure_subscription_id',
                    'azure_resource_group', 'azure_cleanup_deadline'):
            if key in config:
                cleanup[key] = config[key]
        success = azure_utils.cleanup_azure(cleanup)
        if success:
            from .cleanup_engine import archive_deployment_logs
            archive_deployment_logs(config['deployment_id'])
        return success


def azure_attack_box_adapter():
    return AzureAttackBoxAdapter()
