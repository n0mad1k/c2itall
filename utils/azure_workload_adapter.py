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


class AzureSingleVmWorkloadAdapter(WorkloadAdapter):
    """Shared recoverable lifecycle for one-VM Azure service workloads."""

    workload = None
    address_key = None
    playbook_name = None
    service_log_suffix = None
    service_config_keys = ()
    manages_ssh_key = True

    def gather_config(self):
        return azure_utils.gather_azure_config()

    def playbook(self, config):
        self._validate_definition()
        return str(azure_utils.ROOT / 'providers' / 'Azure' /
                   self.playbook_name)

    def _validate_definition(self):
        values = (self.workload, self.address_key, self.playbook_name,
                  self.service_log_suffix)
        if not all(isinstance(value, str) and value for value in values):
            raise TypeError('Azure single-VM workload metadata is incomplete')
        if (not isinstance(self.service_config_keys, tuple) or
                not all(isinstance(key, str) and key
                        for key in self.service_config_keys)):
            raise TypeError('Azure service_config_keys must be a string tuple')

    def _label(self):
        if isinstance(self.workload, str) and self.workload:
            return self.workload.replace('_', '-')
        return 'single-vm-workload'

    def _validate_workload(self, config):
        raise NotImplementedError

    def _inbound_rules(self, config):
        return []

    def _infrastructure_config(self, config):
        self._validate_definition()
        if config.get('provider') != 'azure' or config.get('provider_workload') != self.workload:
            raise ValueError(
                'Azure {0} route does not match its provider workload'.format(
                    self._label()))
        self._validate_workload(config)
        deployment_id = config['deployment_id']
        key = Path.home() / '.ssh' / ('c2deploy_' + deployment_id)
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
            'azure_inbound_rules': self._inbound_rules(config),
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

    def _public_ipv4(self, value):
        address = ipaddress.ip_address(value)
        if address.version != 4 or not address.is_global:
            raise ValueError(
                'Azure {0} deployment returned an invalid public IP'.format(
                    self._label()))
        return address

    def _service_variables(self, config):
        self._validate_definition()
        allowed = {
            'provider', 'provider_workload', 'deployment_id',
            'deployment_type',
        } | set(self.service_config_keys)
        return {key: value for key, value in config.items()
                if key in allowed and value is not None}

    def _run_service_playbook(self, config):
        address = self._public_ipv4(config[self.address_key])
        private_key = Path(config['ssh_private_key_path'])
        if not private_key.is_file() or private_key.is_symlink():
            raise ValueError('Azure {0} private key is unavailable'.format(
                self._label()))
        state_root = Path(config.get('azure_state_dir') or azure_utils.STATE_DIR)
        log_dir = state_root / 'logs'
        known_hosts = log_dir / (config['deployment_id'] + '-known-hosts')
        service_vars = self._service_variables(config)
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
        log_path = log_dir / (config['deployment_id'] + '-' +
                              self.service_log_suffix + '.log')
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
            parsed = self._public_ipv4(address)
            config.update({key: value for key, value in infrastructure.items()
                           if key.startswith('azure_') or key in (
                               'operator_ip', 'ssh_key_path',
                               'ssh_private_key_path', 'ssh_key_generated')})
            config.update({self.address_key: str(parsed),
                           'ssh_user': 'azureuser',
                           'ssh_key': infrastructure['ssh_private_key_path']})
            if not self._run_service_playbook(config):
                return False
            from .deployment_engine import save_deployment_info
            save_deployment_info(config)
            return True
        except (Exception, KeyboardInterrupt) as exc:
            logging.error('Azure %s deployment failed: %s', self._label(), exc)
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


class AzureAttackBoxAdapter(AzureSingleVmWorkloadAdapter):
    """Provision and configure the supported Azure attack-box workload."""

    workload = 'attack_box'
    address_key = 'attack_box_ip'
    playbook_name = 'attack_box.yml'
    service_log_suffix = 'attack-box'
    service_config_keys = (
        'attack_box_name', 'attack_box_type', 'domain',
        'enhanced_opsec', 'project_name', 'setup_domain', 'setup_tor',
        'setup_vpn', 'tool_name', 'work_dir',
    )

    def _validate_workload(self, config):
        if (config.get('attack_box_type') != 'quick_recon' or
                config.get('deployment_type') != 'quick_recon_box'):
            raise ValueError(
                'Azure currently supports only the quick-recon attack-box subtype')

    def _inbound_rules(self, config):
        rules = []
        if config.get('setup_vpn'):
            rules.append({'name': 'openvpn', 'protocol': 'Udp',
                          'port': 1194, 'source': '*'})
        return rules


def azure_attack_box_adapter():
    return AzureAttackBoxAdapter()
