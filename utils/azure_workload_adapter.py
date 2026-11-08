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
    inventory_group = None
    image = None
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
        image = config.get('azure_image') or self.image
        if image:
            result['azure_image'] = image
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
            inventory = str(address) + ','
            if self.inventory_group:
                # Shared service tasks classify hosts by their legacy group name.
                inventory = str(Path(temporary) / 'inventory.ini')
                Path(inventory).write_text(
                    '[' + self.inventory_group + ']\n' + str(address) +
                    ' ansible_host=' + str(address) + '\n')
            result = azure_utils.run_command([
                'ansible-playbook', self.playbook(config),
                '-i', inventory, '-u', 'azureuser',
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


class AzureRedirectorAdapter(AzureSingleVmWorkloadAdapter):
    """Provision and configure an Azure redirector that fronts an operator backend."""

    workload = 'redirector'
    address_key = 'redirector_ip'
    playbook_name = 'redirector.yml'
    service_log_suffix = 'redirector'
    inventory_group = 'redirectors'
    service_config_keys = (
        'redirector_name', 'domain', 'redirector_subdomain', 'backend_type',
        'backend_ip', 'backend_port', 'redirector_type', 'letsencrypt_email',
        'operator_ip', 'redirector_ip', 'c2_ip', 'shell_handler_port',
        'havoc_teamserver_port', 'havoc_http_port', 'havoc_https_port',
        'zero_logs', 'randomize_ports', 'legitimate_redirect',
        'allowed_referrers',
    )

    def _validate_workload(self, config):
        if not config.get('domain'):
            raise ValueError('Azure redirector requires a domain')
        backend = config.get('backend_ip') or config['operator_ip']
        if ipaddress.ip_address(str(backend).removesuffix('/32')).version != 4:
            raise ValueError('Azure redirector backend must be an IPv4 address')

    def _inbound_rules(self, config):
        return [
            {'name': 'http', 'protocol': 'Tcp', 'port': 80, 'source': '*'},
            {'name': 'https', 'protocol': 'Tcp', 'port': 443, 'source': '*'},
            {'name': 'shell-handler', 'protocol': 'Tcp',
             'port': int(config.get('shell_handler_port') or 4488),
             'source': '*'},
        ]

    def _service_variables(self, config):
        variables = super()._service_variables(config)
        backend = config.get('backend_ip') or config['operator_ip']
        variables.setdefault('c2_ip', str(backend).removesuffix('/32'))
        variables.setdefault('shell_handler_port', 4488)
        return variables


def azure_redirector_adapter():
    return AzureRedirectorAdapter()


KALI_IMAGE = {'publisher': 'kali-linux', 'offer': 'kali', 'sku': 'kali-2026-2',
              'version': 'latest', 'plan': True}


class AzureC2Adapter(AzureSingleVmWorkloadAdapter):
    """Provision a Kali VM and configure the shared Havoc C2 and mail stack."""

    workload = 'c2'
    address_key = 'c2_ip'
    playbook_name = 'c2.yml'
    service_log_suffix = 'c2'
    inventory_group = 'c2servers'
    image = KALI_IMAGE
    service_config_keys = (
        'c2_name', 'redirector_name', 'domain', 'c2_subdomain',
        'redirector_subdomain', 'redirector_port', 'c2_framework',
        'letsencrypt_email', 'operator_ip', 'c2_ip', 'redirector_ip',
        'ssh_key_path', 'smtp_auth_user', 'smtp_auth_pass', 'zero_logs',
        'secure_memory', 'disable_history', 'randomize_ports',
        'gophish_admin_port', 'gophish_phish_port', 'havoc_teamserver_port',
        'havoc_http_port', 'havoc_https_port', 'havoc_payload_port',
        'havoc_admin_user', 'havoc_admin_password', 'havoc_spawn',
        'havoc_sleep', 'havoc_jitter', 'havoc_sleep_mask_technique',
        'setup_integrated_tracker', 'tracker_domain', 'tracker_port',
        'c2_only', 'redirector_only', 'deploy_redirector', 'deploy_tracker',
    )

    def _redirector(self, config):
        address = str(config.get('redirector_ip') or '').removesuffix('/32')
        if not address:
            return None
        parsed = ipaddress.ip_address(address)
        if parsed.is_loopback:
            return None
        if parsed.version != 4 or not parsed.is_global:
            raise ValueError('Azure C2 redirector address must be a public IPv4')
        return str(parsed)

    def _validate_workload(self, config):
        if not config.get('domain'):
            raise ValueError('Azure C2 requires a domain')
        if config.get('c2_framework', 'havoc') != 'havoc':
            raise ValueError('Azure C2 supports only the Havoc framework')
        self._redirector(config)

    def _inbound_rules(self, config):
        operator = config['operator_ip']
        rules = [
            {'name': 'havoc-teamserver', 'protocol': 'Tcp',
             'port': int(config.get('havoc_teamserver_port') or 40056), 'source': operator},
            {'name': 'gophish-admin', 'protocol': 'Tcp',
             'port': int(config.get('gophish_admin_port') or 2222), 'source': operator},
        ]
        if config.get('setup_integrated_tracker'):
            rules.append({'name': 'tracker', 'protocol': 'Tcp',
                          'port': int(config.get('tracker_port') or 5000), 'source': operator})
        redirector = self._redirector(config)
        if redirector:
            for name, key, default in (('havoc-http', 'havoc_http_port', 8080),
                                       ('havoc-https', 'havoc_https_port', 9443),
                                       ('havoc-payload', 'havoc_payload_port', 8443),
                                       ('gophish-phish', 'gophish_phish_port', 8081)):
                rules.append({'name': name, 'protocol': 'Tcp',
                              'port': int(config.get(key) or default), 'source': redirector})
        return rules

    def _service_variables(self, config):
        variables = super()._service_variables(config)
        variables.setdefault('redirector_ip', self._redirector(config) or '127.0.0.1')
        variables.setdefault('c2_subdomain', 'mail')
        variables.setdefault('redirector_subdomain', 'cdn')
        variables.setdefault('gophish_admin_port', '2222')
        variables.setdefault('redirector_only', False)
        return variables


def azure_c2_adapter():
    return AzureC2Adapter()


class AzurePayloadServerAdapter(AzureSingleVmWorkloadAdapter):
    """Provision an Ubuntu VM and configure the shared payload hosting service."""

    workload = 'payload_server'
    address_key = 'payload_server_ip'
    playbook_name = 'payload_server.yml'
    service_log_suffix = 'payload-server'
    inventory_group = 'payloadservers'
    service_config_keys = (
        'payload_server_name', 'domain', 'payload_subdomain', 'letsencrypt_email',
        'operator_ip', 'payload_server_ip', 'host_executables', 'host_scripts',
        'host_documents', 'host_mobile', 'enable_basic_auth', 'enable_ip_filtering',
        'enable_user_agent_filtering', 'enable_rate_limiting',
        'auto_generate_payloads', 'auth_username', 'auth_password', 'allowed_ips',
    )

    def _validate_workload(self, config):
        if not config.get('domain'):
            raise ValueError('Azure payload server requires a domain')

    def _inbound_rules(self, config):
        return [{'name': 'http', 'protocol': 'Tcp', 'port': 80, 'source': '*'},
                {'name': 'https', 'protocol': 'Tcp', 'port': 443, 'source': '*'}]


def azure_payload_server_adapter():
    return AzurePayloadServerAdapter()
