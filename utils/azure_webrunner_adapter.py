"""Azure scan nodes for the composite WEBRUNNER lifecycle.

The shared composite playbook provisions Linode and AWS nodes inline. Azure
nodes are provisioned here through the recoverable single-VM lifecycle before
that playbook runs, join it as pre-provisioned hosts and are removed once it
returns. Every node keeps its own durable state, so a lost controller still
recovers through the standalone teardown.
"""

import ipaddress
import json
import logging
from pathlib import Path

from . import azure_utils
from .provider_registry import WorkloadAdapter


def node_deployment_id(deployment_id, index):
    return '{0}-n{1:02d}'.format(deployment_id, int(index) + 1)


class AzureWebrunnerAdapter(WorkloadAdapter):
    """Bridge Azure nodes into the preserved composite WEBRUNNER executor."""

    def gather_config(self):
        return azure_utils.gather_azure_config()

    def deploy(self, config):
        raise RuntimeError('Azure WEBRUNNER nodes deploy through the composite playbook')

    def _node_config(self, config, chunk):
        public = Path(config['ssh_key_path']).expanduser()
        node = {
            'provider': 'azure', 'provider_workload': 'webrunner',
            'deployment_id': node_deployment_id(config['deployment_id'], chunk['idx']),
            'deployment_type': 'infrastructure', 'infrastructure_deployment': True,
            'azure_subscription_id': config['azure_subscription_id'],
            'azure_location': config.get('azure_location', 'eastus'),
            'azure_vm_size': config.get('azure_vm_size', 'Standard_D2as_v4'),
            'azure_os_disk_gb': config.get('azure_os_disk_gb', 32),
            'azure_inbound_rules': [],
            'operator_ip': config['operator_ip'],
            'ssh_key_path': str(public),
            'ssh_private_key_path': str(public).removesuffix('.pub'),
            # The module key is shared by every provider's nodes; the composite
            # executor removes it only after all providers prove absence.
            'ssh_key_generated': False,
        }
        node['azure_resource_group'] = 'c2itall-' + node['deployment_id']
        for name in ('azure_state_dir', 'azure_deadline', 'azure_cleanup_deadline'):
            if name in config:
                node[name] = config[name]
        return node

    def deploy_with_legacy(self, config, legacy_deploy):
        if 'azure' not in (config.get('providers') or ()):
            raise ValueError('Azure is not part of this WEBRUNNER deployment')
        if not callable(legacy_deploy):
            raise TypeError('Legacy executor must be callable')
        chunks = [chunk for chunk in json.loads(Path(config['node_chunks_file']).read_text())
                  if chunk.get('provider') == 'azure']
        nodes = []
        try:
            azure_utils.ensure_azure_auth(config['azure_subscription_id'])
            for chunk in chunks:
                node = self._node_config(config, chunk)
                azure_utils.prepare_state(node)
                if not azure_utils.deploy_azure(node):
                    raise RuntimeError('Azure node provisioning failed: ' + node['deployment_id'])
                state = azure_utils.load_state(node['deployment_id'], config.get('azure_state_dir'))
                address = ipaddress.ip_address(
                    state.get('outputs', {}).get('public_ip', {}).get('value', ''))
                if address.version != 4 or not address.is_global:
                    raise ValueError('Azure node returned an invalid public IP')
                nodes.append({'node_name': chunk['node_name'], 'ip': str(address),
                              'idx': chunk['idx'], 'cidrs': chunk['cidrs'],
                              'ip_count': chunk['ip_count'],
                              'deployment_id': node['deployment_id']})
        except (Exception, KeyboardInterrupt) as exc:
            logging.error('Azure WEBRUNNER provisioning failed: %s', exc)
            if config.get('teardown_after_scan', True):
                self._remove_nodes(config)
            return False
        config['azure_nodes'] = nodes
        # Exactly one call into the preserved composite executor; it removes the
        # Linode and AWS nodes in-play and owns the shared key's lifecycle.
        success = legacy_deploy(config)
        if config.get('teardown_after_scan', True):
            return self._remove_nodes(config) and success
        return success

    def _remove_nodes(self, config):
        # The composite ID owns every <id>-nNN node; a node ID owns only itself.
        wanted = config['deployment_id']
        verified = True
        for state in azure_utils.list_states(config.get('azure_state_dir')):
            if state.get('provider_workload') != 'webrunner' or (
                    state['deployment_id'] != wanted and
                    not state['deployment_id'].startswith(wanted + '-n')):
                continue
            cleanup = {'deployment_id': state['deployment_id']}
            for key in ('azure_state_dir', 'azure_cleanup_deadline'):
                if key in config:
                    cleanup[key] = config[key]
            verified = azure_utils.cleanup_azure(cleanup) and verified
        return verified

    def cleanup(self, config):
        if not self._remove_nodes(config):
            return False
        from .cleanup_engine import archive_deployment_logs, cleanup_ssh_keys_for_deployment
        if not config.get('preserve_local_keys') and 'azure_resource_group' not in config:
            # Only the composite record retires the key every provider's nodes share.
            cleanup_ssh_keys_for_deployment(config['deployment_id'], config.get('ssh_key_path'))
        archive_deployment_logs(config['deployment_id'])
        return True


def azure_webrunner_adapter():
    return AzureWebrunnerAdapter()
