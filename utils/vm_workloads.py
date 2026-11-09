"""Generic workload adapters: run any profiled workload through any cloud driver.

The driver plans, creates and retires VMs; the profile says what the VM must
look like and which service playbook configures it. These adapters hold the
recoverable lifecycle between them, so neither side has to know the other.
"""

import ipaddress
import json
import logging
import os
from pathlib import Path
import tempfile
import time

from .cloud_driver import CloudDriver, DriverInfrastructureAdapter, ProvisionRequest
from .controller_io import ROOT, regular_file, secure_directory
from .provider_registry import WorkloadAdapter, _load
from .workloads import load_profile


class SingleVmAdapter(WorkloadAdapter):
    """Recoverable lifecycle for one VM running one service playbook."""

    def __init__(self, driver, profile):
        self.driver = driver
        self.profile = profile
        self.manages_ssh_key = profile.manages_ssh_key
        self.recovers_from_log = profile.recovers_from_log

    @property
    def workload(self):
        return self.profile.workload

    @property
    def address_key(self):
        return self.profile.address_key

    @property
    def inventory_group(self):
        return self.profile.inventory_group

    def gather_config(self):
        return self.driver.gather_config()

    def playbook(self, config):
        return str(ROOT / self.profile.service_playbook)

    def _label(self):
        return self.profile.label()

    def _request(self, config):
        if (config.get('provider') != self.driver.provider or
                config.get('provider_workload') != self.profile.workload):
            raise ValueError('{0} {1} route does not match its provider workload'.format(
                self.driver.provider, self._label()))
        self.profile.validate(config)
        deployment_id = config['deployment_id']
        if self.profile.component:
            deployment_id += '-' + self.profile.component
        if self.profile.manages_ssh_key:
            key = Path.home() / '.ssh' / ('c2deploy_' + config['deployment_id'])
            generated = True
        else:
            # The module key is shared by every VM of this deployment.
            key = Path(str(Path(config['ssh_key_path']).expanduser()).removesuffix('.pub'))
            generated = False
        return ProvisionRequest(
            deployment_id, self.profile.workload, self.profile.inbound_rules(config),
            self.profile.image_role_for(config), self.profile.disk_gb(config),
            str(key) + '.pub', str(key), generated)

    def _infrastructure_config(self, config):
        return self.driver.plan(config, self._request(config))

    def _public_ipv4(self, value):
        address = ipaddress.ip_address(value)
        if address.version != 4 or not address.is_global:
            raise ValueError('{0} {1} deployment returned an invalid public IP'.format(
                self.driver.provider, self._label()))
        return address

    def _service_variables(self, config):
        allowed = {'provider', 'provider_workload', 'deployment_id',
                   'deployment_type'} | set(self.profile.config_keys)
        variables = {key: value for key, value in config.items()
                     if key in allowed and value is not None}
        return self.profile.service_variables(config, variables)

    def _run_service_playbook(self, config):
        address = self._public_ipv4(config[self.profile.address_key])
        private_key = Path(config['ssh_private_key_path'])
        if not private_key.is_file() or private_key.is_symlink():
            raise ValueError('{0} {1} private key is unavailable'.format(
                self.driver.provider, self._label()))
        log_dir = self.driver.log_dir(config)
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
        deadline = config.get('service_deadline', time.monotonic() + 1800)
        with secure_directory(log_dir, create=True):
            pass
        with tempfile.TemporaryDirectory(prefix='c2itall-service-') as temporary:
            variables = Path(temporary) / 'variables.json'
            variables.write_text(json.dumps(service_vars))
            variables.chmod(0o600)
            inventory = str(address) + ','
            if self.profile.inventory_group:
                # Shared service tasks classify hosts by their legacy group name.
                inventory = str(Path(temporary) / 'inventory.ini')
                Path(inventory).write_text(
                    '[' + self.profile.inventory_group + ']\n' + str(address) +
                    ' ansible_host=' + str(address) + '\n')
            result = self.driver.run_command([
                'ansible-playbook', self.playbook(config),
                '-i', inventory, '-u', self.driver.ssh_user,
                '--private-key', str(private_key),
                '--extra-vars', '@' + str(variables),
            ], timeout=1800, deadline=deadline, check=False)
        log_path = log_dir / (config['deployment_id'] + '-' + self.profile.log_suffix + '.log')
        with secure_directory(log_dir) as directory:
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, 'O_NOFOLLOW'):
                flags |= os.O_NOFOLLOW
            fd = os.open(log_path.name, flags, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'a') as stream:
                regular_file(stream.fileno())
                stream.write(result.stdout)
                stream.write(result.stderr)
        if result.returncode:
            logging.error('%s %s service playbook failed (%s); see %s',
                          self.driver.provider, self._label(), result.returncode, log_path)
            return False
        return True

    def deploy(self, config):
        infrastructure = None
        try:
            planned = self._infrastructure_config(config)
            # Recovery may only retire state this call created; a conflict
            # with an existing deployment must leave that deployment alone.
            self.driver.prepare_state(planned)
            infrastructure = planned
            self.driver.prepare_ssh_key(infrastructure)
            if not self.driver.deploy(infrastructure):
                return self._recover(config, infrastructure)
            address = self.driver.public_address(infrastructure['deployment_id'], config)
            parsed = self._public_ipv4(address)
            config.update(self.driver.exported_config(infrastructure))
            config.update({self.profile.address_key: str(parsed),
                           'ssh_user': self.driver.ssh_user,
                           'ssh_key': infrastructure['ssh_private_key_path']})
            if not self._run_service_playbook(config):
                return self._recover(config, infrastructure)
            from .deployment_engine import save_deployment_info
            save_deployment_info(config)
            return True
        except KeyboardInterrupt:
            logging.error('%s %s deployment interrupted; recovery state retained',
                          self.driver.provider, self._label())
            return False
        except Exception as exc:
            logging.error('%s %s deployment failed: %s', self.driver.provider, self._label(), exc)
            return self._recover(config, infrastructure)

    def _recover(self, config, infrastructure):
        """Match the legacy route: verified cleanup before reporting failure."""
        if infrastructure is None:
            return False
        logging.warning('Deployment failed; attempting verified provider cleanup')
        cleanup = dict(config, deployment_id=infrastructure['deployment_id'])
        for key in self.driver.option_keys + self.driver.identity_keys:
            if key in infrastructure:
                cleanup[key] = infrastructure[key]
        if not self.cleanup(cleanup):
            logging.error(
                'Failed deployment cleanup was not verified; retain recovery data')
        return False

    def cleanup(self, config):
        success = self.driver.cleanup(self.driver.cleanup_request(config))
        if success:
            from .cleanup_engine import archive_deployment_logs
            archive_deployment_logs(config['deployment_id'])
        return success


class ComponentAdapter(WorkloadAdapter):
    """Deploy the enabled components in order and retire them together."""

    def __init__(self, driver, profile):
        self.driver = driver
        self.profile = profile
        self.manages_ssh_key = profile.manages_ssh_key
        self.recovers_from_log = profile.recovers_from_log

    def gather_config(self):
        return self.driver.gather_config()

    def component(self, name):
        for _flag, profile in self.profile.components:
            if profile.component == name:
                return SingleVmAdapter(self.driver, profile)
        raise KeyError(name)

    def deploy(self, config):
        enabled = [SingleVmAdapter(self.driver, profile)
                   for flag, profile in self.profile.components if config.get(flag)]
        if not enabled:
            logging.error('%s requires at least one enabled component', self.profile.label())
            return False
        self.profile.prepare(config)
        for component in enabled:
            if not component.deploy(config):
                logging.error('%s component failed; entering verified cleanup',
                              self.profile.label())
                self.cleanup(dict(config, preserve_local_keys=True))
                return False
        return True

    def cleanup(self, config):
        wanted = config['deployment_id']
        # Only a component's own state carries an ownership marker and cleans
        # itself; a record or module config retires every component, even
        # after a deployed component copied its identity into it.
        ids = {wanted} if 'ownership_marker' in config else {
            wanted + '-' + profile.component for _flag, profile in self.profile.components}
        verified = True
        for state in self.driver.list_states(config):
            if (state['deployment_id'] not in ids or
                    state.get('provider_workload') != self.profile.workload):
                continue
            request = self.driver.cleanup_request(
                dict(config, deployment_id=state['deployment_id']), identity=False)
            verified = self.driver.cleanup(request) and verified
        if not verified:
            return False
        from .cleanup_engine import archive_deployment_logs, cleanup_ssh_keys_for_deployment
        if not config.get('preserve_local_keys') and 'ownership_marker' not in config:
            cleanup_ssh_keys_for_deployment(wanted, config.get('ssh_key_path'))
        archive_deployment_logs(wanted)
        return True


class NodeAdapter(WorkloadAdapter):
    """Provision scan nodes for the composite executor and remove them after it."""

    def __init__(self, driver, profile):
        self.driver = driver
        self.profile = profile
        self.manages_ssh_key = profile.manages_ssh_key

    def gather_config(self):
        return self.driver.gather_config()

    def deploy(self, config):
        raise RuntimeError(self.profile.label() + ' nodes deploy through the composite playbook')

    def _node_config(self, config, chunk):
        public = Path(config['ssh_key_path']).expanduser()
        request = ProvisionRequest(
            self.profile.node_id(config['deployment_id'], chunk['idx']),
            self.profile.workload, [], self.profile.image_role_for(config),
            self.profile.disk_gb(config),
            str(public), str(public).removesuffix('.pub'),
            # The module key is shared by every provider's nodes; the composite
            # executor removes it only after all providers prove absence.
            False)
        return self.driver.plan(config, request)

    def deploy_with_legacy(self, config, legacy_deploy):
        provider = self.driver.provider
        if provider not in (config.get('providers') or ()):
            raise ValueError(provider + ' is not part of this ' + self.profile.label() + ' deployment')
        if not callable(legacy_deploy):
            raise TypeError('Legacy executor must be callable')
        chunks = [chunk for chunk in json.loads(Path(config['node_chunks_file']).read_text())
                  if chunk.get('provider') == provider]
        nodes = []
        try:
            for chunk in chunks:
                node = self._node_config(config, chunk)
                self.driver.prepare_state(node)
                if not self.driver.deploy(node):
                    raise RuntimeError(provider + ' node provisioning failed: ' + node['deployment_id'])
                address = ipaddress.ip_address(
                    self.driver.public_address(node['deployment_id'], config))
                if address.version != 4 or not address.is_global:
                    raise ValueError(provider + ' node returned an invalid public IP')
                nodes.append({'node_name': chunk['node_name'], 'ip': str(address),
                              'idx': chunk['idx'], 'cidrs': chunk['cidrs'],
                              'ip_count': chunk['ip_count'],
                              'deployment_id': node['deployment_id']})
        except (Exception, KeyboardInterrupt) as exc:
            logging.error('%s %s provisioning failed: %s', provider, self.profile.label(), exc)
            if config.get('teardown_after_scan', True):
                self._remove_nodes(config)
            return False
        config[provider + '_nodes'] = nodes
        # Exactly one call into the preserved composite executor; it removes the
        # legacy providers' nodes in-play and owns the shared key's lifecycle.
        success = legacy_deploy(config)
        if config.get('teardown_after_scan', True):
            return self._remove_nodes(config) and success
        return success

    def _remove_nodes(self, config):
        # The composite ID owns every derived node; a node ID owns only itself.
        wanted = config['deployment_id']
        verified = True
        for state in self.driver.list_states(config):
            if state.get('provider_workload') != self.profile.workload or (
                    state['deployment_id'] != wanted and
                    not state['deployment_id'].startswith(wanted + '-n')):
                continue
            request = self.driver.cleanup_request(
                dict(config, deployment_id=state['deployment_id']), identity=False)
            verified = self.driver.cleanup(request) and verified
        return verified

    def cleanup(self, config):
        if not self._remove_nodes(config):
            return False
        from .cleanup_engine import archive_deployment_logs, cleanup_ssh_keys_for_deployment
        if not config.get('preserve_local_keys') and 'ownership_marker' not in config:
            # Only the composite record, never a node state, retires the shared key.
            cleanup_ssh_keys_for_deployment(config['deployment_id'], config.get('ssh_key_path'))
        archive_deployment_logs(config['deployment_id'])
        return True


class HandoffAdapter(SingleVmAdapter):
    """Provision one VM and hand it to a module that configures the host itself."""

    def deploy(self, config):
        infrastructure = self._infrastructure_config(config)
        self.driver.prepare_state(infrastructure)
        self.driver.prepare_ssh_key(infrastructure)
        if not self.driver.deploy(infrastructure):
            return False
        parsed = self._public_ipv4(
            self.driver.public_address(infrastructure['deployment_id'], config))
        config.update(self.driver.exported_config(infrastructure))
        config.update(target_host=str(parsed), ssh_user=self.driver.ssh_user,
                      ssh_key=infrastructure['ssh_private_key_path'],
                      provider_workload=self.profile.workload)
        return True

    def cleanup(self, config):
        return self.driver.cleanup(self.driver.cleanup_request(config))


_KINDS = {'single': SingleVmAdapter, 'components': ComponentAdapter,
          'nodes': NodeAdapter, 'handoff': HandoffAdapter}


def load_driver(reference):
    driver = _load(reference)()
    if not isinstance(driver, CloudDriver):
        raise TypeError('Provider driver is not a CloudDriver: ' + reference)
    return driver.check()


def driver_route(reference, workload):
    """Build the adapter a driver-backed provider uses for a workload, or None."""
    driver = load_driver(reference)
    if workload == 'infrastructure':
        return DriverInfrastructureAdapter(driver)
    profile = load_profile(workload)
    if profile is None:
        return None
    return _KINDS[profile.kind](driver, profile)


def adapter(provider, workload):
    """Resolve a provider's route for one workload through the registry."""
    from .provider_registry import provider_dispatcher
    return provider_dispatcher(provider).route(workload)
