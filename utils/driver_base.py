"""Recoverable lifecycle shared by drivers that create VMs through a provider API.

A StatefulDriver persists intent before any provider call, serializes the
lifecycle per deployment, validates the inputs every provider shares
(deployment ID, operator /32, inbound rules, key paths) and waits for SSH.
A concrete driver adds the validation of its own prefixed keys, the
deterministic resource identities it plans, and the API calls that create,
inspect and remove those resources.
"""

import ipaddress
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from .cloud_driver import CloudDriver
from .controller_io import ROOT, interruption_handlers, run_command, secure_directory
from .state_store import StateStore

ID_PATTERN = re.compile(r'[a-z0-9][a-z0-9-]{0,39}')
WORKLOAD_PATTERN = re.compile(r'[a-z][a-z0-9_]{1,39}')
RULE_NAME = re.compile(r'[a-z][a-z0-9-]{0,39}')
PUBLIC_KEY = re.compile(r'(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+(?: [^\r\n]+)?')
HOSTNAME = re.compile(r'(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
EDGE_FORWARDING = ('HttpsOnly', 'HttpOnly', 'MatchRequest')
COMMON_KEYS = frozenset({
    'provider', 'deployment_id', 'deployment_type', 'infrastructure_deployment',
    'provider_workload', 'operator_ip', 'ssh_key_path', 'ssh_private_key_path',
    'ssh_key_generated',
})


def host_cidr(value, label):
    """One global IPv4 host as the /32 a rule or identity names."""
    text = str(value or '').strip()
    if '/' not in text:
        text += '/32'
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        raise ValueError(label + ' must be one global IPv4 host')
    if network.version != 4 or network.prefixlen != 32 or not network.network_address.is_global:
        raise ValueError(label + ' must be one global IPv4 host')
    return str(network)


def ownership_tags(state):
    return {'c2itall-deployment': state['deployment_id'], 'c2itall-owner': state['ownership_marker']}


class StatefulDriver(CloudDriver):
    # Subclasses set these; the prefix keys below derive from them.
    state_root = None
    edge_source = None
    deploy_timeout = 1800
    max_rules = 16
    disk_range = (8, 2048)

    def __init__(self):
        self.store = StateStore(
            validate=lambda state: self.validate_config(state, require_key=False),
            planned_ids=self.planned_ids, label=self.provider)

    # --- provider hooks ------------------------------------------------------
    def validate_provider(self, result):
        """Validate and normalize the prefixed keys in place."""
        raise NotImplementedError

    def planned_ids(self, state):
        raise NotImplementedError

    def lock_target(self, state):
        """The provider-side identity cleanup and deploy must serialize on."""
        raise NotImplementedError

    def create(self, state, deadline):
        """Create or resume the planned resources; return the outputs dict."""
        raise NotImplementedError

    def delete(self, state, deadline):
        """Delete owned resources and raise unless they are proven absent."""
        raise NotImplementedError

    def inspect(self, state, deadline):
        raise NotImplementedError

    def cleanup_timeout(self, state):
        return 600

    # --- keys ---------------------------------------------------------------
    @property
    def config_keys(self):
        return COMMON_KEYS | {self.prefix + name for name in self.provider_keys}

    # Prefixed keys beyond the shared ones every stateful driver carries.
    provider_keys = ()

    def _key(self, name):
        return self.prefix + name

    def state_dir(self, config=None):
        return Path((config or {}).get(self._key('state_dir')) or self.state_root)

    # --- validation ---------------------------------------------------------
    def validate_config(self, config, require_key=True):
        keys = self.config_keys | {self._key(name) for name in (
            'inbound_rules', 'disk_gb', 'edge', 'image_role', 'state_dir')}
        result = {k: v for k, v in config.items() if k in keys}
        if result.get('provider') != self.provider or result.get('infrastructure_deployment') is not True:
            raise ValueError(self.provider + ' supports infrastructure deployments only')
        if result.get('deployment_type') != 'infrastructure':
            raise ValueError(self.provider + ' deployment_type must be infrastructure')
        workload = result.get('provider_workload', 'infrastructure')
        if not isinstance(workload, str) or not WORKLOAD_PATTERN.fullmatch(workload):
            raise ValueError('Invalid ' + self.provider + ' provider_workload')
        result['provider_workload'] = workload
        deployment_id = result.get('deployment_id', '')
        if not isinstance(deployment_id, str) or not ID_PATTERN.fullmatch(deployment_id):
            raise ValueError('Invalid ' + self.provider + ' deployment ID')
        result['operator_ip'] = host_cidr(result.get('operator_ip'), 'operator_ip')
        disk = result.get(self._key('disk_gb'), 32)
        if type(disk) is not int or not self.disk_range[0] <= disk <= self.disk_range[1]:
            raise ValueError(self._key('disk_gb') + ' must be an integer from {0} through {1}'.format(*self.disk_range))
        result[self._key('disk_gb')] = disk
        role = result.get(self._key('image_role'), 'ubuntu')
        if role not in ('ubuntu', 'ubuntu2204', 'kali'):
            raise ValueError('Invalid ' + self.provider + ' image role')
        result[self._key('image_role')] = role
        result[self._key('inbound_rules')] = self._rules(result.get(self._key('inbound_rules'), []))
        edge = result.get(self._key('edge'))
        if edge is not None:
            if self.edge_source is None:
                raise ValueError(self.provider + ' cannot place an edge in front of a VM')
            if (not isinstance(edge, dict) or set(edge) != {'host_header', 'forwarding', 'name'}
                    or not HOSTNAME.fullmatch(str(edge['host_header']))
                    or edge['forwarding'] not in EDGE_FORWARDING
                    or not re.fullmatch(r'[a-z][a-z0-9-]{0,45}', str(edge['name']))):
                raise ValueError('Invalid ' + self.provider + ' edge request')
            result[self._key('edge')] = {key: str(edge[key]) for key in ('host_header', 'forwarding', 'name')}
        state_dir = result.get(self._key('state_dir'))
        if state_dir is not None and (not isinstance(state_dir, str) or not state_dir):
            raise ValueError('Invalid ' + self.provider + ' state directory')
        public = Path(result['ssh_key_path']).expanduser().absolute()
        private = Path(result.get('ssh_private_key_path', str(public).removesuffix('.pub'))).expanduser().absolute()
        if public == private:
            raise ValueError('ssh_key_path must point to a .pub public key')
        result.update(ssh_key_path=str(public), ssh_private_key_path=str(private))
        if not isinstance(result.get('ssh_key_generated', False), bool):
            raise ValueError('ssh_key_generated must be a boolean')
        result.setdefault('ssh_key_generated', False)
        if result['ssh_key_generated']:
            expected = Path.home() / '.ssh' / ('c2deploy_' + deployment_id)
            if private != expected or public != Path(str(expected) + '.pub'):
                raise ValueError('Generated SSH key paths do not belong to this deployment')
            if private.is_symlink() or public.is_symlink():
                raise ValueError('Generated SSH key paths must not be symlinks')
        self.validate_provider(result)
        if require_key and not PUBLIC_KEY.fullmatch(public.read_text().strip()):
            raise ValueError('Invalid SSH public key')
        return result

    def _rules(self, rules):
        if not isinstance(rules, list) or len(rules) > self.max_rules:
            raise ValueError(self._key('inbound_rules') + ' must be a list of at most {0} rules'.format(self.max_rules))
        normalized, seen = [], set()
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {'name', 'protocol', 'port', 'source'}:
                raise ValueError('Invalid ' + self.provider + ' inbound rule shape')
            protocol = str(rule['protocol']).title()
            try:
                port = int(rule['port'])
            except (TypeError, ValueError):
                raise ValueError('Invalid ' + self.provider + ' inbound rule port')
            source = rule['source']
            if source == 'edge':
                raise ValueError('Edge rules must be translated by the driver plan')
            if source not in ('*', self.edge_source):
                source = host_cidr(source, 'inbound rule source')
            if (not isinstance(rule['name'], str) or not RULE_NAME.fullmatch(rule['name'])
                    or protocol not in ('Tcp', 'Udp') or not 1 <= port <= 65535 or port == 22):
                raise ValueError('Invalid ' + self.provider + ' inbound rule')
            identity = (protocol, port, source)
            if identity in seen:
                raise ValueError('Duplicate ' + self.provider + ' inbound rule')
            seen.add(identity)
            normalized.append({'name': rule['name'], 'protocol': protocol,
                               'port': str(port), 'source': source})
        return normalized

    # --- planning -----------------------------------------------------------
    def base_plan(self, config, request):
        rules = []
        for rule in request.inbound_rules:
            if rule['source'] == 'edge':
                if self.edge_source is None:
                    raise ValueError(self.provider + ' has no edge network to admit')
                rule = dict(rule, source=self.edge_source)
            rules.append(dict(rule))
        result = {
            'provider': self.provider, 'provider_workload': request.workload,
            'deployment_id': request.deployment_id,
            'deployment_type': 'infrastructure', 'infrastructure_deployment': True,
            'operator_ip': config['operator_ip'],
            self._key('inbound_rules'): rules,
            self._key('disk_gb'): request.disk_gb,
            self._key('image_role'): request.image_role or 'ubuntu',
            'ssh_private_key_path': request.ssh_private,
            'ssh_key_path': request.ssh_public,
            'ssh_key_generated': request.ssh_generated,
        }
        for name in ('state_dir', 'deadline', 'cleanup_deadline'):
            if self._key(name) in config:
                result[self._key(name)] = config[self._key(name)]
        if request.edge:
            result[self._key('edge')] = dict(request.edge)
        return result

    # --- durable state ------------------------------------------------------
    def lock(self, state):
        return self.store.lock(state['deployment_id'], self.lock_target(state), self.state_dir(state))

    def save(self, state):
        self.store.save(state, self.state_dir(state))

    def prepare_state(self, infrastructure):
        validated = self.validate_config(infrastructure, require_key=False)
        with self.lock(validated):
            return self.store.prepare(validated, self.state_dir(validated))

    def prepare_ssh_key(self, infrastructure):
        """Generate the deployment key behind the lifecycle lock, in a bounded child."""
        normalized = self.validate_config(infrastructure, require_key=False)
        with self.lock(normalized):
            state = self.prepare_state(infrastructure)
            if not state['ssh_key_generated']:
                return state['ssh_private_key_path']
            with secure_directory(Path(state['ssh_private_key_path']).parent, create=True):
                pass
            code = ('import sys; from utils.ssh_utils import generate_ssh_key; '
                    'sys.exit(0 if generate_ssh_key(sys.argv[1]) else 1)')
            self.run_command([sys.executable, '-c', code, state['deployment_id']],
                             timeout=60, deadline=infrastructure.get(self._key('deadline')))
            return state['ssh_private_key_path']

    def load_state(self, deployment_id):
        if not isinstance(deployment_id, str) or not ID_PATTERN.fullmatch(deployment_id):
            return None
        try:
            return self.store.load(deployment_id, self.state_root)
        except FileNotFoundError:
            return None

    def list_states(self, config=None):
        return self.store.list(self.state_dir(config))

    def local_artifacts(self, deployment_id, config=None):
        return [self.store.path(deployment_id, self.state_dir(config))]

    def log_dir(self, config):
        return self.state_dir(config) / 'logs'

    # --- lifecycle ----------------------------------------------------------
    def deploy(self, infrastructure):
        try:
            normalized = self.validate_config(infrastructure, require_key=False)
            with self.lock(normalized):
                return self._deploy_locked(infrastructure)
        except (Exception, KeyboardInterrupt) as exc:
            logging.error('%s deployment unavailable: %s', self.provider, exc)
            return False

    def _deploy_locked(self, config):
        state = None
        deadline = config.get(self._key('deadline'), time.monotonic() + self.deploy_timeout)
        try:
            with interruption_handlers():
                self.validate_config(config)
                state = self.prepare_state(config)
                state['status'] = 'provisioning'
                self.save(state)
                outputs = self.create(state, deadline)
                state.update(status='waiting_for_ssh', outputs=outputs)
                self.save(state)
                self.wait_for_ssh(state, deadline)
                state['status'] = 'ready'
                self.save(state)
                return True
        except (Exception, KeyboardInterrupt) as exc:
            logging.error('%s deployment failed: %s', self.provider, exc)
            if state:
                state.update(status='failed', error=str(exc))
                self.save(state)
            return False

    def public_address(self, deployment_id, config):
        state = self.store.load(deployment_id, self.state_dir(config))
        return (state.get('outputs') or {}).get('public_ip', '')

    def cleanup(self, request):
        try:
            state = self.store.load(request['deployment_id'], self.state_dir(request))
            with self.lock(state):
                return self._cleanup_locked(request, state)
        except (Exception, KeyboardInterrupt) as exc:
            logging.error('%s cleanup unavailable; state retained: %s', self.provider, exc)
            return False

    def _cleanup_locked(self, request, state):
        deadline = request.get(self._key('cleanup_deadline'))
        if deadline is None:
            deadline = time.monotonic() + self.cleanup_timeout(state)
        try:
            with interruption_handlers():
                for key in self.identity_keys + ('ownership_marker',):
                    if key in request and request[key] != state[key]:
                        raise ValueError('Cleanup {0} does not match saved state'.format(key))
                state.update(status='deleting', deletion_started=True)
                self.save(state)
                self.delete(state, deadline)
                self.store.retire(state, self.state_dir(request))
                return True
        except (Exception, KeyboardInterrupt) as exc:
            logging.error('%s cleanup failed; retaining state and resource IDs: %s', self.provider, exc)
            state.update(status='cleanup_failed', error=str(exc))
            self.save(state)
            return False

    def health(self, config):
        state = self.store.load(config['deployment_id'], self.state_dir(config))
        for key in self.identity_keys + ('ownership_marker',):
            if key in config and config[key] != state[key]:
                raise ValueError('Health-check identity does not match saved state')
        deadline = min(config.get(self._key('deadline'), float('inf')), time.monotonic() + 60)
        return self.inspect(state, deadline)

    def exported_config(self, infrastructure):
        exported = super().exported_config(infrastructure)
        # Credentials never enter a plan, so every prefixed key is safe to keep.
        exported.pop(self._key('inbound_rules'), None)
        return exported

    # --- SSH ----------------------------------------------------------------
    def ssh_argv(self, state, address, known_hosts, key=None):
        return ['ssh', '-F', '/dev/null', '-i', str(key or state['ssh_private_key_path']),
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'StrictHostKeyChecking=accept-new',
                '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'UserKnownHostsFile=' + str(known_hosts),
                '-o', 'ConnectTimeout=10', self.ssh_user + '@' + str(address)]

    def wait_for_ssh(self, state, deadline):
        """Return only after the VM accepts the deployment key."""
        address = ipaddress.ip_address((state.get('outputs') or {}).get('public_ip', ''))
        if address.version != 4 or not address.is_global:
            raise RuntimeError(self.provider + ' returned an invalid public IP')
        private_key = Path(state['ssh_private_key_path'])
        if (not private_key.is_file() or private_key.is_symlink()
                or private_key.stat().st_uid != os.getuid()):
            raise RuntimeError(self.provider + ' SSH private key is unavailable')
        with tempfile.TemporaryDirectory(prefix='c2itall-' + self.provider + '-ssh-') as temporary:
            command = self.ssh_argv(state, address, Path(temporary) / 'known_hosts') + ['true']
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError(self.provider + ' SSH readiness deadline exceeded')
                try:
                    result = self.run_command(command, timeout=15, deadline=deadline, check=False)
                except subprocess.TimeoutExpired:
                    result = None
                if result is not None and result.returncode == 0:
                    return
                time.sleep(min(5, max(0, deadline - time.monotonic())))

    def run_command(self, argv, timeout=60, deadline=None, check=True):
        return run_command(argv, timeout=timeout, deadline=deadline, check=check,
                           label=self.provider)


def wait_until(deadline, predicate, interval=5, what='condition'):
    """Poll a predicate until it returns a truthy value or the deadline passes."""
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise TimeoutError(what + ' deadline exceeded')
        time.sleep(min(interval, max(0, deadline - time.monotonic())))


STATE_ROOT = ROOT / 'deployments'
