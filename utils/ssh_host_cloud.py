"""Adopt-a-host driver: a server the operator already owns, reached over root SSH.

There is no provisioning API. The driver installs the deployment key on the
host with the operator's existing root access, enforces the workload's
inbound rules with ufw, and on cleanup revokes the key again. The host itself
stays until the operator removes it. FlokiNET (hand-ordered servers) and
local (bare metal, home-lab VMs) are the two registrations.
"""

import re
import shlex
import subprocess
import time
from pathlib import Path

from .driver_base import DISABLE_PASSWORD_LOGIN, StatefulDriver, host_cidr
from .ssh_utils import ssh_options


class SshHostDriver(StatefulDriver):
    ssh_user = 'root'
    provider_keys = ('host', 'bootstrap_key')
    deploy_timeout = 600
    # One pre-provisioned host per deployment; a scan pool gets one node.
    node_quota = 1
    adopt_prompt = 'Enter one host that already accepts root SSH.'
    host_label = 'Host'
    keep_message = ('keeps running: the deployment key is revoked, but the service and '
                    'the host itself must be removed by hand.')

    # --- configuration -----------------------------------------------------
    def gather_config(self):
        print(self.adopt_prompt)
        return {
            self._key('host'): input(self.host_label + ' IPv4: ').strip(),
            self._key('bootstrap_key'): input(
                'Private key that currently opens root@host (blank = ssh agent/default keys): ').strip(),
            'operator_ip': input('Operator IPv4 (SSH /32): ').strip(),
        }

    def validate_provider(self, result):
        result[self._key('host')] = host_cidr(
            result.get(self._key('host')), self._key('host'),
            private_ok=self.private_addresses).removesuffix('/32')
        key = result.get(self._key('bootstrap_key')) or ''
        if not isinstance(key, str) or (key and re.search(r'[\0\n]', key)):
            raise ValueError('Invalid ' + self._key('bootstrap_key'))
        result[self._key('bootstrap_key')] = key

    def plan(self, config, request):
        result = self.base_plan(config, request)
        result[self._key('host')] = config[self._key('host')]
        result[self._key('bootstrap_key')] = config.get(self._key('bootstrap_key'), '')
        return result

    def planned_ids(self, state):
        return {'host': state[self._key('host')]}

    def lock_target(self, state):
        return state[self._key('host')]

    def cleanup_timeout(self, state):
        return 120

    def check_connection(self):
        return {'mode': 'bring-your-own-host'}

    # --- SSH ---------------------------------------------------------------
    def _known_hosts(self, state):
        return self.log_dir(state) / (state['deployment_id'] + '-known-hosts')

    def _bootstrap_argv(self, state):
        key = state.get(self._key('bootstrap_key')) or None
        return ['ssh', *ssh_options(self._known_hosts(state),
                                    Path(key).expanduser() if key else None,
                                    state.get('ssh_proxy')),
                'root@' + state[self._key('host')]]

    def _run_stdin(self, argv, script, deadline):
        self.log_dir({}).mkdir(parents=True, exist_ok=True)
        timeout = 300 if deadline is None else max(1, min(300, deadline - time.monotonic()))
        result = subprocess.run(argv, input=script, text=True, capture_output=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError('{0} host command failed ({1}): {2}'.format(
                self.provider, result.returncode, (result.stderr or result.stdout).strip()[-2000:]))
        return result

    def _firewall_script(self, state):
        lines = ['command -v ufw >/dev/null || { apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q ufw; }',
                 'ufw --force reset >/dev/null', 'ufw default deny incoming >/dev/null',
                 'ufw default allow outgoing >/dev/null',
                 'ufw allow from ' + shlex.quote(state['operator_ip']) + ' to any port 22 proto tcp >/dev/null']
        for rule in state[self._key('inbound_rules')]:
            source = '' if rule['source'] == '*' else 'from ' + shlex.quote(rule['source']) + ' '
            lines.append('ufw allow ' + source + 'to any port ' + rule['port'] + ' proto ' +
                         rule['protocol'].lower() + ' >/dev/null')
        lines.append('ufw --force enable >/dev/null')
        return lines

    def create(self, state, deadline):
        public_key = Path(state['ssh_key_path']).read_text().strip()
        script = '\n'.join([
            'set -eu', 'umask 077', 'mkdir -p /root/.ssh', 'touch /root/.ssh/authorized_keys',
            'grep -qxF ' + shlex.quote(public_key) + ' /root/.ssh/authorized_keys || '
            'printf "%s\\n" ' + shlex.quote(public_key) + ' >> /root/.ssh/authorized_keys',
            'chmod 700 /root/.ssh', 'chmod 600 /root/.ssh/authorized_keys',
            *DISABLE_PASSWORD_LOGIN, *self._firewall_script(state), 'echo adopted']) + '\n'
        self._run_stdin(self._bootstrap_argv(state) + ['bash', '-s'], script, deadline)
        state.setdefault('resources', {})['host'] = state[self._key('host')]
        return {'public_ip': state[self._key('host')]}

    def delete(self, state, deadline):
        public_key = Path(state['ssh_key_path']).read_text().strip() if Path(state['ssh_key_path']).is_file() else ''
        if public_key:
            script = '\n'.join([
                'set -eu', 'umask 077',
                'test -f /root/.ssh/authorized_keys || exit 0',
                'grep -vxF ' + shlex.quote(public_key) + ' /root/.ssh/authorized_keys > /root/.ssh/authorized_keys.new || true',
                'mv /root/.ssh/authorized_keys.new /root/.ssh/authorized_keys', 'echo revoked']) + '\n'
            argv = self.ssh_argv(state, state[self._key('host')], self._known_hosts(state))
            try:
                self._run_stdin(argv + ['bash', '-s'], script, deadline)
            except RuntimeError:
                self._run_stdin(self._bootstrap_argv(state) + ['bash', '-s'], script, deadline)
        print('{0} host {1} {2}'.format(self.provider, state[self._key('host')], self.keep_message))

    def inspect(self, state, deadline):
        argv = self.ssh_argv(state, state[self._key('host')], self._known_hosts(state))
        result = self.run_command(argv + ['true'], timeout=15, deadline=deadline, check=False)
        return {'healthy': result.returncode == 0,
                'detail': 'host accepts the deployment key' if result.returncode == 0 else 'host refused SSH'}
