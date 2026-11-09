"""FlokiNET driver: a host the operator ordered by hand, adopted through SSH.

FlokiNET has no provisioning API. The driver installs the deployment key on
the host with the operator's existing root access, enforces the workload's
inbound rules with ufw, and on cleanup revokes the key again. The server
itself stays until the operator cancels it in the FlokiNET panel.
"""

import re
import shlex
import subprocess
import time
from pathlib import Path

from .driver_base import STATE_ROOT, StatefulDriver, host_cidr


class FlokinetDriver(StatefulDriver):
    provider = 'flokinet'
    ssh_user = 'root'
    prefix = 'flokinet_'
    identity_keys = ('flokinet_host',)
    option_keys = ('flokinet_state_dir', 'flokinet_cleanup_deadline')
    provider_keys = ('host', 'bootstrap_key')
    state_root = STATE_ROOT / 'flokinet'
    deploy_timeout = 600
    # One pre-provisioned host per deployment; a scan pool gets one node.
    node_quota = 1

    # --- configuration -----------------------------------------------------
    def gather_config(self):
        print('FlokiNET servers are ordered by hand; enter one host that already accepts root SSH.')
        return {
            'flokinet_host': input('FlokiNET host public IPv4: ').strip(),
            'flokinet_bootstrap_key': input(
                'Private key that currently opens root@host (blank = ssh agent/default keys): ').strip(),
            'operator_ip': input('Operator public IPv4 (SSH /32): ').strip(),
        }

    def validate_provider(self, result):
        result['flokinet_host'] = host_cidr(result.get('flokinet_host'), 'flokinet_host').removesuffix('/32')
        key = result.get('flokinet_bootstrap_key') or ''
        if not isinstance(key, str) or (key and re.search(r'[\0\n]', key)):
            raise ValueError('Invalid flokinet_bootstrap_key')
        result['flokinet_bootstrap_key'] = key

    def plan(self, config, request):
        result = self.base_plan(config, request)
        result.update(flokinet_host=config['flokinet_host'],
                      flokinet_bootstrap_key=config.get('flokinet_bootstrap_key', ''))
        return result

    def planned_ids(self, state):
        return {'host': state['flokinet_host']}

    def lock_target(self, state):
        return state['flokinet_host']

    def cleanup_timeout(self, state):
        return 120

    def check_connection(self):
        return {'mode': 'bring-your-own-host'}

    # --- SSH ---------------------------------------------------------------
    def _bootstrap_argv(self, state):
        argv = ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=accept-new', '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'UserKnownHostsFile=' + str(self.log_dir(state) / (state['deployment_id'] + '-known-hosts')),
                '-o', 'ConnectTimeout=10']
        if state.get('flokinet_bootstrap_key'):
            argv += ['-i', str(Path(state['flokinet_bootstrap_key']).expanduser()), '-o', 'IdentitiesOnly=yes']
        return argv + ['root@' + state['flokinet_host']]

    def _run_stdin(self, argv, script, deadline):
        self.log_dir({}).mkdir(parents=True, exist_ok=True)
        timeout = 300 if deadline is None else max(1, min(300, deadline - time.monotonic()))
        result = subprocess.run(argv, input=script, text=True, capture_output=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError('FlokiNET host command failed ({0}): {1}'.format(
                result.returncode, (result.stderr or result.stdout).strip()[-2000:]))
        return result

    def _firewall_script(self, state):
        lines = ['command -v ufw >/dev/null || { apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q ufw; }',
                 'ufw --force reset >/dev/null', 'ufw default deny incoming >/dev/null',
                 'ufw default allow outgoing >/dev/null',
                 'ufw allow from ' + shlex.quote(state['operator_ip']) + ' to any port 22 proto tcp >/dev/null']
        for rule in state['flokinet_inbound_rules']:
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
            *self._firewall_script(state), 'echo adopted']) + '\n'
        self._run_stdin(self._bootstrap_argv(state) + ['bash', '-s'], script, deadline)
        state.setdefault('resources', {})['host'] = state['flokinet_host']
        return {'public_ip': state['flokinet_host']}

    def delete(self, state, deadline):
        public_key = Path(state['ssh_key_path']).read_text().strip() if Path(state['ssh_key_path']).is_file() else ''
        if public_key:
            script = '\n'.join([
                'set -eu', 'umask 077',
                'test -f /root/.ssh/authorized_keys || exit 0',
                'grep -vxF ' + shlex.quote(public_key) + ' /root/.ssh/authorized_keys > /root/.ssh/authorized_keys.new || true',
                'mv /root/.ssh/authorized_keys.new /root/.ssh/authorized_keys', 'echo revoked']) + '\n'
            argv = self.ssh_argv(state, state['flokinet_host'],
                                 self.log_dir(state) / (state['deployment_id'] + '-known-hosts'))
            try:
                self._run_stdin(argv + ['bash', '-s'], script, deadline)
            except RuntimeError:
                self._run_stdin(self._bootstrap_argv(state) + ['bash', '-s'], script, deadline)
        print('FlokiNET host ' + state['flokinet_host'] + ' keeps running: the deployment key is revoked, '
              'but the service and the server itself must be removed by hand in the FlokiNET panel.')

    def inspect(self, state, deadline):
        argv = self.ssh_argv(state, state['flokinet_host'],
                             self.log_dir(state) / (state['deployment_id'] + '-known-hosts'))
        result = self.run_command(argv + ['true'], timeout=15, deadline=deadline, check=False)
        return {'healthy': result.returncode == 0,
                'detail': 'host accepts the deployment key' if result.returncode == 0 else 'host refused SSH'}


def flokinet_driver():
    return FlokinetDriver()


def gather_flokinet_config():
    return FlokinetDriver().gather_config()
