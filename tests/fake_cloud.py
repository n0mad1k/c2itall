"""A complete, minimal CloudDriver kept in memory.

This is the reference for adding a provider: everything the generic
adapters, menus, teardown, health checks and the live harness need from a
provider is on this class, and nothing here names a workload. Tests
register it as the provider ``fakecloud`` and drive every workload through
it; see docs/EXTENDING.md.
"""

import json
from pathlib import Path
import subprocess

from utils.cloud_driver import CloudDriver


class FakeDriver(CloudDriver):
    provider = 'fakecloud'
    ssh_user = 'operator'
    prefix = 'fakecloud_'
    identity_keys = ('fakecloud_project',)
    option_keys = ('fakecloud_state_dir',)
    node_quota = 3

    def __init__(self):
        self.states = {}
        self.addresses = {}
        self.calls = []
        self.runs = []
        self.deploy_result = True

    # --- configuration -----------------------------------------------------
    def gather_config(self):
        return {'provider': self.provider, 'fakecloud_project': 'lab',
                'fakecloud_region': 'moon-1'}

    def validate_config(self, config, require_key=True):
        if not config.get('fakecloud_project'):
            raise ValueError('fakecloud_project is required')
        return dict(config)

    def image(self, role):
        return {'ubuntu': 'img-ubuntu', 'kali': 'img-kali'}[role]

    def region(self, config):
        return config.get('fakecloud_region', 'moon-1')

    # --- lifecycle ---------------------------------------------------------
    def plan(self, config, request):
        return {
            'provider': self.provider, 'provider_workload': request.workload,
            'deployment_id': request.deployment_id,
            'fakecloud_project': config.get('fakecloud_project', 'lab'),
            'fakecloud_region': self.region(config),
            'fakecloud_image': self.image(request.image_role),
            'fakecloud_disk_gb': request.disk_gb,
            'fakecloud_rules': list(request.inbound_rules),
            'fakecloud_state_dir': config.get('fakecloud_state_dir'),
            'operator_ip': config.get('operator_ip'),
            'ssh_key_path': request.ssh_public,
            'ssh_private_key_path': request.ssh_private,
            'ssh_key_generated': request.ssh_generated,
        }

    def prepare_state(self, infrastructure):
        self.calls.append(('prepare_state', infrastructure['deployment_id']))
        self.states[infrastructure['deployment_id']] = dict(infrastructure)

    def prepare_ssh_key(self, infrastructure):
        self.calls.append(('prepare_ssh_key', infrastructure['deployment_id']))
        if infrastructure['ssh_key_generated']:
            private = Path(infrastructure['ssh_private_key_path'])
            private.parent.mkdir(parents=True, exist_ok=True)
            private.write_text('fake private key\n')
            Path(infrastructure['ssh_key_path']).write_text('ssh-ed25519 AAAA fake\n')

    def deploy(self, infrastructure):
        self.calls.append(('deploy', infrastructure['deployment_id']))
        if self.deploy_result:
            self.addresses[infrastructure['deployment_id']] = (
                '8.8.8.' + str(10 + len(self.addresses)))
        return self.deploy_result

    def public_address(self, deployment_id, config):
        return self.addresses[deployment_id]

    def cleanup(self, request):
        self.calls.append(('cleanup', request['deployment_id'], tuple(sorted(request))))
        self.states.pop(request['deployment_id'], None)
        self.addresses.pop(request['deployment_id'], None)
        return True

    def health(self, state):
        return {'healthy': state['deployment_id'] in self.addresses}

    # --- durable state -----------------------------------------------------
    def load_state(self, deployment_id):
        return self.states.get(deployment_id)

    def list_states(self, config=None):
        return [dict(state) for state in self.states.values()]

    def local_artifacts(self, deployment_id, config=None):
        return [Path('/nonexistent/fakecloud') / (deployment_id + '.json')]

    # --- controller plumbing ----------------------------------------------
    def log_dir(self, config):
        return Path(config['fakecloud_state_dir']) / 'logs'

    def run_command(self, argv, timeout=60, deadline=None, check=True):
        variables = None
        if '--extra-vars' in argv:
            variables = json.loads(Path(argv[argv.index('--extra-vars') + 1][1:]).read_text())
        self.runs.append({'argv': [str(arg) for arg in argv], 'variables': variables})
        return subprocess.CompletedProcess(list(argv), 0, 'ok\n', '')

    def check_connection(self):
        return {'project': 'lab'}


DRIVER = FakeDriver()


def fake_driver():
    return DRIVER
