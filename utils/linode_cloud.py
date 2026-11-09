"""Linode cloud driver: one Linode behind one Cloud Firewall per deployment.

The API is called directly over HTTPS; the token comes from the controller
environment or Infisical and never enters a plan or a state file. Both
resources carry the deployment and ownership tags, and cleanup refuses
anything that does not.
"""

import os
import re
import secrets
import subprocess
from pathlib import Path

import requests

from .driver_base import STATE_ROOT, StatefulDriver, wait_until

API = 'https://api.linode.com/v4'
IMAGES = {'ubuntu': 'linode/ubuntu24.04', 'ubuntu2204': 'linode/ubuntu22.04', 'kali': 'linode/kali'}
ATTACK_BOX_SIZES = {'small': 'g6-standard-2', 'medium': 'g6-standard-4',
                    'large': 'g6-standard-8', 'xlarge': 'g6-standard-16'}
REGION = re.compile(r'[a-z]{2}-[a-z0-9-]{2,20}')
PLAN = re.compile(r'g\d+-[a-z]+-\d+')


def ownership_labels(state):
    # Linode tags are flat strings of at most 50 characters.
    return ['c2itall-deployment-' + state['deployment_id'],
            'c2itall-owner-' + state['ownership_marker'].replace('-', '')]


class LinodeDriver(StatefulDriver):
    provider = 'linode'
    ssh_user = 'root'
    prefix = 'linode_'
    identity_keys = ('linode_region',)
    option_keys = ('linode_state_dir', 'linode_cleanup_deadline')
    provider_keys = ('region', 'instance_type')
    state_root = STATE_ROOT / 'linode'
    node_quota = 10

    def __init__(self):
        super().__init__()
        self._token = None
        self._types = None

    # --- configuration -----------------------------------------------------
    def gather_config(self):
        regions = [region.strip() for region in input(
            'Linode region(s), comma-separated; pools spread across them [us-east]: ').split(',')
            if region.strip()] or ['us-east']
        return {
            'linode_region': regions[0], 'linode_regions': regions,
            'linode_instance_type': input('Linode plan [g6-standard-2]: ').strip() or 'g6-standard-2',
            'operator_ip': input('Operator public IPv4 (SSH /32): ').strip(),
        }

    def validate_provider(self, result):
        if not REGION.fullmatch(str(result.get('linode_region', ''))):
            raise ValueError('Invalid linode_region')
        result.setdefault('linode_instance_type', 'g6-standard-2')
        if not PLAN.fullmatch(str(result['linode_instance_type'])):
            raise ValueError('Invalid linode_instance_type')

    region_key = 'linode_region'

    def region(self, config):
        return config.get('linode_region', 'us-east')

    def regions(self, config):
        return list(config.get('linode_regions') or [self.region(config)])

    def image(self, role):
        return IMAGES[role]

    def apply_profile(self, config, workload, profile, value):
        if workload != 'attack_box' or profile != 'instance_size':
            return config
        if value not in ATTACK_BOX_SIZES:
            raise ValueError('Unsupported Linode attack-box instance size')
        config['linode_instance_type'] = ATTACK_BOX_SIZES[value]
        return config

    def plan(self, config, request):
        result = self.base_plan(config, request)
        result.update(linode_region=self.region(config),
                      linode_instance_type=config.get('linode_instance_type', 'g6-standard-2'))
        return result

    def planned_ids(self, state):
        name = 'c2itall-' + state['deployment_id']
        return {'linode': name, 'firewall': name}

    def lock_target(self, state):
        return state['linode_region'] + '/c2itall-' + state['deployment_id']

    # --- API ---------------------------------------------------------------
    def token(self):
        if self._token is None:
            token = os.environ.get('LINODE_TOKEN', '')
            if not token:
                try:
                    token = subprocess.check_output(
                        [os.path.expanduser('~/.local/bin/creds'), 'get', 'LINODE_TOKEN', 'homelab'],
                        text=True, stderr=subprocess.DEVNULL).strip()
                except (OSError, subprocess.CalledProcessError):
                    token = ''
            if not token:
                raise RuntimeError('Linode token is unavailable: set LINODE_TOKEN or Infisical homelab/LINODE_TOKEN')
            self._token = token
        return self._token

    def request(self, method, path, body=None, ok=(200,)):
        response = requests.request(
            method, API + path, json=body, timeout=60,
            headers={'Authorization': 'Bearer ' + self.token(), 'Accept': 'application/json'})
        if response.status_code not in ok:
            try:
                reasons = '; '.join(item.get('reason', '') for item in response.json().get('errors', []))
            except ValueError:
                reasons = ''
            raise RuntimeError('Linode API {0} {1} failed with HTTP {2}: {3}'.format(
                method, path, response.status_code, reasons))
        if response.status_code == 404 or not response.content:
            return {}
        return response.json()

    def pages(self, path):
        page = 1
        while True:
            payload = self.request('GET', path + ('&' if '?' in path else '?') + 'page={0}&page_size=500'.format(page))
            yield from payload.get('data', [])
            if page >= int(payload.get('pages', 1)):
                return
            page += 1

    def check_connection(self):
        profile = self.request('GET', '/profile')
        instances = self.request('GET', '/linode/instances?page_size=25')
        return {'user': profile.get('username', ''), 'instances': instances.get('results', 0)}

    # --- sizing ------------------------------------------------------------
    def plan_for(self, requested, disk_gb):
        """The requested plan, or the cheapest standard plan whose disk fits the workload."""
        if self._types is None:
            self._types = {item['id']: item for item in self.pages('/linode/types')}
        if requested not in self._types:
            raise ValueError('Unknown Linode plan: ' + requested)
        if self._types[requested]['disk'] >= disk_gb * 1024:
            return requested
        candidates = sorted((item for item in self._types.values()
                             if item['class'] == 'standard' and item['disk'] >= disk_gb * 1024),
                            key=lambda item: item['price']['hourly'])
        if not candidates:
            raise ValueError('No Linode plan offers a {0} GB disk'.format(disk_gb))
        return candidates[0]['id']

    # --- resources ---------------------------------------------------------
    def owned(self, state):
        tags = set(ownership_labels(state))
        linodes = [item for item in self.pages('/linode/instances') if tags <= set(item.get('tags') or [])]
        firewalls = [item for item in self.pages('/networking/firewalls') if tags <= set(item.get('tags') or [])]
        return {'linode': linodes, 'firewall': firewalls}

    def _firewall_rules(self, state):
        rules = [{'label': 'operator-ssh', 'protocol': 'TCP', 'ports': '22', 'action': 'ACCEPT',
                  'addresses': {'ipv4': [state['operator_ip']]}}]
        for rule in state['linode_inbound_rules']:
            addresses = ({'ipv4': ['0.0.0.0/0'], 'ipv6': ['::/0']} if rule['source'] == '*'
                         else {'ipv4': [rule['source']]})
            rules.append({'label': rule['name'][:32], 'protocol': rule['protocol'].upper(),
                          'ports': rule['port'], 'action': 'ACCEPT', 'addresses': addresses})
        return {'inbound': rules, 'inbound_policy': 'DROP', 'outbound': [], 'outbound_policy': 'ACCEPT'}

    def create(self, state, deadline):
        resources = state.setdefault('resources', {})
        owned = self.owned(state)
        for kind, items in owned.items():
            if len(items) > 1:
                raise RuntimeError('More than one owned {0} exists for this deployment'.format(kind))
            if items and resources.get(kind) not in (None, items[0]['id']):
                raise RuntimeError('Recorded {0} differs from the owned one'.format(kind))
            if items:
                resources[kind] = items[0]['id']
        name = 'c2itall-' + state['deployment_id']
        if 'firewall' not in resources:
            resources['firewall'] = self.request('POST', '/networking/firewalls', {
                'label': name, 'rules': self._firewall_rules(state),
                'tags': ownership_labels(state)})['id']
            self.save(state)
        if 'linode' not in resources:
            resources['plan'] = self.plan_for(state['linode_instance_type'], state['linode_disk_gb'])
            created = self.request('POST', '/linode/instances', {
                'label': name, 'region': state['linode_region'], 'type': resources['plan'],
                'image': self.image(state['linode_image_role']),
                'authorized_keys': [Path(state['ssh_key_path']).read_text().strip()],
                # Root logs in with the deployment key only; the password is discarded.
                'root_pass': secrets.token_urlsafe(32),
                'firewall_id': resources['firewall'], 'tags': ownership_labels(state),
                'booted': True, 'private_ip': False})
            resources['linode'] = created['id']
            self.save(state)
        instance = wait_until(
            deadline,
            lambda: self._running(resources['linode']),
            interval=5, what='Linode boot')
        return {'public_ip': instance['ipv4'][0]}

    def _running(self, linode_id):
        instance = self.request('GET', '/linode/instances/{0}'.format(linode_id))
        return instance if instance.get('status') == 'running' else None

    def delete(self, state, deadline):
        resources = state.get('resources', {})
        owned = self.owned(state)
        for kind, items in owned.items():
            recorded = resources.get(kind)
            if recorded and recorded not in [item['id'] for item in items] and self._exists(kind, recorded):
                raise ValueError('Refusing to delete a foreign {0}: {1}'.format(kind, recorded))
        for kind, path in (('linode', '/linode/instances/'), ('firewall', '/networking/firewalls/')):
            for item in owned[kind]:
                self.request('DELETE', path + str(item['id']), ok=(200, 204, 404))
                wait_until(deadline, lambda: not self._exists(kind, item['id']),
                           interval=5, what='Linode ' + kind + ' deletion')
        remaining = {kind: [item['id'] for item in items] for kind, items in self.owned(state).items() if items}
        if remaining:
            raise RuntimeError('Owned resources remain after deletion: ' + str(remaining))

    def _exists(self, kind, resource_id):
        path = {'linode': '/linode/instances/', 'firewall': '/networking/firewalls/'}[kind]
        return bool(self.request('GET', path + str(resource_id), ok=(200, 404)))

    def inspect(self, state, deadline):
        linode_id = (state.get('resources') or {}).get('linode')
        if not linode_id:
            return {'healthy': False, 'detail': 'No Linode was recorded'}
        instance = self.request('GET', '/linode/instances/{0}'.format(linode_id), ok=(200, 404))
        if not instance:
            return {'healthy': False, 'detail': 'Linode is absent'}
        return {'healthy': instance.get('status') == 'running', 'power_state': instance.get('status'),
                'detail': 'Linode ' + str(instance.get('status'))}


def linode_driver():
    return LinodeDriver()


def gather_linode_config():
    return LinodeDriver().gather_config()
