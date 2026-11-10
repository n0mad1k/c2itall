"""The lab record through the generic adapters and the in-memory driver.

A gateway registers itself, members join through it with a proxied SSH
path and the spoke play, and teardown unwinds members, gateway and the
shared network in that order.
"""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests import fake_cloud
from tests.test_extension_contracts import FAKE_SPEC
from utils import lab as lab_mod
from utils import provider_registry as registry
from utils import vm_workloads
from utils.workloads import load_profile


class OverlayOnlyDriver(fake_cloud.FakeDriver):
    provider = 'overlaycloud'
    capabilities = frozenset()


class LocalLikeDriver(fake_cloud.FakeDriver):
    provider = 'localcloud'
    capabilities = frozenset()
    private_addresses = True


class LabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        home = Path(self.temp.name) / 'home'
        (home / '.ssh').mkdir(parents=True, mode=0o700)
        (Path(self.temp.name) / 'logs').mkdir()
        self.cwd = os.getcwd()
        os.chdir(self.temp.name)
        self.patches = [
            mock.patch.dict(os.environ, {'HOME': str(home)}),
            mock.patch.object(lab_mod, 'LAB_ROOT', Path(self.temp.name) / 'lab'),
            mock.patch.dict(registry.PROVIDER_SPECS, {'fakecloud': FAKE_SPEC}),
        ]
        for patch in self.patches:
            patch.start()
        self.driver = fake_cloud.DRIVER
        self.driver.__init__()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        os.chdir(self.cwd)
        self.temp.cleanup()

    def config(self, workload, deployment_id, **extra):
        return {'provider': 'fakecloud', 'provider_workload': workload,
                'deployment_id': deployment_id, 'lab': 'unit', 'operator_ip': '8.8.4.4',
                'fakecloud_project': 'lab', 'fakecloud_state_dir': self.temp.name, **extra}

    def test_gateway_then_member_join_and_teardown_unwinds_in_order(self):
        lab = lab_mod.create('unit', ['192.168.1.0/24'])
        self.assertTrue(Path(lab['ssh_private_key_path']).is_file())
        self.assertEqual(lab['blocked_cidrs'], ['192.168.1.0/24'])
        gateway = vm_workloads.SingleVmAdapter(self.driver, load_profile('lab_gateway'))
        self.assertTrue(gateway.deploy(self.config('lab_gateway', 'gw1')))
        self.assertIn(('lab_network', 'unit'), self.driver.calls)
        state = self.driver.states['gw1']
        self.assertEqual([(r['protocol'], r['port']) for r in state['fakecloud_rules']], [('Udp', 51820)])
        self.assertEqual(state['operator_ip'], '8.8.4.4')
        lab = lab_mod.load('unit')
        self.assertEqual((lab['gateway']['public_ip'], lab['gateway']['status']), ('8.8.8.10', 'ready'))
        self.assertEqual(lab['networks']['fakecloud']['cidr'], '198.18.16.0/20')
        run = self.driver.runs[-1]
        self.assertEqual(run['variables']['lab']['hub']['public_ip'], '8.8.8.10')
        self.assertNotIn('ProxyCommand', run['variables']['ansible_ssh_common_args'])

        member = vm_workloads.SingleVmAdapter(self.driver, load_profile('tracker'))
        config = self.config('tracker', 'm1', domain='lab.test')
        self.assertTrue(member.deploy(config))
        state = self.driver.states['m1']
        self.assertEqual(state['fakecloud_rules'], [])
        self.assertEqual(state['operator_ip'], '8.8.8.10/32')
        self.assertEqual(state['ssh_proxy']['host'], '8.8.8.10')
        placement = state['fakecloud_lab']
        self.assertEqual((placement['role'], placement['lab_ip'], placement['public_ip'],
                          placement['egress_via_hub']), ('member', '198.18.0.10', False, False))
        self.assertEqual((config['tracker_ip'], config['ssh_host']), ('198.18.0.10', '8.8.8.11'))
        spoke, service = self.driver.runs[-2], self.driver.runs[-1]
        self.assertTrue(spoke['argv'][1].endswith('modules/lab/spoke.yml'))
        self.assertEqual(spoke['variables']['spoke'], {
            'deployment_id': 'm1', 'lab_ip': '198.18.0.10', 'egress_via_hub': False, 'hub_routes': []})
        self.assertEqual(set(spoke['inventory']), {'member', 'gateway'})
        self.assertIn('8.8.8.10', spoke['inventory']['gateway']['hosts'])
        self.assertIn('ProxyCommand', spoke['inventory']['member']['hosts']['8.8.8.11']['ansible_ssh_common_args'])
        self.assertIn('-W %h:%p operator@8.8.8.10', service['variables']['ansible_ssh_common_args'])
        self.assertTrue(service['argv'][service['argv'].index('-i') + 1].endswith('inventory.ini'))
        lab = lab_mod.load('unit')
        self.assertEqual(lab['members']['m1']['status'], 'ready')

        self.assertTrue(lab_mod.teardown('unit'))
        order = [call[0] + ':' + call[1] for call in self.driver.calls
                 if call[0] in ('cleanup', 'delete_lab_network')]
        self.assertEqual(order, ['cleanup:m1', 'cleanup:gw1', 'delete_lab_network:unit'])
        self.assertTrue((Path(self.temp.name) / 'lab' / 'archive' / 'lab-unit.json').is_file())
        self.assertFalse(Path(lab['ssh_private_key_path']).exists())

    def test_placement_rules_per_driver_kind(self):
        lab = lab_mod.create('unit')
        profile = load_profile('tracker')
        with self.assertRaisesRegex(ValueError, 'lab network is not ready'):
            lab_mod.placement(lab, self.driver, 'm1', profile, '8.8.4.4')
        lab_mod.ensure_network(lab, self.driver, {})
        with self.assertRaisesRegex(ValueError, 'no ready gateway'):
            lab_mod.placement(lab, self.driver, 'm1', profile, '8.8.4.4')
        lab_mod.placement(lab, self.driver, 'gw1', load_profile('lab_gateway'), '8.8.4.4')
        lab_mod.register(lab, 'gw1', '8.8.8.10', public_ip='8.8.8.10')
        with self.assertRaisesRegex(ValueError, 'already has gateway'):
            lab_mod.placement(lab, self.driver, 'gw2', load_profile('lab_gateway'), '8.8.4.4')
        other = OverlayOnlyDriver()
        overlay = lab_mod.placement(lab, other, 'm2', profile, '8.8.4.4')
        self.assertEqual((overlay['public_ip'], overlay['egress_via_hub'], overlay['ssh_source'],
                          overlay['ssh_proxy']['host'], overlay['network']),
                         (True, True, '8.8.8.10/32', '8.8.8.10', None))
        local = lab_mod.placement(lab, LocalLikeDriver(), 'm3', profile, '192.168.56.1')
        self.assertEqual((local['ssh_source'], local['ssh_proxy'], local['lab_ip']),
                         ('192.168.56.1', None, '198.18.0.11'))
        self.assertEqual(lab_mod.placement(lab, other, 'm2', profile, '8.8.4.4')['lab_ip'], '198.18.0.10')
        native_elsewhere = type('Other', (fake_cloud.FakeDriver,), {'provider': 'elsewhere'})()
        lab['networks']['elsewhere'] = {'status': 'ready', 'cidr': '198.18.32.0/20'}
        with self.assertRaisesRegex(ValueError, 'needs the lab gateway on elsewhere'):
            lab_mod.placement(lab, native_elsewhere, 'm4', profile, '8.8.4.4')

    def test_blocks_secrets_and_journal(self):
        lab = lab_mod.create('unit')
        self.assertEqual(lab_mod.next_block(lab, 'a'), '198.18.16.0/20')
        self.assertEqual(lab_mod.next_block(lab, 'b'), '198.18.32.0/20')
        self.assertEqual(lab_mod.next_block(lab, 'a'), '198.18.16.0/20')
        path = lab_mod.write_secret(lab, 'exfil.json', {'user': 'drop'})
        self.assertEqual(oct(path.stat().st_mode & 0o777), '0o600')
        self.assertEqual(lab_mod.read_secret(lab, 'exfil.json'), {'user': 'drop'})
        with self.assertRaisesRegex(ValueError, 'Falcon exception'):
            lab_mod.journal(lab, {'action': 'implant', 'vm': 'WS01'})
        lab_mod.journal(lab, {'action': 'implant', 'vm': 'WS01', 'falcon_exception': 'none'})
        lines = (lab_mod.secret_dir(lab) / 'journal.jsonl').read_text().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertIn('"falcon_exception": "none"', lines[0])
        with self.assertRaisesRegex(ValueError, 'Lab name'):
            lab_mod.create('Bad Name')
        self.assertEqual(lab_mod.list_labs(), ['unit'])


if __name__ == '__main__':
    unittest.main()
