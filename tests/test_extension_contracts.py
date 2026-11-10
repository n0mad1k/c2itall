"""Extension contracts: new providers and modules plug in without edits elsewhere.

A provider is one CloudDriver plus one registry line; a module is one
profile, one service play and one registry line. These tests register the
in-memory driver from tests/fake_cloud.py as a provider and prove that every
layer that used to carry a per-provider branch now serves it unchanged, and
that provider code and workload code never name each other.
"""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / 'scripts'):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from tests import fake_cloud
from utils import cleanup_engine, deployment_engine, provider_utils
from utils import provider_registry as registry
from utils import vm_workloads
from utils.workloads import WorkloadProfile, load_profile, profiled_workloads

FAKE_SPEC = registry.ProviderSpec(
    'FakeCloud', 'operator', False, driver='tests.fake_cloud:fake_driver')
PROVIDER_NAMES = re.compile(r'\b(azure|aws|linode|flokinet)\b', re.IGNORECASE)
WORKLOAD_NAMES = re.compile(
    r'phishing|redirector|attack.box|phantom|webrunner|payload|gophish|havoc',
    re.IGNORECASE)


def load_module(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def code_lines(path):
    """Source lines without comments and docstrings."""
    text = re.sub(r'""".*?"""', '', path.read_text(), flags=re.DOTALL)
    return [line for line in text.splitlines() if not line.lstrip().startswith('#')]


class FakeProviderTests(unittest.TestCase):
    def setUp(self):
        self.driver = fake_cloud.DRIVER
        self.driver.__init__()

    def test_registering_one_driver_serves_every_profiled_workload(self):
        with mock.patch.dict(registry.PROVIDER_SPECS, {'fakecloud': FAKE_SPEC}):
            summary = registry.validate_provider_registry(load_references=True)
            self.assertEqual(summary['providers'], 6)
            for workload in registry.driver_workloads():
                with self.subTest(workload=workload):
                    self.assertIn('fakecloud', registry.providers_for(workload))
                    self.assertEqual(
                        registry.provider_route_kind('fakecloud', workload), 'native')
                    self.assertIsInstance(
                        registry.provider_dispatcher('fakecloud').route(workload),
                        registry.WorkloadAdapter)
            self.assertEqual(
                registry.provider_supported_variants('fakecloud', 'attack_box'),
                frozenset({'quick_recon', 'kali', 'ubuntu'}))
            self.assertEqual(
                provider_utils.available_providers('c2', legacy_fallback=True),
                ['aws', 'linode', 'flokinet', 'azure', 'local', 'fakecloud'])
            self.assertEqual(
                provider_utils.gather_provider_config('fakecloud', 'redirector'),
                dict(self.driver.gather_config(), provider_manages_ssh_key=True))
            self.assertEqual(registry.provider_label('fakecloud'), 'FakeCloud')
            self.assertIs(registry.provider_driver('fakecloud'), self.driver)
            self.assertEqual(registry.infrastructure_health(), [])

            audit = load_module('scripts/audit_provider_coverage.py', 'coverage_audit_fake')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(audit.main([]), 0)
            rows = [line.split() for line in output.getvalue().splitlines()
                    if line.startswith('fakecloud')]
            self.assertEqual({row[2] for row in rows}, {'native'})
            self.assertEqual(len(rows), len(registry.driver_workloads()))

    def test_menus_connectivity_and_harness_derive_the_new_provider(self):
        with mock.patch.dict(registry.PROVIDER_SPECS, {'fakecloud': FAKE_SPEC}):
            webrunner = load_module('modules/webrunner/deploy_webrunner.py', 'webrunner_fake')
            self.assertEqual(
                webrunner._provider_regions('fakecloud', {'fakecloud_region': 'moon-2'}),
                ['moon-2'])
            self.assertEqual(webrunner._provider_node_quota('fakecloud'), 3)
            output = io.StringIO()
            with mock.patch.object(webrunner, 'available_providers',
                                   return_value=['fakecloud', 'linode']), \
                    mock.patch('builtins.input', return_value='2'), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(webrunner._select_providers(), ['fakecloud'])
            self.assertIn('2) FakeCloud', output.getvalue())

            import deploy as app
            output = io.StringIO()
            with mock.patch.object(app, 'wait_for_input'), contextlib.redirect_stdout(output):
                app.test_provider_connectivity()
            self.assertIn('FakeCloud connected: project=lab', output.getvalue())

            import test_provider_workload_live as harness
            self.assertEqual(
                harness.driver_target('fakecloud', 'r-x', 'x'),
                ('r-x', 'operator', Path.home() / '.ssh' / 'c2deploy_x'))
            self.assertIn(Path('/nonexistent/fakecloud/x.json'), harness.driver_artifacts('x'))
            with mock.patch.object(harness, 'live_config', return_value={}), \
                    mock.patch.object(harness, 'prepare_module_ssh_key',
                                      return_value=(True, Path('/tmp/test-key'))):
                redirector = harness.Redirector().config('fakecloud', 'lt', '8.8.8.8')
            self.assertEqual(redirector['backend_ip'], harness.Redirector.test_backend_ip)
            self.assertNotEqual(redirector['backend_ip'], redirector['operator_ip'])
            self.assertEqual(harness.Webrunner().identity('fakecloud', 'lt'),
                             {'deployment_id': 'lt-n01', 'names': ['wr-lt-01']})

    def test_single_vm_adapter_runs_a_profile_through_the_driver(self):
        adapter = vm_workloads.SingleVmAdapter(self.driver, load_profile('payload_server'))
        self.assertTrue(adapter.manages_ssh_key)
        with tempfile.TemporaryDirectory() as temp:
            config = {
                'provider': 'fakecloud', 'provider_workload': 'payload_server',
                'deployment_id': 'ext-ps', 'deployment_type': 'secure_payload_server',
                'domain': 'payload-lab.test', 'operator_ip': '8.8.4.4',
                'fakecloud_project': 'lab', 'fakecloud_state_dir': temp,
                'auth_password': None, 'linode_token': 'excluded', 'host_scripts': True,
            }
            infrastructure = adapter._infrastructure_config(config)
            self.assertEqual(infrastructure['fakecloud_image'], 'img-ubuntu')
            self.assertEqual(infrastructure['fakecloud_disk_gb'], 32)
            self.assertEqual([rule['port'] for rule in infrastructure['fakecloud_rules']],
                             [80, 443])
            with mock.patch.object(Path, 'home', return_value=Path(temp)), \
                    mock.patch.object(deployment_engine, 'save_deployment_info') as saved:
                self.assertTrue(adapter.deploy(config))
            saved.assert_called_once_with(config)
            self.assertEqual([call[0] for call in self.driver.calls],
                             ['prepare_state', 'prepare_ssh_key', 'deploy'])
            self.assertEqual(config['payload_server_ip'], '8.8.8.10')
            self.assertEqual(config['ssh_user'], 'operator')
            self.assertEqual(config['fakecloud_region'], 'moon-1')
            self.assertEqual(config['ssh_key'], str(Path(temp) / '.ssh' / 'c2deploy_ext-ps'))
            self.assertEqual(
                config['ssh_known_hosts_path'],
                str(Path(temp) / 'logs' / 'ext-ps-known-hosts'))
            run = self.driver.runs[0]
            self.assertTrue(run['argv'][1].endswith('modules/payload-server/service.yml'))
            self.assertEqual(run['argv'][4:6], ['-u', 'operator'])
            self.assertEqual(run['variables']['payload_server_ip'], '8.8.8.10')
            self.assertEqual(run['variables']['provider'], 'fakecloud')
            for excluded in ('linode_token', 'fakecloud_project', 'auth_password'):
                self.assertNotIn(excluded, run['variables'])
            self.assertTrue((Path(temp) / 'logs' / 'ext-ps-payload-server.log').is_file())

            with mock.patch.object(cleanup_engine, 'archive_deployment_logs') as archived:
                self.assertTrue(adapter.cleanup(config))
            archived.assert_called_once_with('ext-ps')
            self.assertEqual(self.driver.calls[-1], (
                'cleanup', 'ext-ps',
                ('deployment_id', 'fakecloud_project', 'fakecloud_state_dir')))
            self.assertEqual(self.driver.states, {})

            self.driver.deploy_result = False
            with mock.patch.object(Path, 'home', return_value=Path(temp)), \
                    mock.patch.object(cleanup_engine, 'archive_deployment_logs'):
                self.assertFalse(adapter.deploy(dict(config, deployment_id='ext-fail')))
            self.assertEqual(self.driver.calls[-1][:2], ('cleanup', 'ext-fail'))
            self.assertNotIn('ext-fail', self.driver.states)

    def test_component_adapter_deploys_each_enabled_component(self):
        adapter = vm_workloads.adapter('azure', 'phishing').__class__(
            self.driver, load_profile('phishing'))
        self.assertIsInstance(adapter, vm_workloads.ComponentAdapter)
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / 'c2deploy_ph.pub'
            key.write_text('ssh-ed25519 AAAA fake\n')
            config = {
                'provider': 'fakecloud', 'provider_workload': 'phishing', 'deployment_id': 'ph',
                'deployment_type': 'basic_phishing', 'deploy_mta_front': True,
                'deploy_gophish': True, 'domain': 'lab.test', 'phishing_domain': 'lab.test',
                'operator_ip': '8.8.4.4', 'ssh_key_path': str(key),
                'gophish_admin_port': '3333', 'smtp_auth_user': 'operator',
                'smtp_auth_pass': None, 'fakecloud_project': 'lab',
            }
            with mock.patch.object(vm_workloads.SingleVmAdapter, '_run_service_playbook',
                                   return_value=True), \
                    mock.patch.object(deployment_engine, 'save_deployment_info'):
                self.assertTrue(adapter.deploy(config))
            self.assertEqual(sorted(self.driver.states), ['ph-gophish', 'ph-mta'])
            self.assertEqual({state['provider_workload'] for state in self.driver.states.values()},
                             {'phishing'})
            self.assertFalse(self.driver.states['ph-mta']['ssh_key_generated'])
            self.assertEqual((config['mta_ip'], config['gophish_ip']),
                             ('8.8.8.10', '8.8.8.11'))
            self.assertTrue(config['smtp_auth_pass'])

            with mock.patch.object(cleanup_engine, 'archive_deployment_logs'), \
                    mock.patch.object(cleanup_engine, 'cleanup_ssh_keys_for_deployment') as keys:
                self.assertTrue(adapter.cleanup({
                    'provider': 'fakecloud', 'provider_workload': 'phishing',
                    'deployment_id': 'ph', 'fakecloud_project': 'lab', 'ssh_key_path': str(key)}))
            keys.assert_called_once_with('ph', str(key))
            self.assertEqual(self.driver.states, {})
            # A record retires components without re-proving the identity keys.
            self.assertEqual([call[2] for call in self.driver.calls if call[0] == 'cleanup'],
                             [('deployment_id',), ('deployment_id',)])

    def test_node_adapter_provisions_nodes_around_the_composite_executor(self):
        adapter = vm_workloads.NodeAdapter(self.driver, load_profile('webrunner'))
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / 'c2deploy_wr.pub'
            key.write_text('ssh-ed25519 AAAA fake\n')
            chunks = Path(temp) / 'chunks.json'
            chunks.write_text(json.dumps([
                {'idx': 0, 'node_name': 'wr-01', 'provider': 'fakecloud',
                 'cidrs': ['8.8.4.4/32'], 'ip_count': 1},
                {'idx': 1, 'node_name': 'wr-02', 'provider': 'linode',
                 'cidrs': ['8.8.4.5/32'], 'ip_count': 1}]))
            config = {
                'provider_workload': 'webrunner', 'deployment_id': 'wr',
                'providers': ['fakecloud', 'linode'], 'ssh_key_path': str(key),
                'node_chunks_file': str(chunks), 'teardown_after_scan': True,
                'fakecloud_project': 'lab',
            }
            legacy = mock.Mock(return_value=True)
            with mock.patch.object(cleanup_engine, 'archive_deployment_logs'):
                self.assertTrue(adapter.deploy_with_legacy(config, legacy))
            legacy.assert_called_once_with(config)
            self.assertEqual(config['fakecloud_nodes'], [{
                'node_name': 'wr-01', 'ip': '8.8.8.10', 'idx': 0,
                'cidrs': ['8.8.4.4/32'], 'ip_count': 1, 'deployment_id': 'wr-n01',
                'ssh_user': 'operator'}])
            self.assertEqual(self.driver.states, {})
            self.assertIn(('cleanup', 'wr-n01', ('deployment_id',)), self.driver.calls)

    def test_handoff_adapter_gives_the_module_a_configured_host(self):
        adapter = vm_workloads.HandoffAdapter(self.driver, load_profile('phantom'))
        with tempfile.TemporaryDirectory() as temp:
            config = {
                'provider': 'fakecloud', 'provider_workload': 'phantom',
                'deployment_id': 'vpn1', 'server_type': 'vpn',
                'operator_ip': '8.8.4.4', 'fakecloud_project': 'lab',
                'fakecloud_state_dir': temp,
            }
            with mock.patch.object(self.driver, 'prepare_ssh_key'):
                self.assertTrue(adapter.deploy(config))
            self.assertEqual(
                config['ssh_known_hosts_path'],
                str(Path(temp) / 'logs' / 'vpn1-known-hosts'))
        self.assertEqual(config['target_host'], '8.8.8.10')
        self.assertEqual(config['ssh_user'], 'operator')
        self.assertEqual(config['provider_workload'], 'phantom')
        self.assertEqual([(rule['protocol'], rule['port'])
                          for rule in self.driver.states['vpn1']['fakecloud_rules']],
                         [('Udp', 51820)])
        self.assertEqual(adapter._infrastructure_config(
            dict(config, server_type='tak'))['fakecloud_disk_gb'], 64)
        self.assertTrue(adapter.cleanup(config))
        self.assertEqual(self.driver.states, {})


class ProfileContractTests(unittest.TestCase):
    def test_every_profiled_workload_is_complete_with_an_existing_play(self):
        self.assertEqual(profiled_workloads(), [
            'attack_box', 'c2', 'redirector', 'phishing', 'payload_server',
            'webrunner', 'phantom', 'chat', 'tracker', 'logging_server', 'share',
            'hashtopolis'])
        self.assertEqual(registry.driver_workloads(), ['infrastructure', *profiled_workloads()])
        for workload in profiled_workloads():
            profile = load_profile(workload)
            with self.subTest(workload=workload):
                self.assertIs(profile.check(), profile)
                self.assertIn(profile.kind, vm_workloads._KINDS)
                plays = {'single': lambda: [profile.service_playbook],
                         'components': lambda: [component.service_playbook
                                                for _flag, component in profile.components]
                         }.get(profile.kind, list)()
                self.assertTrue(plays or profile.kind in ('nodes', 'handoff'))
                for play in plays:
                    self.assertTrue((ROOT / play).is_file(), play)
                    self.assertTrue(play.startswith('modules/'), play)

    def test_incomplete_profiles_are_rejected(self):
        class Nameless(WorkloadProfile):
            pass

        class HalfSingle(WorkloadProfile):
            workload = 'example'
            address_key = 'example_ip'

        class BadComponents(WorkloadProfile):
            kind = 'components'
            workload = 'example'
            components = (('flag', object()),)

        for profile, message in ((Nameless(), 'must name its workload'),
                                 (HalfSingle(), 'metadata is incomplete'),
                                 (BadComponents(), 'needs \\(flag, profile\\) components')):
            with self.subTest(profile=type(profile).__name__), \
                    self.assertRaisesRegex(TypeError, message):
                profile.check()

    def test_provider_and_workload_code_never_name_each_other(self):
        provider_core = [ROOT / 'utils' / name for name in (
            'cloud_driver.py', 'azure_cloud.py')] + [ROOT / 'tests' / 'fake_cloud.py']
        for path in provider_core:
            with self.subTest(path=path.name):
                offenders = [line for line in code_lines(path) if WORKLOAD_NAMES.search(line)]
                self.assertEqual(offenders, [])
        neutral = [ROOT / 'utils' / name for name in (
            'vm_workloads.py', 'workloads.py', 'cloud_driver.py', 'state_store.py')]
        for path in neutral:
            with self.subTest(path=path.name):
                offenders = [line for line in code_lines(path) if PROVIDER_NAMES.search(line)]
                self.assertEqual(offenders, [])
        for path in sorted((ROOT / 'modules').glob('*/workload.py')) + sorted(
                (ROOT / 'modules').glob('*/service*.yml')):
            with self.subTest(path=str(path.relative_to(ROOT))):
                offenders = [line for line in code_lines(path) if PROVIDER_NAMES.search(line)]
                self.assertEqual(offenders, [])


if __name__ == '__main__':
    unittest.main()
