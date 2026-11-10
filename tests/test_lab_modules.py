"""Lab mode in the red-side modules: C2 renders for the lab address, the lab
menu builds member configs around the lab record, teardown reaches a lab."""

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils import lab as lab_mod
from utils.workloads import load_profile


def render(template, **context):
    from jinja2 import Environment, FileSystemLoader
    path = ROOT / template
    env = Environment(loader=FileSystemLoader(path.parent))
    return env.get_template(path.name).render(lookup=lambda *args, **kwargs: 'generated', **context)


def load(relative):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SpokeRenderTests(unittest.TestCase):
    def test_hub_route_comes_from_the_main_table_default(self):
        context = dict(spoke={'lab_ip': '198.18.0.10', 'egress_via_hub': True, 'hub_routes': []},
                       spoke_keys={'stdout_lines': ['PUB', 'PRIV']}, hub_public={'stdout': 'HUB'},
                       lab={'hub': {'public_ip': '203.0.113.5', 'port': 51820}}, allowed_ips=['198.18.0.0/16', '0.0.0.0/0'],
                       hub_route={'stdout': 'via 203.0.113.1 dev eth0'})
        conf = render('modules/lab/templates/spoke.conf.j2', **context)
        self.assertIn('PostUp = ip route replace 203.0.113.5/32 via 203.0.113.1 dev eth0\n', conf)
        self.assertIn('Endpoint = 203.0.113.5:51820', conf)
        context['spoke']['egress_via_hub'] = False
        self.assertNotIn('PostUp', render('modules/lab/templates/spoke.conf.j2', **context))


class C2LabRenderTests(unittest.TestCase):
    LAB = {'member': {'lab_ip': '198.18.0.11'}, 'cidrs': ['198.18.0.0/16'], 'range_cidrs': []}

    def test_havoc_listens_on_the_lab_address_without_a_certificate(self):
        lab = render('modules/c2/templates/havoc-config.yaotl.j2', lab=self.LAB, domain='lab.internal',
                     redirector_subdomain='c2', havoc_admin_user='admin', havoc_admin_password='pw',
                     havoc_operators=[{'name': 'red1', 'password': 'a'}, {'name': 'red2', 'password': 'b'}])
        self.assertIn('"198.18.0.11"', lab)
        self.assertNotIn('letsencrypt', lab)
        self.assertNotIn('Cert {', lab)
        self.assertIn('user "red1"', lab)
        self.assertIn('user "red2"', lab)
        public = render('modules/c2/templates/havoc-config.yaotl.j2', domain='lab.test',
                        redirector_subdomain='cdn', havoc_admin_user='admin', havoc_admin_password='pw')
        self.assertIn('"cdn.lab.test"', public)
        self.assertIn('/etc/letsencrypt/live/lab.test/fullchain.pem', public)

    def test_payload_generator_targets_the_lab_address_and_records_hashes(self):
        lab = render('modules/c2/templates/generate_havoc_payloads.sh.j2', lab=self.LAB,
                     ansible_host='198.18.16.7', domain='lab.internal', redirector_subdomain='c2',
                     havoc_https_port=9443)
        self.assertIn('REDIRECTOR_HOST="198.18.0.11"', lab)
        self.assertIn('REDIRECTOR_PORT="9443"', lab)
        self.assertIn('windows_exe_sha256', lab)
        self.assertIn('havoc_commit', lab)
        public = render('modules/c2/templates/generate_havoc_payloads.sh.j2', ansible_host='8.8.8.8',
                        domain='lab.test', redirector_subdomain='cdn', redirector_port='443')
        self.assertIn('REDIRECTOR_HOST="cdn.lab.test"', public)
        self.assertIn('REDIRECTOR_PORT="443"', public)

    def test_profiles_relax_public_requirements_only_inside_a_lab(self):
        c2 = load_profile('c2')
        c2.validate({'lab': 'blue', 'c2_framework': 'havoc'})
        with self.assertRaises(ValueError):
            c2.validate({'c2_framework': 'havoc'})
        logging = load_profile('logging_server')
        config = {'operator_ip': '8.8.8.8', 'logging_ingest_sources': ['198.18.0.11']}
        with self.assertRaises(ValueError):
            logging.validate(config)
        logging.validate(dict(config, lab='blue'))
        self.assertEqual(logging.inbound_rules(dict(config, lab='blue'))[1]['source'], '198.18.0.11/32')
        self.assertIn('havoc_killall.sh', (ROOT / 'modules/c2/tasks/configure_c2.yml').read_text())
        self.assertTrue(os.access(ROOT / 'modules/c2/files/havoc_killall.sh', os.X_OK))


class RedBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        home = Path(self.temp.name) / 'home'
        (home / '.ssh').mkdir(parents=True, mode=0o700)
        self.patches = [mock.patch.dict(os.environ, {'HOME': str(home)}),
                        mock.patch.object(lab_mod, 'LAB_ROOT', Path(self.temp.name) / 'lab')]
        for patch in self.patches:
            patch.start()
        with mock.patch.object(lab_mod, 'generate_ssh_key', return_value=str(home / '.ssh/c2deploy_lab-blue')):
            self.lab = lab_mod.create('blue')
        self.lab['members']['c2-1'] = {'lab_ip': '198.18.0.11', 'workload': 'c2', 'status': 'ready',
                                       'provider': 'fakecloud'}
        self.lab['range_cidrs'] = ['10.7.0.0/16']
        lab_mod.save(self.lab)
        self.red = load('modules/lab/red.py')
        self.deployed = []
        self.patches += [
            mock.patch.object(self.red, 'select_provider', return_value='fakecloud'),
            mock.patch.object(self.red, 'gather_provider_config',
                              return_value={'operator_ip': '8.8.8.8', 'fakecloud_region': 'x'}),
            mock.patch.object(self.red, 'confirm_action', return_value=True),
            mock.patch.object(self.red, 'apply_provider_profile', lambda config, *a: config),
            mock.patch('utils.deployment_engine.deploy_infrastructure',
                       side_effect=lambda config: self.deployed.append(config) or True),
        ]
        for patch in self.patches[2:]:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def test_c2_builder_names_operators_and_keeps_their_secrets_outside_the_config_log(self):
        with mock.patch('builtins.input', return_value='red1, red2'):
            self.assertTrue(self.red.c2(self.lab))
        config = self.deployed[-1]
        self.assertEqual((config['lab'], config['domain'], config['c2_only'], config['zero_logs']),
                         ('blue', 'lab.internal', True, False))
        self.assertEqual(config['ssh_key_path'], self.lab['ssh_key_path'])
        self.assertEqual([op['name'] for op in config['havoc_operators']], ['red1', 'red2'])
        secret = lab_mod.secret_dir(self.lab) / 'c2-operators.json'
        self.assertEqual(oct(secret.stat().st_mode & 0o777), '0o600')
        first = lab_mod.read_secret(self.lab, 'c2-operators.json')
        with mock.patch('builtins.input', return_value='red1'):
            self.red.c2(self.lab)
        self.assertEqual(lab_mod.read_secret(self.lab, 'c2-operators.json'), first)
        self.assertEqual(self.deployed[-1]['havoc_admin_password'], first['admin'])
        with mock.patch('builtins.input', return_value='bad"name'):
            self.assertFalse(self.red.c2(self.lab))

    def test_other_builders_scope_services_to_the_lab(self):
        self.assertTrue(self.red.payload_server(self.lab))
        payload = self.deployed[-1]
        self.assertEqual(payload['allowed_ips'], ['198.18.0.0/16', '10.7.0.0/16'])
        self.assertTrue(payload['enable_ip_filtering'])
        self.assertFalse(payload['enable_basic_auth'])
        self.assertTrue(self.red.attack_box(self.lab))
        box = self.deployed[-1]
        self.assertEqual((box['attack_box_type'], box['setup_vpn'], box['setup_tor']), ('kali', False, False))
        self.assertTrue(self.red.logging_server(self.lab))
        self.assertEqual(self.deployed[-1]['logging_ingest_sources'], ['198.18.0.11'])
        for config in self.deployed:
            self.assertEqual(config['lab'], 'blue')
            self.assertFalse(config['ssh_after_deploy'])


class MenuAndTeardownTests(unittest.TestCase):
    def test_main_menu_and_teardown_reach_the_lab(self):
        source = (ROOT / 'deploy.py').read_text()
        self.assertIn("launch_module('lab', 'deploy_lab.py', 'lab_menu')", source)
        teardown = load('teardown.py')
        with mock.patch.object(lab_mod, 'load', return_value={'members': {'a': {}}, 'gateway': {}, 'networks': {}}), \
                mock.patch.object(lab_mod, 'teardown', return_value=True) as torn:
            self.assertTrue(teardown.teardown_lab('blue', force=True))
        torn.assert_called_once_with('blue')
        menu = load('modules/lab/deploy_lab.py')
        self.assertTrue(callable(menu.lab_menu))
        with mock.patch.object(lab_mod, 'list_labs', return_value=[]):
            self.assertIsNone(menu.pick_lab())


if __name__ == '__main__':
    unittest.main()
