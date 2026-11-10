"""LUDUS module: range rendering, identities validation, dataset generation,
workload validation and lab-secret persistence."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils import lab as lab_mod
from utils.workloads import load_profile

MODULE_DIR = ROOT / 'modules' / 'ludus'


def _load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


render = _load_module('c2itall_test_ludus_render', 'modules/ludus/render.py')

LAB_VARS = {
    'cidrs': ['198.18.0.0/16'], 'range_cidrs': [], 'blocked_cidrs': ['192.168.1.0/24'],
    'members': {
        'c2-1': {'workload': 'c2', 'lab_ip': '198.18.0.20'},
        'exfil-1': {'workload': 'exfil_receiver', 'lab_ip': '198.18.0.21'},
    },
    'datasets_url': 'http://198.18.0.30:8000',
}


def _passwords(identities):
    return {
        'ad_domain_admin': 'rangeadmin', 'ad_domain_admin_password': 'Aa1!admin0000',
        'ad_domain_user': 'ranguser', 'ad_domain_user_password': 'Aa1!user00000',
        'ad_domain_safe_mode_password': 'Aa1!safemode0',
        'users': {user['sam']: 'Aa1!' + user['sam'] for user in identities['users']},
    }


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.identities = render.load_identities()
        self.passwords = _passwords(self.identities)

    def test_render_corp_and_mini(self):
        for name in ('corp', 'mini'):
            result = render.render_range(name, LAB_VARS, self.identities, self.passwords, [], None)
            hostnames = [vm['hostname'] for vm in result['ludus']]
            self.assertTrue(all(len(hostname) <= 15 for hostname in hostnames))
            by_vlan = {}
            for vm in result['ludus']:
                by_vlan.setdefault(vm['vlan'], []).append(vm['ip_last_octet'])
            for octets in by_vlan.values():
                self.assertEqual(len(octets), len(set(octets)))
            primary = [vm for vm in result['ludus'] if vm['domain']['role'] == 'primary-dc']
            self.assertEqual(len(primary), 1)
            for key in ('snapshot_with_RAM', 'stale_hours', 'ad_domain_functional_level',
                        'ad_forest_functional_level', 'ad_domain_admin', 'ad_domain_admin_password',
                        'ad_domain_user', 'ad_domain_user_password', 'ad_domain_safe_mode_password',
                        'timezone', 'enable_dynamic_wallpaper'):
                self.assertIn(key, result['defaults'])
            self.assertEqual(result['network']['always_blocked_networks'], LAB_VARS['blocked_cidrs'])
            self.assertTrue(all(any(cidr in command for command in result['router']['iptables_commands'])
                                for cidr in LAB_VARS['cidrs']))
            self.assertEqual(result['global_role_vars']['c2_ip'], '198.18.0.20')
            self.assertEqual(result['global_role_vars']['exfil_ip'], '198.18.0.21')
            self.assertIsNone(result['global_role_vars']['payload_ip'])
            self.assertFalse(any('lab_falcon' in vm['roles'] for vm in result['ludus']))
            ws01 = next(vm for vm in result['ludus'] if vm['vm_name'] == 'WS01')
            self.assertEqual(ws01['windows']['autologon_user'], 'ranguser')
            self.assertEqual(ws01['windows']['autologon_password'], 'Aa1!user00000')
            round_tripped = yaml.safe_load(render.dump(result))
            self.assertEqual(round_tripped, result)

    def test_falcon_toggle_keeps_lab_falcon_only_with_an_installer(self):
        without = render.render_range('mini', LAB_VARS, self.identities, self.passwords, [],
                                      {'cid': 'ABCDEF', 'installer': False})
        self.assertFalse(any('lab_falcon' in vm['roles'] for vm in without['ludus']))
        with_installer = render.render_range('mini', LAB_VARS, self.identities, self.passwords, [],
                                             {'cid': 'ABCDEF', 'installer': True})
        self.assertTrue(any('lab_falcon' in vm['roles'] for vm in with_installer['ludus']))
        self.assertEqual(with_installer['global_role_vars']['falcon_cid'], 'ABCDEF')

    def test_implant_lands_on_the_chosen_vm_only(self):
        implant = {'vm': 'WS01', 'role_vars': {'lab_implant_user': 'ranguser'}}
        result = render.render_range('mini', LAB_VARS, self.identities, self.passwords, [], None, implant)
        carriers = [vm for vm in result['ludus'] if 'lab_implant' in vm['roles']]
        self.assertEqual([vm['vm_name'] for vm in carriers], ['WS01'])
        self.assertEqual(carriers[0]['role_vars']['lab_implant_user'], 'ranguser')

    def test_unknown_implant_vm_is_rejected(self):
        implant = {'vm': 'NOPE', 'role_vars': {}}
        with self.assertRaisesRegex(ValueError, 'not found'):
            render.render_range('mini', LAB_VARS, self.identities, self.passwords, [], None, implant)

    def test_weaknesses_pass_through_sorted(self):
        result = render.render_range('mini', LAB_VARS, self.identities, self.passwords,
                                     {'local_admin_on_ws02', 'kerberoastable_service_account'}, None)
        self.assertEqual(result['global_role_vars']['weaknesses'],
                         ['kerberoastable_service_account', 'local_admin_on_ws02'])

    def test_reserved_ranges_extracts_second_octet_of_10_x(self):
        self.assertEqual(render.reserved_ranges(['10.7.0.0/16', '192.168.1.0/24', '10.42.3.0/24']), [7, 42])


class IdentitiesTests(unittest.TestCase):
    def _write(self, data):
        handle = tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False)
        yaml.safe_dump(data, handle)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def _base(self):
        return {'ous': ['IT'], 'groups': {}, 'users': [], 'protect': [], 'shares': {}, 'weaknesses': {}}

    def test_duplicate_sam_rejected(self):
        data = self._base()
        data['users'] = [{'sam': 'dup', 'name': 'A', 'ou': 'IT', 'groups': []},
                         {'sam': 'dup', 'name': 'B', 'ou': 'IT', 'groups': []}]
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            render.load_identities(self._write(data))

    def test_unknown_group_rejected(self):
        data = self._base()
        data['users'] = [{'sam': 'a', 'name': 'A', 'ou': 'IT', 'groups': ['NoSuchGroup']}]
        with self.assertRaisesRegex(ValueError, 'Unknown group'):
            render.load_identities(self._write(data))

    def test_unknown_weakness_role_rejected(self):
        data = self._base()
        data['weaknesses'] = {'bogus': {'role': 'not_a_role'}}
        with self.assertRaisesRegex(ValueError, 'unknown weakness role'):
            render.load_identities(self._write(data))

    def test_weakness_referencing_unknown_user_rejected(self):
        data = self._base()
        data['weaknesses'] = {'bogus': {'role': 'lab_host', 'user': 'ghost'}}
        with self.assertRaisesRegex(ValueError, 'unknown user'):
            render.load_identities(self._write(data))

    def test_the_shipped_identities_yml_is_valid(self):
        render.load_identities()


class MakeDatasetsTests(unittest.TestCase):
    def test_generate_small_set_at_scale(self):
        script = str(MODULE_DIR / 'files' / 'make_datasets.py')
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, script, '--set', 'small', '--scale', '0.02', '--out', out],
                           check=True, capture_output=True, text=True, timeout=60)
            manifest = json.loads((Path(out) / 'manifest-small.json').read_text())
            self.assertTrue(manifest['canary_token'])
            self.assertGreater(manifest['total_bytes'], 0)
            for entry in manifest['files']:
                path = Path(out) / entry['path']
                self.assertEqual(path.stat().st_size, entry['size'])
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry['sha256'])
            docx_files = [Path(out) / entry['path'] for entry in manifest['files']
                         if entry['path'].endswith('.docx')]
            self.assertEqual(len(docx_files), 2)
            for docx in docx_files:
                with zipfile.ZipFile(docx) as archive:
                    self.assertIsNone(archive.testzip())
            conn = sqlite3.connect(Path(out) / 'small' / 'employees.sqlite3')
            count = conn.execute('SELECT COUNT(*) FROM employees').fetchone()[0]
            conn.close()
            self.assertGreater(count, 0)

    def test_all_sets_at_scale(self):
        script = str(MODULE_DIR / 'files' / 'make_datasets.py')
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([sys.executable, script, '--all', '--scale', '0.02', '--out', out],
                           check=True, capture_output=True, text=True, timeout=120)
            for name in ('small', 'medium', 'large'):
                self.assertTrue((Path(out) / ('manifest-' + name + '.json')).is_file())


class WorkloadTests(unittest.TestCase):
    def setUp(self):
        self.profile = load_profile('ludus_host')

    def test_validate_requires_a_lab(self):
        with self.assertRaises(ValueError):
            self.profile.validate({'lab_range': 'mini'})

    def test_validate_rejects_bad_range(self):
        with self.assertRaises(ValueError):
            self.profile.validate({'lab': 'x', 'lab_range': 'huge'})

    def test_validate_rejects_unknown_weakness(self):
        with self.assertRaises(ValueError):
            self.profile.validate({'lab': 'x', 'lab_range': 'mini', 'ludus_weaknesses': ['not_real']})

    def test_validate_rejects_missing_falcon_installer(self):
        with self.assertRaises(ValueError):
            self.profile.validate({'lab': 'x', 'lab_range': 'mini', 'falcon_installer_path': '/no/such/file'})

    def test_validate_accepts_a_good_config(self):
        self.profile.validate({'lab': 'x', 'lab_range': 'mini', 'ludus_weaknesses': ['local_admin_on_ws02']})

    def test_service_variables_default_min_ram_per_range(self):
        self.assertEqual(self.profile.service_variables({'lab_range': 'mini'}, {})['ludus_min_ram_gb'], 14)
        self.assertEqual(self.profile.service_variables({'lab_range': 'corp'}, {})['ludus_min_ram_gb'], 30)

    def test_service_variables_keeps_an_explicit_override(self):
        variables = self.profile.service_variables({'lab_range': 'mini', 'ludus_min_ram_gb': 64}, {'ludus_min_ram_gb': 64})
        self.assertEqual(variables['ludus_min_ram_gb'], 64)


class SecretPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        home = Path(self.temp.name) / 'home'
        (home / '.ssh').mkdir(parents=True, mode=0o700)
        self.cwd = os.getcwd()
        os.chdir(self.temp.name)
        self.patches = [mock.patch.dict(os.environ, {'HOME': str(home)}),
                       mock.patch.object(lab_mod, 'LAB_ROOT', Path(self.temp.name) / 'lab')]
        for patch in self.patches:
            patch.start()
        self.deploy_ludus = _load_module('c2itall_test_deploy_ludus', 'modules/ludus/deploy_ludus.py')

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        os.chdir(self.cwd)
        self.temp.cleanup()

    def test_passwords_generate_once_and_persist(self):
        lab = lab_mod.create('unit')
        identities = render.load_identities()
        first = self.deploy_ludus._ensure_passwords(lab, identities)
        second = self.deploy_ludus._ensure_passwords(lab_mod.load('unit'), identities)
        self.assertEqual(first, second)
        self.assertEqual(set(first['users']), {user['sam'] for user in identities['users']})
        self.assertEqual(lab_mod.read_secret(lab, 'identities.json'), first)

    def test_journal_refuses_an_implant_entry_without_a_falcon_exception(self):
        lab = lab_mod.create('unit')
        with self.assertRaisesRegex(ValueError, 'Falcon exception'):
            lab_mod.journal(lab, {'action': 'implant', 'vm': 'WS01'})
        lab_mod.journal(lab, {'action': 'implant', 'vm': 'WS01', 'falcon_exception': 'none'})
        lines = (lab_mod.secret_dir(lab) / 'journal.jsonl').read_text().splitlines()
        self.assertEqual(len(lines), 1)


if __name__ == '__main__':
    unittest.main()
