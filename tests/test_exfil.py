"""The exfil receiver: the standalone script's subcommands, the profile gate,
and credential generation/reuse through the controller.
"""

import base64
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils import lab as lab_mod
from utils.workloads import load_profile

RECEIVER_PATH = ROOT / 'modules' / 'exfil' / 'files' / 'exfil_receiver.py'
DEPLOY_PATH = ROOT / 'modules' / 'exfil' / 'deploy_exfil.py'


def _load_module(path, name, env=None):
    with mock.patch.dict(os.environ, env or {}):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


def _load_receiver(root):
    return _load_module(RECEIVER_PATH, 'exfil_receiver_under_test_' + str(id(root)),
                         {'EXFIL_ROOT': str(root)})


def _wait_for_port(host, port, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


class SftpSourceTests(unittest.TestCase):
    def test_pam_logins_count_as_the_sftp_source(self):
        receiver = _load_module(RECEIVER_PATH, 'exfil_receiver_sftp')
        journal = subprocess.CompletedProcess([], 0, stdout=(
            'Accepted keyboard-interactive/pam for drop from 198.18.0.1 port 49834 ssh2\n'
            'pam_unix(sshd:session): session opened for user drop(uid=1000) by drop(uid=0)\n'), stderr='')
        with mock.patch.object(receiver.subprocess, 'run', return_value=journal):
            self.assertEqual(receiver._sftp_source(), '198.18.0.1')


class ExfilReceiverServeTests(unittest.TestCase):
    """serve(): basic auth, name validation, length, upload, and the audit gate."""

    @classmethod
    def setUpClass(cls):
        if not shutil.which('openssl'):
            raise unittest.SkipTest('openssl is required to generate a test certificate')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        etc = self.root / 'etc' / 'exfil'
        etc.mkdir(parents=True)
        subprocess.run(
            ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-subj', '/CN=test.exfil', '-keyout', str(etc / 'key.pem'), '-out', str(etc / 'cert.pem')],
            capture_output=True, check=True)
        (etc / 'http.env').write_text('EXFIL_HTTP_USER=opuser\nEXFIL_HTTP_PASSWORD=oppass\n')
        self.receiver = _load_receiver(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def _start(self, https_port, audit_port):
        self.receiver.HTTPS_PORT = https_port
        self.receiver.AUDIT_PORT = audit_port
        thread = threading.Thread(target=self.receiver.serve, daemon=True)
        thread.start()
        self.assertTrue(_wait_for_port('127.0.0.1', https_port))
        self.assertTrue(_wait_for_port('127.0.0.1', audit_port))

    def _connection(self, port):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=5)

    def _auth_header(self):
        return 'Basic ' + base64.b64encode(b'opuser:oppass').decode()

    def test_401_without_auth(self):
        self._start(18443, 18081)
        conn = self._connection(18443)
        conn.request('PUT', '/upload/report.txt', body=b'x')
        self.assertEqual(conn.getresponse().status, 401)

    def test_400_for_a_bad_name(self):
        self._start(18444, 18082)
        conn = self._connection(18444)
        conn.request('PUT', '/upload/..%2F..%2Fetc%2Fpasswd', body=b'x',
                      headers={'Authorization': self._auth_header()})
        self.assertEqual(conn.getresponse().status, 400)

    def test_411_without_content_length(self):
        self._start(18445, 18083)
        conn = self._connection(18445)
        conn.putrequest('PUT', '/upload/report.txt')
        conn.putheader('Authorization', self._auth_header())
        conn.endheaders()
        self.assertEqual(conn.getresponse().status, 411)

    def test_201_for_a_good_put_and_ledger_line(self):
        self._start(18446, 18084)
        body = b'the quarterly numbers'
        conn = self._connection(18446)
        conn.request('PUT', '/upload/report.txt', body=body,
                      headers={'Authorization': self._auth_header()})
        response = conn.getresponse()
        self.assertEqual((response.status, response.getheader('Content-Length')), (201, '0'))
        ledger = self.root / 'var' / 'log' / 'exfil' / 'ledger.jsonl'
        self.assertEqual(ledger.stat().st_mode & 0o777, 0o660, 'root and the service user both append')
        ledger_line = ledger.read_text().splitlines()[-1]
        entry = json.loads(ledger_line)
        self.assertEqual(entry['sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual((entry['channel'], entry['name'], entry['size']), ('http', 'report.txt', len(body)))

    def test_audit_is_loopback_only(self):
        self.assertTrue(self.receiver._is_loopback('127.0.0.1'))
        self.assertFalse(self.receiver._is_loopback('10.1.2.3'))

    def test_audit_from_loopback_records_the_source(self):
        self._start(18447, 18085)
        conn = http.client.HTTPConnection('127.0.0.1', 18085, timeout=5)
        event = json.dumps({'api': {'name': 'PutObject', 'bucket': 'drop', 'object': 'secret.docx'},
                             'remoteHost': '198.18.16.20'}).encode()
        conn.request('POST', '/audit', body=event)
        self.assertEqual(conn.getresponse().status, 200)
        time.sleep(0.2)
        audit_map = json.loads((self.root / 'var' / 'lib' / 'exfil' / 'audit.json').read_text())
        self.assertEqual(audit_map['drop/secret.docx'], '198.18.16.20')


OBJECT_NAME = 'leak.csv'
OBJECT_BODY = b'name,ssn\nalice,000-00-0000\n'


def _install_fake_mc():
    """A fake `mc` on PATH that lists and serves one S3 object."""
    bin_dir = Path(tempfile.mkdtemp())
    mc_path = bin_dir / 'mc'
    mc_path.write_text(
        '#!/usr/bin/env python3\n'
        'import sys\n'
        'if sys.argv[1] == "ls":\n'
        '    print(\'{"status":"success","type":"file","key":"%s","size":%d}\')\n'
        'elif sys.argv[1] == "cat":\n'
        '    sys.stdout.buffer.write(%r)\n'
        'elif sys.argv[1] == "rm":\n'
        '    pass\n'
        % (OBJECT_NAME, len(OBJECT_BODY), OBJECT_BODY)
    )
    mc_path.chmod(mc_path.stat().st_mode | stat.S_IEXEC)
    return bin_dir


class ExfilReceiverScanVerifyCleanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        bin_dir = _install_fake_mc()
        self.addCleanup(shutil.rmtree, bin_dir, ignore_errors=True)
        self.env_patch = mock.patch.dict(os.environ, {'PATH': str(bin_dir) + os.pathsep + os.environ['PATH']})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.receiver = _load_receiver(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_scan_ledgers_the_s3_object_once(self):
        self.receiver.scan()
        lines = (self.root / 'var' / 'log' / 'exfil' / 'ledger.jsonl').read_text().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry['sha256'], hashlib.sha256(OBJECT_BODY).hexdigest())
        self.assertEqual((entry['channel'], entry['name']), ('s3', OBJECT_NAME))
        self.receiver.scan()
        lines = (self.root / 'var' / 'log' / 'exfil' / 'ledger.jsonl').read_text().splitlines()
        self.assertEqual(len(lines), 1, 'a second scan must not duplicate the ledger line')

    def test_verify_passes_and_fails(self):
        self.receiver.scan()
        digest = hashlib.sha256(OBJECT_BODY).hexdigest()
        manifest = {'set': 'small', 'generated': 'now', 'canary_token': 'c', 'total_bytes': len(OBJECT_BODY),
                    'files': [{'path': OBJECT_NAME, 'size': len(OBJECT_BODY), 'sha256': digest}]}
        manifest_path = self.root / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest))
        self.assertEqual(self.receiver.verify(str(manifest_path)), 0)

        missing_manifest = dict(manifest, files=manifest['files'] + [
            {'path': 'ghost.csv', 'size': 1, 'sha256': 'f' * 64}])
        missing_path = self.root / 'missing.json'
        missing_path.write_text(json.dumps(missing_manifest))
        self.assertEqual(self.receiver.verify(str(missing_path)), 1)

    def test_clean_rotates_the_ledger(self):
        self.receiver.scan()
        ledger = self.root / 'var' / 'log' / 'exfil' / 'ledger.jsonl'
        self.assertTrue(ledger.is_file())
        self.receiver.clean()
        self.assertFalse(ledger.exists())
        rotated = list((self.root / 'var' / 'log' / 'exfil').glob('ledger.*.jsonl'))
        self.assertEqual(len(rotated), 1)


class ExfilProfileTests(unittest.TestCase):
    def test_validate_refuses_missing_credentials(self):
        profile = load_profile('exfil_receiver')
        with self.assertRaises(ValueError):
            profile.validate({'lab': 'unit'})
        with self.assertRaisesRegex(ValueError, 'exfil_minio_user'):
            profile.validate({'lab': 'unit', 'exfil_minio_password': 'x', 'exfil_http_user': 'x',
                               'exfil_http_password': 'x', 'exfil_sftp_password': 'x'})
        profile.validate({'lab': 'unit', 'exfil_minio_user': 'exfil', 'exfil_minio_password': 'x',
                           'exfil_http_user': 'exfil', 'exfil_http_password': 'x', 'exfil_sftp_password': 'x'})

    def test_validate_requires_a_lab(self):
        profile = load_profile('exfil_receiver')
        with self.assertRaisesRegex(ValueError, 'lives inside a lab'):
            profile.validate({})


class ExfilDeployCredentialTests(unittest.TestCase):
    """deploy_exfil generates lab exfil credentials once and reuses them on retry."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        home = Path(self.temp.name) / 'home'
        (home / '.ssh').mkdir(parents=True, mode=0o700)
        self.cwd = os.getcwd()
        os.chdir(self.temp.name)
        self.patches = [
            mock.patch.dict(os.environ, {'HOME': str(home)}),
            mock.patch.object(lab_mod, 'LAB_ROOT', Path(self.temp.name) / 'lab'),
        ]
        for patch in self.patches:
            patch.start()
        self.deploy_exfil = _load_module(DEPLOY_PATH, 'deploy_exfil_under_test')

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        os.chdir(self.cwd)
        self.temp.cleanup()

    def test_credentials_generated_once_and_reused(self):
        lab = lab_mod.create('unit')
        first = self.deploy_exfil._credentials(lab)
        self.assertEqual((first['minio_user'], first['http_user'], first['sftp_user']),
                          ('exfil', 'exfil', 'drop'))
        for key in ('minio_password', 'http_password', 'sftp_password'):
            self.assertTrue(first[key])
        second = self.deploy_exfil._credentials(lab)
        self.assertEqual(first, second)
        self.assertEqual(lab_mod.read_secret(lab, 'exfil.json'), first)


if __name__ == '__main__':
    unittest.main()
