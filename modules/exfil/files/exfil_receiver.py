#!/usr/bin/env python3
"""Exfil receiver: HTTPS upload, S3/SFTP harvesting, ledger, manifest verification.

Subcommands: serve | scan | verify <manifest.json> | clean

Paths are constants below, all rooted under EXFIL_ROOT (default "/") so a
test suite can redirect the whole tree into a temp directory.
"""

import base64
import hashlib
import hmac
import http.server
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(os.environ.get('EXFIL_ROOT', '/'))
SRV = ROOT / 'srv' / 'exfil'
HTTP_DIR = SRV / 'http'
SFTP_UPLOAD_DIR = SRV / 'sftp' / 'upload'
LOG_DIR = ROOT / 'var' / 'log' / 'exfil'
LEDGER = LOG_DIR / 'ledger.jsonl'
STATE_DIR = ROOT / 'var' / 'lib' / 'exfil'
AUDIT_MAP = STATE_DIR / 'audit.json'
SEEN_FILE = STATE_DIR / 'seen.json'
PENDING_FILE = STATE_DIR / 'pending.json'
ETC_DIR = ROOT / 'etc' / 'exfil'
HTTP_ENV = ETC_DIR / 'http.env'
CERT = ETC_DIR / 'cert.pem'
KEY = ETC_DIR / 'key.pem'

NAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,128}$')
HTTPS_PORT = 8443
AUDIT_HOST = '127.0.0.1'
AUDIT_PORT = 8081


def _now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def _load_env(path):
    """Parse KEY=VALUE lines from an EnvironmentFile-style file."""
    env = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, value = line.partition('=')
            env[key.strip()] = value.strip()
    return env


def _load_json(path, default):
    if path.is_file():
        try:
            return json.loads(path.read_text())
        except ValueError:
            pass
    return default


def _save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def _append_ledger(channel, src, name, size, digest):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    entry = {'ts': _now(), 'channel': channel, 'src': src, 'name': name, 'size': size, 'sha256': digest}
    # Root's scan and the exfil service user both append: whoever creates the
    # file leaves it group-writable (the log directory is setgid exfil).
    mask = os.umask(0o007)
    try:
        fd = os.open(LEDGER, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o660)
    finally:
        os.umask(mask)
    with os.fdopen(fd, 'a') as stream:
        stream.write(json.dumps(entry) + '\n')


def _is_loopback(address):
    return address == '127.0.0.1'


def _authorized(handler, env):
    header = handler.headers.get('Authorization', '')
    if not header.startswith('Basic '):
        return False
    try:
        decoded = base64.b64decode(header[6:]).decode()
    except (ValueError, UnicodeDecodeError):
        return False
    expected = env.get('EXFIL_HTTP_USER', '') + ':' + env.get('EXFIL_HTTP_PASSWORD', '')
    return hmac.compare_digest(decoded, expected)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'exfil-receiver/1'

    def log_message(self, fmt, *args):
        pass  # ponytail: the ledger and systemd journal already record activity

    def do_PUT(self):
        self._upload()

    def do_POST(self):
        if self.path == '/audit':
            self._audit()
        else:
            self._upload()

    def _upload(self):
        if not _authorized(self, _load_env(HTTP_ENV)):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="exfil"')
            self.end_headers()
            return
        match = re.match(r'^/upload/([^/]+)$', self.path)
        name = match.group(1) if match else ''
        if not match or not NAME_RE.fullmatch(name):
            self.send_error(400, 'Bad name')
            return
        length = self.headers.get('Content-Length')
        if length is None:
            self.send_error(411)
            return
        try:
            remaining = int(length)
        except ValueError:
            self.send_error(400, 'Bad length')
            return
        HTTP_DIR.mkdir(parents=True, exist_ok=True)
        dest = HTTP_DIR / name
        digest = hashlib.sha256()
        size = 0
        with open(dest, 'wb') as stream:
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                stream.write(chunk)
                digest.update(chunk)
                size += len(chunk)
                remaining -= len(chunk)
        _append_ledger('http', self.client_address[0], name, size, digest.hexdigest())
        self.send_response(201)
        self.end_headers()

    def _audit(self):
        if not _is_loopback(self.client_address[0]):
            self.send_error(403)
            return
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else b''
        self.send_response(200)
        self.end_headers()
        try:
            event = json.loads(body) if body else {}
        except ValueError:
            return
        _record_audit(event)


def _record_audit(event):
    """Remember which host PUT each S3 key, from one MinIO audit webhook event."""
    api = event.get('api') or {}
    if api.get('name') != 'PutObject':
        return
    bucket, obj = api.get('bucket') or '', api.get('object') or ''
    if not bucket or not obj:
        return
    # MinIO writes `remotehost`, sometimes with the source port appended.
    remote = str(event.get('remotehost') or event.get('remoteHost') or 'unknown').rsplit(':', 1)[0]
    audit_map = _load_json(AUDIT_MAP, {})
    audit_map[bucket + '/' + obj] = remote
    _save_json(AUDIT_MAP, audit_map)


def serve():
    env = _load_env(HTTP_ENV)
    if not env.get('EXFIL_HTTP_USER') or not env.get('EXFIL_HTTP_PASSWORD'):
        print('exfil-receiver: missing HTTP credentials in ' + str(HTTP_ENV), file=sys.stderr)
        return 1
    audit_server = http.server.ThreadingHTTPServer((AUDIT_HOST, AUDIT_PORT), Handler)
    threading.Thread(target=audit_server.serve_forever, daemon=True).start()
    upload_server = http.server.ThreadingHTTPServer(('0.0.0.0', HTTPS_PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(CERT), str(KEY))
    upload_server.socket = context.wrap_socket(upload_server.socket, server_side=True)
    upload_server.serve_forever()
    return 0


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _sftp_source():
    """The most recent 'drop' login in the last hour.

    ponytail: one shared source per scan pass rather than per file; a file
    collides with the wrong login only if two drop sessions race inside the
    same 30s window. Upgrade: tag files by inode mtime against journal
    timestamps if per-session attribution ever matters.
    """
    result = subprocess.run(
        ['journalctl', '-u', 'sshd-exfil', '-o', 'cat', '--since', '-1h'],
        capture_output=True, text=True, check=False)
    # sshd logs 'password' or, with PAM, 'keyboard-interactive/pam'.
    matches = re.findall(r'Accepted \S+ for drop from (\S+)', result.stdout)
    return matches[-1] if matches else None


def _s3_objects():
    result = subprocess.run(['mc', 'ls', '--json', 'local/drop', '--recursive'],
                             capture_output=True, text=True, check=False)
    objects = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            objects.append(json.loads(line))
        except ValueError:
            continue
    return objects


def _hash_s3_object(key):
    result = subprocess.run(['mc', 'cat', 'local/drop/' + key], capture_output=True, check=False)
    return hashlib.sha256(result.stdout).hexdigest(), len(result.stdout)


def scan():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    seen = set(_load_json(SEEN_FILE, []))
    pending = _load_json(PENDING_FILE, {})
    new_pending = {}
    source = None

    if SFTP_UPLOAD_DIR.is_dir():
        for entry in sorted(SFTP_UPLOAD_DIR.iterdir()):
            if not entry.is_file():
                continue
            size = entry.stat().st_size
            key = str(entry)
            if pending.get(key) == size:
                digest = _sha256_file(entry)
                token = 'sftp:' + entry.name + ':' + digest
                if token not in seen:
                    if source is None:
                        source = _sftp_source() or 'unknown'
                    _append_ledger('sftp', source, entry.name, size, digest)
                    seen.add(token)
            else:
                new_pending[key] = size

    audit_map = _load_json(AUDIT_MAP, {})
    for obj in _s3_objects():
        if obj.get('type') != 'file':
            continue
        name = obj.get('key') or ''
        if not name:
            continue
        digest, size = _hash_s3_object(name)
        token = 's3:' + name + ':' + digest
        if token not in seen:
            _append_ledger('s3', audit_map.get('drop/' + name, 'unknown'), name, size, digest)
            seen.add(token)

    _save_json(SEEN_FILE, sorted(seen))
    _save_json(PENDING_FILE, new_pending)
    return 0


def verify(manifest_path):
    manifest = json.loads(Path(manifest_path).read_text())
    ledger_entries = []
    if LEDGER.is_file():
        for line in LEDGER.read_text().splitlines():
            if line.strip():
                ledger_entries.append(json.loads(line))
    ledger_hashes = {entry['sha256'] for entry in ledger_entries}
    missing = [item for item in manifest.get('files', []) if item['sha256'] not in ledger_hashes]
    if missing:
        for item in missing:
            print('MISSING ' + item['sha256'] + ' ' + item['path'])
        return 1
    wanted = {item['sha256'] for item in manifest.get('files', [])}
    counts = {}
    for entry in ledger_entries:
        if entry['sha256'] in wanted:
            counts[entry['channel']] = counts.get(entry['channel'], 0) + 1
    for channel in sorted(counts):
        print(channel + ': ' + str(counts[channel]))
    return 0


def clean():
    for directory in (HTTP_DIR, SFTP_UPLOAD_DIR):
        if directory.is_dir():
            for entry in directory.iterdir():
                if entry.is_file():
                    entry.unlink()
    subprocess.run(['mc', 'rm', '--recursive', '--force', 'local/drop'], capture_output=True, check=False)
    if LEDGER.is_file():
        LEDGER.rename(LOG_DIR / ('ledger.' + str(int(time.time())) + '.jsonl'))
    for path in (SEEN_FILE, PENDING_FILE, AUDIT_MAP):
        if path.is_file():
            path.unlink()
    print('Exfil receiver cleaned. Target-side checklist:')
    print('  - delete staged copies on the targets')
    print('  - clear tool histories and saved credentials used for the exercise')
    print('  - record the exercise ticket')
    return 0


def main(argv):
    if len(argv) < 2:
        print('usage: exfil-receiver serve|scan|verify <manifest.json>|clean', file=sys.stderr)
        return 2
    command = argv[1]
    if command == 'serve':
        return serve()
    if command == 'scan':
        return scan()
    if command == 'verify':
        if len(argv) < 3:
            print('usage: exfil-receiver verify <manifest.json>', file=sys.stderr)
            return 2
        return verify(argv[2])
    if command == 'clean':
        return clean()
    print('unknown command: ' + command, file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
