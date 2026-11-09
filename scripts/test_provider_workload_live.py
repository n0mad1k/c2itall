#!/usr/bin/env python3
"""Deploy, verify, repeat and remove one real cloud offensive workload.

The default invocation is a dry run. ``--activate`` performs the lifecycle
through the shared provider registry exactly as the interactive modules do,
then removes every cloud and local artifact through standalone teardown in a
fresh process and proves the provider inventory returned to its baseline.
Nothing is scanned or attacked: verification only inspects the deployed host.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
from unittest import mock
import uuid

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
for path in (SCRIPT_DIR, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from live_clouds import (CLOUDS, REGIONS, LiveError, LiveInterrupted, build_cloud,
                         live_config, public_ipv4, redacted, require)
from utils.common import setup_logging
from utils.deployment_engine import (deploy_infrastructure, dispatch_composite_workload,
                                     dispatch_workload)
from utils.provider_registry import (PROVIDER_SPECS, prepare_provider_environment,
                                     provider_driver, provider_label)
from utils.provider_utils import apply_provider_profile, prepare_module_ssh_key

# A fresh teardown process must hold no provider credential at all.
CREDENTIAL_ENVIRONMENT = tuple(
    environment for spec in PROVIDER_SPECS.values()
    for _, environment in spec.credential_environment) + ('AWS_DEFAULT_REGION',)
SSH_DIR = Path.home() / '.ssh'
# Never fails; records why an sshd check could fail without a second deployment.
SSHD_DIAGNOSTICS = (
    "sudo -n /usr/sbin/sshd -T 2>&1 | grep -i '^passwordauthentication'; "
    "grep -n -i 'passwordauthentication\\|^include' /etc/ssh/sshd_config; "
    "ls -la /etc/ssh/sshd_config.d/ 2>&1; "
    "sudo -n sh -c 'head -20 /etc/ssh/sshd_config.d/*.conf' 2>&1; true")


class Runner:
    def __init__(self, evidence):
        self.evidence = evidence
        self.counter = 0
        self.cleaning = False
        self.interrupted = False

    def handle_signal(self, signum, _frame):
        self.interrupted = True
        if not self.cleaning:
            raise LiveInterrupted('Interrupted by signal ' + str(signum))

    def record(self, name, content):
        path = self.evidence / name
        with path.open('w') as stream:
            os.chmod(path, 0o600)
            json.dump(content, stream, indent=2, default=str)

    def run(self, argv, timeout=60, env=None, check=True):
        process = subprocess.run(
            [str(arg) for arg in argv], cwd=ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=timeout)
        self.counter += 1
        self.record('command-{0:03d}.json'.format(self.counter), {
            'command': [str(arg) for arg in argv],
            'returncode': process.returncode,
            'stdout': process.stdout[-20000:], 'stderr': process.stderr[-20000:],
        })
        if check and process.returncode:
            raise LiveError('Command failed ({0}): {1}: {2}'.format(
                process.returncode, argv[0], process.stderr[-3000:]))
        return process.stdout.strip()


def checks(context, items, timeout=90):
    """Run named host checks; the first failure names itself on stderr."""
    script = 'set -u; ' + ' '.join(
        '{ ' + command + '; } || { echo "FAILED CHECK: ' + label + '" >&2; exit 1; };'
        for label, command in items)
    context.ssh(script, timeout=timeout)
    return {label: True for label, _ in items}


def load_module(relative):
    spec = importlib.util.spec_from_file_location(Path(relative).stem + '_live', ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def submission_auth(address, user, password):
    """Prove the relay accepts the operator credential over STARTTLS and nothing else."""
    import smtplib
    import ssl
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.check_hostname = False
    tls.verify_mode = ssl.CERT_NONE
    with smtplib.SMTP(address, 587, timeout=30) as smtp:
        smtp.starttls(context=tls)
        smtp.login(user, password)
    with smtplib.SMTP(address, 587, timeout=30) as smtp:
        smtp.starttls(context=tls)
        try:
            smtp.login(user, password + 'x')
        except smtplib.SMTPAuthenticationError:
            return True
    raise LiveError('MTA front accepted a wrong SASL password')


def key_files(stem):
    return [SSH_DIR / stem, SSH_DIR / (stem + '.pub'), SSH_DIR / (stem + '.pem')]


def driver_artifacts(deployment_id):
    """Local state any driver-backed provider keeps for one deployment ID."""
    paths = []
    for provider in PROVIDER_SPECS:
        driver = provider_driver(provider)
        if driver is not None:
            paths.extend(driver.local_artifacts(deployment_id))
    return paths


def shared_artifacts(deployment_id):
    return key_files('c2deploy_' + deployment_id) + driver_artifacts(deployment_id)


def driver_target(provider, name, key_stem):
    """SSH target for a driver-backed provider: its user, the module key."""
    return name, provider_driver(provider).ssh_user, SSH_DIR / ('c2deploy_' + key_stem)


class AttackBox:
    name = 'attack_box'
    variants = ('quick_recon', 'kali', 'ubuntu')
    source_paths = ('modules/attack-box',)

    def __init__(self, variant='quick_recon'):
        if variant not in self.variants:
            raise ValueError('Unknown attack-box variant: ' + str(variant))
        self.variant = variant

    def config(self, provider, deployment_id, operator_ip):
        prefix = {'quick_recon': 'qr', 'kali': 'ka', 'ubuntu': 'ub'}[self.variant]
        box = prefix + '-' + deployment_id
        deployment_type = ('quick_recon_box' if self.variant == 'quick_recon'
                           else self.variant + '_attack_box')
        quick = self.variant == 'quick_recon'
        config = {
            'deployment_id': deployment_id, 'provider': provider,
            'provider_workload': 'attack_box', 'deployment_type': deployment_type,
            'attack_box_type': self.variant, 'attack_box_name': box,
            'instance_size': 'small' if quick else 'medium',
            'setup_tor': quick, 'setup_vpn': False,
            'setup_domain': False, 'operator_ip': operator_ip,
            'ssh_after_deploy': False, 'enhanced_opsec': True,
            'work_dir': '/root/' + deployment_id, 'tool_name': 'toolkit',
            'project_name': deployment_id, 'auto_teardown_on_fail': False,
            'attack_box_deployment': True, 'quick_deployment': quick,
        }
        config.update(live_config(provider, self.name))
        if provider == 'azure' and not quick:
            config['azure_os_disk_gb'] = 64
        apply_provider_profile(config, 'instance_size', config['instance_size'])
        ready, _ = prepare_module_ssh_key(config, box)
        require(ready, 'Could not generate the module SSH key')
        return config

    def identity(self, config):
        deployment_id = config['deployment_id']
        return {'deployment_id': deployment_id, 'names': [config['attack_box_name']]}

    def target(self, provider, config):
        return driver_target(provider, config['attack_box_name'], config['deployment_id'])

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_' + config['attack_box_name']) + shared_artifacts(deployment_id) + [
            ROOT / 'logs' / ('attack_box_' + deployment_id + '_info.txt')]

    def verify(self, context, config):
        deployment_id = config['deployment_id']
        expected_os = 'ubuntu' if self.variant == 'ubuntu' else 'kali'
        common = [
            ('os', "grep -q '^ID=" + expected_os + "$' /etc/os-release"),
            ('workspace', 'sudo -n test -d /root/' + deployment_id + '/scans'),
            ('nmap', 'command -v nmap >/dev/null'), ('dig', 'command -v dig >/dev/null'),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ]
        if self.variant == 'quick_recon':
            specific = [
                ('quick_guide', 'sudo -n test -s /root/QUICK_RECON_GUIDE.txt'),
                ('tor', 'command -v tor >/dev/null'),
                ('torsocks', 'command -v torsocks >/dev/null'),
                ('proxychains', 'command -v proxychains4 >/dev/null'),
                ('tor_enabled', 'test "$(systemctl is-enabled tor)" = enabled'),
                ('tor_active', 'systemctl is-active tor >/dev/null'),
                ('alias', "sudo -n grep -Fq \"alias qr='cd /root/" + deployment_id + "'\" /root/.bashrc"),
            ]
        else:
            specific = [
                ('workspace_targets', 'sudo -n test -s /root/' + deployment_id + '/targets/targets.txt'),
                ('opsec_script', 'sudo -n test -x /root/' + deployment_id + '/tools/scripts/opsec-check.sh'),
                ('pipx', 'command -v pipx >/dev/null'),
                ('go_runtime', 'sudo -n test -x /usr/local/go/bin/go'),
                ('go_tool', 'sudo -n test -x /root/' + deployment_id + '/tools/go/bin/assetfinder'),
                ('workspace_alias', "sudo -n grep -Fq \"alias ops=\" /root/.bashrc"),
            ]
        report = checks(context, common + specific, timeout=180)
        rules = context.cloud.inbound_rules(deployment_id)
        require(rules == [('tcp', '22', config['operator_ip'] + '/32')],
                provider_label(context.provider) + ' attack box exposes more than operator SSH: ' + str(rules))
        report['security_group_rules'] = rules
        return report


class Redirector:
    name = 'redirector'
    source_paths = ('modules/redirectors', 'common')
    test_backend_ip = '192.0.2.10'

    def config(self, provider, deployment_id, operator_ip):
        config = {
            'deployment_id': deployment_id, 'provider': provider,
            'provider_workload': 'redirector', 'domain': 'redirector-lab.test',
            'redirector_subdomain': 'cdn', 'backend_type': 'c2',
            # A documentation-only address deliberately distinct from the
            # operator proves that providers wire backend_ip, not operator_ip.
            'backend_ip': self.test_backend_ip,
            'redirector_type': 'https', 'letsencrypt_email': 'admin@redirector-lab.test',
            'operator_ip': operator_ip, 'ssh_after_deploy': False,
            'deployment_type': 'c2_redirector', 'redirector_only': True,
            'c2_only': False,
        }
        config.update(live_config(provider, self.name))
        ready, _ = prepare_module_ssh_key(config, deployment_id)
        require(ready, 'Could not generate the module SSH key')
        return config

    def identity(self, config):
        deployment_id = config['deployment_id']
        return {'deployment_id': deployment_id, 'names': ['r-' + deployment_id]}

    def target(self, provider, config):
        return driver_target(provider, 'r-' + config['deployment_id'], config['deployment_id'])

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_' + deployment_id) + shared_artifacts(deployment_id)

    def verify(self, context, config):
        # The site answers only its own hostname; the catch-all vhost bounces every other Host.
        host = config['redirector_subdomain'] + '.' + config['domain']
        report = checks(context, [
            ('nginx_active', 'test "$(systemctl is-active nginx)" = active'),
            ('nginx_enabled', 'test "$(systemctl is-enabled nginx)" = enabled'),
            ('shell_handler_enabled', 'test "$(systemctl is-enabled shell-handler)" = enabled'),
            ('http_listening', "ss -ltn | grep -q ':80 '"),
            ('https_listening', "ss -ltn | grep -q ':443 '"),
            ('nginx_backend_wired', "sudo -n grep -Rqs -- 'proxy_pass https://" +
             self.test_backend_ip + ":' /etc/nginx"),
            ('shell_backend_wired', "sudo -n grep -qs -- 'Environment=\"C2_HOST=" +
             self.test_backend_ip + "\"' /etc/systemd/system/shell-handler.service"),
            ('local_https', 'test "$(curl -ks -o /dev/null -w \'%{http_code}\' -H \'Host: ' + host +
             '\' https://127.0.0.1/)" = 200'),
            ('post_install_script', 'sudo -n test -x /root/Tools/post_install_redirector.sh'),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ])
        base = ['curl', '-ks', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20']
        url = 'https://' + context.address + '/'
        status = context.run(base + ['-H', 'Host: ' + host, url])
        require(status == '200', 'Redirector HTTPS front page is not public: ' + status)
        unknown = context.run(base + [url])
        require(unknown == '301', 'Redirector answered an unknown Host instead of bouncing it: ' + unknown)
        report['unknown_host_bounced'] = True
        rules = context.cloud.inbound_rules(config['deployment_id'])
        require(('tcp', '22', config['operator_ip'] + '/32') in rules and
                all(source == '*' for proto, port, source in rules if port != '22'),
                provider_label(context.provider) + ' redirector rules are not operator-SSH plus public web: ' + str(rules))
        report['security_group_rules'] = rules
        return report


class FrontedRedirector(Redirector):
    """A redirector whose web ports admit only the provider's edge."""
    name = 'fronted_redirector'

    def config(self, provider, deployment_id, operator_ip):
        config = super().config(provider, deployment_id, operator_ip)
        # The lab domain has no certificate, so the edge reaches the origin over HTTP.
        config.update(deployment_type='fronted_c2_redirector', fronting=True,
                      fronting_endpoint_name='cdn-' + uuid.uuid4().hex[:6],
                      fronting_origin_protocol='http')
        return config

    def verify(self, context, config):
        host = config['redirector_subdomain'] + '.' + config['domain']
        edge_id = config['edge_id']
        header = config['edge_header']
        local = 'curl -s -o /dev/null -w \'%{http_code}\' --max-time 10 -H \'Host: ' + host + '\' '
        report = checks(context, [
            ('nginx_active', 'test "$(systemctl is-active nginx)" = active'),
            ('shell_handler_enabled', 'test "$(systemctl is-enabled shell-handler)" = enabled'),
            ('edge_guard_configured', "sudo -n grep -qs -- '\"" + edge_id + "\" 1;' /etc/nginx/sites-available/default"),
            ('unfronted_http_dropped', 'test "$(' + local + 'http://127.0.0.1/)" = 000'),
            ('unfronted_https_dropped', 'test "$(' + local + '-k https://127.0.0.1/)" = 000'),
            ('fronted_http_served', 'test "$(' + local + '-H \'' + header + ': ' + edge_id + '\' http://127.0.0.1/)" = 200'),
            ('fronted_https_served', 'test "$(' + local + '-k -H \'' + header + ': ' + edge_id + '\' https://127.0.0.1/)" = 200'),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ])
        direct = subprocess.run(
            ['curl', '-ks', '-o', '/dev/null', '--max-time', '15', '-H', 'Host: ' + host,
             'https://' + context.address + '/'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        require(direct.returncode != 0, 'The origin answered the operator directly despite the edge lockdown')
        report['origin_closed_to_internet'] = True
        rules = context.cloud.inbound_rules(config['deployment_id'])
        web = {source for proto, port, source in rules if port in ('80', '443', '80-443')}
        require(len(web) == 1 and '*' not in web and config['operator_ip'] not in str(web),
                'Fronted redirector web ports are not limited to the edge network: ' + str(rules))
        report['security_group_rules'] = rules
        # The edge takes minutes to propagate; the first 200 proves the whole chain.
        base = ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20']
        url = 'https://' + config['edge_hostname'] + '/'
        deadline = time.monotonic() + 900
        while True:
            status = context.run(base + [url], check=False)
            if status == '200':
                break
            require(time.monotonic() < deadline, 'Edge endpoint never served the origin page: ' + status)
            time.sleep(20)
        report['edge_hostname'] = config['edge_hostname']
        report['served_through_edge'] = True
        return report


class C2:
    name = 'c2'
    source_paths = ('modules/c2', 'common')

    def config(self, provider, deployment_id, operator_ip):
        config = {
            'deployment_id': deployment_id, 'provider': provider,
            'provider_workload': 'c2', 'domain': 'c2-lab.test', 'c2_subdomain': 'mail',
            'redirector_subdomain': 'cdn',
            'redirector_name': 'r-' + deployment_id, 'c2_name': 's-' + deployment_id,
            'c2_framework': 'havoc', 'letsencrypt_email': 'admin@c2-lab.test',
            'operator_ip': operator_ip, 'smtp_auth_user': 'admin',
            'smtp_auth_pass': secrets.token_urlsafe(12), 'zero_logs': True,
            'ssh_after_deploy': False, 'deployment_type': 'c2_only', 'c2_only': True,
            'gophish_admin_port': '2222',
        }
        config.update(live_config(provider, self.name))
        ready, _ = prepare_module_ssh_key(config, deployment_id)
        require(ready, 'Could not generate the module SSH key')
        return config

    def identity(self, config):
        deployment_id = config['deployment_id']
        return {'deployment_id': deployment_id, 'names': [config['c2_name']]}

    def target(self, provider, config):
        return driver_target(provider, config['c2_name'], config['deployment_id'])

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_' + deployment_id) + shared_artifacts(deployment_id)

    def verify(self, context, config):
        report = checks(context, [
            ('kali', "grep -q '^ID=kali' /etc/os-release"),
            ('havoc_teamserver', 'sudo -n test -x /root/Tools/Havoc/havoc'),
            ('havoc_config', 'sudo -n test -s /root/Tools/Havoc/data/havoc.yaotl'),
            ('havoc_guide', 'sudo -n test -s /root/havoc-guide.txt'),
            ('havoc_installer', 'sudo -n test -x /root/Tools/havoc_installer.sh'),
            ('postfix_active', 'test "$(systemctl is-active postfix)" = active'),
            ('dovecot_active', 'test "$(systemctl is-active dovecot)" = active'),
            ('opendkim_active', 'test "$(systemctl is-active opendkim)" = active'),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ], timeout=120)
        rules = context.cloud.inbound_rules(config['deployment_id'])
        require(('tcp', '22', config['operator_ip'] + '/32') in rules,
                provider_label(context.provider) + ' C2 does not restrict SSH to the operator /32: ' + str(rules))
        report['security_group_rules'] = rules
        return report


class PayloadServer:
    name = 'payload_server'
    source_paths = ('modules/payload-server',)

    def config(self, provider, deployment_id, operator_ip):
        config = {
            'deployment_id': deployment_id, 'provider': provider,
            'provider_workload': 'payload_server', 'deployment_type': 'secure_payload_server',
            'payload_server_name': 'ps-' + deployment_id, 'domain': 'payload-lab.test',
            'payload_subdomain': 'cdn', 'host_executables': True, 'host_scripts': True,
            'host_documents': False, 'host_mobile': False, 'enable_basic_auth': True,
            'enable_ip_filtering': True, 'enable_user_agent_filtering': True,
            'enable_rate_limiting': True, 'auto_generate_payloads': False,
            'auth_username': 'operator', 'auth_password': None,
            'letsencrypt_email': 'admin@payload-lab.test', 'operator_ip': operator_ip,
            'ssh_after_deploy': False,
        }
        config.update(live_config(provider, self.name))
        ready, _ = prepare_module_ssh_key(config, deployment_id)
        require(ready, 'Could not generate the module SSH key')
        return config

    def identity(self, config):
        deployment_id = config['deployment_id']
        return {'deployment_id': deployment_id, 'names': ['ps-' + deployment_id]}

    def target(self, provider, config):
        return driver_target(provider, 'ps-' + config['deployment_id'], config['deployment_id'])

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_' + deployment_id) + shared_artifacts(deployment_id)

    def verify(self, context, config):
        report = checks(context, [
            ('nginx_active', 'test "$(systemctl is-active nginx)" = active'),
            ('nginx_enabled', 'test "$(systemctl is-enabled nginx)" = enabled'),
            ('https_listening', "ss -ltn | grep -q ':443 '"),
            ('local_denied_by_allowlist',
             'test "$(curl -ks -o /dev/null -w \'%{http_code}\' -A Mozilla/5.0 https://127.0.0.1/)" = 403'),
            ('payload_dirs', 'sudo -n test -d /var/www/payloads/windows -a -d /var/www/payloads/scripts'),
            ('go_donut_built', 'sudo -n test -x /root/Tools/go-donut/go-donut'),
            ('guide', 'sudo -n test -s /root/PAYLOAD_SERVER_GUIDE.txt'),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ])
        credentials = context.ssh("sudo -n sed -n 's/^Basic auth: //p' /root/PAYLOAD_SERVER_GUIDE.txt")
        user, password = credentials.split(' / ')
        base = ['curl', '-ks', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20']
        url = 'https://' + context.address + '/'
        anonymous = context.run(base + ['-A', 'Mozilla/5.0', url])
        require(anonymous == '401', 'Payload server did not demand basic auth: ' + anonymous)
        authorized = context.run(base + ['-A', 'Mozilla/5.0', '-u', user + ':' + password, url])
        require(authorized == '200', 'Payload server refused valid credentials: ' + authorized)
        scanner = context.runner.run(base + [url], check=False)
        require(scanner == '000', 'Payload server answered a tool user agent: ' + scanner)
        report.update({'public_basic_auth': True, 'public_authorized': True,
                       'tool_user_agent_dropped': True})
        rules = context.cloud.inbound_rules(config['deployment_id'])
        require(('tcp', '22', config['operator_ip'] + '/32') in rules and
                all(source == '*' for proto, port, source in rules if port != '22'),
                provider_label(context.provider) + ' payload server rules are not operator-SSH plus public web: ' + str(rules))
        report['security_group_rules'] = rules
        return report


class SingleHost:
    """Shared shape for the single-VM team services added with the stubs."""
    repeat = {}
    legacy_paths = ()
    prefix = ''

    def base_config(self, provider, deployment_id, operator_ip):
        config = {
            'deployment_id': deployment_id, 'provider': provider,
            'provider_workload': self.name, 'deployment_type': self.deployment_type,
            self.name + '_name': self.prefix + deployment_id, 'operator_ip': operator_ip,
            'ssh_after_deploy': False,
        }
        config.update(live_config(provider, self.name))
        # The profile sizes its own disk; the account default must not shrink it.
        config.pop('azure_os_disk_gb', None)
        ready, _ = prepare_module_ssh_key(config, deployment_id)
        require(ready, 'Could not generate the module SSH key')
        return config

    def identity(self, config):
        deployment_id = config['deployment_id']
        return {'deployment_id': deployment_id, 'names': [self.prefix + deployment_id]}

    def target(self, provider, config):
        return driver_target(provider, self.prefix + config['deployment_id'], config['deployment_id'])

    def local_artifacts(self, provider, config):
        return key_files('c2deploy_' + config['deployment_id']) + shared_artifacts(config['deployment_id'])

    def expect_rules(self, context, config, expected):
        rules = context.cloud.inbound_rules(config['deployment_id'])
        require(rules == sorted(expected), provider_label(context.provider) + ' ' + self.name +
                ' rules differ from the profile: ' + str(rules))
        return rules


class Tracker(SingleHost):
    name = 'tracker'
    deployment_type = 'email_tracker'
    prefix = 't-'
    source_paths = ('modules/tracker',)

    def config(self, provider, deployment_id, operator_ip):
        config = self.base_config(provider, deployment_id, operator_ip)
        config.update(domain='tracker-lab.test', tracker_subdomain='track',
                      letsencrypt_email='admin@tracker-lab.test', zero_logs=True)
        return config

    def verify(self, context, config):
        local = "curl -ks -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: track.tracker-lab.test' "
        report = checks(context, [
            ('tracker_active', 'test "$(systemctl is-active tracker)" = active'),
            ('tracker_enabled', 'test "$(systemctl is-enabled tracker)" = enabled'),
            ('nginx_active', 'test "$(systemctl is-active nginx)" = active'),
            ('https_listening', "ss -ltn | grep -q ':443 '"),
            ('app_outside_root', 'sudo -n test -x /opt/tracker/simple_email_tracker.py'),
            ('runs_as_tracker', 'test "$(ps -o user= -C python)" = tracker || ps -o user= -C python | grep -qx tracker'),
            ('pixel_public', 'test "$(' + local + 'https://127.0.0.1/pixel/local.png)" = 200'),
            ('dashboard_not_local', 'test "$(' + local + 'https://127.0.0.1/)" = 403'),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ], timeout=180)
        base = ['curl', '-ks', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20']
        pixel = context.run(base + ['https://' + context.address + '/pixel/live.png'])
        require(pixel == '200', 'Tracking pixel is not public: ' + pixel)
        dashboard = context.run(base + ['https://' + context.address + '/'])
        require(dashboard == '200', 'Dashboard does not answer the operator: ' + dashboard)
        details = context.run(base + ['https://' + context.address + '/details/live'])
        require(details == '200', 'Pixel hit was not recorded: ' + details)
        report.update({'pixel_public': True, 'dashboard_operator_only': True, 'hit_recorded': True})
        report['security_group_rules'] = self.expect_rules(context, config, [
            ('tcp', '22', config['operator_ip'] + '/32'), ('tcp', '443', '*'), ('tcp', '80', '*')])
        return report


class LoggingServer(SingleHost):
    name = 'logging_server'
    deployment_type = 'logging_server'
    prefix = 'log-'
    source_paths = ('modules/logging-server',)
    # A placeholder peer must be a global address: the profile refuses documentation ranges.
    shipper = '9.9.9.9'

    def config(self, provider, deployment_id, operator_ip):
        config = self.base_config(provider, deployment_id, operator_ip)
        config.update(logging_ingest_sources=[self.shipper], logging_cert_name='logs.internal',
                      redelk_ref='master')
        return config

    def verify(self, context, config):
        report = checks(context, [
            ('docker_active', 'test "$(systemctl is-active docker)" = active'),
            ('elasticsearch_up', "sudo -n docker ps --format '{{.Names}}' | grep -qx redelk-elasticsearch"),
            ('logstash_up', "sudo -n docker ps --format '{{.Names}}' | grep -qx redelk-logstash"),
            ('kibana_up', "sudo -n docker ps --format '{{.Names}}' | grep -qx redelk-kibana"),
            ('nginx_up', "sudo -n docker ps --format '{{.Names}}' | grep -qx redelk-nginx"),
            ('beats_listening', "ss -ltn | grep -q ':5044 '"),
            ('packages_kept', 'sudo -n test -s /opt/redelk/redirs.tgz -a -s /opt/redelk/c2servers.tgz'),
            ('creds_private', 'test "$(sudo -n stat -c %a /opt/redelk-elk/elkserver/.env)" = 600'),
            ('creds_present', "sudo -n grep -q '^CREDS_redelk=.\\+' /opt/redelk-elk/elkserver/.env"),
            ('no_placeholders', "! sudo -n grep -q 'MODIFYME' /opt/redelk/certs/config.cnf"),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ], timeout=240)
        status = context.run(['curl', '-ks', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20',
                              'https://' + context.address + '/'])
        require(status in ('200', '302', '401'), 'Kibana front end does not answer the operator: ' + status)
        report['kibana_reachable'] = status
        report['security_group_rules'] = self.expect_rules(context, config, [
            ('tcp', '22', config['operator_ip'] + '/32'), ('tcp', '443', config['operator_ip'] + '/32'),
            ('tcp', '5044', self.shipper + '/32')])
        return report


class Hashtopolis(SingleHost):
    name = 'hashtopolis'
    deployment_type = 'hashtopolis'
    prefix = 'h-'
    source_paths = ('modules/hashtopolis',)
    agent = '9.9.9.9'

    def config(self, provider, deployment_id, operator_ip):
        config = self.base_config(provider, deployment_id, operator_ip)
        config.update(hashtopolis_agent_sources=[self.agent], hashtopolis_admin_user='liveadmin',
                      domain='')
        return config

    def verify(self, context, config):
        report = checks(context, [
            ('docker_active', 'test "$(systemctl is-active docker)" = active'),
            ('backend_up', "sudo -n docker ps --format '{{.Names}}' | grep -qx hashtopolis-backend"),
            ('frontend_up', "sudo -n docker ps --format '{{.Names}}' | grep -qx hashtopolis-frontend"),
            ('db_up', "sudo -n docker ps --format '{{.Names}}' | grep -qx hashtopolis-db"),
            ('loopback_only', "! ss -ltn | grep -E '0\\.0\\.0\\.0:(8080|4200) '"),
            ('creds_private', 'test "$(sudo -n stat -c %a /opt/hashtopolis/.env)" = 600'),
            ('admin_set', "sudo -n grep -q '^HASHTOPOLIS_ADMIN_USER=liveadmin$' /opt/hashtopolis/.env"),
            ('nginx_active', 'test "$(systemctl is-active nginx)" = active'),
            ('local_denied', 'test "$(curl -ks -o /dev/null -w \'%{http_code}\' --max-time 10 https://127.0.0.1/)" = 403'),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ], timeout=240)
        base = ['curl', '-ks', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20']
        ui = context.run(base + ['https://' + context.address + '/'])
        require(ui == '200', 'Hashtopolis UI does not answer the operator: ' + ui)
        # The agent handshake is the only query the API answers without credentials.
        api = context.run(['curl', '-ks', '--max-time', '20', '-H', 'Content-Type: application/json',
                           '-d', '{"action":"testConnection"}', 'https://' + context.address + '/api/server.php'])
        require('"response":"SUCCESS"' in api, 'Hashtopolis agent API did not accept testConnection: ' + api[:200])
        report.update({'ui_reachable': True, 'agent_api': 'testConnection SUCCESS'})
        report['security_group_rules'] = self.expect_rules(context, config, [
            ('tcp', '22', config['operator_ip'] + '/32'), ('tcp', '443', config['operator_ip'] + '/32'),
            ('tcp', '443', self.agent + '/32')])
        return report


class Phishing:
    """Basic phishing: an MTA front plus a GoPhish server, verified from the operator."""
    name = 'phishing'
    instances = 2
    source_paths = ('modules/phishing', 'common')

    def config(self, provider, deployment_id, operator_ip):
        domain = 'phish-lab.test'
        config = {
            'deployment_id': deployment_id, 'provider': provider, 'provider_workload': 'phishing',
            'deployment_type': 'basic_phishing', 'phishing_deployment': True,
            'deploy_mta_front': True, 'deploy_gophish': True,
            'phishing_domain': domain, 'primary_domain': domain, 'domain': domain,
            'mta_hostname': 'mail.' + domain, 'phishing_hostname': 'portal.' + domain,
            'mta_name': 'mta-' + deployment_id, 'gophish_name': 'gophish-' + deployment_id,
            'phishing_redirector_name': 'phr-' + deployment_id,
            'phishing_webserver_name': 'pw-' + deployment_id,
            'smtp_auth_user': 'operator', 'smtp_auth_pass': secrets.token_urlsafe(12),
            'gophish_admin_port': '3333', 'campaign_name': 'lab', 'sender_name': 'Lab',
            'sender_email': 'noreply@' + domain, 'email_template': 'office365_login',
            'enable_credential_harvesting': False, 'enable_attachment_tracking': False,
            'enable_link_tracking': False, 'letsencrypt_email': 'admin@' + domain,
            'operator_ip': operator_ip, 'ssh_after_deploy': False, 'open_admin_panel': False,
            'use_lander': False,
        }
        config.update(live_config(provider, self.name))
        # Both hosts share the module key.
        config.pop('provider_manages_ssh_key', None)
        ready, _ = prepare_module_ssh_key(config, deployment_id)
        require(ready, 'Could not generate the module SSH key')
        return config

    def deploy(self, config):
        module = load_module('modules/phishing/deploy_phishing.py')
        return dispatch_workload(config)

    def identity(self, config):
        deployment_id = config['deployment_id']
        names = ['mta-' + deployment_id, 'gophish-' + deployment_id]
        return {'deployment_id': deployment_id, 'names': names,
                # Every driver deploys one record per component.
                'components': {'mta-' + deployment_id: deployment_id + '-mta',
                               'gophish-' + deployment_id: deployment_id + '-gophish'}}

    def target(self, provider, config):
        return driver_target(provider, 'mta-' + config['deployment_id'], config['deployment_id'])

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_' + deployment_id) + [
            path for part in ('mta', 'gophish') for path in driver_artifacts(deployment_id + '-' + part)]

    def verify(self, context, config):
        domain = config['domain']
        deployment_id = config['deployment_id']
        sshd = ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'")
        report = {'mta': checks(context, [
            ('postfix_active', 'test "$(systemctl is-active postfix)" = active'),
            ('dovecot_active', 'test "$(systemctl is-active dovecot)" = active'),
            ('opendkim_active', 'test "$(systemctl is-active opendkim)" = active'),
            ('smtp_listening', "ss -ltn | grep -q ':25 '"),
            ('submission_listening', "ss -ltn | grep -q ':587 '"),
            ('dkim_key', 'sudo -n test -s /etc/opendkim/keys/' + domain + '/mail.private'),
            ('guide', 'sudo -n test -s /root/MTA_FRONT_GUIDE.txt'),
            sshd,
        ])}
        report['mta']['sasl_submission'] = submission_auth(
            context.address, config['smtp_auth_user'], config['smtp_auth_pass'])
        identity = self.identity(config)
        gophish_address = context.cloud.address(identity, 'gophish-' + deployment_id)
        gophish = Context(context.runner, context.cloud, context.provider, gophish_address,
                          context.user, context.key)
        admin_port = str(config['gophish_admin_port'])
        report['gophish'] = checks(gophish, [
            ('gophish_active', 'test "$(systemctl is-active gophish)" = active'),
            ('gophish_enabled', 'test "$(systemctl is-enabled gophish)" = enabled'),
            ('runs_as_gophish', 'test "$(ps -o user= -C gophish | head -1)" = gophish'),
            ('admin_listening', "ss -ltn | grep -q ':" + admin_port + " '"),
            ('phish_listening', "ss -ltn | grep -q ':80 '"),
            ('guide', 'sudo -n test -s /root/GOPHISH_GUIDE.txt'),
            sshd,
        ])
        base = ['curl', '-ks', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20']
        login = context.run(base + ['https://' + gophish_address + ':' + admin_port + '/login'])
        require(login == '200', 'GoPhish admin login page did not answer the operator: ' + login)
        landing = context.run(base + ['http://' + gophish_address + '/'])
        require(landing in ('200', '404'), 'GoPhish phishing listener did not answer: ' + landing)
        report['gophish'].update({'admin_login_page': True, 'phish_listener_status': landing,
                                  'address': gophish_address})
        operator = config['operator_ip'] + '/32'
        mta_rules = context.cloud.inbound_rules(deployment_id + '-mta')
        gophish_rules = context.cloud.inbound_rules(deployment_id + '-gophish')
        require(mta_rules == sorted([('tcp', '22', operator), ('tcp', '25', '*'), ('tcp', '587', '*')]),
                provider_label(context.provider) + ' MTA front rules are not operator SSH plus mail: ' + str(mta_rules))
        require(gophish_rules == sorted([('tcp', '22', operator), ('tcp', admin_port, operator),
                                         ('tcp', '80', '*')]),
                provider_label(context.provider) + ' GoPhish rules are not operator SSH/admin plus public phish: ' + str(gophish_rules))
        report['security_group_rules'] = {'mta': mta_rules, 'gophish': gophish_rules}
        return report


class Share(SingleHost):
    """Phantom's Nextcloud handed a driver VM, then bound to the tailnet only."""
    name = 'share'
    deployment_type = 'share_drive'
    source_paths = ('modules/share-drive',)

    def module(self):
        spec = importlib.util.spec_from_file_location(
            'live_share_module', ROOT / 'modules' / 'share-drive' / 'deploy_share.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def config(self, provider, deployment_id, operator_ip):
        config = self.base_config(provider, deployment_id, operator_ip)
        # A blank auth key leaves Tailscale installed but unauthenticated, which is
        # all a live run may do: joining a tailnet is an operator decision.
        config.update(server_type='cloud', domain='share.internal', cloud_admin_user='liveadmin',
                      cloud_storage_gb='10', tailscale_auth_key='')
        return config

    def deploy(self, config):
        # Phantom asks "Deploy? [y/N]" on its own; the Azure Phantom harness answers the same way.
        with mock.patch('builtins.input', return_value='y'):
            return self.module().deploy_share(config)

    def verify(self, context, config):
        local = "curl -ks -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: share.internal' "
        occ = 'sudo -n -u www-data php /var/www/nextcloud/occ '
        report = checks(context, [
            ('mariadb_active', 'test "$(systemctl is-active mariadb)" = active'),
            ('nginx_active', 'test "$(systemctl is-active nginx)" = active'),
            ('tailscaled_active', 'test "$(systemctl is-active tailscaled)" = active'),
            ('tailscaled_enabled', 'test "$(systemctl is-enabled tailscaled)" = enabled'),
            ('tailscale_cli', 'command -v tailscale >/dev/null'),
            ('admin_password_private', 'test "$(sudo -n stat -c %a /var/www/nextcloud/.admin_password)" = 600'),
            ('nextcloud_installed', occ + "status --output=json | grep -Eq '\"installed\"[[:space:]]*:[[:space:]]*true'"),
            ('trusted_domain', occ + 'config:system:get trusted_domains | grep -qx share.internal'),
            ('firewall_tailnet_only', "sudo -n ufw status | grep -q tailscale0"),
            ('no_public_web_rule', "! sudo -n ufw status | grep -Eq '^(80|443)/tcp +ALLOW +Anywhere'"),
            ('local_status_page', 'test "$(' + local + 'https://127.0.0.1/status.php)" = 200'),
            ('sshd_no_password', "sudo -n /usr/sbin/sshd -T | grep -iq '^passwordauthentication no$'"),
        ], timeout=180)
        exposed = subprocess.run(
            ['curl', '-k', '--silent', '--max-time', '15', '-o', '/dev/null',
             'https://' + context.address + '/status.php'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        require(exposed.returncode != 0, 'The share drive answered the public internet')
        report['closed_to_internet'] = True
        report['security_group_rules'] = self.expect_rules(context, config, [
            ('tcp', '22', config['operator_ip'] + '/32'), ('udp', '41641', '*')])
        return report

    def phantom_work(self, config):
        return self.module()._load_phantom().WORK_DIR / config['deployment_id']

    def local_artifacts(self, provider, config):
        return super().local_artifacts(provider, config) + [self.phantom_work(config)]

    def clean_local(self, config):
        # Phantom keeps its own vars and inventory per deployment; the Azure
        # Phantom harness removes them the same way after a verified teardown.
        shutil.rmtree(self.phantom_work(config), ignore_errors=True)


WORKLOADS = {cls.name: cls for cls in (Share, AttackBox, Redirector, FrontedRedirector, C2, PayloadServer, Phishing,
                                        Tracker, LoggingServer, Hashtopolis)}


class Webrunner:
    """One composite scan node per provider, scanning only the operator's own /32."""
    name = 'webrunner'
    source_paths = ('modules/webrunner', 'providers/webrunner.yml', 'providers/{dir}')

    def config(self, provider, deployment_id, operator_ip, keep_nodes):
        name = 'wr-' + deployment_id
        config = {
            'deployment_id': deployment_id, 'engagement': 'livetest',
            'deployment_type': 'webrunner', 'provider_workload': 'webrunner',
            'webrunner_deployment': True, 'webrunner_name': name, 'providers': [provider],
            'scan_mode': 'masscan-only', 'ports': [22], 'ports_str': '22', 'masscan_rate': 1000,
            'use_tor': False, 'targets_file': '', 'total_ips': 1, 'preset': 'sprint',
            'chunk_size': 500000, 'operator_ip': operator_ip, 'enhanced_opsec': False,
            'teardown_after_scan': not keep_nodes,
        }
        config.update(live_config(provider, self.name))
        # Every provider's scan nodes share the module key, so a driver must not own one.
        config.pop('provider_manages_ssh_key', None)
        ready, private = prepare_module_ssh_key(config, name)
        require(ready and private, 'Could not generate the module SSH key')
        config['ssh_key_name'] = Path(private).name
        logs = ROOT / 'logs'
        chunks = logs / ('node_chunks_' + deployment_id + '.json')
        chunks.write_text(json.dumps([{
            'idx': 0, 'node_name': name + '-01', 'provider': provider,
            'region': REGIONS[provider], 'cidrs': [operator_ip + '/32'], 'ip_count': 1}]))
        chunks.chmod(0o600)
        config['node_chunks_file'] = str(chunks)
        config['scanner_ip_log'] = str(logs / ('scanner_ips_' + name + '.txt'))
        config['results_dir'] = str(logs / ('webrunner_' + deployment_id))
        return config

    def identity(self, provider, deployment_id):
        # The node adapters derive one state record per node.
        return {'deployment_id': deployment_id + '-n01', 'names': ['wr-' + deployment_id + '-01']}

    def target(self, provider, config):
        return driver_target(provider, config['webrunner_name'] + '-01', config['webrunner_name'])

    def local_artifacts(self, provider, config):
        deployment_id = config['deployment_id']
        return key_files('c2deploy_wr-' + deployment_id) + driver_artifacts(deployment_id + '-n01')

    def verify(self, runner, cloud, provider, config, identity, keep_nodes):
        node, user, key = self.target(provider, config)
        merged = json.loads((Path(config['results_dir']) / 'merged_results.json').read_text())
        require([item['node_name'] for item in merged['nodes']] == [node] and
                merged['nodes'][0]['scan_mode'] == 'masscan-only',
                'Merged results do not describe the single scan node: ' + json.dumps(merged['nodes']))
        logged = re.search('^' + re.escape(node) + r': (\S+)$',
                           Path(config['scanner_ip_log']).read_text(), re.MULTILINE)
        require(logged, 'Scanner IP log does not list the node')
        address = public_ipv4(logged.group(1))
        report = {'nodes': merged['nodes'], 'total_results': merged['total_results'],
                  'scanner_ip': address, 'target': config['operator_ip'] + '/32 tcp/22'}
        inventory = cloud.inventory(identity)
        if keep_nodes:
            require(len(inventory['instances']) == 1 and inventory['instances'][0]['state'] == 'running',
                    'Expected exactly one running scan node')
            require(cloud.address(identity, node) == address, 'Scanner IP log disagrees with the cloud inventory')
            require(key.is_file(), 'Module SSH key is missing: ' + str(key))
            context = Context(runner, cloud, provider, address, user, key)
            report['host'] = checks(context, [
                ('masscan_installed', 'command -v masscan'),
                ('scanner_present', 'sudo -n test -s /root/webrunner/node_scanner.py'),
                ('results_present', 'sudo -n test -s /root/webrunner/results.json'),
            ])
            rules = cloud.inbound_rules(identity['deployment_id'])
            require(rules == [('tcp', '22', config['operator_ip'] + '/32')],
                    provider_label(provider) + ' scan node allows more than operator SSH: ' + str(rules))
            report['security_group_rules'] = rules
        else:
            require(empty(inventory), 'Scan node remains after the in-play teardown')
            require(not key.exists(), 'Module key remains after the in-play teardown')
            report['in_play_teardown'] = True
        report['cloud'] = inventory
        return report

    def collect(self, runner, config, label):
        for source in (Path(config['results_dir']), Path(config['scanner_ip_log']),
                       Path(config['node_chunks_file'])):
            if source.exists():
                shutil.move(str(source), str(runner.evidence / (label + '-' + source.name)))


class Context:
    def __init__(self, runner, cloud, provider, address, user, key):
        self.runner = runner
        self.cloud = cloud
        self.provider = provider
        self.address = address
        self.user = user
        self.key = key

    def run(self, argv, timeout=60):
        return self.runner.run(argv, timeout=timeout)

    def ssh(self, command, timeout=90):
        argv = ['ssh', '-F', '/dev/null', '-i', str(self.key),
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new',
                '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'UserKnownHostsFile=' + str(self.runner.evidence / 'known_hosts'),
                self.user + '@' + self.address, command]
        deadline = time.monotonic() + 300
        while True:
            try:
                return self.runner.run(argv, timeout=timeout)
            except LiveError as exc:
                transient = any(marker in str(exc).lower() for marker in (
                    'connection refused', 'connection timed out', 'connection reset',
                    'kex_exchange_identification', 'connection closed by'))
                if not transient or time.monotonic() >= deadline:
                    raise
                time.sleep(10)


def verify_committed_source(runner, provider, workload):
    directory = PROVIDER_SPECS[provider].directory
    paths = ['utils', 'teardown.py', 'scripts/test_provider_workload_live.py',
             'scripts/live_clouds.py']
    paths += [path.format(dir=directory) for path in workload.source_paths]
    # A provider's whole directory is part of its infrastructure contract.
    paths.append('providers/' + directory)
    for path in paths:
        runner.run(['git', 'diff', '--quiet', 'HEAD', '--', path])
    return runner.run(['git', 'rev-parse', 'HEAD'])


def empty(inventory):
    return not any(inventory.values())


def activate(provider, workload_name, operator_ip=None, repeat=None, variant=None):
    workload = (WORKLOADS[workload_name](variant or 'quick_recon')
                if workload_name == 'attack_box' else WORKLOADS[workload_name]())
    os.chdir(ROOT)
    deployment_id = 'lt-{0}-{1}-{2}'.format(
        provider, workload_name.replace('_', '')[:6], uuid.uuid4().hex[:6])
    evidence = ROOT / 'logs' / '{0}-{1}-live'.format(provider, workload_name.replace('_', '-')) / deployment_id
    evidence.mkdir(parents=True, mode=0o700)
    runner = Runner(evidence)
    previous = {sig: signal.signal(sig, runner.handle_signal)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    config = cloud = identity = None
    live_passed = cleanup_passed = deployed = False
    failure = None
    try:
        # The project venv carries Ansible plus the AWS and Linode SDKs its
        # controller lookups import; prefer it over a system ansible-playbook.
        venv_bin = Path(sys.executable).parent
        if (venv_bin / 'ansible-playbook').is_file():
            os.environ['PATH'] = str(venv_bin) + os.pathsep + os.environ.get('PATH', '')
        for executable in ('ansible-playbook', 'ssh', 'ssh-keygen', 'curl', 'git'):
            require(shutil.which(executable), 'Required tool unavailable: ' + executable)
        runner.record('source.json', {'commit': verify_committed_source(runner, provider, workload)})
        prepare_provider_environment({'provider': provider})
        cloud = build_cloud(provider, evidence)
        operator_ip = public_ipv4(operator_ip or runner.run([
            'curl', '-4', '--fail', '--silent', '--show-error', '--max-time', '15',
            'https://api.ipify.org']))
        config = workload.config(provider, deployment_id, operator_ip)
        identity = workload.identity(config)
        require(empty(cloud.inventory(identity)), 'Live-test identity already owns cloud resources')
        generated = [path for path in workload.local_artifacts(provider, config) if path.exists()]
        expected_key = Path(config.get('ssh_key_path') or
                            SSH_DIR / ('c2deploy_' + deployment_id + '.pub')).with_suffix('')
        require(set(generated) <= {expected_key, Path(str(expected_key) + '.pub')},
                'Unexpected local artifacts exist for the live-test identity')
        baseline = cloud.totals()
        runner.record('baseline.json', {'identity': identity, 'totals': baseline,
                                        'operator_ip': operator_ip})
        runner.record('config.json', redacted(config))
        setup_logging(deployment_id, 'live_test')

        deployed = True
        deploy = getattr(workload, 'deploy', deploy_infrastructure)
        expected = getattr(workload, 'instances', 1)
        require(deploy(config), 'Initial routed deployment failed')
        first = cloud.inventory(identity)
        require(len(first['instances']) == expected and
                all(item['state'] == 'running' for item in first['instances']),
                'Expected exactly {0} running instance(s) after deployment'.format(expected))
        name, user, key = workload.target(provider, config)
        require(key.is_file(), 'Expected SSH key is missing: ' + str(key))
        address = cloud.address(identity, name)
        context = Context(runner, cloud, provider, address, user, key)
        runner.record('host-diagnostics.json', {'sshd': context.ssh(SSHD_DIAGNOSTICS)})
        service = workload.verify(context, config)
        runner.record('first-deployment.json', {'cloud': first, 'address': address, 'service': service})

        # Every driver adapter is idempotent by contract.
        if repeat is None or repeat:
            require(deploy(config), 'Repeated routed deployment failed')
            repeated = cloud.inventory(identity)
            require(repeated == first, 'Repeated deployment changed cloud resource identities')
            require(cloud.address(identity, name) == address, 'Repeated deployment changed the public address')
            runner.record('repeat-deployment.json', {
                'cloud': repeated, 'service': workload.verify(context, config),
                'resource_identity_preserved': True})
        else:
            runner.record('repeat-deployment.json', {'skipped': True, 'reason': 'requested'})
        live_passed = True
    except BaseException as exc:
        failure = str(exc)
        runner.record('failure.json', {'error': failure})
        print('{0} {1} live test did not pass: {2}'.format(provider, workload_name, failure), file=sys.stderr)
    finally:
        runner.cleaning = True
        try:
            if config is not None and cloud is not None:
                cleanup_passed = cleanup(runner, cloud, provider, workload, config, identity, deployed)
            elif config is None:
                cleanup_passed = True
        except BaseException as exc:
            runner.record('cleanup-failure.json', {'error': str(exc)})
            print('{0} {1} cleanup failed: {2}'.format(provider, workload_name, exc), file=sys.stderr)
        for sig, handler in previous.items():
            signal.signal(sig, handler)

    passed = live_passed and cleanup_passed and not runner.interrupted
    runner.record('result.json', {
        'passed': passed, 'live_workflow_passed': live_passed,
        'cleanup_passed': cleanup_passed, 'failure': failure,
        'deployment_id': deployment_id, 'provider': provider, 'workload': workload_name,
    })
    print('Evidence: ' + str(evidence))
    return 0 if passed else 1


def cleanup(runner, cloud, provider, workload, config, identity, deployed):
    deployment_id = config['deployment_id']
    info = ROOT / 'logs' / ('deployment_info_' + deployment_id + '.txt')
    report = {'standalone_teardown': None}
    if info.exists():
        # Prove recovery from a fresh process that holds no provider credential.
        env = {key: value for key, value in os.environ.items() if key not in CREDENTIAL_ENVIRONMENT}
        result = subprocess.run(
            [sys.executable, 'teardown.py', '--deployment-id', deployment_id, '--force'],
            cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1800)
        runner.record('standalone-teardown.json', {'returncode': result.returncode,
                                                   'output': result.stdout[-30000:]})
        report['standalone_teardown'] = result.returncode == 0
        require(result.returncode == 0, 'Standalone routed teardown failed')
    elif deployed:
        report['standalone_teardown'] = 'not-recorded'
    deadline = time.monotonic() + 600
    while True:
        remaining = cloud.inventory(identity)
        if empty(remaining):
            break
        if time.monotonic() >= deadline:
            runner.record('residual-cloud.json', remaining)
            raise LiveError('Cloud resources remain after teardown: ' + json.dumps(remaining))
        time.sleep(10)
    baseline = json.loads((runner.evidence / 'baseline.json').read_text())['totals']
    getattr(cloud, 'settle', lambda: None)()
    totals = cloud.totals()
    require(totals == baseline, 'Provider inventory was not restored: {0} != {1}'.format(totals, baseline))
    getattr(workload, 'clean_local', lambda config: None)(config)
    leftovers = [str(path) for path in workload.local_artifacts(provider, config) if path.exists()]
    for path in (ROOT / 'logs' / ('deployment_' + deployment_id + '.log'), info):
        if path.exists():
            leftovers.append(str(path))
    require(not leftovers, 'Local artifacts remain after teardown: ' + ', '.join(leftovers))
    report.update({'cloud_absent': True, 'inventory_restored': True, 'local_artifacts_absent': True,
                   'totals': totals})
    runner.record('final-cleanup.json', report)
    return True


def activate_webrunner(provider, operator_ip=None):
    """Keep the first run's node for inspection and routed teardown; the second
    run exercises the module's own in-play teardown. Both scan only the
    operator's /32 on tcp/22."""
    workload = Webrunner()
    os.chdir(ROOT)
    deployment_id = 'lt-{0}-webrun-{1}'.format(provider, uuid.uuid4().hex[:6])
    evidence = ROOT / 'logs' / (provider + '-webrunner-live') / deployment_id
    evidence.mkdir(parents=True, mode=0o700)
    runner = Runner(evidence)
    previous = {sig: signal.signal(sig, runner.handle_signal)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    cloud = None
    pending = []
    live_passed = cleanup_passed = False
    failure = None
    try:
        venv_bin = Path(sys.executable).parent
        if (venv_bin / 'ansible-playbook').is_file():
            os.environ['PATH'] = str(venv_bin) + os.pathsep + os.environ.get('PATH', '')
        for executable in ('ansible-playbook', 'ssh', 'ssh-keygen', 'curl', 'git'):
            require(shutil.which(executable), 'Required tool unavailable: ' + executable)
        runner.record('source.json', {'commit': verify_committed_source(runner, provider, workload)})
        prepare_provider_environment({'provider': provider})
        cloud = build_cloud(provider, evidence)
        operator_ip = public_ipv4(operator_ip or runner.run([
            'curl', '-4', '--fail', '--silent', '--show-error', '--max-time', '15',
            'https://api.ipify.org']))
        module = load_module('modules/webrunner/deploy_webrunner.py')
        baseline = None
        for label, run_id, keep in (('kept', deployment_id, True),
                                    ('self-teardown', deployment_id + '-r', False)):
            identity = workload.identity(provider, run_id)
            require(empty(cloud.inventory(identity)), 'Live-test identity already owns cloud resources')
            require(not [path for path in workload.local_artifacts(provider, {'deployment_id': run_id})
                         if path.exists()], 'Unexpected local artifacts exist for the live-test identity')
            if baseline is None:
                baseline = cloud.totals()
                runner.record('baseline.json', {'identity': identity, 'totals': baseline,
                                                'operator_ip': operator_ip})
            config = workload.config(provider, run_id, operator_ip, keep)
            runner.record(label + '-config.json', redacted(config))
            setup_logging(run_id, 'live_test')
            pending.append((label, config, identity))
            require(dispatch_composite_workload(config, module._execute_webrunner_legacy),
                    'Routed WEBRUNNER deployment failed (' + label + ')')
            report = workload.verify(runner, cloud, provider, config, identity, keep)
            runner.record(label + '-deployment.json', report)
            workload.collect(runner, config, label)
            runner.cleaning = True
            require(cleanup(runner, cloud, provider, workload, config, identity, True),
                    'Cleanup did not verify (' + label + ')')
            for name in ('final-cleanup.json', 'standalone-teardown.json'):
                if (runner.evidence / name).exists():
                    (runner.evidence / name).rename(runner.evidence / (label + '-' + name))
            runner.cleaning = False
            pending.pop()
        live_passed = True
    except BaseException as exc:
        failure = str(exc)
        runner.record('failure.json', {'error': failure})
        print('{0} webrunner live test did not pass: {1}'.format(provider, failure), file=sys.stderr)
    finally:
        runner.cleaning = True
        cleanup_passed = True
        for label, config, identity in pending:
            try:
                workload.collect(runner, config, label)
                node_state = driver_artifacts(config['deployment_id'] + '-n01')
                if any(path.exists() for path in node_state) and not (
                        ROOT / 'logs' / ('deployment_info_' + config['deployment_id'] + '.txt')).exists():
                    # Provisioning failed before the playbook recorded the run.
                    runner.run([sys.executable, 'teardown.py', '--deployment-id',
                                config['deployment_id'] + '-n01', '--force'], timeout=1800)
                cleanup_passed = cleanup(runner, cloud, provider, workload, config, identity, True) and cleanup_passed
            except BaseException as exc:
                cleanup_passed = False
                runner.record('cleanup-failure.json', {'error': str(exc)})
                print('{0} webrunner cleanup failed: {1}'.format(provider, exc), file=sys.stderr)
        for sig, handler in previous.items():
            signal.signal(sig, handler)

    passed = live_passed and cleanup_passed and not runner.interrupted
    runner.record('result.json', {
        'passed': passed, 'live_workflow_passed': live_passed,
        'cleanup_passed': cleanup_passed, 'failure': failure,
        'deployment_id': deployment_id, 'provider': provider, 'workload': 'webrunner',
    })
    print('Evidence: ' + str(evidence))
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=sorted(CLOUDS), required=True)
    parser.add_argument('--workload', choices=sorted(WORKLOADS) + ['webrunner'], required=True)
    parser.add_argument('--variant', choices=AttackBox.variants,
                        help='attack-box subtype (default: quick_recon)')
    parser.add_argument('--activate', action='store_true')
    parser.add_argument('--operator-ip')
    parser.add_argument('--repeat', dest='repeat', action='store_true', default=None)
    parser.add_argument('--no-repeat', dest='repeat', action='store_false')
    args = parser.parse_args(argv)
    if args.variant and args.workload != 'attack_box':
        parser.error('--variant is only valid with --workload attack_box')
    if not args.activate:
        print('DRY RUN: no cloud mutations. Target: {0} / {1} / {2}'.format(
            args.provider, REGIONS[args.provider], args.workload))
        return 0
    if args.workload == 'webrunner':
        return activate_webrunner(args.provider, args.operator_ip)
    return activate(args.provider, args.workload, args.operator_ip, args.repeat, args.variant)


if __name__ == '__main__':
    sys.exit(main())
