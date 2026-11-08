"""Phishing profile: an MTA front and a GoPhish server as two recoverable VMs.

Each component reuses the single-VM lifecycle under its own deployment ID
(``<id>-mta``, ``<id>-gophish``) and the module's shared SSH key, so a lost
controller recovers either VM alone or the whole deployment from its record.
"""

import secrets

from utils.workloads import WorkloadProfile


class PhishingComponent(WorkloadProfile):
    workload = 'phishing'
    manages_ssh_key = False

    def validate(self, config):
        if not config.get('domain'):
            raise ValueError('Phishing requires a domain')
        if config.get('deploy_phishing_redirector') or config.get('deploy_phishing_webserver'):
            raise ValueError('Native phishing supports the MTA front and GoPhish components only')


class MtaFront(PhishingComponent):
    component = 'mta'
    address_key = 'mta_ip'
    service_playbook = 'modules/phishing/service-mta.yml'
    log_suffix = 'phishing-mta'
    inventory_group = 'mta_fronts'
    config_keys = (
        'domain', 'phishing_domain', 'mta_hostname', 'mta_name', 'operator_ip',
        'smtp_auth_user', 'smtp_auth_pass', 'zero_logs', 'mta_ip',
    )

    def inbound_rules(self, config):
        return [{'name': 'smtp', 'protocol': 'Tcp', 'port': 25, 'source': '*'},
                {'name': 'submission', 'protocol': 'Tcp', 'port': 587, 'source': '*'}]


class GophishServer(PhishingComponent):
    component = 'gophish'
    address_key = 'gophish_ip'
    service_playbook = 'modules/phishing/service-gophish.yml'
    log_suffix = 'phishing-gophish'
    inventory_group = 'gophish_servers'
    config_keys = (
        'domain', 'phishing_domain', 'phishing_hostname', 'gophish_name',
        'gophish_admin_port', 'gophish_phish_port', 'mta_ip', 'operator_ip',
        'smtp_auth_user', 'smtp_auth_pass', 'zero_logs', 'gophish_ip',
    )

    def inbound_rules(self, config):
        return [{'name': 'phish', 'protocol': 'Tcp',
                 'port': int(config.get('gophish_phish_port') or 80), 'source': '*'},
                {'name': 'gophish-admin', 'protocol': 'Tcp',
                 'port': int(config.get('gophish_admin_port') or 3333),
                 'source': config['operator_ip']}]


class PhishingProfile(WorkloadProfile):
    kind = 'components'
    workload = 'phishing'
    manages_ssh_key = False
    recovers_from_log = True
    components = (('deploy_mta_front', MtaFront()),
                  ('deploy_gophish', GophishServer()))

    def prepare(self, config):
        if not config.get('smtp_auth_pass'):
            # Both hosts must agree on the relay credential.
            config['smtp_auth_pass'] = secrets.token_urlsafe(16)


PROFILE = PhishingProfile()
