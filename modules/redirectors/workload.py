"""Redirector profile: what any VM provider must supply for this module."""

import ipaddress

from utils.workloads import WorkloadProfile


class RedirectorProfile(WorkloadProfile):
    workload = 'redirector'
    address_key = 'redirector_ip'
    service_playbook = 'modules/redirectors/service.yml'
    log_suffix = 'redirector'
    inventory_group = 'redirectors'
    config_keys = (
        'redirector_name', 'domain', 'redirector_subdomain', 'backend_type',
        'backend_ip', 'redirector_type', 'letsencrypt_email',
        'operator_ip', 'redirector_ip', 'c2_ip', 'shell_handler_port',
        'havoc_teamserver_port', 'havoc_http_port', 'havoc_https_port',
        'zero_logs', 'randomize_ports', 'legitimate_redirect',
        'allowed_referrers',
    )

    def backend(self, config):
        return str(config.get('backend_ip') or config['operator_ip']).removesuffix('/32')

    def validate(self, config):
        if not config.get('domain'):
            raise ValueError('Redirector requires a domain')
        if ipaddress.ip_address(self.backend(config)).version != 4:
            raise ValueError('Redirector backend must be an IPv4 address')

    def inbound_rules(self, config):
        return [
            {'name': 'http', 'protocol': 'Tcp', 'port': 80, 'source': '*'},
            {'name': 'https', 'protocol': 'Tcp', 'port': 443, 'source': '*'},
            {'name': 'shell-handler', 'protocol': 'Tcp',
             'port': int(config.get('shell_handler_port') or 4488), 'source': '*'},
        ]

    def service_variables(self, config, variables):
        variables.setdefault('c2_ip', self.backend(config))
        variables.setdefault('shell_handler_port', 4488)
        return variables


PROFILE = RedirectorProfile()
