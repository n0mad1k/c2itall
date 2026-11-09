"""Redirector profile: what any VM provider must supply for this module."""

import ipaddress
import re

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
        'allowed_referrers', 'fronting', 'edge_id', 'edge_hostname', 'edge_header',
    )
    _forwarding = {'https': 'HttpsOnly', 'http': 'HttpOnly'}

    def backend(self, config):
        return str(config.get('backend_ip') or config['operator_ip']).removesuffix('/32')

    def host(self, config):
        return str(config.get('redirector_subdomain') or 'cdn') + '.' + str(config['domain'])

    def validate(self, config):
        if not config.get('domain'):
            raise ValueError('Redirector requires a domain')
        if ipaddress.ip_address(self.backend(config)).version != 4:
            raise ValueError('Redirector backend must be an IPv4 address')
        if config.get('fronting'):
            if not re.fullmatch(r'[a-z][a-z0-9-]{0,45}', str(config.get('fronting_endpoint_name', ''))):
                raise ValueError('fronting_endpoint_name must be a short lowercase label')
            if config.get('fronting_origin_protocol', 'https') not in self._forwarding:
                raise ValueError('fronting_origin_protocol must be https or http')

    def edge(self, config):
        if not config.get('fronting'):
            return None
        return {'host_header': self.host(config),
                'forwarding': self._forwarding[config.get('fronting_origin_protocol', 'https')],
                'name': config['fronting_endpoint_name']}

    def inbound_rules(self, config):
        # Fronted: only the provider's edge reaches the web ports; the origin
        # address never answers the public internet directly.
        web = 'edge' if config.get('fronting') else '*'
        return [
            {'name': 'http', 'protocol': 'Tcp', 'port': 80, 'source': web},
            {'name': 'https', 'protocol': 'Tcp', 'port': 443, 'source': web},
            {'name': 'shell-handler', 'protocol': 'Tcp',
             'port': int(config.get('shell_handler_port') or 4488), 'source': '*'},
        ]

    def service_variables(self, config, variables):
        variables.setdefault('c2_ip', self.backend(config))
        variables.setdefault('shell_handler_port', 4488)
        return variables


PROFILE = RedirectorProfile()
