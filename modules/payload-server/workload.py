"""Payload server profile: what any VM provider must supply for this module."""

from utils.workloads import WorkloadProfile


class PayloadServerProfile(WorkloadProfile):
    workload = 'payload_server'
    address_key = 'payload_server_ip'
    service_playbook = 'modules/payload-server/service.yml'
    log_suffix = 'payload-server'
    inventory_group = 'payloadservers'
    config_keys = (
        'payload_server_name', 'domain', 'payload_subdomain', 'letsencrypt_email',
        'operator_ip', 'payload_server_ip', 'host_executables', 'host_scripts',
        'host_documents', 'host_mobile', 'enable_basic_auth', 'enable_ip_filtering',
        'enable_user_agent_filtering', 'enable_rate_limiting',
        'auto_generate_payloads', 'auth_username', 'auth_password', 'allowed_ips',
    )

    def validate(self, config):
        if not config.get('domain'):
            raise ValueError('Payload server requires a domain')

    def inbound_rules(self, config):
        return [{'name': 'http', 'protocol': 'Tcp', 'port': 80, 'source': '*'},
                {'name': 'https', 'protocol': 'Tcp', 'port': 443, 'source': '*'}]


PROFILE = PayloadServerProfile()
