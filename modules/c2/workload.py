"""C2 profile: what any VM provider must supply for this module."""

import ipaddress

from utils.workloads import WorkloadProfile

# Frameworks with native service tasks. Adding one is a task file plus an
# entry naming the listener ports its redirector and operator must reach.
FRAMEWORKS = {
    'havoc': {
        'label': 'Havoc',
        'tasks': 'tasks/configure_c2.yml',
        'operator_ports': (('havoc-teamserver', 'havoc_teamserver_port', 40056),),
        'redirector_ports': (('havoc-http', 'havoc_http_port', 8080),
                             ('havoc-https', 'havoc_https_port', 9443),
                             ('havoc-payload', 'havoc_payload_port', 8443)),
    },
}


def framework(config):
    return config.get('c2_framework') or 'havoc'


class C2Profile(WorkloadProfile):
    workload = 'c2'
    frameworks = FRAMEWORKS
    address_key = 'c2_ip'
    service_playbook = 'modules/c2/service.yml'
    log_suffix = 'c2'
    inventory_group = 'c2servers'
    image_role = 'kali'
    config_keys = (
        'c2_name', 'redirector_name', 'domain', 'c2_subdomain',
        'redirector_subdomain', 'redirector_port', 'c2_framework',
        'letsencrypt_email', 'operator_ip', 'c2_ip', 'redirector_ip',
        'ssh_key_path', 'smtp_auth_user', 'smtp_auth_pass', 'zero_logs',
        'secure_memory', 'disable_history', 'randomize_ports',
        'gophish_admin_port', 'gophish_phish_port', 'havoc_teamserver_port',
        'havoc_http_port', 'havoc_https_port', 'havoc_payload_port',
        'havoc_admin_user', 'havoc_admin_password', 'havoc_spawn',
        'havoc_sleep', 'havoc_jitter', 'havoc_sleep_mask_technique',
        'setup_integrated_tracker', 'tracker_domain', 'tracker_port',
        'c2_only', 'redirector_only', 'deploy_redirector', 'deploy_tracker',
    )

    def redirector(self, config):
        address = str(config.get('redirector_ip') or '').removesuffix('/32')
        if not address:
            return None
        parsed = ipaddress.ip_address(address)
        if parsed.is_loopback:
            return None
        if parsed.version != 4 or not parsed.is_global:
            raise ValueError('C2 redirector address must be a public IPv4')
        return str(parsed)

    def validate(self, config):
        if not config.get('domain'):
            raise ValueError('C2 requires a domain')
        if framework(config) not in FRAMEWORKS:
            raise ValueError('C2 supports only these frameworks: ' + ', '.join(sorted(FRAMEWORKS)))
        self.redirector(config)

    def inbound_rules(self, config):
        operator = config['operator_ip']
        selected = FRAMEWORKS[framework(config)]
        rules = [{'name': name, 'protocol': 'Tcp', 'port': int(config.get(key) or default),
                  'source': operator} for name, key, default in selected['operator_ports']]
        rules.append({'name': 'gophish-admin', 'protocol': 'Tcp',
                      'port': int(config.get('gophish_admin_port') or 2222), 'source': operator})
        if config.get('setup_integrated_tracker'):
            rules.append({'name': 'tracker', 'protocol': 'Tcp',
                          'port': int(config.get('tracker_port') or 5000), 'source': operator})
        redirector = self.redirector(config)
        if redirector:
            for name, key, default in (*selected['redirector_ports'],
                                       ('gophish-phish', 'gophish_phish_port', 8081)):
                rules.append({'name': name, 'protocol': 'Tcp',
                              'port': int(config.get(key) or default), 'source': redirector})
        return rules

    def service_variables(self, config, variables):
        variables['c2_framework_tasks'] = FRAMEWORKS[framework(config)]['tasks']
        variables.setdefault('redirector_ip', self.redirector(config) or '127.0.0.1')
        variables.setdefault('c2_subdomain', 'mail')
        variables.setdefault('redirector_subdomain', 'cdn')
        variables.setdefault('gophish_admin_port', '2222')
        variables.setdefault('redirector_only', False)
        return variables


PROFILE = C2Profile()
