"""Attack box profile: what any VM provider must supply for this module."""

from utils.workloads import WorkloadProfile

# Subtypes with native service tasks. Adding one is a task file plus an entry.
VARIANTS = {
    'quick_recon': {'tasks': 'tasks/configure_quick_recon.yml',
                    'deployment_type': 'quick_recon_box'},
}


class AttackBoxProfile(WorkloadProfile):
    workload = 'attack_box'
    address_key = 'attack_box_ip'
    service_playbook = 'modules/attack-box/service.yml'
    log_suffix = 'attack-box'
    config_keys = (
        'attack_box_name', 'attack_box_type', 'domain',
        'enhanced_opsec', 'project_name', 'setup_domain', 'setup_tor',
        'setup_vpn', 'tool_name', 'work_dir',
    )
    variants = frozenset(VARIANTS)

    def validate(self, config):
        variant = VARIANTS.get(config.get('attack_box_type'))
        if variant is None or config.get('deployment_type') != variant['deployment_type']:
            raise ValueError('Native attack boxes currently support only the '
                             + ', '.join(sorted(VARIANTS)).replace('_', '-')
                             + ' attack-box subtype')

    def inbound_rules(self, config):
        rules = []
        if config.get('setup_vpn'):
            rules.append({'name': 'openvpn', 'protocol': 'Udp',
                          'port': 1194, 'source': '*'})
        return rules

    def service_variables(self, config, variables):
        variables['attack_box_tasks'] = VARIANTS[config['attack_box_type']]['tasks']
        return variables


PROFILE = AttackBoxProfile()
