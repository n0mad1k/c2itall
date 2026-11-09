"""Hashtopolis profile: a cracking coordinator any VM provider can host."""

import re

from utils.workloads import WorkloadProfile, host_source


class HashtopolisProfile(WorkloadProfile):
    workload = 'hashtopolis'
    address_key = 'hashtopolis_ip'
    service_playbook = 'modules/hashtopolis/service.yml'
    log_suffix = 'hashtopolis'
    inventory_group = 'hashtopolis'
    config_keys = (
        'hashtopolis_name', 'operator_ip', 'hashtopolis_ip', 'hashtopolis_agent_sources',
        'hashtopolis_admin_user', 'domain', 'letsencrypt_email',
    )

    def disk_gb(self, config):
        return 64

    def service_timeout(self, config):
        return 2400

    def validate(self, config):
        host_source(config.get('operator_ip'))
        sources = config.get('hashtopolis_agent_sources') or []
        if not isinstance(sources, list) or len(sources) > 13:
            raise ValueError('hashtopolis_agent_sources must list at most 13 hosts')
        for source in sources:
            host_source(source, 'hashtopolis_agent_sources')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',
                            str(config.get('hashtopolis_admin_user', 'admin'))):
            raise ValueError('hashtopolis_admin_user is invalid')

    def inbound_rules(self, config):
        rules = [{'name': 'operator-https', 'protocol': 'Tcp', 'port': 443,
                  'source': host_source(config.get('operator_ip'))}]
        for index, source in enumerate(config.get('hashtopolis_agent_sources') or [], 1):
            rules.append({'name': 'agent-' + str(index), 'protocol': 'Tcp', 'port': 443,
                          'source': host_source(source, 'hashtopolis_agent_sources')})
        if config.get('domain'):
            # Only a public-domain deployment needs HTTP, and only for ACME.
            rules.append({'name': 'acme-http', 'protocol': 'Tcp', 'port': 80, 'source': '*'})
        return rules

    def service_variables(self, config, variables):
        variables.setdefault('hashtopolis_agent_sources', [])
        variables.setdefault('hashtopolis_admin_user', 'admin')
        return variables


PROFILE = HashtopolisProfile()
