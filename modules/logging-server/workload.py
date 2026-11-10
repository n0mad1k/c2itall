"""Logging server profile: a RedELK server any VM provider can host."""

import re

from utils.workloads import WorkloadProfile, host_source


class LoggingServerProfile(WorkloadProfile):
    workload = 'logging_server'
    address_key = 'logging_server_ip'
    service_playbook = 'modules/logging-server/service.yml'
    log_suffix = 'logging-server'
    inventory_group = 'logservers'
    config_keys = (
        'logging_server_name', 'operator_ip', 'logging_server_ip',
        'logging_ingest_sources', 'logging_cert_name', 'redelk_ref',
    )

    def disk_gb(self, config):
        return 64

    def service_timeout(self, config):
        # The installer builds and pulls the whole Elastic stack.
        return 3600

    def validate(self, config):
        host_source(config.get('operator_ip'))
        sources = config.get('logging_ingest_sources') or []
        if not isinstance(sources, list) or len(sources) > 14:
            raise ValueError('logging_ingest_sources must list at most 14 hosts')
        for source in sources:
            host_source(source, 'logging_ingest_sources', private_ok=bool(config.get('lab')))
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,63}', str(config.get('redelk_ref', 'master'))):
            raise ValueError('redelk_ref must be a git ref')
        name = str(config.get('logging_cert_name', 'logs.internal'))
        if not re.fullmatch(r'[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*', name):
            raise ValueError('logging_cert_name must be a hostname')

    def inbound_rules(self, config):
        rules = [{'name': 'operator-https', 'protocol': 'Tcp', 'port': 443,
                  'source': host_source(config.get('operator_ip'))}]
        for index, source in enumerate(config.get('logging_ingest_sources') or [], 1):
            rules.append({'name': 'beats-' + str(index), 'protocol': 'Tcp', 'port': 5044,
                          'source': host_source(source, 'logging_ingest_sources',
                                                private_ok=bool(config.get('lab')))})
        return rules

    def service_variables(self, config, variables):
        variables.setdefault('logging_ingest_sources', [])
        variables.setdefault('logging_cert_name', 'logs.internal')
        variables.setdefault('redelk_ref', 'master')
        return variables


PROFILE = LoggingServerProfile()
