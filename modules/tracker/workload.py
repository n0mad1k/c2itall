"""Email tracker profile: what any VM provider must supply for this module."""

from utils.workloads import WorkloadProfile


class TrackerProfile(WorkloadProfile):
    workload = 'tracker'
    address_key = 'tracker_ip'
    service_playbook = 'modules/tracker/service.yml'
    log_suffix = 'tracker'
    inventory_group = 'trackers'
    config_keys = (
        'tracker_name', 'domain', 'tracker_subdomain', 'letsencrypt_email',
        'operator_ip', 'tracker_ip', 'zero_logs',
    )

    def validate(self, config):
        if not config.get('domain'):
            raise ValueError('Email tracker requires a domain')

    def inbound_rules(self, config):
        # The pixel must be public; nginx keeps the dashboard to the operator.
        return [{'name': 'http', 'protocol': 'Tcp', 'port': 80, 'source': '*'},
                {'name': 'https', 'protocol': 'Tcp', 'port': 443, 'source': '*'}]

    def service_variables(self, config, variables):
        variables.setdefault('tracker_subdomain', 'track')
        variables.setdefault('zero_logs', True)
        return variables


PROFILE = TrackerProfile()
