"""LUDUS host profile: a nested-virtualization host that builds the lab's Active Directory range."""

from utils.workloads import WorkloadProfile


class LudusHostProfile(WorkloadProfile):
    workload = 'ludus_host'
    requires = frozenset({'nested_virtualization'})
    address_key = 'ludus_host_ip'
    service_playbook = 'modules/ludus/service.yml'
    log_suffix = 'ludus'
    inventory_group = 'ludushosts'
    image_role = 'debian12'
    config_keys = ('ludus_name', 'operator_ip', 'ludus_host_ip', 'lab_range')

    def disk_gb(self, config):
        return 200

    def service_timeout(self, config):
        return 3600

    def validate(self, config):
        if not config.get('lab'):
            raise ValueError('The LUDUS host lives inside a lab')


PROFILE = LudusHostProfile()
