"""Exfil receiver profile: a private drop point that records every file it receives."""

from utils.workloads import WorkloadProfile


class ExfilProfile(WorkloadProfile):
    workload = 'exfil_receiver'
    address_key = 'exfil_ip'
    service_playbook = 'modules/exfil/service.yml'
    log_suffix = 'exfil'
    config_keys = ('exfil_name', 'operator_ip', 'exfil_ip')

    def disk_gb(self, config):
        return 64

    def validate(self, config):
        if not config.get('lab'):
            raise ValueError('The exfil receiver lives inside a lab')


PROFILE = ExfilProfile()
