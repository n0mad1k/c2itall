"""Exfil receiver profile: a private drop point that records every file it receives."""

from utils.workloads import WorkloadProfile

CREDENTIAL_KEYS = ('exfil_minio_user', 'exfil_minio_password', 'exfil_http_user',
                   'exfil_http_password', 'exfil_sftp_password')


class ExfilProfile(WorkloadProfile):
    workload = 'exfil_receiver'
    address_key = 'exfil_ip'
    service_playbook = 'modules/exfil/service.yml'
    log_suffix = 'exfil'
    config_keys = ('exfil_name', 'operator_ip', 'exfil_ip') + CREDENTIAL_KEYS

    def disk_gb(self, config):
        return 64

    def validate(self, config):
        if not config.get('lab'):
            raise ValueError('The exfil receiver lives inside a lab')
        for key in CREDENTIAL_KEYS:
            if not str(config.get(key) or '').strip():
                raise ValueError(key + ' must not be empty')


PROFILE = ExfilProfile()
