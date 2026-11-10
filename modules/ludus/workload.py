"""LUDUS host profile: a nested-virtualization host that builds the lab's Active Directory range."""

from pathlib import Path

import yaml

from utils.workloads import WorkloadProfile

MODULE_DIR = Path(__file__).resolve().parent
# ponytail: VirtualBox-nested live test tops out at 16 GB; corp needs real headroom.
MIN_RAM_GB = {'mini': 14, 'corp': 30}


class LudusHostProfile(WorkloadProfile):
    workload = 'ludus_host'
    requires = frozenset({'nested_virtualization'})
    address_key = 'ludus_host_ip'
    service_playbook = 'modules/ludus/service.yml'
    log_suffix = 'ludus'
    inventory_group = 'ludushosts'
    image_role = 'debian12'
    config_keys = ('ludus_name', 'operator_ip', 'ludus_host_ip', 'lab_range',
                   'ludus_weaknesses', 'falcon_cid', 'falcon_installer_path',
                   'ludus_min_ram_gb')

    def disk_gb(self, config):
        return 200

    def service_timeout(self, config):
        return 3600

    def validate(self, config):
        if not config.get('lab'):
            raise ValueError('The LUDUS host lives inside a lab')
        if config.get('lab_range') not in ('corp', 'mini'):
            raise ValueError('lab_range must be "corp" or "mini"')
        weaknesses = yaml.safe_load((MODULE_DIR / 'identities.yml').read_text())['weaknesses']
        unknown = set(config.get('ludus_weaknesses') or ()) - set(weaknesses)
        if unknown:
            raise ValueError('Unknown weakness keys: ' + ', '.join(sorted(unknown)))
        installer = config.get('falcon_installer_path')
        if installer and not Path(installer).is_file():
            raise ValueError('falcon_installer_path does not exist: ' + str(installer))

    def service_variables(self, config, variables):
        variables.setdefault('ludus_min_ram_gb', MIN_RAM_GB[config['lab_range']])
        return variables


PROFILE = LudusHostProfile()
