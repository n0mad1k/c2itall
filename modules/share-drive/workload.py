"""Share-drive profile: a Phantom-managed Nextcloud reached only over the tailnet."""

from utils.workloads import WorkloadProfile


class ShareProfile(WorkloadProfile):
    kind = 'handoff'
    workload = 'share'

    def disk_gb(self, config):
        return 32 + int(config.get('cloud_storage_gb') or 10)

    def validate(self, config):
        storage = str(config.get('cloud_storage_gb', '10'))
        if not storage.isdigit() or not 1 <= int(storage) <= 1000:
            raise ValueError('Share drive storage must be 1-1000 GB')

    def inbound_rules(self, config):
        # Private by construction: no public web ports, only direct tailnet UDP.
        return [{'name': 'tailscale-direct', 'protocol': 'Udp', 'port': 41641,
                 'source': '*'}]


PROFILE = ShareProfile()
