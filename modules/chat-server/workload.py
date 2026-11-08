"""Chat profile: a Phantom-managed host that carries the chat service rules."""

from utils.workloads import WorkloadProfile, load_profile


class ChatProfile(WorkloadProfile):
    kind = 'handoff'
    workload = 'chat'

    def disk_gb(self, config):
        return load_profile('phantom').disk_gb(config)

    def inbound_rules(self, config):
        return load_profile('phantom').inbound_rules(config)


PROFILE = ChatProfile()
