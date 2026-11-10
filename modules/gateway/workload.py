"""Lab gateway profile: the WireGuard hub and logged egress every lab member joins."""

from utils.workloads import WorkloadProfile


class GatewayProfile(WorkloadProfile):
    workload = 'lab_gateway'
    lab_role = 'gateway'
    address_key = 'lab_gateway_ip'
    service_playbook = 'modules/gateway/service.yml'
    log_suffix = 'lab-gateway'
    config_keys = ('lab_gateway_name', 'operator_ip', 'lab_gateway_ip')

    def service_timeout(self, config):
        return 900

    def validate(self, config):
        if not config.get('lab'):
            raise ValueError('The lab gateway must belong to a lab')

    def inbound_rules(self, config):
        # WireGuard answers only peers it knows; the operator SSH rule is the driver's.
        return [{'name': 'wireguard', 'protocol': 'Udp', 'port': 51820, 'source': '*'}]


PROFILE = GatewayProfile()
