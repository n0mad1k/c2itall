"""Phantom profile: the privacy-service host any VM provider hands to Phantom."""

import ipaddress

from utils.workloads import WorkloadProfile

_WEB_RULES = (
    {'name': 'public-http', 'protocol': 'Tcp', 'port': 80, 'source': '*'},
    {'name': 'public-https', 'protocol': 'Tcp', 'port': 443, 'source': '*'},
)


def _operator_source(config):
    value = str(config.get('operator_ip', '')).strip()
    if '/' not in value:
        value += '/32'
    network = ipaddress.ip_network(value, strict=True)
    if network.version != 4 or network.prefixlen != 32 or not network.is_global:
        raise ValueError('Phantom operator_ip must be one global IPv4 host')
    return str(network)


def service_rules(config):
    service = config.get('server_type')
    if service == 'all_in_one':
        selected = config.get('services')
        allowed = {'matrix', 'vpn', 'dns', 'cloud', 'vault', 'media'}
        if (not isinstance(selected, (list, tuple)) or not selected or
                any(component not in allowed for component in selected)):
            raise ValueError('All-in-one requires supported selected services')
        rules = []
        seen = set()
        for component in selected:
            component_config = dict(config, server_type=component,
                                    provider_workload='phantom')
            for rule in service_rules(component_config):
                identity = (rule['protocol'].lower(), int(rule['port']),
                            rule['source'])
                if identity not in seen:
                    seen.add(identity)
                    rules.append(rule)
        return rules
    if service == 'vpn':
        return [{'name': 'wireguard', 'protocol': 'Udp',
                 'port': int(config.get('vpn_port', 51820)), 'source': '*'}]
    if service == 'dns':
        operator = _operator_source(config)
        return [
            {'name': 'operator-dns-tcp', 'protocol': 'Tcp', 'port': 53,
             'source': operator},
            {'name': 'operator-dns-udp', 'protocol': 'Udp', 'port': 53,
             'source': operator},
            {'name': 'operator-dns-http', 'protocol': 'Tcp', 'port': 80,
             'source': operator},
            {'name': 'operator-dns-https', 'protocol': 'Tcp', 'port': 443,
             'source': operator},
        ]
    if service == 'matrix':
        rules = [*_WEB_RULES, {'name': 'matrix-federation', 'protocol': 'Tcp',
                               'port': 8448, 'source': '*'}]
        if config.get('provider_workload') == 'chat':
            rules.append({'name': 'tailscale-direct', 'protocol': 'Udp',
                          'port': 41641, 'source': '*'})
        return rules
    if service == 'tak':
        rules = [
            {'name': 'tak-client-tls', 'protocol': 'Tcp', 'port': 8089, 'source': '*'},
            {'name': 'tak-admin', 'protocol': 'Tcp', 'port': 8443, 'source': '*'},
            {'name': 'tak-enrollment', 'protocol': 'Tcp', 'port': 8446, 'source': '*'},
            {'name': 'tailscale-direct', 'protocol': 'Udp', 'port': 41641,
             'source': '*'},
        ]
        if config.get('tak_federation'):
            rules.append({'name': 'tak-federation', 'protocol': 'Tcp',
                          'port': 8444, 'source': '*'})
        return rules
    if service == 'email':
        return [
            *_WEB_RULES,
            *[{'name': 'mail-' + str(port), 'protocol': 'Tcp', 'port': port,
               'source': '*'} for port in (25, 465, 587, 993, 4190)],
            {'name': 'mail-dns-tcp', 'protocol': 'Tcp', 'port': 53, 'source': '*'},
            {'name': 'mail-dns-udp', 'protocol': 'Udp', 'port': 53, 'source': '*'},
        ]
    if service in ('cloud', 'vault', 'media'):
        return list(_WEB_RULES)
    raise ValueError('Unsupported Phantom service')


class PhantomProfile(WorkloadProfile):
    kind = 'handoff'
    workload = 'phantom'

    def disk_gb(self, config):
        return 64 if config.get('server_type') == 'tak' else 32

    def inbound_rules(self, config):
        return service_rules(config)


PROFILE = PhantomProfile()
