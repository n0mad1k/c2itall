"""FlokiNET driver: a host the operator ordered by hand, adopted through SSH.

FlokiNET has no provisioning API; the shared adopt-a-host lifecycle installs
the deployment key, enforces the inbound rules with ufw and revokes the key
on cleanup. A dedicated FlokiNET server can host LUDUS; the operator attests
nested virtualization when choosing it.
"""

from .driver_base import STATE_ROOT
from .ssh_host_cloud import SshHostDriver


class FlokinetDriver(SshHostDriver):
    provider = 'flokinet'
    prefix = 'flokinet_'
    identity_keys = ('flokinet_host',)
    option_keys = ('flokinet_state_dir', 'flokinet_cleanup_deadline')
    state_root = STATE_ROOT / 'flokinet'
    capabilities = frozenset({'nested_virtualization'})
    adopt_prompt = 'FlokiNET servers are ordered by hand; enter one host that already accepts root SSH.'
    host_label = 'FlokiNET host public'
    keep_message = ('keeps running: the deployment key is revoked, but the service and the '
                    'server itself must be removed by hand in the FlokiNET panel.')


def flokinet_driver():
    return FlokinetDriver()


def gather_flokinet_config():
    return FlokinetDriver().gather_config()
