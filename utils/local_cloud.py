"""Local driver: bare metal or a VM the operator built, adopted through SSH.

Hosts and the operator may sit on private addresses. The shared adopt-a-host
lifecycle installs the deployment key, enforces the inbound rules with ufw
and revokes the key on cleanup; the machine itself is the operator's.
"""

from .driver_base import STATE_ROOT
from .ssh_host_cloud import SshHostDriver


class LocalDriver(SshHostDriver):
    provider = 'local'
    prefix = 'local_'
    identity_keys = ('local_host',)
    option_keys = ('local_state_dir', 'local_cleanup_deadline')
    state_root = STATE_ROOT / 'local'
    private_addresses = True
    # The operator attests it; the LUDUS play checks vmx/svm before installing.
    capabilities = frozenset({'nested_virtualization'})
    adopt_prompt = 'Local hosts are bare metal or VMs you built; enter one that already accepts root SSH.'
    host_label = 'Host'
    keep_message = 'keeps running: the deployment key is revoked; reset or delete the machine yourself.'


def local_driver():
    return LocalDriver()


def gather_local_config():
    return LocalDriver().gather_config()
