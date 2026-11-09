"""Provider-neutral workload profiles.

A profile is the whole of what a workload asks from a VM provider: the
service playbook to run on the host, the inventory group that playbook
expects, which configuration keys it needs, the image role, the inbound
rules, and the validation of its inputs. Profiles live beside their module
in ``modules/<module>/workload.py`` and are the only place that knowledge
exists, so a provider driver never has to know what runs on the VM.
"""

import importlib.util
from pathlib import Path

from .controller_io import ROOT

_CACHE = {}


class WorkloadProfile:
    """What one workload needs from any provider that can run a VM."""

    # 'single': one VM running service_playbook.
    # 'components': several single VMs, one per enabled (flag, profile) pair.
    # 'nodes': scan nodes provisioned for a composite executor, no service play.
    # 'handoff': one VM handed to the module controller as target_host.
    kind = 'single'
    workload = None
    component = None
    address_key = None
    service_playbook = None
    log_suffix = None
    inventory_group = None
    config_keys = ()
    image_role = 'ubuntu'
    # None means every variant the workload catalog declares.
    variants = None
    manages_ssh_key = True
    recovers_from_log = False
    components = ()

    def disk_gb(self, config):
        return 32

    def image_role_for(self, config):
        """Return the provider-neutral image role for this configuration."""
        return self.image_role

    def prepare(self, config):
        """Settle module inputs every component must share before provisioning."""

    def validate(self, config):
        """Raise ValueError when the module inputs cannot be served."""

    def inbound_rules(self, config):
        """Return [{'name', 'protocol', 'port', 'source'}] the provider must open."""
        return []

    def service_variables(self, config, variables):
        """Add the defaults the service playbook expects; return variables."""
        return variables

    def label(self):
        name = self.workload or 'workload'
        if self.component:
            name += '-' + self.component
        return name.replace('_', '-')

    def check(self):
        if not isinstance(self.workload, str) or not self.workload:
            raise TypeError('Workload profile must name its workload')
        if self.kind not in ('single', 'components', 'nodes', 'handoff'):
            raise TypeError('Unknown workload profile kind: ' + str(self.kind))
        if self.kind == 'single':
            values = (self.address_key, self.service_playbook, self.log_suffix)
            if not all(isinstance(value, str) and value for value in values):
                raise TypeError(self.label() + ' profile metadata is incomplete')
        if self.kind == 'components':
            if not self.components or any(
                    not isinstance(flag, str) or not isinstance(profile, WorkloadProfile)
                    for flag, profile in self.components):
                raise TypeError(self.label() + ' profile needs (flag, profile) components')
            for _flag, profile in self.components:
                profile.check()
        if (not isinstance(self.config_keys, tuple) or
                not all(isinstance(key, str) and key for key in self.config_keys)):
            raise TypeError(self.label() + ' config_keys must be a string tuple')
        if self.variants is not None and not isinstance(self.variants, frozenset):
            raise TypeError(self.label() + ' variants must be a frozenset or None')
        return self


def profile_path(workload):
    from .provider_registry import WORKLOAD_SPECS
    spec = WORKLOAD_SPECS[workload]
    return ROOT / (spec.profile or str(Path(spec.entrypoint).parent / 'workload.py'))


def load_profile(workload):
    """Return the module's profile, or None when the workload has no native profile."""
    if workload in _CACHE:
        return _CACHE[workload]
    path = profile_path(workload)
    if not path.is_file():
        _CACHE[workload] = None
        return None
    spec = importlib.util.spec_from_file_location('c2itall_workload_' + workload, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    profile = getattr(module, 'PROFILE', None)
    if not isinstance(profile, WorkloadProfile) or profile.workload != workload:
        raise TypeError('Workload profile does not describe ' + workload + ': ' + str(path))
    _CACHE[workload] = profile.check()
    return profile


def profiled_workloads():
    from .provider_registry import WORKLOAD_SPECS
    return [workload for workload in WORKLOAD_SPECS if load_profile(workload) is not None]
