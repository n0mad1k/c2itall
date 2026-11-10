"""The provider contract: cloud-only operations every VM provider implements.

A driver knows how to turn a provisioning request into its own resources,
how to persist and recover the state of those resources, and how to prove
they are gone. It never knows what runs on the VM; that comes from the
workload profiles in ``modules/<module>/workload.py`` through the generic
adapters in ``vm_workloads``.
"""

from . import controller_io
from .provider_registry import InfrastructureAdapter


class ProvisionRequest:
    """Everything a driver needs to plan one VM for a workload."""

    def __init__(self, deployment_id, workload, inbound_rules, image_role,
                 disk_gb, ssh_public, ssh_private, ssh_generated, edge=None, lab=None):
        self.deployment_id = deployment_id
        self.workload = workload
        # A rule whose source is 'edge' admits only the provider's own edge
        # (CDN) network; drivers translate it to their service tag or ranges.
        self.inbound_rules = list(inbound_rules)
        self.image_role = image_role
        self.disk_gb = disk_gb
        self.ssh_public = ssh_public
        self.ssh_private = ssh_private
        self.ssh_generated = ssh_generated
        # Optional edge in front of the VM: {'host_header', 'forwarding', 'name'}.
        # forwarding is HttpsOnly, HttpOnly or MatchRequest; name is the
        # public endpoint label the provider derives a hostname from.
        self.edge = dict(edge) if edge else None
        # Lab placement from utils.lab.placement(): role, lab_ip, cidrs,
        # public_ip, ssh_source, ssh_proxy, egress_via_hub, network.
        self.lab = dict(lab) if lab else None


class CloudDriver:
    provider = None
    ssh_user = None
    # What this provider can offer beyond a VM: 'lab_network' (a shared private
    # subnet with managed NAT and flow logs), 'nested_virtualization'.
    capabilities = frozenset()
    # True when hosts and the operator may sit on private addresses (local VMs).
    private_addresses = False
    # Configuration keys the driver owns, e.g. 'azure_'; exported to the module
    # config after provisioning so records and teardown carry them.
    prefix = None
    # Keys that identify the provider-side target and must match saved state.
    identity_keys = ()
    # Keys that only tune a lifecycle call (state directory, deadlines).
    option_keys = ()
    # Safe number of pool nodes per region before a default quota bites.
    node_quota = 10
    # True when plan() honours ProvisionRequest.edge and the 'edge' rule source.
    supports_edge = False

    def check(self):
        for name in ('provider', 'ssh_user', 'prefix'):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise TypeError('Cloud driver must define ' + name)
        return self

    # --- configuration -----------------------------------------------------
    def gather_config(self):
        """Ask the operator for the provider inputs (credentials come from the vault)."""
        raise NotImplementedError

    def validate_config(self, config, require_key=True):
        raise NotImplementedError

    def image(self, role):
        """Return the provider image reference for 'ubuntu' or 'kali', or None for the default."""
        return None

    def region(self, config):
        return 'default'

    # Configuration key that places one VM in a region; None when regions are fixed.
    region_key = None

    def regions(self, config):
        """Regions a pool may spread nodes across; one unless the operator listed more."""
        return [self.region(config)]

    def apply_profile(self, config, workload, profile, value):
        """Translate a neutral workload tuning knob into this provider's sizing."""
        return config

    # --- lifecycle ---------------------------------------------------------
    def plan(self, config, request):
        """Return the validated infrastructure record for one requested VM."""
        raise NotImplementedError

    def prepare_state(self, infrastructure):
        raise NotImplementedError

    def prepare_ssh_key(self, infrastructure):
        raise NotImplementedError

    def deploy(self, infrastructure):
        """Create the planned resources; return True only when they are ready."""
        raise NotImplementedError

    def public_address(self, deployment_id, config):
        raise NotImplementedError

    def edge_endpoint(self, deployment_id, config):
        """Return {'edge_id', 'edge_hostname', 'edge_header'} for a fronted VM.

        edge_id is the value the edge stamps into the edge_header request
        header on every forwarded request, so the origin can drop traffic
        that did not come through this edge.
        """
        raise NotImplementedError

    def cleanup(self, request):
        """Delete owned resources; return True only after proving they are absent."""
        raise NotImplementedError

    def health(self, state):
        raise NotImplementedError

    # --- lab networks ------------------------------------------------------
    def lab_network(self, lab, config):
        """Create or reuse this provider's shared lab network; return its record."""
        raise NotImplementedError

    def delete_lab_network(self, lab, network):
        """Delete the shared lab network once no member remains; prove absence."""
        raise NotImplementedError

    # --- durable state -----------------------------------------------------
    def load_state(self, deployment_id):
        """Return the recovery state for an ID, or None when there is none."""
        raise NotImplementedError

    def list_states(self, config=None):
        raise NotImplementedError

    def infrastructure_playbook(self, config):
        return None

    def local_artifacts(self, deployment_id, config=None):
        """Local files kept for one deployment ID (durable state, caches)."""
        return []

    # --- controller plumbing ----------------------------------------------
    def log_dir(self, config):
        """Directory for service playbook logs of this provider's deployments."""
        raise NotImplementedError

    def run_command(self, argv, timeout=60, deadline=None, check=True):
        return controller_io.run_command(argv, timeout=timeout, deadline=deadline,
                                         check=check, label=self.provider)

    def check_connection(self):
        """Read-only connectivity probe; return a dict describing the account."""
        raise NotImplementedError

    def exported_config(self, infrastructure):
        """Keys the module config keeps after provisioning for records and teardown."""
        return {key: value for key, value in infrastructure.items()
                if key.startswith(self.prefix) or key in (
                    'operator_ip', 'ssh_key_path', 'ssh_private_key_path', 'ssh_key_generated',
                    'ssh_proxy')}

    def cleanup_request(self, config, identity=True):
        request = {'deployment_id': config['deployment_id']}
        keys = self.option_keys + (self.identity_keys if identity else ())
        for key in keys:
            if key in config:
                request[key] = config[key]
        return request


class DriverInfrastructureAdapter(InfrastructureAdapter):
    """The neutral infrastructure lifecycle served by any cloud driver."""

    def __init__(self, driver):
        self.driver = driver

    def gather_config(self):
        return self.driver.gather_config()

    def validate_config(self, config, require_key=True):
        return self.driver.validate_config(config, require_key=require_key)

    def prepare_key(self, config):
        return self.driver.prepare_ssh_key(config)

    def playbook(self, config):
        return self.driver.infrastructure_playbook(config)

    def deploy(self, config):
        return self.driver.deploy(config)

    def cleanup(self, config):
        return self.driver.cleanup(config)

    def health(self, config):
        return self.driver.health(config)

    def load_state(self, deployment_id):
        return self.driver.load_state(deployment_id)

    def list_states(self):
        return self.driver.list_states()
