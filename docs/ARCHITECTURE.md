# Architecture

c2itall deploys offensive infrastructure through three independent layers.
A **workload** says what a host must look like and how it is configured. A
**provider** knows how to create, address and destroy VMs. The **registry**
and a set of **generic adapters** join the two without either naming the
other. Read this before `docs/EXTENDING.md`.

## One deployment, end to end

```
deploy.py main menu
  └─ modules/<module>/deploy_<module>.py        controller: prompts, builds config
       ├─ select_provider('<workload>')         registry: who can serve it
       ├─ gather_provider_config(provider, wl)  route.gather_config()
       └─ dispatch_workload(config, legacy_fn)  deployment_engine
            └─ registry.workload_route(config)
                 └─ vm_workloads.<Kind>Adapter(driver, profile)
                       plan ─► prepare_state ─► prepare_ssh_key ─► deploy
                       ─► public_address ─► service play over SSH ─► record
```

Teardown runs the same route selection in reverse: `teardown.py`, the
Cleanup menu and `modules/infrastructure/deploy_infrastructure.py --teardown-id`
find the deployment record or durable state, resolve the route, and call the
adapter's `cleanup`, which returns true only after the driver proves the
resources are gone.

## Layers

### Workload profiles: `modules/<module>/workload.py`

Each module exposes `PROFILE`, a `WorkloadProfile` (`utils/workloads.py`).
It is the complete statement of what the workload needs from any VM provider:

| Attribute | Meaning |
|---|---|
| `kind` | `single` (one VM, one play), `components` (several VMs in order, one play each), `nodes` (scan nodes handed to a composite executor), `handoff` (one VM handed to a module that configures it) |
| `workload` | canonical name, must match `WORKLOAD_SPECS` |
| `address_key` | config key that receives the public IPv4 |
| `service_playbook` | the provider-neutral play, under `modules/` |
| `inventory_group` | host group the play targets |
| `log_suffix` | per-deployment service log name |
| `config_keys` | the only module keys passed to the play |
| `image_role` | `ubuntu` or `kali`; the driver maps it to an image |
| `variants` | subtypes with native service tasks, or `None` for all declared |
| `manages_ssh_key` | true when the provider generates a per-deployment key |
| `validate`, `inbound_rules`, `disk_gb`, `service_variables`, `prepare` | per-config hooks |
| `edge` | `None`, or `{'host_header', 'forwarding', 'name'}` to put the provider's edge (CDN) in front of the VM; the profile's rules then use source `'edge'` for the ports the edge reaches |

Catalogs of variants live in the profile too: `FRAMEWORKS` in the C2 profile,
`VARIANTS` in the attack-box profile, `service_rules` in the Phantom profile,
the `(flag, component)` list in the phishing profile. Menus enumerate them.

### Service plays: `modules/<module>/service*.yml`

A service play targets the profile's inventory group, asserts the inputs it
needs, and includes task files from `modules/<module>/tasks/` and
`common/tasks/`. It receives `provider`, `provider_workload`, `deployment_id`,
`deployment_type` and the profile's `config_keys`, nothing else. Provider
credentials never reach it. The adapter runs it with Ansible over SSH using
the driver's SSH user and the deployment's private key.

### Cloud drivers: `utils/cloud_driver.py`

`CloudDriver` is the whole provider contract. A driver answers in terms of a
`ProvisionRequest` (deployment ID, workload name, inbound rules, image role,
disk size, SSH key paths) and its own infrastructure record:

- configuration: `gather_config`, `validate_config`, `image(role)`, `region(config)`
- lifecycle: `plan`, `prepare_state`, `prepare_ssh_key`, `deploy`,
  `public_address`, `cleanup`, `health`
- edge (optional, `supports_edge = True`): `plan` honours
  `ProvisionRequest.edge` and translates the `'edge'` rule source to its own
  network; `edge_endpoint` returns the edge identifier, hostname and the
  header the edge stamps on forwarded requests
- durable state: `load_state`, `list_states`, `local_artifacts`,
  `infrastructure_playbook`
- plumbing: `log_dir`, `run_command`, `check_connection`, `exported_config`,
  `cleanup_request`
- identity: `provider`, `ssh_user`, `prefix` (its config-key prefix),
  `identity_keys`, `option_keys`, `node_quota`, `region_key`
- pools: `regions(config)` lists the regions a WEBRUNNER pool may spread
  across; `apply_profile(config, workload, profile, value)` maps a module's
  sizing choice (attack-box `instance_size`) onto the provider's own plan names

`utils/driver_base.py` (`StatefulDriver`) is what the real drivers share:
the `StateStore` wiring, common validation (IDs, workload names, operator
/32, at most sixteen inbound rules that never include 22, edge requests),
the lifecycle lock, status transitions, the SSH wait and ownership tags.
A subclass supplies `create`, `delete` and `inspect` against its own API.

| Driver | Network boundary and VM | Edge |
|---|---|---|
| `utils/azure_cloud.py` | one resource group holding VNet, NSG, static IP, NIC and VM from an ARM template through the Azure CLI (`utils/azure_utils.py`) | Front Door Standard in the same ARM deployment; origin admits `AzureFrontDoor.Backend`, redirector checks `X-Azure-FDID` |
| `utils/aws_cloud.py` | one VPC, IGW, subnet, route and security group, one EC2 instance keyed by cloud-init, through boto3 | CloudFront distribution on the instance's public DNS; origin admits the `cloudfront.origin-facing` prefix list, redirector checks `X-Origin-Verify` |
| `utils/linode_cloud.py` | one Cloud Firewall and one Linode through the v4 REST API | none |
| `utils/flokinet_cloud.py` | a host the operator ordered by hand, adopted over SSH: deployment key installed, `ufw` enforces the rules | none |

None of them names a workload. `tests/fake_cloud.py` is a complete in-memory
driver used by the contract tests and the reference for writing a new one;
`tests/test_cloud_drivers.py` proves the three API-backed drivers against
in-memory EC2, CloudFront and Linode fakes.

### Generic adapters: `utils/vm_workloads.py`

One adapter per profile kind binds any driver to any profile:

| Adapter | Lifecycle |
|---|---|
| `SingleVmAdapter` | plan, persist state, key, create, address, export driver keys into the config, fetch the edge endpoint when the profile asked for one, run the service play, write the deployment record; any failure after state exists enters verified cleanup |
| `ComponentAdapter` | `prepare` shared inputs, then one `SingleVmAdapter` per enabled component under `<id>-<component>`; a record retires every component, a component state retires itself |
| `NodeAdapter` | provision `<id>-nNN` nodes for the composite executor, call it exactly once, remove the nodes afterwards |
| `HandoffAdapter` | provision one VM and hand `target_host`, `ssh_user`, `ssh_key` to a module that runs its own plays (Phantom, chat) |

`DriverInfrastructureAdapter` serves the plain infrastructure-only VM.

### The registry: `utils/provider_registry.py`

`WORKLOAD_SPECS` lists every canonical workload with its controller
entrypoint, whether legacy fallback is allowed, its declared variants and
(optionally) where its profile lives. `PROVIDER_SPECS` lists every provider:

- Every built-in provider sets `driver='utils.<name>_cloud:<factory>'` and
  lists no per-workload routes. Its capabilities are derived:
  `infrastructure` plus every workload that has a profile. Explicit or staged
  routes that would shadow a driver workload are rejected by validation.
- A provider registered with `legacy_menu=True` and `legacy_capabilities`
  instead routes those workloads to the module's preserved legacy executor.
  No built-in provider does; the path survives for the engine tests.

`validate_provider_registry()` checks all of this without deploying anything
and is run by the test suite and `scripts/audit_provider_coverage.py`.
`provider_label`, `provider_driver`, `providers_for`, `provider_route_kind`
and `provider_supported_variants` are what menus and tools call instead of
naming providers.

### Durable state and recovery

`utils/state_store.py` is a generic per-deployment JSON store with locking,
ownership markers and an archive; a driver may use it or bring its own. Every
built-in driver saves intent before any resource exists under
`deployments/<provider>/<id>.json`, so a lost controller recovers by ID.
Successful teardown moves the record to `deployments/<provider>/archive/`.
Deployment records under `logs/deployment_info_<id>.txt` are written as
well; teardown tooling reads both.

### Process and file hygiene

`utils/controller_io.py` runs provider CLIs with timeouts and lifecycle
deadlines, forwards interruptions to children, and opens log and state
directories without following symlinks. Every driver's `run_command` defaults
to it.

## Where the provider branches went

| Formerly a per-provider branch | Now |
|---|---|
| WEBRUNNER provider labels, region pools, quota warnings, inline provisioning | `provider_label`, `driver.regions`, `driver.node_quota`; the drivers provision the nodes and `providers/webrunner.yml` only configures and scans |
| Tools menu connectivity test and config validation | iterate `PROVIDER_SPECS`; drivers answer `check_connection` and `validate_config` |
| Chat module Azure disk size | the Phantom profile's `disk_gb` |
| C2 framework menus | the C2 profile's `FRAMEWORKS` |
| Attack-box image names and sizes | each driver maps the subtype to an image and `instance_size` to its own plans |
| Live harness SSH users, keys, state files, rule checks | `driver.ssh_user`, `driver.local_artifacts`; cloud inventory classes in `scripts/live_clouds.py` |

## Verification tooling

| Command | What it proves |
|---|---|
| `venv/bin/python -m pytest tests/ -q` | registry validity, adapter lifecycles, provider isolation, playbook syntax |
| `venv/bin/python scripts/audit_provider_coverage.py [--require-provider P]` | which provider/workload pairs are native, legacy fallback, staged or unsupported |
| `venv/bin/python scripts/test_provider_workload_live.py --provider P --workload W --activate` | real deploy, verify over SSH, repeat, standalone teardown, inventory restored |
| `venv/bin/python scripts/test_azure_phantom_live.py --activate` | the Phantom handoff route on Azure |
| `venv/bin/python deploy.py --deploy --azure-smoke --dry-run` | the reviewed Azure infrastructure smoke, non-mutating |
