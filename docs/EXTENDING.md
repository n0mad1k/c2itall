# Extending c2itall

Providers and workloads are independent. A provider is one `CloudDriver` and
one registry line; a workload is one profile, one service play and one
registry line. Neither side names the other, and `tests/test_extension_contracts.py`
fails if that changes.

## Where things live

| Concern | File |
|---|---|
| What a workload needs from any VM provider | `modules/<module>/workload.py` (`PROFILE`) |
| How that workload is configured on the host | `modules/<module>/service.yml` (provider-neutral play) |
| The operator menu and controller for a workload | `modules/<module>/deploy_<module>.py` |
| The provider contract | `utils/cloud_driver.py` (`CloudDriver`, `ProvisionRequest`) |
| One driver per provider | `utils/azure_cloud.py` (real), `tests/fake_cloud.py` (minimal reference) |
| Generic lifecycles that bind a driver to a profile | `utils/vm_workloads.py` (single, components, nodes, handoff) |
| Durable per-deployment state any driver can reuse | `utils/state_store.py` |
| The catalog of providers and workloads | `utils/provider_registry.py` (`PROVIDER_SPECS`, `WORKLOAD_SPECS`) |
| Live harness cloud inventories and account inputs | `scripts/live_clouds.py` |

## Add a provider

Nothing under `modules/` is opened for this.

1. Write `utils/<name>_cloud.py` with a `CloudDriver` subclass and a factory
   function that returns it. Copy `tests/fake_cloud.py`; it implements every
   method. The driver answers:
   - identity: `provider`, `ssh_user`, `prefix` (its config-key prefix),
     `identity_keys`, `option_keys`, `node_quota`
   - configuration: `gather_config`, `validate_config`, `image(role)` for
     `ubuntu`/`kali`, `region(config)`
   - lifecycle: `plan(config, request)`, `prepare_state`, `prepare_ssh_key`,
     `deploy`, `public_address`, `cleanup` (must prove absence), `health`
   - durable state: `load_state`, `list_states`, `local_artifacts`,
     `infrastructure_playbook` if it uses an Ansible play
   - plumbing: `log_dir`, `check_connection`; `run_command` and
     `exported_config` have usable defaults
   `plan` receives a `ProvisionRequest` with the deployment ID, workload name,
   inbound rules, image role, disk size and SSH key paths. It returns the
   provider's own infrastructure record; the adapters never look inside it
   except for `deployment_id` and `ssh_private_key_path`.
2. Add one line to `PROVIDER_SPECS`:
   ```python
   'name': ProviderSpec('DisplayName', 'sshuser', False,
                        driver='utils.name_cloud:name_driver',
                        credential_environment=(('name_token', 'NAME_TOKEN'),),
                        teardown_keys=('name_token', 'name_project')),
   ```
   Explicit or staged routes may not name a workload the driver already
   serves; the registry rejects them.
3. Optional: `providers/<DisplayName>/` for an infrastructure play and
   templates when the driver provisions through Ansible, and a cloud class plus
   `CLOUDS`/`REGIONS`/`_account_inputs` entries in `scripts/live_clouds.py` for
   live verification. The class returns inbound rules as
   `(protocol, port, source)` tuples and maps the harness's component IDs to
   its own resource names.
4. Verify:
   ```bash
   venv/bin/python -m pytest tests/test_extension_contracts.py tests/test_azure_provider.py -q
   venv/bin/python scripts/audit_provider_coverage.py --require-provider name
   ```

The new provider then appears in every workload menu, the WEBRUNNER pool
picker, the connectivity test, configuration validation, health checks,
standalone teardown and the live harness.

## Add a workload (module)

Nothing under `utils/<provider>_cloud.py` is opened for this.

1. `modules/<module>/deploy_<module>.py` with a `<module>_menu()` entry point
   that calls `select_provider` and `gather_provider_config` for its canonical
   workload name.
2. `modules/<module>/workload.py` exposing `PROFILE`, a `WorkloadProfile`:
   - `kind`: `single` (one VM, one play), `components` (several VMs, one play
     each, deployed in order), `nodes` (scan nodes for a composite executor) or
     `handoff` (one VM given to a module that configures it itself)
   - `workload`, `address_key`, `service_playbook`, `log_suffix`,
     `inventory_group`, `image_role`, `config_keys` (the only module keys the
     play receives), `variants`, `manages_ssh_key`
   - `validate(config)`, `inbound_rules(config)`, `disk_gb(config)`,
     `service_variables(config, variables)`, `prepare(config)`
3. `modules/<module>/service.yml`: a play against `inventory_group` that uses
   only `config_keys` plus `provider`, `provider_workload`, `deployment_id` and
   `deployment_type`. Shared tasks come from `common/`.
4. One `WorkloadSpec` line in `WORKLOAD_SPECS` naming the controller
   entrypoint, whether legacy fallback applies, and the variant names.

Every driver-backed provider serves the workload immediately. Transition
providers (AWS, Linode, FlokiNET) only serve it if an explicit route or legacy
play is added for them.

## Add a variant

| Variant | Where |
|---|---|
| C2 framework | `FRAMEWORKS` in `modules/c2/workload.py` plus `modules/c2/tasks/configure_<fw>.yml`; both C2 menus enumerate the catalog |
| Attack-box subtype | `VARIANTS` in `modules/attack-box/workload.py` plus its task file; the name must also appear in the workload's `WorkloadSpec.variants` |
| Phantom or chat service | `service_rules` in `modules/phantom/workload.py` |
| Phishing component | a `PhishingComponent` subclass and a `(flag, profile)` entry in `modules/phishing/workload.py` plus its play |

## Guardrails

`tests/test_extension_contracts.py` registers `tests/fake_cloud.py` as a
provider and asserts that it is served everywhere without edits, drives every
generic adapter through it, checks each profile is complete with an existing
play, and greps that provider code never names a workload and workload code
never names a provider. Run it after any change in this area.
