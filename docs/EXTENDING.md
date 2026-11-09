# Extending c2itall

Providers and workloads are independent. A provider is one `CloudDriver` and
one registry line. A workload is one controller, one profile, one service play
and one registry line. A variant is one catalog entry and one task file.
`tests/test_extension_contracts.py` fails if provider code starts naming a
workload or workload code starts naming a provider.

`docs/ARCHITECTURE.md` explains how the layers fit. This document is the
recipes.

## Where things live

| Concern | File |
|---|---|
| What a workload needs from any VM provider | `modules/<module>/workload.py` (`PROFILE`) |
| How that workload is configured on the host | `modules/<module>/service.yml` and `modules/<module>/tasks/` |
| The operator menu and controller for a workload | `modules/<module>/deploy_<module>.py` |
| The provider contract | `utils/cloud_driver.py` (`CloudDriver`, `ProvisionRequest`) |
| One driver per provider | `utils/azure_cloud.py` (real), `tests/fake_cloud.py` (minimal reference) |
| Generic lifecycles that bind a driver to a profile | `utils/vm_workloads.py` |
| Durable per-deployment state any driver can reuse | `utils/state_store.py` |
| Bounded subprocesses and safe directory handling | `utils/controller_io.py` |
| The catalog of providers and workloads | `utils/provider_registry.py` (`PROVIDER_SPECS`, `WORKLOAD_SPECS`) |
| Legacy plays for transition providers | `providers/<Dir>/<workload>.yml` |
| Live harness cloud inventories and account inputs | `scripts/live_clouds.py` |

---

## Add a provider

Nothing under `modules/` is opened for this.

### 1. Write the driver

Create `utils/<name>_cloud.py`. Copy `tests/fake_cloud.py` as the starting
point; it implements every method in memory, and `utils/azure_cloud.py` shows
the same methods backed by a real CLI.

```python
"""<Name> cloud driver: provisioning only, no workload knowledge."""

from pathlib import Path

from .cloud_driver import CloudDriver


class NameDriver(CloudDriver):
    provider = 'name'            # registry key, lowercase
    ssh_user = 'ubuntu'          # user the service plays log in as
    prefix = 'name_'             # config keys this driver owns
    identity_keys = ('name_project',)      # must match saved state on cleanup
    option_keys = ('name_state_dir',)      # tune a call, never identify a target
    node_quota = 10              # safe scan nodes per region

    # configuration ---------------------------------------------------------
    def gather_config(self):
        """Prompt for non-secret inputs; credentials come from the vault."""

    def validate_config(self, config, require_key=True):
        """Return the normalized config or raise ValueError."""

    def image(self, role):
        """Map 'ubuntu' / 'kali' to this provider's image reference."""

    def region(self, config):
        return config.get('name_region', 'default')

    # lifecycle ---------------------------------------------------------------
    def plan(self, config, request):
        """Return the infrastructure record for one VM.

        request.deployment_id, .workload, .inbound_rules, .image_role,
        .disk_gb, .ssh_public, .ssh_private, .ssh_generated are everything
        the workload asks for. Keep 'deployment_id', 'provider',
        'provider_workload' and 'ssh_private_key_path' in the record; the
        adapters read nothing else from it.
        """

    def prepare_state(self, infrastructure):
        """Persist intent before any resource exists (see utils/state_store.py)."""

    def prepare_ssh_key(self, infrastructure):
        """Generate the key when infrastructure['ssh_key_generated'] is true."""

    def deploy(self, infrastructure):
        """Create or update the planned resources; True only when ready."""

    def public_address(self, deployment_id, config):
        """Return the VM's public IPv4 as a string."""

    # edge (optional) ---------------------------------------------------------
    # supports_edge = True
    # def plan(...): translate rule source 'edge' to your CDN's source ranges
    #                or service tag and keep request.edge in the record
    # def edge_endpoint(self, deployment_id, config):
    #     return {'edge_id': ..., 'edge_hostname': ..., 'edge_header': ...}

    def cleanup(self, request):
        """Delete owned resources; True only after proving they are absent.

        request carries 'deployment_id' plus option_keys and, for a record
        that owns the identity, identity_keys.
        """

    def health(self, state):
        return {'healthy': bool, 'detail': str}

    # durable state -----------------------------------------------------------
    def load_state(self, deployment_id):
        """Recovery record for one ID, or None."""

    def list_states(self, config=None):
        """Every recovery record; each has 'deployment_id' and 'provider_workload'."""

    def local_artifacts(self, deployment_id, config=None):
        """Local files kept for one ID, so teardown proofs can check them."""

    # plumbing ------------------------------------------------------------------
    def log_dir(self, config):
        return Path(config.get('name_state_dir') or DEFAULT_STATE_DIR) / 'logs'

    def check_connection(self):
        """Read-only probe; return a dict the Tools menu prints."""


def name_driver():
    return NameDriver()
```

Rules the adapters rely on:

- `plan` must be pure: no resources, no files. State is written by
  `prepare_state`, which runs before `prepare_ssh_key` and `deploy`.
- `deploy` must be repeatable with the same record and keep the same public
  address; the live harness repeats every deployment and compares.
- `cleanup` must refuse foreign resources and return false if anything
  remains. The adapters never retry through another path.
- A derived ID (`<id>-mta`, `<id>-n01`) must own its own resources, never
  share with the parent ID.
- Never read provider credentials from the config; use the environment
  mapping declared in the registry or the vault.
- Leave `supports_edge` false unless `plan` really honours
  `request.edge` and `edge_endpoint` returns the identifier the edge stamps
  on every forwarded request; a fronted profile is refused otherwise.

### 2. Register it

One line in `PROVIDER_SPECS` in `utils/provider_registry.py`:

```python
'name': ProviderSpec('Name', 'ubuntu', False,
                     driver='utils.name_cloud:name_driver',
                     credential_environment=(('name_token', 'NAME_TOKEN'),),
                     teardown_keys=('name_token', 'name_project'),
                     cleanup_guidance=('Open the Name console',
                                       'Delete resources tagged {deployment_id}')),
```

`'Name'` is both the display label and the `providers/Name/` directory. The
third argument (`legacy_menu=False`) keeps the provider out of legacy-only
menus. Do not add `routes` or `staged_routes` for workloads the driver serves;
validation rejects them with "Explicit routes shadow the provider driver".

### 3. Optional pieces

- `providers/Name/` with an infrastructure play and templates when the driver
  provisions through Ansible; return its path from `infrastructure_playbook`.
- `providers/Name/vars.example.yaml` documenting the non-secret inputs; the
  Tools menu validates `providers/Name/vars.yaml` through `validate_config`
  when it exists.
- Live verification: in `scripts/live_clouds.py` add a cloud class with
  `inventory(identity)`, `totals()`, `address(identity, name)` and
  `inbound_rules(deployment_id)` returning `(protocol, port, source)` tuples,
  then entries in `CLOUDS`, `REGIONS` and `_account_inputs`. The class maps
  the harness's `identity['components']` IDs to its own resource names.

### 4. Verify

```bash
venv/bin/python -m pytest tests/test_extension_contracts.py tests/test_azure_provider.py -q
venv/bin/python scripts/audit_provider_coverage.py --require-provider name
venv/bin/python scripts/test_provider_workload_live.py --provider name --workload redirector --activate
```

The audit exits nonzero while any workload is only partially covered by
variants; today that is attack boxes, where only `quick_recon` has native
service tasks.

### What the provider gets without further work

Every workload menu offers it for attack box, C2, redirector, phishing,
payload server, WEBRUNNER, Phantom and chat. The WEBRUNNER picker, region
pools and quota warnings use its driver. The Tools menu's connectivity test
and configuration validation include it. Standalone `teardown.py`, the Cleanup
menu, the infrastructure health check and the live harness all route to it.

---

## Add a workload (module)

Nothing under `utils/<provider>_cloud.py` is opened for this.

### 1. The controller: `modules/<module>/deploy_<module>.py`

The controller owns the prompts and the deployment summary. It must call
`gather_provider_config` so the registry recognizes it as a workload
controller. Minimal shape:

```python
#!/usr/bin/env python3
"""<Module>: one-line purpose."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from utils.common import COLORS, clear_screen, print_banner, wait_for_input, confirm_action
from utils.common import generate_deployment_id, setup_logging
from utils.deployment_engine import dispatch_workload, save_deployment_info
from utils.provider_utils import gather_provider_config, prepare_module_ssh_key, select_provider


def gather_parameters():
    config = {'deployment_id': generate_deployment_id(), 'provider_workload': 'example'}
    provider = select_provider('example', legacy_fallback=True)
    if provider is None:
        return None
    provider_config = gather_provider_config(provider, 'example', legacy_fallback=True)
    if provider_config is None:
        return None
    config.update(provider_config, provider=provider)
    config['domain'] = input('Domain: ').strip()
    config['operator_ip'] = input('Your public IPv4: ').strip()
    config['deployment_type'] = 'example_basic'
    if not prepare_module_ssh_key(config, config['deployment_id'])[0]:
        return None
    return config


def execute_deployment(config):
    setup_logging(config['deployment_id'], 'example_deployment')
    if not confirm_action('Proceed?', default=False):
        return
    # The legacy executor only runs for transition providers that list this
    # workload; driver providers never reach it.
    success = dispatch_workload(config, _execute_legacy)
    print('Deployed' if success else 'Deployment failed')
    wait_for_input()


def _execute_legacy(config):
    from utils.deployment_engine import determine_playbook, execute_playbook
    playbook = determine_playbook(config)
    if not playbook or not execute_playbook(playbook, config):
        return False
    save_deployment_info(config)
    return True


def example_menu():
    while True:
        clear_screen()
        print_banner()
        print('1) Deploy example')
        print('99) Return to Main Menu')
        choice = input('\nSelect an option: ').strip()
        if choice == '1':
            config = gather_parameters()
            if config:
                execute_deployment(config)
        elif choice == '99':
            return
```

Wire it into `deploy.py`'s main menu the way the existing entries are (a
`print` line and an `elif` that imports the module and calls `example_menu()`).

### 2. The profile: `modules/<module>/workload.py`

```python
"""Example profile: what any VM provider must supply for this module."""

from utils.workloads import WorkloadProfile


class ExampleProfile(WorkloadProfile):
    kind = 'single'                     # or 'components' | 'nodes' | 'handoff'
    workload = 'example'                # matches WORKLOAD_SPECS
    address_key = 'example_ip'          # receives the public IPv4
    service_playbook = 'modules/example/service.yml'
    log_suffix = 'example'
    inventory_group = 'exampleservers'
    image_role = 'ubuntu'               # or 'kali'
    config_keys = ('domain', 'operator_ip', 'example_ip', 'letsencrypt_email')
    # variants = frozenset({'basic'})   # subset of the WorkloadSpec variants with native tasks

    def validate(self, config):
        if not config.get('domain'):
            raise ValueError('Example requires a domain')

    def inbound_rules(self, config):
        return [{'name': 'https', 'protocol': 'Tcp', 'port': 443, 'source': '*'},
                {'name': 'admin', 'protocol': 'Tcp', 'port': 8443,
                 'source': config['operator_ip']}]

    def disk_gb(self, config):
        return 32

    def service_variables(self, config, variables):
        variables.setdefault('letsencrypt_email', 'admin@' + config['domain'])
        return variables


PROFILE = ExampleProfile()
```

SSH from the operator's /32 is always opened by the driver; list only the
service ports. `source` is `'*'`, one global IPv4 host (`utils.workloads.host_source`
normalizes it to a /32), or `'edge'` when the profile also returns an edge
request from `edge(config)`; the driver then admits only its own edge network
on that port and the service play receives `edge_id`, `edge_hostname` and
`edge_header` (see `modules/redirectors/workload.py`). Use `'components'`
with a `components = ((flag, Profile()), ...)` tuple for several VMs (see
`modules/phishing/workload.py`), `'nodes'` for scan pools (see
`modules/webrunner/workload.py`), or `'handoff'` when the module runs its own
plays against `config['target_host']` (see `modules/phantom/workload.py`).

### 3. The service play: `modules/<module>/service.yml`

```yaml
---
- name: Wait for the example server
  hosts: all
  gather_facts: false
  tasks:
    - name: Wait for SSH connectivity
      ansible.builtin.wait_for_connection:
        delay: 10
        timeout: 300

- name: Configure the example server
  hosts: exampleservers
  become: true
  gather_facts: true
  tasks:
    - name: Validate the route inputs
      ansible.builtin.assert:
        that:
          - provider_workload == 'example'
          - domain | length > 0
        fail_msg: Example requires a domain

    - name: Harden the host
      ansible.builtin.include_tasks: "{{ playbook_dir }}/../../common/tasks/security_hardening.yml"

    - name: Configure the service
      ansible.builtin.include_tasks: "{{ playbook_dir }}/tasks/configure_example.yml"
```

The play sees only `provider`, `provider_workload`, `deployment_id`,
`deployment_type` and the profile's `config_keys`. It must not reference a
provider name or a provider credential. Put the real work in
`modules/<module>/tasks/*.yml`; shared behaviour (hardening, tool install,
mail, port randomization) is in `common/tasks/`.

### 4. Register it

One line in `WORKLOAD_SPECS` in `utils/provider_registry.py`, in menu order:

```python
'example': WorkloadSpec('modules/example/deploy_example.py', True,
                        {'basic'}),          # variants, or omit
```

The second argument says whether transition providers may fall back to a
legacy play for it. The profile is found at `modules/example/workload.py`
automatically; pass `profile='path'` only when it lives elsewhere.

### 5. Transition providers

Every driver-backed provider serves the new workload immediately. AWS,
Linode and FlokiNET only serve it if you also:

1. add it to that provider's set in `LEGACY_TRANSITION_CAPABILITIES`;
2. write `providers/<Dir>/<workload>.yml`, a localhost play that creates the
   instance and configures it, and teach `determine_legacy_playbook` which
   config flag selects it.

Leave both out and the menu simply will not offer those providers for it.

### 6. Verify

```bash
venv/bin/ansible-playbook --syntax-check modules/example/service.yml
venv/bin/python -m pytest tests/ -q
venv/bin/python scripts/audit_provider_coverage.py
venv/bin/python scripts/test_provider_workload_live.py --provider azure --workload example --activate
```

The live harness needs a workload class in
`scripts/test_provider_workload_live.py` (config, identity, target, verify,
local_artifacts) before the last command works; copy `PayloadServer`, or
subclass `SingleHost` as the tracker, logging server and Hashtopolis do. A
handoff workload built on Phantom (the share drive) is verified by
`scripts/test_azure_phantom_live.py --service <name>` instead.

---

## Add a variant

| Variant | What to add | What enumerates it |
|---|---|---|
| C2 framework | an entry in `FRAMEWORKS` in `modules/c2/workload.py` (label, task file, operator and redirector listener ports) plus `modules/c2/tasks/configure_<fw>.yml` | both C2 menus, the C2 inbound rules, the service play's include |
| Attack-box subtype | an entry in `VARIANTS` in `modules/attack-box/workload.py` (task file, deployment_type) plus `modules/attack-box/tasks/configure_<subtype>.yml`; the name must already be in the attack-box `WorkloadSpec` variants | the attack-box menu's provider list for that subtype, the coverage audit |
| Phantom or chat service | a branch in `service_rules` in `modules/phantom/workload.py` and, if the disk differs, `disk_gb` | Phantom's own menus; the rules reach every driver |
| Service built on a Phantom play (share drive pattern) | a `handoff` profile with its own rules, a controller that calls `phantom.deploy(<service>, config)` then its own addon play | the main menu; teardown routes through the same adapter |
| Fronted redirector on another provider | `supports_edge`, the `'edge'` source mapping and `edge_endpoint` in that driver | the redirector's CDN-fronted entry |
| Phishing component | a `PhishingComponent` subclass with its own `component`, play and ports, plus a `(flag, profile)` entry in `PhishingProfile.components` and `modules/phishing/service-<component>.yml` | the phishing controller's component flags |

A transition provider's legacy play has to understand the new variant
separately; the native path does not.

---

## Files you never open

| To add a… | Never touch |
|---|---|
| provider | anything under `modules/`, `utils/vm_workloads.py`, `utils/workloads.py`, the menus in `deploy.py`, `teardown.py`, the harness workload classes |
| workload | `utils/<provider>_cloud.py`, `utils/cloud_driver.py`, `utils/vm_workloads.py`, `scripts/live_clouds.py` |
| variant | anything outside the module that owns it |

## Validation errors you may hit

| Message | Cause |
|---|---|
| `Explicit routes shadow the provider driver: <p>` | a driver provider lists `routes` or `staged_routes` for a workload that has a profile; delete them |
| `Provider driver identity drift: <p>` | the driver's `provider` or `ssh_user` disagrees with its `ProviderSpec` |
| `Provider driver returned an invalid adapter` | `driver_route` built something that is not a `WorkloadAdapter`; usually a profile `kind` typo |
| `Workload profile does not describe <w>` | `PROFILE.workload` does not match the registry key |
| `<label> profile metadata is incomplete` | a `single` profile is missing `address_key`, `service_playbook` or `log_suffix` |
| `Provider workload controller catalog drift` | a `modules/*/deploy_*.py` calls `gather_provider_config` but has no `WorkloadSpec`, or vice versa |
| `Cloud driver must define <name>` | `provider`, `ssh_user` or `prefix` is unset on the driver |
| `<p> <w> deployment returned an invalid public IP` | the driver returned something other than a global IPv4 string |
| `<p> cannot front <w> with an edge` | the profile returned an edge request but the driver has `supports_edge = False` |
| `Invalid Azure edge request` | `azure_edge` is not `{host_header, forwarding, name}` with a hostname, `HttpsOnly`/`HttpOnly`/`MatchRequest` and a short lowercase label |
| `<key> must be one global IPv4 host` | a profile's operator or allowlist input is private, a CIDR, or not IPv4 |

## Guardrails

`tests/test_extension_contracts.py` registers `tests/fake_cloud.py` as a
provider and asserts that it is served everywhere without edits, drives every
generic adapter through it, checks each profile is complete with an existing
play, and greps that provider code never names a workload and workload code
never names a provider. Run it after any change in this area.
