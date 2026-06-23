# c2itall — Red Team Infrastructure Automation

Infrastructure-as-Code platform for deploying and managing full red team engagement infrastructure across multiple cloud providers. Built to reduce time-to-operational from hours to minutes while enforcing consistent OPSEC posture across every deployment.

> **Portfolio note:** This is a sanitized public version. Files containing active TTPs (implant source mutations, payload build pipelines, phishing lures, credential capture logic) have been replaced with documented stubs that describe exactly what each component does and why. The architecture, orchestration layer, and all non-weaponized infrastructure code are intact.

---

## What This Is

Red team engagements require standing up a consistent stack of infrastructure — C2 servers, traffic redirectors, phishing mail infrastructure, payload delivery servers — quickly, correctly, and with OPSEC controls baked in from the first `ssh`. Doing this by hand is error-prone and slow. This tool automates the entire lifecycle:

- **Provision** cloud nodes across AWS, Linode, or FlokiNET
- **Harden** each node to a consistent baseline (firewall, fail2ban, log suppression, memory protections)
- **Deploy** role-specific services (Havoc C2, nginx redirectors, Postfix MTA, payload servers)
- **Configure** the inter-node traffic routing, SSL certs, and DKIM/DMARC records
- **Teardown** the full stack cleanly when the engagement ends

The result is reproducible, version-controlled infrastructure — every deployment is documented, every configuration is auditable, and every node reaches the same hardened baseline regardless of who ran the deployment.

---

## Architecture

```
deploy.py (Rich TUI interactive menu)
    │
    ├── providers/
    │   ├── AWS/          — EC2 provisioning, security groups, keypair management
    │   ├── Linode/       — Linode API node provisioning
    │   └── FlokiNET/     — Pre-provisioned node integration (bulletproof hosting)
    │
    ├── modules/
    │   ├── c2/           — Havoc C2 server deployment + payload pipeline [stubs]
    │   ├── redirectors/  — nginx HTTPS redirectors + credential capture [stubs]
    │   ├── phishing/     — Postfix MTA + GoPhish + lure pages [stubs]
    │   ├── payload-server/  — Encrypted payload hosting + delivery
    │   ├── attack-box/   — Kali/Ubuntu operator boxes
    │   ├── webrunner/    — Distributed cloud scanning infrastructure
    │   ├── tracker/      — Email open/click tracking server
    │   └── chat-server/  — Encrypted team comms (Matrix/Element)
    │
    ├── common/
    │   ├── files/        — Shared scripts, HID payloads [stubs]
    │   └── templates/    — Cross-module Jinja2 templates (stagers, loaders) [stubs]
    │
    └── utils/
        ├── common.py     — Shared utilities, ANSI output, helpers
        ├── ssh_utils.py  — SSH connection management, tunneling
        └── deployment_engine.py  — Ansible playbook execution engine
```

---

## Module Breakdown

### C2 Server (`modules/c2/`)

Deploys a hardened Havoc C2 Framework teamserver. Havoc was chosen over Cobalt Strike for its open source auditability and active development of modern evasion primitives.

**Infrastructure side (intact):**
- Ansible playbooks for full Havoc installation from source
- Teamserver systemd service with automatic restart
- Firewall rules limiting teamserver port exposure to operator IPs only
- Let's Encrypt SSL automation for HTTPS C2 traffic
- Payload synchronization to redirector nodes

**Payload pipeline (stubbed):**
- `implant_mutator.sh` — randomizes Havoc Demon source identifiers (mutex names, pipe names, compile-time strings) before each build to defeat static signatures
- `havoc_mutate.sh` — generates per-engagement randomized Havoc teamserver profiles (sleep jitter, traffic malleable C2 patterns, kill dates)
- `generate_evasive_beacons.sh.j2` — shellcode compile pipeline: cross-compile → encrypt → inject into hollow process template → sign
- `generate_havoc_payloads.sh.j2` — produces EXE, DLL, and raw shellcode variants from a single Demon build

**EDR evasion techniques implemented:**
- Sleep masking (encrypted heap during sleep intervals)
- Stack spoofing (synthetic call stacks to evade call stack analysis)
- AMSI/ETW patching (in-memory patch of scanning hooks before payload execution)
- Indirect syscalls (bypass user-mode API hooks via direct syscall stubs)
- Binary signature randomization per build

### Redirectors (`modules/redirectors/`)

HTTPS redirectors sit in front of the C2 server, forwarding only valid beacon traffic while serving decoy content to scanners and incident responders. They also serve as the phishing landing infrastructure.

**Infrastructure side (intact):**
- nginx reverse proxy configuration with category-matched domain front
- Automatic SSL via Let's Encrypt
- Traffic filtering rules: forward beacons matching URI/User-Agent profile, serve 200 OK decoy to everything else
- Fail2ban tuned for redirector traffic patterns

**Landing page infrastructure (stubbed):**
- `capture.php.j2` — credential capture with transparent redirect; logs POST data and forwards the victim to the legitimate service so the submission appears to succeed
- `fake-login.html.j2` — cloned login page template structure (placeholders for target branding)

### Phishing Infrastructure (`modules/phishing/`)

Deploys a complete phishing mail stack: Postfix MTA, GoPhish campaign manager, and lure page hosting.

**Infrastructure side (intact):**
- Postfix + Dovecot configuration with DKIM signing
- DMARC/SPF record generation instructions
- GoPhish deployment and service configuration
- Email tracking pixel integration

**Lure content (stubbed):**
- Five email templates (file share notification, O365 login prompt, password expiry, security alert, vendor-branded alert) — stubs describe the social engineering angle and urgency framing each uses
- `fedramp-compliance.j2` — FedRAMP-themed lure landing page

### WEBRUNNER (`modules/webrunner/`)

Distributed cloud-based scanning infrastructure. Spins up scan nodes across multiple providers simultaneously, runs recon tasks in parallel, and aggregates results back to a central collection point. Designed to avoid rate-limiting and distribute scan signatures across provider ASNs.

Full implementation intact — this is infrastructure automation, not a weaponized component.

### Attack Box (`modules/attack-box/`)

Provisions operator workboxes (Kali or custom Ubuntu) in cloud providers for pivoting, scanning, and exfil staging. Handles SSH keypair injection, tool installation, and VPN configuration.

### Payload Server (`modules/payload-server/`)

Encrypted payload hosting with one-time-download links, delivery logging, and automatic expiry. Payloads are pulled from the C2 node at deployment time and served via HTTPS with access controls.

---

## Secrets Management

No credentials are hardcoded anywhere. All provider API keys, SSH keypairs, and domain registrar tokens are pulled at runtime from a secrets manager (Infisical). The `creds` CLI fetches them by key name and folder:

```bash
eval $(creds env aws)          # exports AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
eval $(creds env linode)       # exports LINODE_TOKEN
```

Deployment scripts source these at execution time and never write them to disk.

---

## Deployment Flow

```
1. Select provider + deployment type from interactive menu
2. Provision node(s) via provider API
3. Wait for SSH availability
4. Run hardening playbook (baseline OS config, firewall, fail2ban, log controls)
5. Run role-specific playbook (C2 / redirector / phishing / etc.)
6. Run post-deploy verification (service health checks, connectivity tests)
7. Output deployment manifest (IPs, ports, credentials) to encrypted local file
```

Teardown reverses the provisioning step, destroying all cloud resources and deleting the deployment manifest.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Orchestration | Python 3.10+, Click, Rich |
| Configuration management | Ansible 2.14+ |
| Template engine | Jinja2 |
| Cloud providers | AWS (boto3), Linode API v4, FlokiNET |
| C2 framework | Havoc (open source) |
| Web server | nginx |
| Mail stack | Postfix + Dovecot + GoPhish |
| SSL | Let's Encrypt (certbot) |
| Secrets | Infisical (self-hosted) |

---

## Requirements

- Python 3.10+
- Ansible 2.9+
- Provider credentials in secrets manager
- SSH keypair for node access
- Registered domain (required for Let's Encrypt and mail DKIM)

```bash
pip install -r requirements.txt
ansible --version
```

---

## Usage

```bash
python3 deploy.py
```

Interactive Rich TUI menu. All deployment options are accessible from the menu — no need to pass CLI flags manually.

---

## Authorization

This tool is built for authorized red team engagements and penetration testing with written scope agreements. The operational content (payloads, lures, credential capture) is excluded from this public copy precisely because it is only appropriate in a scoped, authorized context.

If you're reviewing this as a potential employer: the stubs throughout this repo document exactly what was there and why it was built that way. The engineering decisions — modular Ansible roles, secrets management, provider abstraction, OPSEC-hardened defaults — are all visible in the intact infrastructure code.
