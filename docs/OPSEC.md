# OPSEC: what each deployment leaves behind

Every deployment leaves three kinds of trace: artifacts on the host, metadata
at the provider, and state on the controller workstation. This page lists
them per module so the operator can decide what is acceptable for an
engagement and what a teardown actually removes.

## Shared by every driver-backed deployment

| Where | Trace | Removed by teardown |
|---|---|---|
| Provider | resource group `c2itall-<id>`; every resource named `c2itall-<id>-<kind>`; tags `c2itall-deployment` and `c2itall-owner` | yes |
| Host | VM hostname `c2itall-<id>-vm` (the ARM `computerName`); the host's own logs name it | with the VM |
| Host | Ubuntu 24.04 or Kali marketplace image, `azureuser` with the deployment's SSH key, password authentication off | with the VM |
| Controller | `deployments/azure/<id>.json` (owner-only), `~/.ssh/c2deploy_<id>`, `logs/deployment_info_<id>.txt`, service logs under `deployments/azure/logs/` | state archived to `deployments/azure/archive/`, keys and records removed, logs archived |

The `c2itall-` prefix in resource names, tags and the VM hostname is a tool
fingerprint. It is visible to anyone with access to the subscription and to
anyone who lands on the host; it is not visible to targets over the network.
Changing it is a coordinated change across `utils/azure_utils.py`,
`utils/azure_cloud.py`, the Azure infrastructure play and the live harness
inventories and is listed under Open items below.

## Email tracker

| Where | Trace |
|---|---|
| Network | the pixel path `/pixel/<id>.png` and the dashboard are served on the tracker hostname; the dashboard answers only the operator /32 (nginx `allow`), everyone else gets 403 |
| Host | `/opt/tracker` (service user `tracker`, no shell), `tracking_data.json` and `tracker.log` under `/opt/tracker/data`; nginx access log off when `zero_logs` (default) |
| Certificate | Let's Encrypt when the hostname already resolves to the VM at deploy time, which publishes the hostname to certificate-transparency logs; otherwise self-signed, which publishes nothing |
| Provider | inbound 80 and 443 from anywhere, SSH from the operator |

## Logging server (RedELK)

| Where | Trace |
|---|---|
| Network | Kibana behind nginx on 443 answers only the operator /32; the beats port 5044 opens only to the hosts named at deploy time and stays closed otherwise; no other port is reachable |
| Host | RedELK checkout under `/opt/redelk` with the generated CA and the onboarding packages `redirs.tgz` and `c2servers.tgz`; the server install under `/opt/redelk-elk`; credentials in `/opt/redelk-elk/elkserver/.env` (root, 0600); Docker images for Elasticsearch, Logstash, Kibana and nginx |
| Certificate | self-signed from the RedELK CA with the name given at deploy time (`logs.internal` by default) and the VM's address; nothing public |
| Caution | Docker publishes ports around `ufw`; the provider's inbound rules are the boundary that matters. Nothing ships logs until the operator installs the packages on redirectors or C2 servers by hand, and those hosts must be named at deploy time so 5044 is open to them |

## Share drive

| Where | Trace |
|---|---|
| Network | no public web port at all; Nextcloud answers on the `tailscale0` interface only; the only public inbound rule is Tailscale's direct UDP 41641 |
| Host | Phantom's Nextcloud install (`/var/www/nextcloud`, MariaDB, Redis, PHP-FPM), admin password in `/var/www/nextcloud/.admin_password` (0600); Tailscale with hostname `share-<id>`; the Tailscale auth key is used once and never written to the host |
| Certificate | self-signed for `share.internal`; nothing in DNS or certificate logs |
| Tailnet | the node `share-<id>` appears in the tailnet's admin console; remove it there after teardown |

## Hashtopolis

| Where | Trace |
|---|---|
| Network | 443 answers only the operator /32 and the agent addresses given at deploy time; the compose stack publishes on loopback only; port 80 opens only when a public domain was given, for ACME |
| Host | `/opt/hashtopolis` (root, 0700) with the compose file and `.env` holding generated database and admin passwords (0600); Docker images for the backend, frontend and MySQL; hashlists and wordlists uploaded later live in Docker volumes |
| Certificate | self-signed by default; Let's Encrypt only when a public domain is given, which publishes that name |

## CDN-fronted redirector

| Where | Trace |
|---|---|
| Network | beacons talk to `<label>-<hash>.z01.azurefd.net`; the origin's 80 and 443 admit only the `AzureFrontDoor.Backend` service tag, and nginx returns nothing (444) unless the request carries this deployment's `X-Azure-FDID`; the shell-handler port stays public as for any redirector |
| Edge | the Front Door profile `c2itall-<id>-edge` and endpoint label are visible in the subscription; the public hostname is derived from the label you choose, so pick one that fits the pretext |
| Edge to origin | `https` requires a CA-issued certificate on the redirector (DNS must point at it when the deploy runs); `http` carries beacon traffic in clear between the edge and the origin inside the provider's network, so use it only for labs or when the C2 protocol is itself encrypted |
| Client address | the origin trusts `X-Forwarded-For` only in fronted mode, where the edge is the only possible sender, so the security-IP maps judge the real client and not the edge |
| Teardown | the resource group deletion removes the edge; a Front Door profile takes several minutes longer to delete than a VM and the cleanup deadline is extended accordingly |
| Cost | Front Door Standard carries a base monthly fee plus egress; it is billed hourly while it exists |

What the fronted redirector is not: true domain fronting (a TLS SNI for one
domain and a Host header for another) no longer works on the major CDNs. This
is CDN-fronted redirection with origin lockdown, which is what remains
operationally viable.

## Open items

- The `c2itall-` prefix in Azure resource names, tags and the VM hostname is
  the only tool name that reaches hosts and provider metadata from the driver
  path. A configurable, neutral prefix would remove it; it touches the Azure
  driver, its play, the ownership validation and the live harness, so it is a
  deliberate change rather than a rename.
- Linode and FlokiNET transition plays tag instances `c2itall`
  (`providers/Linode/*.yml`, `providers/FlokiNET/flokinet_phishing.yml`).
- The TAK chat server names its CA `c2itall-<id>` and its organization
  `c2itall` (`modules/chat-server/deploy_chat.py`); the names ship inside
  the client package.
- The mail play writes `/etc/dovecot/conf.d/auth-c2itall.conf.ext` on mail
  hosts (`common/tasks/configure_mail.yml`).
