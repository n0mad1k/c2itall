# OPSEC: what each deployment leaves behind

Every deployment leaves three kinds of trace: artifacts on the host, metadata
at the provider, and state on the controller workstation. This page lists
them per module so the operator can decide what is acceptable for an
engagement and what a teardown actually removes.

## Shared by every deployment

| Where | Trace | Removed by teardown |
|---|---|---|
| Host | one account that holds only the deployment's SSH key (`azureuser`, `ec2-user` or `root`), password authentication off, the key line carries no comment | with the VM; FlokiNET keeps the host and loses the key line |
| Provider | every resource named or labelled `c2itall-<id>` and marked with the deployment and owner tags below | yes, and cleanup refuses anything without the marks |
| Controller | `deployments/<provider>/<id>.json` (owner-only), `~/.ssh/c2deploy_<id>`, `logs/deployment_info_<id>.txt`, `logs/deployment_<id>.log`, service logs under `deployments/<provider>/logs/` | state archived to `deployments/<provider>/archive/`, keys and records removed, logs archived |

Provider SDK debug output is kept out of `logs/deployment_<id>.log`; the AWS
log would otherwise record every signed request header, access key ID
included.

The `c2itall-` prefix in resource names, tags and labels is a tool
fingerprint. It is visible to anyone with access to the account and, where
it becomes the hostname, to anyone who lands on the host; it is not visible
to targets over the network. Changing it is a coordinated change across the
four drivers, the Azure play, the ownership validation and the live harness
inventories and is listed under Open items below.

### Azure

| Where | Trace |
|---|---|
| Provider | resource group `c2itall-<id>`; VNet, NSG, static IP, NIC and VM named `c2itall-<id>-<kind>`; tags `c2itall-deployment` and `c2itall-owner`; managed boot diagnostics |
| Host | hostname `c2itall-<id>-vm` (the ARM `computerName`); Ubuntu 24.04, 22.04 or the Kali marketplace image |

### AWS

| Where | Trace |
|---|---|
| Provider | one VPC, internet gateway, subnet and security group per deployment, each tagged `Name=c2itall-<id>`, `c2itall-deployment` and `c2itall-owner`; the security group is also named `c2itall-<id>`; no EC2 key pair is created |
| Host | the instance keeps the image's default hostname (`ip-10-0-1-N`); the deployment key arrives through cloud-init user-data, which stays readable from the instance metadata service for the life of the instance |
| Account | CloudTrail records every API call the driver makes under the access key you give it |

### Linode

| Where | Trace |
|---|---|
| Provider | one Linode and one Cloud Firewall labelled `c2itall-<id>`, tagged `c2itall-deployment-<id>` and `c2itall-owner-<marker>` (the marker is per deployment); the tags also appear in the account's tag list until the last resource carrying them is gone |
| Host | images with cloud-init apply the label as the hostname; root with the deployment key only, the API-mandated root password is random and discarded, password login is turned off as soon as the key works |
| Account | the account event log records the create and delete calls |

### FlokiNET

| Where | Trace |
|---|---|
| Host | the deployment key line in `/root/.ssh/authorized_keys` (removed on teardown); `ufw` is reset and rebuilt from the workload's rules, so any rules you had are gone; password login is turned off; everything the service installed stays |
| Provider | nothing is created; the server you ordered stays until you cancel it in the panel |

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
| Network | beacons talk to the edge hostname; the origin's 80 and 443 admit only the edge network, and nginx returns nothing (444) unless the request carries this deployment's edge identifier; the shell-handler port stays public as for any redirector |
| Edge to origin | `https` requires a CA-issued certificate on the redirector (DNS must point at it when the deploy runs); `http` carries beacon traffic in clear between the edge and the origin inside the provider's network, so use it only for labs or when the C2 protocol is itself encrypted |
| Client address | the origin trusts `X-Forwarded-For` only in fronted mode, where the edge is the only possible sender, so the security-IP maps judge the real client and not the edge |

Azure Front Door:

| Where | Trace |
|---|---|
| Edge | hostname `<label>-<hash>.z01.azurefd.net`; the origin admits the `AzureFrontDoor.Backend` service tag and checks `X-Azure-FDID`; the profile `c2itall-<id>-edge` and the endpoint label are visible in the subscription, and the public hostname is derived from the label you choose, so pick one that fits the pretext |
| Teardown | the resource group deletion removes the edge; a Front Door profile takes several minutes longer to delete than a VM and the cleanup deadline is extended accordingly |
| Cost | Front Door Standard carries a base monthly fee plus egress; it is billed hourly while it exists |
| Subscription | Azure refuses Front Door on Free Trial and Student subscriptions; the fronted route needs a pay-as-you-go or enterprise subscription and the `Microsoft.Cdn` provider registered |

AWS CloudFront:

| Where | Trace |
|---|---|
| Edge | hostname `<random>.cloudfront.net`, not chosen by you; the origin is the instance's public DNS name, so the distribution config in the account names the origin; the origin admits the `cloudfront.origin-facing` managed prefix list on one 80-443 port range (the list counts as 55 of the 60 rules a security group may hold, so the two web ports share a reference; nothing listens in between) and checks a per-deployment `X-Origin-Verify` secret the distribution stamps on every forwarded request |
| Caching | disabled; every viewer header except `Host` is forwarded, HTTP and HTTPS are both accepted at the edge, all HTTP methods pass |
| Teardown | the distribution is disabled, waited on and deleted before the VPC goes; that takes ten to fifteen minutes and the cleanup deadline is extended accordingly |
| Cost | CloudFront bills per request and per GB; a distribution serving nothing costs nothing, but the instance behind it bills as usual |

What the fronted redirector is not: true domain fronting (a TLS SNI for one
domain and a Host header for another) no longer works on the major CDNs. This
is CDN-fronted redirection with origin lockdown, which is what remains
operationally viable.

## Open items

- The `c2itall-` prefix in resource names, tags and labels on every provider,
  and in the Azure hostname, is the only tool name that reaches hosts and
  provider metadata from the driver path. A configurable, neutral prefix
  would remove it; it touches the four drivers, the Azure play, the ownership
  validation and the live harness, so it is a deliberate change rather than a
  rename.
- Accounts used with the retired per-provider plays may still hold their
  leftovers: EC2 key pairs named `c2deploy_*` and Linode profile SSH keys.
  The drivers never create either, and the live harness only polices
  resources carrying the current deployment tags, so review and delete them
  by hand.
- The TAK chat server names its CA `c2itall-<id>` and its organization
  `c2itall` (`modules/chat-server/deploy_chat.py`); the names ship inside
  the client package.
- The mail play writes `/etc/dovecot/conf.d/auth-c2itall.conf.ext` on mail
  hosts (`common/tasks/configure_mail.yml`).
