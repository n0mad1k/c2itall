#!/usr/bin/env python3
"""
WEBRUNNER node scanner — runs on each cloud node.
Reads cidrs.txt, runs scan pipeline, writes results.json.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

WORKDIR = Path("/root/webrunner")
NMAP_WORKERS = int(os.environ.get("WEBRUNNER_NMAP_WORKERS", "10"))
NMAP_TIMING = int(os.environ.get("WEBRUNNER_NMAP_TIMING", "4"))
NMAP_TIMEOUT = int(os.environ.get("WEBRUNNER_NMAP_TIMEOUT", "60"))


def log(msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def run_masscan(ports: str, rate: int) -> list[dict]:
    cidr_file = WORKDIR / "cidrs.txt"
    out_file = WORKDIR / "masscan.json"
    out_file.unlink(missing_ok=True)

    cmd = [
        "masscan",
        f"--rate={rate}",
        f"--ports={ports}",
        "-iL", str(cidr_file),
        "-oJ", str(out_file),
        "--wait", "3",
    ]
    log(f"masscan starting: rate={rate} ports={ports}")
    try:
        subprocess.run(cmd, timeout=36000, check=False)
    except subprocess.TimeoutExpired:
        log("masscan timed out after 10h")

    if not out_file.exists():
        return []

    raw = out_file.read_text(errors="replace").strip()
    if not raw or raw == "[]":
        return []
    raw = raw.rstrip(",\n")
    if not raw.endswith("]"):
        raw += "]"
    if not raw.startswith("["):
        raw = "[" + raw
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        log("masscan JSON parse error")
        return []

    hits = []
    for entry in data:
        ip = entry.get("ip")
        for pe in entry.get("ports", []):
            port = pe.get("port")
            if ip and port:
                hits.append({"ip": ip, "port": port})
    log(f"masscan found {len(hits)} open port/host pairs")
    return hits


def group_hits_by_ip(hits: list[dict]) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for h in hits:
        result.setdefault(h["ip"], []).append(h["port"])
    return result


def run_nmap(ip: str, ports: list[int]) -> dict:
    port_str = ",".join(str(p) for p in sorted(set(ports)))
    out_file = WORKDIR / f"nmap_{ip.replace('.', '_')}.xml"

    cmd = [
        "nmap", "-sV", "--version-intensity", "5",
        "-p", port_str, f"-T{NMAP_TIMING}", "--open",
        "-oX", str(out_file), ip,
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=NMAP_TIMEOUT, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}

    if not out_file.exists():
        return {}
    try:
        tree = ET.parse(out_file)
    except ET.ParseError:
        return {}

    result = {}
    for port_el in tree.findall(".//port"):
        portid = int(port_el.get("portid", 0))
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port_el.find("service")
        info: dict = {}
        if svc is not None:
            info["service"] = svc.get("name", "")
            info["product"] = svc.get("product", "")
            info["version"] = svc.get("version", "")
            info["banner"] = " ".join(filter(None, [
                svc.get("product", ""), svc.get("version", ""), svc.get("extrainfo", "")
            ]))
        result[portid] = info
    return result


def probe_service(ip: str, port: int) -> str:
    import socket
    try:
        with socket.create_connection((ip, port), timeout=3) as s:
            s.settimeout(3)
            try:
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                banner = s.recv(512).decode(errors="replace").strip()
                return banner[:200]
            except Exception:
                try:
                    banner = s.recv(512).decode(errors="replace").strip()
                    return banner[:200]
                except Exception:
                    return ""
    except Exception:
        return ""


def scan_masscan_only(ports: str, rate: int, node_name: str) -> list[dict]:
    hits = run_masscan(ports, rate)
    results = [{"ip": h["ip"], "port": h["port"]} for h in hits]
    return results


def scan_nmap_only(ports: str, node_name: str) -> list[dict]:
    cidr_file = WORKDIR / "cidrs.txt"
    cidrs = [l.strip() for l in cidr_file.read_text().splitlines() if l.strip()]
    port_str = ports
    out_file = WORKDIR / "nmap_sweep.xml"

    cmd = [
        "nmap", "-sV", "--version-intensity", "3",
        "-p", port_str, "-T4", "--open",
        "-oX", str(out_file),
    ] + cidrs

    log(f"nmap starting across {len(cidrs)} CIDRs")
    try:
        subprocess.run(cmd, timeout=36000, check=False)
    except subprocess.TimeoutExpired:
        log("nmap timed out")

    if not out_file.exists():
        return []

    results = []
    try:
        tree = ET.parse(out_file)
    except ET.ParseError:
        return []

    for host_el in tree.findall(".//host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        for port_el in host_el.findall(".//port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port_el.get("portid", 0))
            svc = port_el.find("service")
            entry: dict = {"ip": ip, "port": portid}
            if svc is not None:
                entry["service"] = svc.get("name", "")
                entry["banner"] = " ".join(filter(None, [
                    svc.get("product", ""), svc.get("version", ""), svc.get("extrainfo", "")
                ]))
            results.append(entry)

    log(f"nmap found {len(results)} open ports")
    return results


def scan_masscan_nmap(ports: str, rate: int, node_name: str) -> list[dict]:
    hits = run_masscan(ports, rate)
    if not hits:
        return []

    by_ip = group_hits_by_ip(hits)
    log(f"nmap fingerprinting {len(by_ip)} hosts (workers={NMAP_WORKERS})...")
    results = []
    done = 0
    with ThreadPoolExecutor(max_workers=NMAP_WORKERS) as pool:
        futures = {pool.submit(run_nmap, ip, ip_ports): (ip, ip_ports) for ip, ip_ports in by_ip.items()}
        for future in as_completed(futures):
            ip, ip_ports = futures[future]
            nmap_info = future.result()
            for port in ip_ports:
                entry: dict = {"ip": ip, "port": port}
                if port in nmap_info:
                    entry.update(nmap_info[port])
                results.append(entry)
            done += 1
            if done % 50 == 0:
                log(f"  nmap: {done}/{len(by_ip)} hosts done")
    return results


def scan_geo_scout(ports: str, rate: int, node_name: str) -> list[dict]:
    hits = run_masscan(ports, rate)
    if not hits:
        return []

    by_ip = group_hits_by_ip(hits)
    log(f"nmap + probe fingerprinting {len(by_ip)} hosts...")

    targets_file = WORKDIR / "targets.yaml"
    target_ports: dict[int, dict] = {}
    if targets_file.exists():
        try:
            import yaml
            with open(targets_file) as f:
                tdata = yaml.safe_load(f)
            for t in tdata.get("targets", []):
                for p in t.get("ports", []):
                    target_ports[p] = t
        except Exception:
            pass

    def scan_one(ip: str, ip_ports: list[int]) -> list[dict]:
        nmap_info = run_nmap(ip, ip_ports)
        entries = []
        for port in ip_ports:
            entry: dict = {"ip": ip, "port": port}
            if port in nmap_info:
                entry.update(nmap_info[port])
            banner = probe_service(ip, port)
            if banner:
                entry["probe_banner"] = banner
            if port in target_ports:
                t = target_ports[port]
                entry["target_name"] = t.get("name", "")
                entry["target_desc"] = t.get("description", "")
            entries.append(entry)
        return entries

    results = []
    done = 0
    with ThreadPoolExecutor(max_workers=NMAP_WORKERS) as pool:
        futures = {pool.submit(scan_one, ip, ip_ports): ip for ip, ip_ports in by_ip.items()}
        for future in as_completed(futures):
            results.extend(future.result())
            done += 1
            if done % 50 == 0:
                log(f"  geo-scout: {done}/{len(by_ip)} hosts done")
    return results


def run_nuclei(targets: list[str], template: str, rate: int, concurrency: int, timeout: int) -> list[dict]:
    targets_file = WORKDIR / "nuclei_targets.txt"
    targets_file.write_text("\n".join(targets) + "\n")

    out_file = WORKDIR / "nuclei_results.jsonl"
    out_file.unlink(missing_ok=True)

    cmd = [
        "nuclei",
        "-t", template,
        "-l", str(targets_file),
        "-rl", str(rate),
        "-c", str(concurrency),
        "-timeout", str(timeout),
        "-j",
        "-o", str(out_file),
        "-silent",
        "-no-color",
        "-disable-update-check",
    ]

    log(f"nuclei starting: template={template} targets={len(targets)} rate={rate} concurrency={concurrency}")
    try:
        subprocess.run(cmd, timeout=43200, check=False)
    except subprocess.TimeoutExpired:
        log("nuclei timed out after 12h")

    if not out_file.exists():
        return []

    results = []
    for line in out_file.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = entry.get("host", "")
        ip = entry.get("ip", "")

        if not ip and host:
            raw = host.split("//")[-1].split("/")[0]
            ip_part = raw.rsplit(":", 1)[0] if ":" in raw else raw
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)$", ip_part)
            ip = m.group(1) if m else ip_part

        port = 0
        matched_at = entry.get("matched-at", host)
        raw_host = matched_at.split("//")[-1].split("/")[0]
        if ":" in raw_host:
            try:
                port = int(raw_host.rsplit(":", 1)[1])
            except (ValueError, IndexError):
                pass

        results.append({
            "ip": ip,
            "port": port,
            "template_id": entry.get("template-id", ""),
            "vuln_name": entry.get("info", {}).get("name", ""),
            "severity": entry.get("info", {}).get("severity", ""),
            "matched_at": entry.get("matched-at", ""),
            "vuln": True,
        })

    log(f"nuclei found {len(results)} vulnerable hosts/services")
    return results


def scan_masscan_nuclei(ports: str, rate: int, template: str, nuclei_rate: int, nuclei_concurrency: int, nuclei_timeout: int, node_name: str) -> list[dict]:
    if not template:
        log("ERROR: --template required for masscan+nuclei mode")
        return []

    hits = run_masscan(ports, rate)
    if not hits:
        return []

    targets = [f"{h['ip']}:{h['port']}" for h in hits]
    log(f"nuclei scanning {len(targets)} ip:port targets from masscan...")
    return run_nuclei(targets, template, nuclei_rate, nuclei_concurrency, nuclei_timeout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True,
                        choices=["masscan-only", "nmap-only", "masscan+nmap", "geo-scout", "masscan+nuclei"])
    parser.add_argument("--ports", required=True)
    parser.add_argument("--rate", type=int, default=3000)
    parser.add_argument("--node-name", default="node")
    parser.add_argument("--template", default="")
    parser.add_argument("--nmap-timing", type=int, default=None, choices=[1, 2, 3, 4])
    parser.add_argument("--nmap-timeout", type=int, default=None)
    parser.add_argument("--nmap-workers", type=int, default=None)
    parser.add_argument("--nuclei-rate", type=int, default=150)
    parser.add_argument("--nuclei-concurrency", type=int, default=25)
    parser.add_argument("--nuclei-timeout", type=int, default=10)
    args = parser.parse_args()

    global NMAP_WORKERS, NMAP_TIMING, NMAP_TIMEOUT
    if args.nmap_workers is not None:
        NMAP_WORKERS = args.nmap_workers
    if args.nmap_timing is not None:
        NMAP_TIMING = args.nmap_timing
    if args.nmap_timeout is not None:
        NMAP_TIMEOUT = args.nmap_timeout

    log(f"WEBRUNNER node scanner starting — mode={args.mode} node={args.node_name}")

    if args.mode == "masscan-only":
        results = scan_masscan_only(args.ports, args.rate, args.node_name)
    elif args.mode == "nmap-only":
        results = scan_nmap_only(args.ports, args.node_name)
    elif args.mode == "masscan+nmap":
        results = scan_masscan_nmap(args.ports, args.rate, args.node_name)
    elif args.mode == "geo-scout":
        results = scan_geo_scout(args.ports, args.rate, args.node_name)
    elif args.mode == "masscan+nuclei":
        results = scan_masscan_nuclei(
            args.ports, args.rate, args.template,
            args.nuclei_rate, args.nuclei_concurrency, args.nuclei_timeout,
            args.node_name,
        )
    else:
        log(f"Unknown mode: {args.mode}")
        sys.exit(1)

    out = {
        "node_name": args.node_name,
        "scan_mode": args.mode,
        "result_count": len(results),
        "results": results,
    }

    out_file = WORKDIR / "results.json"
    out_file.write_text(json.dumps(out, indent=2))
    log(f"Done — {len(results)} results written to {out_file}")


if __name__ == "__main__":
    main()
