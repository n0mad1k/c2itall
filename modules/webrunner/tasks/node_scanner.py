#!/usr/bin/env python3
"""
WEBRUNNER node scanner — runs on each cloud node.
Reads cidrs.txt, runs scan pipeline, writes results.json.
"""

import argparse
import json
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

WORKDIR = Path("/root/webrunner")


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
        "-p", port_str, "-T4", "--open",
        "-oX", str(out_file), ip,
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=60, check=False)
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
                s.send(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
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

    targets_arg = " ".join(cidrs[:50])  # nmap handles CIDRs natively
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
    log(f"nmap fingerprinting {len(by_ip)} hosts...")
    results = []
    for idx, (ip, ip_ports) in enumerate(by_ip.items()):
        nmap_info = run_nmap(ip, ip_ports)
        for port in ip_ports:
            entry: dict = {"ip": ip, "port": port}
            if port in nmap_info:
                entry.update(nmap_info[port])
            results.append(entry)
        if (idx + 1) % 50 == 0:
            log(f"  nmap: {idx + 1}/{len(by_ip)} hosts done")
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

    results = []
    for idx, (ip, ip_ports) in enumerate(by_ip.items()):
        nmap_info = run_nmap(ip, ip_ports)
        for port in ip_ports:
            entry: dict = {"ip": ip, "port": port}
            if port in nmap_info:
                entry.update(nmap_info[port])
            # Banner grab / probe
            banner = probe_service(ip, port)
            if banner:
                entry["probe_banner"] = banner
            # Match against target profile
            if port in target_ports:
                t = target_ports[port]
                entry["target_name"] = t.get("name", "")
                entry["target_desc"] = t.get("description", "")
            results.append(entry)
        if (idx + 1) % 50 == 0:
            log(f"  geo-scout: {idx + 1}/{len(by_ip)} hosts done")
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True,
                        choices=["masscan-only", "nmap-only", "masscan+nmap", "geo-scout"])
    parser.add_argument("--ports", required=True)
    parser.add_argument("--rate", type=int, default=3000)
    parser.add_argument("--node-name", default="node")
    args = parser.parse_args()

    log(f"WEBRUNNER node scanner starting — mode={args.mode} node={args.node_name}")

    if args.mode == "masscan-only":
        results = scan_masscan_only(args.ports, args.rate, args.node_name)
    elif args.mode == "nmap-only":
        results = scan_nmap_only(args.ports, args.node_name)
    elif args.mode == "masscan+nmap":
        results = scan_masscan_nmap(args.ports, args.rate, args.node_name)
    elif args.mode == "geo-scout":
        results = scan_geo_scout(args.ports, args.rate, args.node_name)
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
