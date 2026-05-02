#!/usr/bin/env python3
"""
WEBRUNNER merge — combine per-node results.json files into a unified report.
Run by Ansible on the controller after all nodes complete.
"""

import argparse
import ipaddress
import json
import sys
from pathlib import Path


def _build_cidr_map(cc_cidrs: dict) -> list[tuple]:
    result = []
    for cc, cidrs in cc_cidrs.items():
        for cidr in cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                result.append((net, cc.upper()))
            except ValueError:
                pass
    result.sort(key=lambda x: x[0].prefixlen, reverse=True)
    return result


def _lookup_country(ip: str, cidr_map: list[tuple]) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for net, cc in cidr_map:
        if addr in net:
            return cc
    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--cidr-map", default="", help="JSON file mapping country codes to CIDR lists")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    node_files = sorted(results_dir.glob("*_results.json"))

    if not node_files:
        print(f"No result files found in {results_dir}", file=sys.stderr)
        sys.exit(1)

    cidr_map: list[tuple] = []
    if args.cidr_map:
        try:
            cc_cidrs = json.loads(Path(args.cidr_map).read_text())
            cidr_map = _build_cidr_map(cc_cidrs)
        except (OSError, json.JSONDecodeError):
            pass

    merged: dict = {
        "deployment_id": args.deployment_id,
        "nodes": [],
        "total_results": 0,
        "results": [],
    }

    seen: set[str] = set()  # deduplicate by ip:port

    for f in node_files:
        try:
            data = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError) as e:
            print(f"Skipping {f.name}: {e}", file=sys.stderr)
            continue

        node_summary = {
            "node_name": data.get("node_name", f.stem),
            "scan_mode": data.get("scan_mode", "unknown"),
            "result_count": data.get("result_count", 0),
        }
        merged["nodes"].append(node_summary)

        for entry in data.get("results", []):
            key = f"{entry.get('ip')}:{entry.get('port')}"
            if key not in seen:
                seen.add(key)
                if cidr_map:
                    entry["country"] = _lookup_country(entry.get("ip", ""), cidr_map)
                merged["results"].append(entry)

    merged["total_results"] = len(merged["results"])

    if cidr_map:
        country_counts: dict[str, int] = {}
        for entry in merged["results"]:
            cc = entry.get("country", "")
            country_counts[cc] = country_counts.get(cc, 0) + 1
        merged["country_summary"] = dict(
            sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
        )

    Path(args.output).write_text(json.dumps(merged, indent=2))

    print(f"Merged {len(node_files)} node(s) — {merged['total_results']} unique results")
    for n in merged["nodes"]:
        print(f"  {n['node_name']}: {n['result_count']} results ({n['scan_mode']})")

    if cidr_map and merged.get("country_summary"):
        print("\nVulnerable hosts by country:")
        for cc, count in list(merged["country_summary"].items())[:20]:
            label = cc if cc else "unknown"
            print(f"  {label:<6} {count}")


if __name__ == "__main__":
    main()
