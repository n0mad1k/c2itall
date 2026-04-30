#!/usr/bin/env python3
"""
WEBRUNNER merge — combine per-node results.json files into a unified report.
Run by Ansible on the controller after all nodes complete.
"""

import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--deployment-id", required=True)
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    node_files = sorted(results_dir.glob("*_results.json"))

    if not node_files:
        print(f"No result files found in {results_dir}", file=sys.stderr)
        sys.exit(1)

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
                merged["results"].append(entry)

    merged["total_results"] = len(merged["results"])

    Path(args.output).write_text(json.dumps(merged, indent=2))

    print(f"Merged {len(node_files)} node(s) — {merged['total_results']} unique results")
    for n in merged["nodes"]:
        print(f"  {n['node_name']}: {n['result_count']} results ({n['scan_mode']})")


if __name__ == "__main__":
    main()
