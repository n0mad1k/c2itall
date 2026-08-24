#!/usr/bin/env python3
"""
Drift check — vendored ops-logger.sh vs. the canonical copy at ~/tools/ops-logger.
Run from c2itall root: python3 check_ops_logger_drift.py
"""
import hashlib
import os
import sys

VENDORED = os.path.join(os.path.dirname(__file__), "tools", "redteam", "ops-logger.sh")
CANONICAL = os.path.expanduser("~/tools/ops-logger/ops-logger.sh")


def checksum(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


if not os.path.isfile(CANONICAL):
    print(f"[skip] canonical copy not found at {CANONICAL} — nothing to compare (expected on other machines)")
    sys.exit(0)

if not os.path.isfile(VENDORED):
    print(f"[fail] vendored copy missing at {VENDORED}")
    sys.exit(1)

vendored_sum = checksum(VENDORED)
canonical_sum = checksum(CANONICAL)

if vendored_sum != canonical_sum:
    print(f"[fail] ops-logger.sh has drifted from canonical")
    print(f"    vendored:  {VENDORED} ({vendored_sum})")
    print(f"    canonical: {CANONICAL} ({canonical_sum})")
    print(f"    fix: cp {CANONICAL} {VENDORED}")
    sys.exit(1)

print(f"[ok] ops-logger.sh matches canonical ({vendored_sum})")
sys.exit(0)
