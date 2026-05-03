---
devtrack: 989
timestamp: 2026-05-03T00:00:00Z
findings_addressed: 2
findings_skipped: 3
---

# Fix Summary — DevTrack #989

## Applied

### HIGH — Tuning input validation (AUDIT_SEC_989#1)
**File:** `modules/webrunner/deploy_webrunner.py:181-195`
**Fix:** `_prompt()` now clamps non-positive values to the default and warns the operator. Applies to all tuning keys (masscan_rate, nmap_timing, nmap_timeout, nmap_workers, nuclei_rate, nuclei_concurrency, nuclei_timeout) regardless of whether the value came from interactive input or a vars file.
**Verification:** Engine math also has floors (`max(nmap_workers, 1)`, `max(min(...), 1.0)` in nuclei throughput, `if rate <= 0: return PROVISION_OVERHEAD_HOURS`), so even pre-fix garbage in produced sane numbers — but operator's displayed tuning would have been wrong. Now the displayed and computed values match.

### P3 — Dead code removal (AUDIT_CODE_989#3)
**File:** `modules/webrunner/deploy_webrunner.py:195-196`
**Fix:** Removed the empty `if scan_mode in (...): pass` placeholder that was a refactor leftover. masscan_rate is already prompted unconditionally above.

## Skipped (with justification)

### MEDIUM — Tor warning phrasing (AUDIT_SEC_989#2)
Auditor suggested rewording the masscan-Tor warning. Existing text already states "raw sockets bypass proxychains entirely" and "use 'nmap-only' mode for full Tor coverage" — auditor's suggestion is semantically equivalent. No material improvement.

### MEDIUM — Path traversal in template/yaml file loading (AUDIT_SEC_989#3)
False positive for this threat model. Webrunner is a single-operator attack tool, not multi-tenant. The "attack vector" of "operator supplies malicious vars file pointing at /etc/passwd" doesn't apply — the operator IS the trusted party and runs the tool on their own machine. They can already read any file they want. Adding path restriction would just frustrate legitimate workflows (e.g., operator's nuclei templates are typically in `~/templates/` outside the WEBRUNNER_INPUTS dir). YAML uses `safe_load` so no code execution. The file content goes only to the operator's stdout, not to a remote server.

### LOW — Estimate display discloses scope (AUDIT_SEC_989#5)
Interactive console output to the operator. Not logged externally. Operator chose to run the tool. Suppression flag is overkill for a tool with one user.

## Gate Review Status
Ready for gate-reviewer. No P1 or unaddressed HIGH findings remain.
