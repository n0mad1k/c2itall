---
agent: fix-planner
status: COMPLETE
timestamp: 2026-05-01T23:45:00Z
total_findings_raw: 15
total_findings_deduped: 13
p1_count: 1
p2_count: 2
p3_count: 3
p4_count: 2
devtrack_items_created: []
errors: []
---

# Fix Plan — DevTrack #980: node_scanner.py ThreadPoolExecutor Parallelization

## Summary

Consolidated findings from code-auditor (8 findings) and security-auditor (2 findings) for DevTrack #980.

**Status**: 7 fixes applied and verified. 2 HIGH/MEDIUM severity issues remain (run_scan.yml, estimate_scan_hours partial chunk logic). 4 low-priority items acceptable for backlog.

---

## Fixes Applied ✓

### Applied Fixes (Verified)

1. **[node_scanner.py:204-216]** ThreadPoolExecutor parallelization in `scan_masscan_nmap()` — 10 workers via `NMAP_WORKERS` env var (default 10)
2. **[node_scanner.py:260-266]** ThreadPoolExecutor parallelization in `scan_geo_scout()` — same 10-worker pattern
3. **[node_scanner.py:126]** Bytes format bug fixed: `ip.encode()` used directly instead of `%b` format string
4. **[node_scanner.py:145-192]** Dead variable `targets_arg` removed from `scan_nmap_only()`
5. **[provider_rates.py:55-63]** `estimate_scan_hours()` now accepts `scan_mode` parameter for accurate nmap time estimation
6. **[provider_rates.py:50-52]** Constants added: `NMAP_TIME_PER_HOST_SEC=10`, `MASSCAN_HIT_RATE=0.01`, `_NMAP_WORKERS=10`
7. **[provider_rates.py:104]** `build_estimate_table()` passes `scan_mode` to `estimate_scan_hours()`

---

## Remaining Issues

### P1 — Block Deploy

- [ ] **[HIGH] [run_scan.yml:14-18]** Ansible template injection via unquoted variables | Sources: security-auditor | Effort: S | Status: NOT FIXED

  **Description**: Arguments in `command:` module use unquoted Ansible template vars (`{{ scan_mode }}`, `{{ ports_str }}`, `{{ node_name }}`). If `node_name` is injected with shell metacharacters (e.g., `node-1; rm -rf /`), Ansible's `command:` module will execute shell commands.

  **Attack vector**: Operator misconfigures Ansible extra-vars with malicious node_name or ports_str → arbitrary command execution on cloud node.

  **Remediation**: Use Ansible `command:` as list form (args: [python3, script.py, --mode, "{{ scan_mode }}", ...]) or validate inputs upstream in deploy_webrunner.py.

  **Risk**: HIGH — affects production cloud deployment pipeline. Requires manual Ansible remediation (file not in Python audit scope).

---

### P2 — Fix This Week

- [ ] **[HIGH] [provider_rates.py:91-118]** Partial chunk cost overestimation in `build_estimate_table()` | Sources: code-auditor | Effort: M | Status: NOT FIXED

  **Description**: Line 104 assumes each chunk costs the same time as `preset['chunk_size']` IPs. If `total_ips % preset['chunk_size'] != 0`, the last chunk is smaller, but cost calculation doesn't account for it. Example: 2.5M IPs across 2-chunk preset (2M chunks) = chunk 1 (2M hrs) + chunk 2 (0.5M hrs), but current code bills chunk 2 as 2M hrs.

  **Current code**: `hours = estimate_scan_hours(preset['chunk_size'], n_ports, mode_rate, scan_mode)` — always uses full chunk_size.

  **Fix**: Calculate per-chunk IP count separately:
  ```python
  for i in range(n_chunks):
      chunk_ips = min(preset['chunk_size'], total_ips - i * preset['chunk_size'])
      hours = estimate_scan_hours(chunk_ips, n_ports, mode_rate, scan_mode)
      provider = providers[i % len(providers)]
      instance = DEFAULT_INSTANCE.get(provider, 'g6-standard-2')
      total_cost += node_cost(provider, instance, hours)
  ```

  **Impact**: Cost estimates 1.5-2x too high for non-aligned IP counts; may oversell capacity planning.

- [ ] **[MEDIUM] [node_scanner.py:225-239]** Import inside function — `import yaml` at line 232 | Sources: code-auditor | Effort: XS | Status: NOT FIXED

  **Description**: `import yaml` appears inside `scan_geo_scout()` function. Move to top-level imports for clarity and consistency.

  **Fix**: Add `import yaml` to line 16 (after `ET` import), remove line 232.

---

### P3 — Fix This Month

- [ ] **[MEDIUM] [node_scanner.py:21-23]** `print()` in production code — `log()` function uses `print()` | Sources: code-auditor | Effort: S | Status: NOT FIXED

  **Description**: Line 23 calls `print()` directly. Should use Python `logging` module or Rich (per c2itall style guide).

  **Fix**: Replace `log()` function with logging.info or Rich console output for consistency.

- [ ] **[LOW] [node_scanner.py:139-192]** Unused parameter `node_name` — passed to all scan_* functions but never used | Sources: code-auditor | Effort: XS | Status: NOT FIXED

  **Description**: Parameter `node_name` appears in `scan_masscan_only()`, `scan_nmap_only()`, `scan_masscan_nmap()`, `scan_geo_scout()` signatures but is not referenced in function bodies. These functions don't write node metadata to results.

  **Assessment**: Intentionally kept for interface consistency (caller always passes it, avoids conditional logic).

  **Fix**: Document as "reserved for future node metadata logging" or remove for clarity. Non-blocking.

- [ ] **[LOW] [provider_rates.py:76-88]** Comment ambiguity — Tor multiplier description misleading | Sources: code-auditor | Effort: XS | Status: NOT FIXED

  **Description**: Line 86 comment says "Tor adds ~5x latency overhead" but line 88 sets `TOR_RATE_MULTIPLIER = 0.2` (which is 1/5, not 5x). Comment is correct in spirit but confusingly worded.

  **Fix**: Change comment to "Tor reduces throughput to 1/5 (0.2x)" or "multiplier 0.2 ≈ 5x latency".

---

### P4 — Backlog

- [ ] **[LOW] [provider_rates.py:57]** Magic number 0.018 — Linode default rate hardcoded | Status: NOT FIXED

  **Description**: Line 7 (`'g6-standard-2': 0.018`) and line 67 (fallback rate) hardcode 0.018. Should be named constant.

  **Fix**: Add `DEFAULT_INSTANCE_RATE = 0.018` and reference it.

- [ ] **[LOW] [node_scanner.py]** Missing docstrings — module + function docstrings absent | Status: NOT FIXED

  **Description**: Module docstring present (line 2-4) but individual functions lack docstrings. Low impact — code is self-documenting.

---

## Deduplication Notes

- **Socket leak risk (probe_service)**: Marked as false alarm in code-auditor; context manager guarantees cleanup. No action needed.
- **Thread safety (run_nmap concurrent writes)**: Verified safe — per-IP XML files unique (`nmap_{ip.replace('.', '_')}.xml`). No collision risk.
- **XXE/entity expansion in ET.parse()**: PASS — ET default config disables external entity expansion. nmap output is trusted. No action needed.
- **Resource exhaustion (socket connections)**: MEDIUM severity in security-auditor. Noted as acceptable risk for current sequential structure. ThreadPoolExecutor 10-worker design with 3-second socket timeout is within system limits. Semaphore capping recommended for future scaling but not blocking.

---

## Action Items

### Critical Path (Block #980 deployment):
1. **run_scan.yml**: Convert Ansible `command:` module to list form OR validate node_name upstream
2. **provider_rates.py**: Fix partial-chunk cost calculation in `build_estimate_table()`

### Nice-to-have (P3-P4):
- Move `import yaml` to top level
- Replace `print()` with logging/Rich
- Add Tor multiplier comment clarity
- Extract 0.018 magic number to constant

---

## Test Coverage

- Unit tests for `estimate_scan_hours()` with partial chunks should verify cost accuracy
- Ansible playbook syntax validation required for run_scan.yml
- Manual integration test with non-aligned IP count (e.g., 2.5M across 2M presets)

