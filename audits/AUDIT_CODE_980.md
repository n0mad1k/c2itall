---
agent: code-auditor
status: COMPLETE
timestamp: 2026-05-01T00:00:00Z
duration_seconds: 180
files_scanned: 2
findings_count: 8
errors: []
skipped_checks: []
---

# Code Audit — DevTrack #980

## Findings

### P1 (Blocker)

- [node_scanner.py:123] **Command injection via string interpolation** — `s.send(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())` uses `%b` format which allows raw bytes; hostname validation required. Not exploitable in this context (internal service), but antipattern. Should be `f"Host: {ip}\r\n"` as string with bytes conversion after.

- [node_scanner.py:117-133] **Socket not guaranteed closed on exception path** — `probe_service()` relies on context manager but inner try/except blocks can suppress exceptions. If `s.recv()` at line 124 raises an exception NOT caught by `except Exception`, the context manager exits cleanly. **Actually safe** — verified: all paths either return or re-raise under `except Exception`, and outer `with` block guarantees cleanup. False alarm, but comment would help clarity.

### P2 (Important)

- [node_scanner.py:148] **Dead code** — `targets_arg = " ".join(cidrs[:50])` (line 148) assigned but never used; removed in scan_nmap_only().

- [provider_rates.py:88] **Logic bug in build_estimate_table()** — Line 88 uses `preset['chunk_size']` to calculate hours, but line 93 calculates `n_chunks` correctly. However, the hours calculation assumes each chunk takes the same time, which is correct only if all chunks are the same size. **For the last chunk**, if `total_ips % preset['chunk_size'] != 0`, the hours are overstated (line 94 always assumes full chunk). This causes cost overestimation for non-aligned IP counts. Should calculate per-chunk IPs separately or clarify in docs that hours are per-chunk-size, not per-actual-chunk.

- [node_scanner.py:77-114] **run_nmap() called concurrently from scan_masscan_nmap() and scan_geo_scout()** — Each writes to `nmap_{ip}.xml` (unique per IP, line 79). **Thread safety: confirmed safe** — XML output files are per-IP and subprocess.run() creates isolated processes. No shared state. Risk: if same IP appears twice in one call, file overwrites but result is same. Non-issue.

### P3 (Minor)

- [node_scanner.py:20] **print() in production code** — Line 20 `log()` function calls `print()` directly. Should use logging module (logging.info) or Rich for consistency with c2itall patterns. Low impact (stderr-friendly for cloud runner), but violates style guidelines.

- [node_scanner.py:136-139] **Unused parameter in scan_masscan_only()** — `node_name` parameter (line 142, 248, 262) passed but never used in any scan function. These functions don't write node metadata to results. Inconsistency with function signature expectations.

- [node_scanner.py:226] **Import inside function** — `import yaml` at line 225 (inside scan_geo_scout). Move to top for clarity. Low cost import, non-blocking.

- [provider_rates.py:76-78] **Comment lacks precision** — "Tor adds ~5x latency overhead" with TOR_RATE_MULTIPLIER = 0.2 (which is 1/5, not 5x). Comment should say "reduces throughput to 1/5" or multiply by 0.2. Currently correct code, ambiguous comment.

### P4 (Nitpick)

- [node_scanner.py] **Two comment blocks (line 3-5, line 76)** without corresponding docstrings. Module-level docstring present, function docstrings absent. Minor — code is self-documenting.

- [provider_rates.py:57] **Magic number 0.018** — Default instance rate hardcoded. Should be a constant (e.g., `DEFAULT_RATE = 0.018`).

## Stats

- print() calls: 1 (in log function)
- TODO/FIXME comments: 0
- Unused imports: 0 (all imports used: ET, Path, subprocess, argparse, json, sys, time, math, socket, yaml lazy-loaded)
- Dead code blocks: 1 (targets_arg, line 148)
- Unused parameters: 3 (node_name in scan_* functions)
- Files >500 lines: 0
- Functions >50 lines: 0 (longest is run_masscan at 44 lines)
- Nesting depth >3: 0 (deepest is 3 levels in build_estimate_table, acceptable)

## Verification Notes

**Thread safety (run_nmap):** Confirmed. Each IP gets unique XML file (`nmap_{ip}.xml`). Concurrent calls from different IPs are safe. Same IP in same call overwrites but idempotent.

**estimate_scan_hours() formula:** `(ip_count * n_ports / rate) / 3600` is correct for time in hours. Rate in packets/sec, result in hours. No mathematical error, but doc should clarify units.

**Socket leak risk (probe_service):** No leak. `with socket.create_connection()` guarantees cleanup; nested exceptions all caught.

