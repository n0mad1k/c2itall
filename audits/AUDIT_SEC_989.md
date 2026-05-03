---
agent: security-auditor
status: COMPLETE
timestamp: 2026-05-02T00:00:00Z
duration_seconds: 15
files_scanned: 3
findings_count: 4
critical_count: 0
high_count: 1
errors: []
skipped_checks: []
---

# Security Audit — DevTrack #989 (Webrunner Estimator Rewrite)

## Scope
Files audited:
- `/home/n0mad1k/tools/c2itall/utils/provider_rates.py` (209 lines)
- `/home/n0mad1k/tools/c2itall/modules/webrunner/deploy_webrunner.py` (617 lines)
- `/home/n0mad1k/tools/c2itall/modules/webrunner/tasks/merge_results.py` (118 lines)

Checks performed: input injection, hardcoded secrets, auth, OPSEC, malformed input handling, path safety, estimate disclosure.

---

## Findings

### HIGH (CVSS 7.0–8.9)

#### 1. Unvalidated Negative/Zero Tuning Parameters Allow Cost Calculation DoS
**Location**: `deploy_webrunner.py:181-191`, `provider_rates.py:177-143`

**Description**: Tuning parameters from vars file or CLI input are cast to `int` without validation. Negative or zero values for `masscan_rate`, `nmap_workers`, `nuclei_concurrency` propagate directly into mathematical operations (division, multiplication) in the estimate functions, resulting in nonsensical estimates or potential floating-point exceptions.

**Attack vector**: Operator provides malformed vars file with `masscan_rate: -100` or `nuclei_concurrency: 0`, causing:
- `estimate_scan_hours()` to compute incorrect hours (negative division result at line 141)
- Cost estimates to be silently corrupted
- Decision-making based on invalid data

**Remediation**: 
- In `_prompt()` (line 181), add validation after cast: `if value <= 0: value = default`
- In `build_estimate_table()` (line 177), enforce minimum values: `masscan_rate = max(1, int(...))`
- Validate `nmap_workers` and `nuclei_concurrency` before use in math (already partially done at line 104, but only for nmap_workers; nuclei_concurrency lacks guard).

---

### MEDIUM (CVSS 4.0–6.9)

#### 2. Tor Warning Phrasing Could Be Misinterpreted — Default Behavior Correct But Language Ambiguous
**Location**: `deploy_webrunner.py:211-227`

**Description**: The warning at line 217 states "CRITICAL OPSEC WARNING — MASSCAN BYPASSES TOR" and explains that masscan uses raw sockets and cannot be proxied. However, the framing "THIS CLOUD NODE'S IP is exposed to targets" is accurate but could mislead an operator into thinking *all* scanning traffic is exposed.

The code correctly defaults to `[y/N]` (line 401), requiring explicit `y` or `yes` to proceed — this is secure. However, the message could clarify that:
1. Only masscan SYN packets leak the node IP.
2. nmap, nuclei, and probes ARE protected by Tor (correctly stated at line 223–224).
3. The operator is consenting to a *known, documented limitation*, not an accidental leak.

**Current text**: "Every SYN packet sent during the masscan phase reveals THIS CLOUD NODE'S IP to the targets and any monitoring along the path."

**Better text**: "Every SYN packet sent during the masscan phase reveals THIS CLOUD NODE'S IP address to targets (raw sockets bypass proxychains entirely). Use 'nmap-only' mode for full Tor protection."

**Remediation**: Update warning wording to disambiguate masscan-only exposure vs. the rest of the stack.

---

#### 3. Path Traversal Risk in Template and Targets File Loading
**Location**: `deploy_webrunner.py:162-173` (nuclei template), `deploy_webrunner.py:133-149` (targets.yaml)

**Description**: User-supplied paths to nuclei templates and targets.yaml files are opened without sanitization:
- Line 169: `local_path = input("  Path to nuclei template (.yaml): ").strip()` → directly to `Path(local_path).exists()` → `open(path)` at line 141.
- Line 136: `raw = input(f"Path to targets.yaml [{default}]: ").strip()` → `path = raw or default` → `open(path)` at line 141.

An operator (or vars file) could supply `../../../etc/passwd` or symlinks, allowing:
1. Reading arbitrary files on the deployment controller.
2. Leaking environment variables or private keys if yaml.safe_load() processes them.

**Attack vector**: Vars file with `nuclei_template: /etc/hostname` or `targets_file: ~/.ssh/id_rsa` — files are read and displayed.

**Remediation**:
- Add path validation: `p = Path(local_path).resolve(); if not p.is_relative_to(Path.cwd()): reject`.
- Alternatively, restrict to a specific directory: `p = (WEBRUNNER_INPUTS / local_path).resolve(); if not p.is_relative_to(WEBRUNNER_INPUTS): reject`.
- Use pathlib consistently to prevent directory traversal.

---

#### 4. YAML Safe-Load Correctly Used — No Code Execution Risk
**Location**: `deploy_webrunner.py:115-130`, `deploy_webrunner.py:139-149`

**Status**: PASS — `yaml.safe_load()` is used (not `yaml.load()`), preventing arbitrary Python object instantiation. No code execution risk from malformed YAML.

---

### LOW (CVSS <4.0)

#### 5. Estimate Display Discloses Target Scope and Timing to Console
**Location**: `deploy_webrunner.py:256-301`, output at lines 272–296

**Description**: The estimate table displays:
- Total IPs being scanned (`fmt_ip_count(total_ips)`)
- Country codes (implicit in CIDR resolution)
- Scan mode (masscan, nmap, nuclei)
- Time estimates per node
- Total cost

This information is printed to stdout and may be captured in shell history, logs, or screenshots. For offensive ops, this data could reveal:
- Scope scale (e.g., "2.5M IPs" suggests multi-country / large infrastructure)
- Duration (e.g., "12h per node" reveals patience/persistence)
- Provider selection (e.g., "Linode + AWS" may hint at region strategy)

**Mitigated by**: 
- Information is shown only during interactive setup (not in batch mode).
- Operator sees warning about provisioning time.
- Cost estimates are precise only for the estimator, not for actual billing.

**Recommendation**: 
- Consider adding a `--quiet` flag to suppress estimate display in sensitive environments.
- Ensure logs are cleaned post-deployment (already handled by log rotation).

---

## Summary

**Secure patterns**:
- YAML loading uses `safe_load()` ✓
- No subprocess injection or eval/exec ✓
- No hardcoded secrets or credentials ✓
- Tor warning defaults to `[y/N]` (opt-in, secure) ✓
- CIDR country map is read-only JSON, not executed ✓

**Action items**:
1. **HIGH**: Add validation to tuning parameters to prevent negative/zero values.
2. **MEDIUM**: Clarify Tor warning wording and add path traversal guards.
3. **LOW**: Consider audit log suppression for estimate table in future versions.

