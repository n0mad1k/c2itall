---
agent: security-auditor
status: COMPLETE
timestamp: 2026-05-01T00:00:00Z
duration_seconds: 15
files_scanned: 4
findings_count: 2
critical_count: 0
high_count: 1
errors: []
skipped_checks: []
---

# Security Audit — DevTrack #980: node_scanner.py ThreadPoolExecutor Parallelization

## Summary
Reviewed `/home/n0mad1k/tools/c2itall/modules/webrunner/tasks/node_scanner.py` and Ansible provisioning tasks for security risks related to:
- Subprocess injection from command-line arguments
- XML parsing (XXE/entity expansion)
- Socket resource handling under concurrency
- File write races in parallelized execution

## Findings

### HIGH: Command Injection via Unquoted Arguments in subprocess.run() — Ansible Template Injection

**File:** `run_scan.yml:14-18` and `node_scanner.py:28-35, 81-85, 149-153`

**Issue:** Arguments passed to `subprocess.run()` include unquoted template variables from Ansible. While Python's subprocess list form prevents shell metacharacter injection **within a single arg**, the Ansible playbook's command templating is not protected.

Example from run_scan.yml:
```yaml
command: >
  python3 /root/webrunner/node_scanner.py
  --mode {{ scan_mode }}
  --ports {{ ports_str }}
  --rate {{ masscan_rate }}
  --node-name {{ node_name }}
```

If `{{ ports_str }}` contains spaces (e.g., "22,80,443"), it's safe in shell. However, if `{{ node_name }}` is injected with shell metacharacters (e.g., `node-1; rm -rf /`), Ansible's `command:` module will execute it as a shell command directly.

**Attack vector:** Operator misconfigures Ansible extra-vars with malicious node_name or ports_str → arbitrary command execution on cloud node.

**Remediation:** Use Ansible's `args:` with list form instead of shell templating:
```yaml
command:
  - python3
  - /root/webrunner/node_scanner.py
  - --mode
  - "{{ scan_mode }}"
  - --ports
  - "{{ ports_str }}"
  - --rate
  - "{{ masscan_rate }}"
  - --node-name
  - "{{ node_name }}"
```
Or validate inputs in deploy_webrunner.py before passing to Ansible.

---

### MEDIUM: XML External Entity (XXE) Risk in ET.parse() — Mitigated by ET default behavior

**File:** `node_scanner.py:94, 166`

**Issue:** `ET.parse()` on lines 94 and 166 parses untrusted XML from nmap output. Python's ElementTree (ET) by default disables external entity expansion, making XXE attacks unlikely. However, entity bombing (billion laughs) is theoretically possible.

**Context:** nmap writes its own XML; this is trusted output from a tool run locally. Risk is LOW in isolation because:
1. nmap is the source, not an external API
2. Attacker would need to compromise the nmap binary itself
3. No feature in nmap that injects user-controlled XML

**Mitigation already in place:** ET default configuration rejects DOCTYPE declarations with external entities.

**Note:** No action required for current implementation. No XXE vector found.

---

## Resource Exhaustion Risk with ThreadPoolExecutor (Planned Change)

**File:** `node_scanner.py:117-133` — probe_service() under parallelism

**Issue:** The planned ThreadPoolExecutor with 10 workers parallelizing `run_nmap()` calls exposes `probe_service()` to connection resource exhaustion:

```python
def probe_service(ip: str, port: int) -> str:
    with socket.create_connection((ip, port), timeout=3) as s:
        # ...
```

With 10 parallel nmap fingerprints, if each nmap finds 50+ open ports, 500 concurrent socket connections could be created in `scan_geo_scout()` at line 242. Each connection opens a file descriptor.

**Mitigation in current code:**
- Socket context manager ensures cleanup
- 3-second timeout prevents hung connections
- Per-port probe only happens in geo_scout mode, not default
- Masscan output is bounded by realistic open port densities

**Risk level:** MEDIUM if combined with extremely high port density (e.g., scanning honeypot ranges). Current code structure (sequential per-IP) avoids this.

**Recommendation:** When implementing ThreadPoolExecutor, add:
1. Resource pool limits (e.g., semaphore capping concurrent probes to 50)
2. Per-worker socket timeout validation
3. Connection pool reset on worker failure

---

## Subprocess Argument Validation

**File:** `node_scanner.py:77-89, 149-153`

**Status:** PASS (No injection risk detected)

- Port arguments use `",".join(str(p) for p in sorted(set(ports)))` — guaranteed numeric
- Rate argument is `type=int` from argparse — validated
- Node name and ip parameters are passed as list items to subprocess — shell metacharacters have no effect
- All subprocess calls use `check=False` and exception handling — no silent failures

---

## File I/O Concurrency

**File:** `node_scanner.py:79, 286`

**Status:** PASS

- Per-IP XML outputs are uniquely named: `nmap_{ip.replace('.', '_')}.xml` — no collision under parallel execution
- results.json written once at end — sequential write after all work complete
- No shared file handles between workers

---

## Secrets & Credentials Exposure

**Status:** PASS

- No hardcoded API keys, tokens, or credentials
- No sensitive data in log output (only counts, timestamps, status)
- Node names do not reveal operator identity (parameterized via `webrunner_name`)
- Tor routing properly abstracted through Ansible conditional — no hardcoded proxy strings

---

## Summary Table

| Category | Status | Severity | Notes |
|----------|--------|----------|-------|
| Subprocess injection | **FAIL** | HIGH | Ansible template injection via unquoted args in run_scan.yml |
| XXE / entity expansion | PASS | — | ET default config sufficient |
| Socket exhaustion (parallelism) | PASS* | MEDIUM | Resource pool limits recommended for 10-worker ThreadPoolExecutor |
| Argument validation | PASS | — | argparse + list form subprocess calls |
| File I/O races | PASS | — | Unique per-IP filenames, sequential final write |
| Secrets exposure | PASS | — | No hardcoded credentials |
| OPSEC (fingerprinting) | PASS | — | Node names parameterized, no tool signature leakage |

*Requires mitigation before high-parallelism production use.

---

## Actionable Fixes

1. **Fix run_scan.yml** — Use Ansible args list form or validate inputs upstream
2. **ThreadPoolExecutor planning** — Add semaphore/resource pool for probe_service() concurrency
3. **No blocking issues** for current sequential implementation

