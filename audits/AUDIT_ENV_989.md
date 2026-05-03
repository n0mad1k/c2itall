---
agent: env-validator
status: PASS
timestamp: 2026-05-02T00:00:00Z
findings_count: 0
errors: []
---

# Env Validation — DevTrack #989

## Summary
Comprehensive secrets hygiene audit for webrunner estimator rewrite (provider_rates.py and deploy_webrunner.py). **All checks passed.**

## PASS

### Secrets in source
- **provider_rates.py**: Clean. Contains only tuning constants (rate tables, timing defaults, cost multipliers). No API keys, tokens, passwords, or credential patterns detected.
- **deploy_webrunner.py**: Clean. Contains no hardcoded secrets. All credential handling is delegated to provider-specific utilities (linode_utils, aws_utils, flokinet_utils) which retrieve secrets from Infisical at runtime.

### API key/token patterns
Searched all files for:
- `ghp_[A-Za-z0-9_]+` (GitHub tokens) — NOT FOUND
- `sk_live_[A-Za-z0-9]+` or `sk_test_[A-Za-z0-9]+` (Stripe) — NOT FOUND
- `AKIA[A-Z0-9]{16}` (AWS access keys) — NOT FOUND
- `Bearer [A-Za-z0-9._-]{20,}` (bearer tokens) — NOT FOUND
- `password\s*=\s*["'][^"']{8,}` (hardcoded passwords) — NOT FOUND
- `api[_-]?key\s*=\s*["'][^"']{10,}` (API keys) — NOT FOUND

### .env file content
- No new .env files created in either module
- No .env file writes detected in code
- Tuning parameters stored in safe yaml configs:
  - `inputs/targets.yaml` — target definitions, probe patterns, vulnerability tags only
  - `inputs/countries.yaml` — country codes, priority levels, exclude lists only
  - User-supplied vars files (optional) — only tuning parameters (masscan_rate, nmap_timing, hit_rate, etc.)

### Credential handling verification
All provider credentials properly retrieved from Infisical:
- **Linode**: `creds get LINODE_TOKEN homelab` (linode_utils.py:16-19)
- **AWS**: `creds get AWS_ACCESS_KEY_ID homelab` and `creds get AWS_SECRET_ACCESS_KEY homelab` (aws_utils.py:17-24)
- Fallback to vars file templates only (marked as placeholders like 'YOUR_AWS')
- No secrets persisted to disk; only set in `os.environ` in memory (deployment_engine.py:set_provider_environment)

### Git history check
- No secrets in recent commits to these files
- 16 commits to webrunner module examined (latest: "Phase-accurate webrunner cost/time estimator...")
- Notable commit: "Fix P1 WEBRUNNER deployment failures and secret leakage" (18039b2) — prior leak was addressed and fixed
- No secret patterns detected in any commit

### Code review
- `provider_rates.py` (209 lines): Pure computation — estimate_scan_hours(), build_estimate_table(), formatting helpers. No file I/O, no env var access.
- `deploy_webrunner.py` (617 lines): Parameter gathering and deployment orchestration. All secrets retrieved via subprocess calls to `creds` binary (lines 16-24 in provider utils). No new credential handling code introduced in this rewrite.

## Findings
**0 issues.**

No hardcoded secrets, no .env writes, no credential handling added. Secrets flow:
```
User input → provider_utils → creds binary (Infisical) → os.environ (memory only)
```
This is correct per secrets management rules.
