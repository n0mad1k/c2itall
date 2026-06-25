---
agent: code-auditor
status: COMPLETE
timestamp: 2026-06-25T10:20:00Z
duration_seconds: 120
files_scanned: 4
findings_count: 6
errors: []
skipped_checks: []
---

# Code Audit

## Files Scanned
- `modules/phishing/lander_gen.py` (103 lines)
- `modules/phishing/deploy_phishing.py` (574 lines, focused: L157-185, L417-424, L445-446)
- `modules/phishing/templates/cloud-lander.html.j2` (31 lines)
- `modules/phishing/templates/js-payload.js.j2` (11 lines)

## Findings

### HIGH
- [lander_gen.py:25-90] `post_deploy_generate_lander()` uses `print()` calls (11 instances, L62-89) in production code. Should use logging or Rich for consistency with c2itall pattern.
- [cloud-lander.html.j2:14] Magic number `20` hardcoded in `makeRandomSub(20)` for random subdomain prefix length. Should be a configurable constant; if log-harvesting becomes a threat, this will need per-request rotation and the number may change.

### MEDIUM
- [lander_gen.py:66-76] Duplicate provider-specific logic pattern. GCS, S3, and Azure blocks each construct `public_url` and `upload_cmd` independently. Same operation (URL + command generation) duplicated 3 times with 5+ line similarity each. Extract to a dict-driven pattern or helper to reduce duplication.
- [deploy_phishing.py:164-184] Nesting depth of 5 levels in lander prompt block (if → if → if → if → if). Input validation and conditional chain is difficult to follow; consider early returns or extracting to a dedicated validation function.
- [cloud-lander.html.j2:13] Hardcoded character set `'abcdefghijklmnopqrstuvwxyz0123456789'` used in random subdomain generation. If character set requirements change (e.g., exclude vowels to avoid accidental offensive domains), this will need updating in multiple places.

### LOW
- [lander_gen.py:87] Comment references "ponytail: fixed JS filename visible in webserver logs" but does not state the upgrade path. Per ponytail rules, shortcut ceilings should name when to upgrade (e.g., "upgrade to per-RId rotation if log-harvesting becomes a threat"). Current comment is incomplete.
- [deploy_phishing.py:445-446] Inline import of `post_deploy_generate_lander` inside success block. While intentional (lazy load post-deploy), this is not consistent with module-level imports at the top of the function. Consider moving to the top for clarity or add a comment explaining the late binding reason.

## Stats
- print() calls: 11 (lander_gen.py L62-89, deploy_phishing.py L158-184)
- TODO/FIXME/HACK: 0
- Files >500 lines: 1 (deploy_phishing.py)
- Functions >50 lines: 0
- Max nesting depth: 5 (deploy_phishing.py L164-184)
- Cyclomatic complexity: 2 (within acceptable range)
- Dead code: None detected
- Duplicate logic blocks: 1 (provider URL/command generation)

## Notes

### Code Quality Observations

**Strengths:**
- Input validation at trust boundaries is solid (HTTPS enforcement, campaign ID regex)
- No unused imports
- Clean separation of concerns (lander_gen.py as pure generation, deploy_phishing.py as orchestration)
- Syntax is valid across all files

**Complexity:**
- The lander prompt block in deploy_phishing.py (L164-184) has legitimate nesting due to cascading user input validation, but would benefit from extraction to reduce cognitive load.
- File sizes are within healthy range (largest is 574 lines, acceptable for a deployment orchestrator).

**Style:**
- Consistent use of COLORS dict for output (good adherence to c2itall pattern)
- Template Jinja2 syntax is correct and minimal

