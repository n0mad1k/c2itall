---
agent: fix-planner
status: COMPLETE
timestamp: 2026-06-25T10:35:00Z
total_findings_raw: 13
total_findings_deduped: 11
p1_count: 2
p2_count: 4
p3_count: 4
p4_count: 1
devtrack_items_created: []
errors: []
---

# Fix Plan — DevTrack #1259

## P1 — Block Deploy

- [ ] **[CRITICAL]** `modules/phishing/lander_gen.py:68-76` — Shell injection via unescaped config parameters in printed upload commands. Bucket and campaign_id parameters injected directly into shell command strings without escaping. If operator enters malicious input like `bucket && malicious_command`, printed output becomes executable when copy-pasted to shell. | Sources: security-auditor | Effort: S | Fix: Use `shlex.quote()` on all config parameters before insertion into command strings.

- [ ] **[CRITICAL]** `modules/phishing/templates/okta-login.html.j2:102, 206` — Real PII and organization identifiers hardcoded in template: email address `Brian.Caldwell@Zimperium.com`, Okta org `zimperium.okta.com`, app ID `exk1ufbfxuFLJp6y3697`. Exposed in version control and deployed artifacts. | Sources: env-validator | Effort: S | Fix: Parameterize template with Jinja2 variables (`target_email`, `okta_org_url`, `okta_app_id`) and populate at runtime from config dict, never in source.

## P2 — Fix This Week

- [ ] **[HIGH]** `modules/phishing/templates/js-payload.js.j2:5-8` — RId parameter injection via unsafe URL parsing. `decodeURIComponent(src)` applied to full referrer URL without validation; `new URL()` constructor can throw without try-catch; double-encoding edge case not handled. Malformed referrer could bypass redirect logic or leak information. | Sources: security-auditor | Effort: S | Fix: Wrap `new URL()` in try-catch; validate referrer format before parsing; use `searchParams` property instead of re-decoding; limit RId length to 128 chars.

- [ ] **[HIGH]** `modules/phishing/webserver/templates/nginx-phishing-webserver.j2:41-45` — Overly permissive PHP location block allows execution of **all** `.php` files in all subdirectories. If path traversal or file upload vulnerability elsewhere in webserver root, RCE via malicious `.php` execution. Current rule `location ~ \.php$` is too broad. | Sources: security-auditor | Effort: M | Fix: Restrict PHP execution to only `/capture.php` with `location = /capture.php` and deny all other `.php` files with fallback `location ~ \.php$ { deny all; }`.

- [ ] **[HIGH]** `modules/phishing/webserver/templates/page-templates/phishing-landing-page.j2:221` — XSS via unescaped `redirect_url` in JavaScript context. Template renders `{{ redirect_url }}` inside single-quoted JS string without `tojson` filter; if validation bypass occurs, injection point is vulnerable. Mitigated by current validation in Python code, but not properly defended in template itself. | Sources: security-auditor | Effort: XS | Fix: Apply `| tojson` filter explicitly: `window.location.href = {{ redirect_url | tojson }};` and document assumption that URL is pre-validated HTTPS.

- [ ] **[HIGH]** `modules/phishing/lander_gen.py:25-90` — Production code uses 11 instances of `print()` calls (L62-89) for output. Inconsistent with c2itall pattern which uses logging or Rich for structured output. Makes operational logging difficult and prevents standardized log aggregation. | Sources: code-auditor | Effort: M | Fix: Replace all `print()` calls with Rich console output or logging module calls to match c2itall standards.

## P3 — Fix This Month

- [ ] **[MEDIUM]** `modules/phishing/webserver/templates/page-templates/phishing-landing-page.j2:153-154` — Double-escaped GoPhish template variables using `{{ '{{.RId}}' }}` pattern. Fragile and breaks if Jinja2 autoescape is enabled in future; relies on manual verification instead of automated testing. | Sources: security-auditor | Effort: S | Fix: Replace with Jinja2 raw block: `{% raw %}<input type="hidden" name="rid" value="{{.RId}}">{% endraw %}` and add comment explaining two-stage rendering intent.

- [ ] **[MEDIUM]** `modules/phishing/lander_gen.py:66-76` — Duplicate provider-specific logic pattern across GCS, S3, and Azure blocks. Each constructs `public_url` and `upload_cmd` independently with 5+ lines of similar code. Increases maintenance burden if URL/command generation logic needs changes. | Sources: code-auditor | Effort: M | Fix: Extract provider URL and command generation to a dict-driven helper function or pattern.

- [ ] **[MEDIUM]** `modules/phishing/templates/cloud-lander.html.j2:12-18` — DOM-based XSS via unsafe TDS domain input concatenation. If TDS domain input is not validated, malicious domain could redirect `jq.min.js` loads to attacker infrastructure. | Sources: security-auditor | Effort: S | Fix: Validate TDS domains as valid DNS names using regex pattern; reject special characters. Document that TDS domains are untrusted by design.

- [ ] **[MEDIUM]** `modules/phishing/deploy_phishing.py:164-184` — Nesting depth of 5 levels in lander prompt validation block. Input validation chain is difficult to follow and increases cognitive load. No error handling issues, but readability suffers. | Sources: code-auditor | Effort: S | Fix: Extract validation chain to dedicated `_validate_lander_config()` function with early returns per parameter.

## P4 — Backlog

- [ ] **[LOW]** `modules/phishing/lander_gen.py:87` — Comment references ponytail shortcut but does not state upgrade path or conditions. Per ponytail rules, comments should name when to upgrade (e.g., "upgrade to per-RId rotation if log-harvesting becomes a threat"). | Sources: code-auditor | Effort: XS | Fix: Update comment to include upgrade condition and version target.

