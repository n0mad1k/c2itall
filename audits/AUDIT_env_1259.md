---
agent: env-validator
status: PARTIAL
timestamp: 2026-06-25T00:00:00Z
findings_count: 2
errors: []
---

# Env Validation — DevTrack #1259

## FAIL
- **okta-login.html.j2:102** — Real email address hardcoded in template: `Brian.Caldwell@Zimperium.com`
  - Location: HTML form hidden input field (`fromURI` parameter)
  - Risk: PII leak in template asset; exposed in version control
  - Details: Value is HTML-encoded (`&#x2f;`, `&amp;`, `%40`, etc.) but fully readable when decoded

- **okta-login.html.j2:206** — Real Okta organization reference hardcoded: `zimperium.okta.com` + Okta app ID `exk1ufbfxuFLJp6y3697`
  - Location: JavaScript variable `baseUrl` and `fromUri` in login page script
  - Risk: Identifies real target organization; enables direct OSINT attack path
  - Details: Okta app ID (`exk1ufbfxuFLJp6y3697`) is a unique identifier that can be used to enumerate target infrastructure

## WARN
None

## PASS
- **lander_gen.py** — Credentials passed via config dict, written to temp JSON files with mode 0o600, deleted after use. No filesystem persistence of secrets.
- **deploy_phishing.py** — SMTP password and other credentials collected via input prompts, stored in memory-only config dict, passed to Ansible via temporary JSON file (mode 0o600). No hardcoded secrets detected.
- **cloud-lander.html.j2, js-payload.js.j2** — Template variables only; no hardcoded secrets.
- **nginx-phishing-webserver.j2** — Nginx configuration template; no hardcoded credentials.
- **phishing-landing-page.j2** — Generic login template with Jinja2 placeholders; no hardcoded PII or secrets.
- **microsoft-login.html.j2** — Phishing template with placeholder values; no real credentials embedded.
- **Git history** — No evidence of secrets committed in recent git history (for these files).

## Remediation Required

### Critical
Replace okta-login.html.j2 with a **parameterized template**:

1. Remove hardcoded `Brian.Caldwell@Zimperium.com` and `zimperium.okta.com`
2. Replace with Jinja2 variables:
   - `{{ target_email | default('') }}`
   - `{{ okta_org_url | default('https://okta.example.com') }}`
   - `{{ okta_app_id | default('') }}`
3. Populate these at deployment time via config dict, never in version control
4. Add a comment in the template: `<!-- Template variables: target_email, okta_org_url, okta_app_id -->`

### Process
Ensure all phishing templates follow the same pattern:
- **No real email addresses** in source
- **No real domain/org references** in source
- **All campaign-specific data injected at runtime** via Jinja2 context
- Credentials and PII sourced from config dict passed by `deploy_phishing.py`, never hardcoded

