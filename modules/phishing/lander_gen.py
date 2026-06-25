#!/usr/bin/env python3
import re
import shlex
from pathlib import Path
from urllib.parse import urlparse
from jinja2 import Environment, FileSystemLoader

from utils.common import COLORS

_CAMPAIGN_ID_RE = re.compile(r'^[a-zA-Z0-9_-]+$')


def _validate_campaign_id(campaign_id: str) -> str:
    if not _CAMPAIGN_ID_RE.match(campaign_id):
        raise ValueError(f"campaign_id contains invalid characters: {campaign_id!r}")
    return campaign_id


def _validate_https_url(url: str, label: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != 'https' or not parsed.netloc:
        raise ValueError(f"{label} must be an https:// URL, got: {url!r}")
    return url


def post_deploy_generate_lander(config: dict) -> None:
    if not config.get('use_lander'):
        return

    campaign_id = _validate_campaign_id(config['lander_campaign_id'])
    provider = config['lander_provider']
    mode = config['lander_mode']
    bucket = config['lander_bucket']
    redirect_url = _validate_https_url(config['lander_redirect_url'], 'redirect_url')
    phishing_hostname = config.get('phishing_hostname', 'phishing.local')
    js_payload_url = _validate_https_url(
        f"https://{phishing_hostname}/static/jq.min.js", 'js_payload_url'
    )

    template_dir = Path(__file__).parent / 'templates'
    env = Environment(loader=FileSystemLoader(str(template_dir)))

    context = {
        'tds_enabled': mode == 'tds',
        'tds_domains': config.get('lander_tds_domains', []),
        'js_payload_url': js_payload_url,
        'redirect_url': redirect_url,
    }

    html_template = env.get_template('cloud-lander.html.j2')
    js_template = env.get_template('js-payload.js.j2')

    html_content = html_template.render(context)
    js_content = js_template.render(context)

    out_dir = Path('.')
    html_file = out_dir / f'lander-{campaign_id}.html'
    js_file = out_dir / f'js-payload-{campaign_id}.js'

    html_file.write_text(html_content)
    js_file.write_text(js_content)

    print(f"\n{COLORS['GREEN']}[+] Lander files generated{COLORS['RESET']}")
    print(f"    {COLORS['CYAN']}{html_file}{COLORS['RESET']}")
    print(f"    {COLORS['CYAN']}{js_file}{COLORS['RESET']}")

    qbucket = shlex.quote(bucket)
    qhtml = shlex.quote(str(html_file))
    qjs = shlex.quote(str(js_file))

    if provider == 'gcs':
        public_url = f"https://storage.googleapis.com/{bucket}/index.html?{campaign_id}"
        upload_cmd = f"gsutil cp {qhtml} gs://{qbucket}/index.html && gsutil acl ch -u AllUsers:R gs://{qbucket}/index.html"
    elif provider == 's3':
        public_url = f"https://{bucket}.s3.amazonaws.com/index.html?{campaign_id}"
        upload_cmd = f"aws s3 cp {qhtml} s3://{qbucket}/index.html --acl public-read"
    elif provider == 'azure':
        public_url = f"https://{bucket}.blob.core.windows.net/$web/index.html?{campaign_id}"
        upload_cmd = f"az storage blob upload -f {qhtml} -c '$web' -n index.html --account-name {qbucket}"
    else:
        public_url = f"<unknown provider: {provider}>"
        upload_cmd = "<unknown provider>"

    print(f"\n{COLORS['YELLOW']}[!] Upload instructions for {COLORS['CYAN']}{provider.upper()}{COLORS['YELLOW']}:{COLORS['RESET']}")
    print(f"    {COLORS['CYAN']}{upload_cmd}{COLORS['RESET']}")
    print(f"\n{COLORS['YELLOW']}[!] Public trusted-domain URL:{COLORS['RESET']}")
    print(f"    {COLORS['CYAN']}{public_url}{COLORS['RESET']}")

    print(f"\n{COLORS['YELLOW']}[!] JS payload deployment:{COLORS['RESET']}")
    webserver_scp = f"scp {qjs} user@webserver:/var/www/phishing/static/jq.min.js"
    print(f"    {COLORS['CYAN']}{webserver_scp}{COLORS['RESET']}")
    # ponytail: fixed JS filename visible in webserver logs; upgrade to per-RId rotation if log-harvesting becomes a threat

    print(f"\n{COLORS['RED']}[!!] CRITICAL: Upload both files BEFORE starting your GoPhish campaign{COLORS['RESET']}\n")


if __name__ == '__main__':
    test_config = {
        'use_lander': False,
        'lander_campaign_id': 'test_001',
        'lander_provider': 'gcs',
        'lander_mode': 'simple',
        'lander_bucket': 'test-bucket',
        'lander_redirect_url': 'https://phishing.local/login',
        'phishing_hostname': 'phishing.local',
    }
    post_deploy_generate_lander(test_config)
    print("Self-check passed: disabled lander returned None without errors")
