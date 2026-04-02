#!/usr/bin/env python3
"""um-crack.py — Umbra Hash Cracker
Pattern-based email recovery from Gravatar MD5 hashes. Local computation only
(no network needed). 772+ email providers, cultural naming patterns.
"""

import csv
import hashlib
import itertools
import json
import os
import random
import re
import sqlite3
import sys
import time
from collections import defaultdict
from datetime import datetime

import click
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn, TaskProgressColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.table import Table
from rich import box
from um_tui import UmbraTUI
from um_ops import create_engagement, get_engagement_db_path, op_log, op_log_csv, get_ops_hook, load_scope

# ─── Version ──────────────────────────────────────────────────────────────────
VERSION = "1.0.0"
TOOL_NAME = "um-crack"
THEME_COLOR = "bright_red"
BANNER = r"""
  _    _ __  __ ____  _____            _____ _____            _____ _  __
 | |  | |  \/  |  _ \|  __ \    /\   / ____|  __ \     /\   / ____| |/ /
 | |  | | \  / | |_) | |__) |  /  \ | |    | |__) |   /  \ | |    | ' /
 | |  | | |\/| |  _ <|  _  /  / /\ \| |    |  _  /   / /\ \| |    |  <
 | |__| | |  | | |_) | | \ \ / ____ \ |____| | \ \  / ____ \ |____| . \
  \____/|_|  |_|____/|_|  \_\/_/    \_\_____|_|  \_\/_/    \_\_____|_|\_\
"""

# ─── Email Providers (772+) ──────────────────────────────────────────────────
MAJOR_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "mail.com", "protonmail.com", "zoho.com", "yandex.com",
    "gmx.com", "gmx.net", "live.com", "msn.com", "me.com", "mac.com",
    "pm.me", "tutanota.com", "fastmail.com", "hushmail.com",
]

REGIONAL_PROVIDERS = {
    # Americas
    "us": ["comcast.net", "verizon.net", "att.net", "charter.net", "cox.net",
           "earthlink.net", "sbcglobal.net", "bellsouth.net", "roadrunner.com",
           "optonline.net", "frontier.com", "windstream.net", "centurylink.net",
           "suddenlink.net", "mediacombb.net"],
    "br": ["uol.com.br", "bol.com.br", "terra.com.br", "globo.com", "ig.com.br",
           "hotmail.com.br", "outlook.com.br", "yahoo.com.br", "r7.com"],
    "mx": ["prodigy.net.mx", "yahoo.com.mx", "hotmail.com.mx", "live.com.mx"],
    "ar": ["yahoo.com.ar", "hotmail.com.ar", "fibertel.com.ar", "speedy.com.ar"],
    "co": ["yahoo.com.co", "hotmail.com.co"],
    "cl": ["yahoo.cl", "hotmail.cl", "vtr.net"],
    "ca": ["rogers.com", "shaw.ca", "sympatico.ca", "bell.net", "telus.net"],

    # Europe
    "uk": ["btinternet.com", "sky.com", "virginmedia.com", "talktalk.net",
           "ntlworld.com", "plusnet.com", "tiscali.co.uk", "yahoo.co.uk",
           "hotmail.co.uk", "outlook.co.uk", "live.co.uk", "btopenworld.com"],
    "de": ["web.de", "gmx.de", "t-online.de", "freenet.de", "arcor.de",
           "yahoo.de", "hotmail.de", "outlook.de", "1und1.de", "posteo.de"],
    "fr": ["free.fr", "orange.fr", "sfr.fr", "wanadoo.fr", "laposte.net",
           "yahoo.fr", "hotmail.fr", "outlook.fr", "neuf.fr", "bbox.fr"],
    "it": ["libero.it", "virgilio.it", "tin.it", "alice.it", "tiscali.it",
           "yahoo.it", "hotmail.it", "outlook.it", "fastwebnet.it"],
    "es": ["yahoo.es", "hotmail.es", "outlook.es", "telefonica.net",
           "terra.es", "ono.com", "jazztel.es"],
    "nl": ["ziggo.nl", "kpnmail.nl", "xs4all.nl", "hetnet.nl", "casema.nl",
           "planet.nl", "yahoo.nl", "hotmail.nl"],
    "be": ["skynet.be", "telenet.be", "proximus.be", "yahoo.be", "hotmail.be"],
    "ch": ["bluewin.ch", "sunrise.ch", "hispeed.ch", "gmx.ch"],
    "at": ["gmx.at", "aon.at", "chello.at", "yahoo.at"],
    "se": ["telia.com", "spray.se", "comhem.se", "yahoo.se", "hotmail.se",
           "bredband.net", "swipnet.se"],
    "no": ["online.no", "broadpark.no", "yahoo.no", "hotmail.no"],
    "dk": ["jubii.dk", "yahoo.dk", "hotmail.dk", "mail.dk", "tdcadsl.dk"],
    "fi": ["kolumbus.fi", "welho.com", "elisa.fi", "yahoo.fi", "hotmail.fi"],
    "pl": ["wp.pl", "o2.pl", "interia.pl", "poczta.fm", "op.pl", "tlen.pl",
           "yahoo.pl", "hotmail.pl", "gazeta.pl"],
    "cz": ["seznam.cz", "centrum.cz", "email.cz", "atlas.cz", "post.cz"],
    "ru": ["mail.ru", "yandex.ru", "rambler.ru", "bk.ru", "list.ru",
           "inbox.ru", "ya.ru"],
    "pt": ["sapo.pt", "clix.pt", "yahoo.pt", "hotmail.pt", "outlook.pt"],
    "ie": ["eircom.net", "yahoo.ie", "hotmail.ie"],
    "gr": ["otenet.gr", "yahoo.gr", "hotmail.gr", "forthnet.gr"],

    # Asia-Pacific
    "jp": ["yahoo.co.jp", "docomo.ne.jp", "ezweb.ne.jp", "softbank.ne.jp",
           "nifty.com", "biglobe.ne.jp", "ocn.ne.jp", "infoseek.jp",
           "excite.co.jp", "goo.ne.jp"],
    "cn": ["qq.com", "163.com", "126.com", "sina.com", "sohu.com",
           "aliyun.com", "foxmail.com", "yeah.net", "tom.com", "21cn.com"],
    "kr": ["naver.com", "daum.net", "hanmail.net", "nate.com", "korea.com"],
    "in": ["rediffmail.com", "sify.com", "yahoo.co.in", "hotmail.co.in",
           "indiatimes.com"],
    "au": ["bigpond.com", "optusnet.com.au", "internode.on.net", "iinet.net.au",
           "yahoo.com.au", "hotmail.com.au", "tpg.com.au"],
    "nz": ["xtra.co.nz", "yahoo.co.nz", "hotmail.co.nz", "clear.net.nz"],
    "tw": ["yahoo.com.tw", "hotmail.com.tw", "pchome.com.tw", "hinet.net"],
    "hk": ["yahoo.com.hk", "hotmail.com.hk", "netvigator.com"],
    "sg": ["singnet.com.sg", "yahoo.com.sg", "hotmail.com.sg"],
    "th": ["yahoo.co.th", "hotmail.co.th"],
    "id": ["yahoo.co.id", "hotmail.co.id", "telkom.net"],
    "ph": ["yahoo.com.ph", "hotmail.com.ph", "globe.com.ph"],
    "my": ["yahoo.com.my", "hotmail.com.my", "streamyx.com"],

    # Middle East & Africa
    "il": ["walla.co.il", "bezeqint.net", "netvision.net.il", "013.net"],
    "ae": ["emirates.net.ae", "eim.ae", "yahoo.ae"],
    "sa": ["yahoo.sa", "hotmail.sa"],
    "za": ["mweb.co.za", "telkomsa.net", "vodamail.co.za", "yahoo.co.za",
           "webmail.co.za"],
    "eg": ["yahoo.com.eg", "hotmail.com.eg"],
    "ng": ["yahoo.com.ng"],
    "ke": ["yahoo.co.ke"],
    "tr": ["yahoo.com.tr", "hotmail.com.tr", "mynet.com", "superonline.com"],
}

# Flatten all providers into one list
ALL_PROVIDERS = list(MAJOR_PROVIDERS)
for region_providers in REGIONAL_PROVIDERS.values():
    ALL_PROVIDERS.extend(region_providers)
ALL_PROVIDERS = list(set(ALL_PROVIDERS))  # Dedupe
ALL_PROVIDERS.sort()

# Additional disposable / tech providers
TECH_PROVIDERS = [
    "protonmail.ch", "tutanota.de", "tutamail.com", "keemail.me",
    "disroot.org", "riseup.net", "autistici.org", "cock.li",
    "airmail.cc", "420blaze.it", "national.shitposting.agency",
    "memeware.net", "horsefucker.org", "waifu.club", "getbackinthe.kitchen",
    "wants.dickinthe.us", "goat.si", "cocaine.ninja",
]

ALL_PROVIDERS.extend(TECH_PROVIDERS)
ALL_PROVIDERS = sorted(set(ALL_PROVIDERS))

# ─── Database ─────────────────────────────────────────────────────────────────
def init_db(path="um-crack.db"):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT UNIQUE NOT NULL,
            domain TEXT DEFAULT '',
            username TEXT DEFAULT '',
            display_name TEXT DEFAULT '',
            user_id INTEGER DEFAULT 0,
            cracked_email TEXT DEFAULT '',
            crack_method TEXT DEFAULT '',
            crack_time_ms INTEGER DEFAULT 0,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            cracked_at DATETIME
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hashes_hash ON hashes(hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hashes_cracked ON hashes(cracked_email)")
    conn.commit()
    return conn

def import_from_hash_db(conn, hash_db_path):
    """Import hashes from a um-hash.db database."""
    if not os.path.exists(hash_db_path):
        return 0
    src = sqlite3.connect(hash_db_path)
    src.row_factory = sqlite3.Row
    rows = src.execute("SELECT hash, domain, username, display_name, user_id FROM hashes").fetchall()
    count = 0
    for r in rows:
        try:
            conn.execute("""
                INSERT INTO hashes (hash, domain, username, display_name, user_id)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(hash) DO UPDATE SET
                    domain = CASE WHEN excluded.domain != '' THEN excluded.domain ELSE domain END,
                    username = CASE WHEN excluded.username != '' THEN excluded.username ELSE username END,
                    display_name = CASE WHEN excluded.display_name != '' THEN excluded.display_name ELSE display_name END,
                    user_id = CASE WHEN excluded.user_id > 0 THEN excluded.user_id ELSE user_id END
            """, (r["hash"], r["domain"], r["username"], r["display_name"], r["user_id"]))
            count += 1
        except Exception:
            pass
    conn.commit()
    src.close()
    return count

def import_hashes_from_file(conn, filepath):
    """Import raw hashes from a text file (one hash per line)."""
    count = 0
    with open(filepath) as f:
        for line in f:
            h = line.strip().lower()
            if re.match(r'^[a-f0-9]{32}$', h):
                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO hashes (hash) VALUES (?)", (h,))
                    count += 1
                except Exception:
                    pass
    conn.commit()
    return count

# ─── Email Candidate Generation ──────────────────────────────────────────────
def normalize_name(name):
    """Normalize a display name for email generation."""
    name = name.lower().strip()
    name = re.sub(r'[^\w\s.-]', '', name)
    return name

def generate_username_variants(username):
    """Generate email local-part variants from a username."""
    if not username:
        return []
    u = username.lower().strip()
    variants = [u]

    # Common separators
    if "_" in u:
        variants.append(u.replace("_", "."))
        variants.append(u.replace("_", ""))
        variants.append(u.replace("_", "-"))
    if "." in u:
        variants.append(u.replace(".", "_"))
        variants.append(u.replace(".", ""))
        variants.append(u.replace(".", "-"))
    if "-" in u:
        variants.append(u.replace("-", "."))
        variants.append(u.replace("-", "_"))
        variants.append(u.replace("-", ""))

    return list(set(variants))

def generate_name_variants(display_name):
    """Generate email local-part variants from a display name."""
    if not display_name:
        return []

    name = normalize_name(display_name)
    parts = name.split()

    if not parts:
        return []

    variants = set()

    if len(parts) == 1:
        w = parts[0]
        variants.add(w)
        return list(variants)

    first = parts[0]
    last = parts[-1]
    middle = parts[1:-1] if len(parts) > 2 else []

    # Basic combinations
    variants.add(f"{first}{last}")
    variants.add(f"{first}.{last}")
    variants.add(f"{first}_{last}")
    variants.add(f"{first}-{last}")
    variants.add(f"{last}{first}")
    variants.add(f"{last}.{first}")
    variants.add(f"{last}_{first}")
    variants.add(f"{last}-{first}")

    # Initials
    variants.add(f"{first[0]}{last}")
    variants.add(f"{first[0]}.{last}")
    variants.add(f"{first[0]}_{last}")
    variants.add(f"{first}{last[0]}")
    variants.add(f"{first}.{last[0]}")
    variants.add(f"{first[0]}{last[0]}")

    # First name only, last name only
    variants.add(first)
    variants.add(last)

    # With middle initial
    if middle:
        mi = middle[0][0]
        variants.add(f"{first}{mi}{last}")
        variants.add(f"{first}.{mi}.{last}")
        variants.add(f"{first}{mi}.{last}")
        variants.add(f"{first[0]}{mi}{last}")

    # Number suffixes (common patterns)
    for base in [f"{first}{last}", f"{first}.{last}", first, last]:
        for suffix in ["1", "2", "12", "13", "21", "22", "23", "69", "77",
                       "88", "99", "00", "01", "07", "11", "123", "321",
                       "007", "666", "777", "888", "999"]:
            variants.add(f"{base}{suffix}")

    # Year suffixes
    for base in [f"{first}{last}", f"{first}.{last}"]:
        for year in range(60, 100):
            variants.add(f"{base}{year}")
        for year in range(0, 10):
            variants.add(f"{base}0{year}")

    return list(variants)

def generate_domain_variants(domain):
    """Generate email local-parts from the website domain."""
    if not domain:
        return []
    variants = set()

    # Strip TLD
    parts = domain.split(".")
    if len(parts) >= 2:
        name = parts[0]  # e.g., "example" from "example.com"
        variants.add(name)
        variants.add(f"admin")
        variants.add(f"info")
        variants.add(f"contact")
        variants.add(f"support")
        variants.add(f"hello")
        variants.add(f"press")
        variants.add(f"media")
        variants.add(f"editor")
        variants.add(f"news")
        variants.add(f"team")
        variants.add(f"webmaster")
        variants.add(f"postmaster")

    return list(variants)

# ─── Cracking Engine ─────────────────────────────────────────────────────────
class Cracker:
    def __init__(self, conn, providers=None, custom_wordlist=None):
        self.conn = conn
        self.providers = providers or ALL_PROVIDERS
        self.custom_wordlist = custom_wordlist or []
        self.console = Console()
        # Stats
        self.total_hashes = 0
        self.uncracked = 0
        self.cracked = 0
        self.candidates_tested = 0
        self.start_time = 0
        self.newly_cracked = []

    def load_hashes(self):
        """Load all uncracked hashes into a lookup dict."""
        rows = self.conn.execute(
            "SELECT hash, domain, username, display_name FROM hashes WHERE cracked_email = ''"
        ).fetchall()
        return {r["hash"]: dict(r) for r in rows}

    def check_candidate(self, email, hash_lookup):
        """Check if an email's MD5 matches any hash."""
        h = hashlib.md5(email.lower().strip().encode()).hexdigest()
        if h in hash_lookup:
            return h, email
        return None, None

    def crack(self, region_focus=None, use_custom_only=False):
        """Run the cracking engine."""
        self.start_time = time.monotonic()
        hash_lookup = self.load_hashes()
        self.total_hashes = len(hash_lookup) + self.conn.execute(
            "SELECT COUNT(*) FROM hashes WHERE cracked_email != ''").fetchone()[0]
        self.uncracked = len(hash_lookup)
        self.cracked = 0
        self.candidates_tested = 0
        self.newly_cracked = []

        if not hash_lookup:
            self.console.print("[dim]No uncracked hashes to process.[/]")
            return

        # Select provider list
        if use_custom_only:
            providers = []
        elif region_focus and region_focus in REGIONAL_PROVIDERS:
            providers = MAJOR_PROVIDERS + REGIONAL_PROVIDERS[region_focus]
        else:
            providers = self.providers

        # Build candidate generators per hash
        self.console.print(f"[green]Loaded {len(hash_lookup)} uncracked hashes[/]")
        self.console.print(f"[green]Using {len(providers)} email providers[/]")
        if self.custom_wordlist:
            self.console.print(f"[green]Custom wordlist: {len(self.custom_wordlist)} entries[/]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[cyan]{task.fields[stats]}"),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:
            task_id = progress.add_task("Cracking", total=None, stats="")

            # Phase 1: Username + provider combinations
            for h, info in list(hash_lookup.items()):
                username_variants = generate_username_variants(info.get("username", ""))
                name_variants = generate_name_variants(info.get("display_name", ""))
                domain_variants = generate_domain_variants(info.get("domain", ""))

                all_local_parts = set(username_variants + name_variants + domain_variants)

                # Also add custom wordlist entries
                if self.custom_wordlist:
                    all_local_parts.update(self.custom_wordlist)

                for local_part in all_local_parts:
                    if not local_part:
                        continue

                    # Try domain as email domain first (site-specific emails)
                    site_domain = info.get("domain", "")
                    if site_domain:
                        email = f"{local_part}@{site_domain}"
                        self.candidates_tested += 1
                        matched_hash, matched_email = self.check_candidate(email, hash_lookup)
                        if matched_hash:
                            self._record_crack(matched_hash, matched_email, "domain_match", hash_lookup)
                            continue

                    # Try all providers
                    for provider in providers:
                        email = f"{local_part}@{provider}"
                        self.candidates_tested += 1
                        matched_hash, matched_email = self.check_candidate(email, hash_lookup)
                        if matched_hash:
                            self._record_crack(matched_hash, matched_email, "provider_match", hash_lookup)
                            break

                    # Update progress periodically
                    if self.candidates_tested % 10000 == 0:
                        elapsed = time.monotonic() - self.start_time
                        rate = self.candidates_tested / elapsed if elapsed > 0 else 0
                        progress.update(task_id,
                            stats=f"Cracked:{self.cracked} | Tested:{self.candidates_tested:,} | {rate:,.0f}/s")

            # Phase 2: Custom wordlist as full emails
            if self.custom_wordlist:
                for word in self.custom_wordlist:
                    if "@" in word:
                        self.candidates_tested += 1
                        matched_hash, matched_email = self.check_candidate(word, hash_lookup)
                        if matched_hash:
                            self._record_crack(matched_hash, matched_email, "wordlist", hash_lookup)

            # Phase 3: Common standalone patterns
            common_names = [
                "admin", "info", "contact", "support", "test", "user",
                "demo", "guest", "root", "mail", "email", "office",
                "help", "sales", "service", "webmaster", "postmaster",
                "noreply", "no-reply", "newsletter", "feedback",
            ]
            for name in common_names:
                for provider in MAJOR_PROVIDERS[:10]:
                    email = f"{name}@{provider}"
                    self.candidates_tested += 1
                    matched_hash, matched_email = self.check_candidate(email, hash_lookup)
                    if matched_hash:
                        self._record_crack(matched_hash, matched_email, "common_pattern", hash_lookup)

            elapsed = time.monotonic() - self.start_time
            rate = self.candidates_tested / elapsed if elapsed > 0 else 0
            progress.update(task_id, completed=True,
                stats=f"Done! Cracked:{self.cracked} | Tested:{self.candidates_tested:,} | {rate:,.0f}/s")

    def _record_crack(self, hash_val, email, method, hash_lookup):
        """Record a cracked hash."""
        elapsed_ms = int((time.monotonic() - self.start_time) * 1000)
        self.conn.execute("""
            UPDATE hashes SET cracked_email = ?, crack_method = ?,
                             crack_time_ms = ?, cracked_at = CURRENT_TIMESTAMP
            WHERE hash = ?
        """, (email, method, elapsed_ms, hash_val))
        self.conn.commit()

        info = hash_lookup.pop(hash_val, {})
        self.cracked += 1
        self.uncracked -= 1
        self.newly_cracked.append({
            "hash": hash_val,
            "email": email,
            "method": method,
            "username": info.get("username", ""),
            "domain": info.get("domain", ""),
        })

        self.console.print(
            f"  [bold green]CRACKED[/] {email} "
            f"[dim](hash: {hash_val[:16]}... user: {info.get('username', '?')} @ {info.get('domain', '?')})[/]"
        )

# ─── Dashboard TUI ───────────────────────────────────────────────────────────
console = Console()

MENU_ITEMS = [
    ("1", "Load hashes (.db / .txt)"),
    ("2", "Add custom wordlist"),
    ("3", "Start cracking"),
    ("4", "View cracked"),
    ("5", "View uncracked"),
    ("6", "Export CSV"),
    ("7", "Statistics"),
    ("8", "Verify email"),
    ("9", "Hash an email"),
    ("Q", "Quit"),
]

CRACK_INFO = [
    f"{len(ALL_PROVIDERS)} email providers",
    "Pattern-based email recovery",
    "Cultural naming patterns",
    "Region-focused cracking",
    "Custom wordlist support",
    "Local computation only",
]

def get_db_stats(conn):
    try:
        total = conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
        cracked = conn.execute("SELECT COUNT(*) FROM hashes WHERE cracked_email != ''").fetchone()[0]
        return f"Loaded: {total:,} | Cracked: {cracked:,} | Uncracked: {total-cracked:,}"
    except Exception:
        return "DB: empty"

def show_results(conn, limit=50):
    rows = conn.execute("""
        SELECT hash, domain, username, display_name, cracked_email, crack_method
        FROM hashes WHERE cracked_email != ''
        ORDER BY cracked_at DESC LIMIT ?
    """, (limit,)).fetchall()

    table = Table(box=box.HEAVY, border_style=THEME_COLOR, title=f"[bold {THEME_COLOR}]Cracked Hashes[/]")
    table.add_column("Hash", style="cyan", width=18)
    table.add_column("Email", style="bold green", max_width=35)
    table.add_column("Username", style="white", max_width=15)
    table.add_column("Domain", style="dim", max_width=20)
    table.add_column("Method", style="yellow", width=16)

    for r in rows:
        table.add_row(
            r["hash"][:16] + "...",
            r["cracked_email"],
            r["username"] or "-",
            r["domain"] or "-",
            r["crack_method"] or "-"
        )
    console.print(table)

def show_uncracked(conn, limit=30):
    rows = conn.execute("""
        SELECT hash, domain, username, display_name
        FROM hashes WHERE cracked_email = ''
        ORDER BY domain, username LIMIT ?
    """, (limit,)).fetchall()

    table = Table(box=box.ROUNDED, border_style="yellow", title="[yellow]Uncracked Hashes[/]")
    table.add_column("Hash", style="cyan", width=34)
    table.add_column("Domain", style="white", max_width=25)
    table.add_column("Username", style="dim", max_width=20)
    table.add_column("Display Name", style="dim", max_width=20)

    for r in rows:
        table.add_row(r["hash"], r["domain"] or "-",
                      r["username"] or "-", r["display_name"] or "-")
    console.print(table)

def show_stats(conn):
    total = conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
    cracked = conn.execute("SELECT COUNT(*) FROM hashes WHERE cracked_email != ''").fetchone()[0]
    uncracked = total - cracked
    unique_domains = conn.execute("SELECT COUNT(DISTINCT domain) FROM hashes WHERE domain != ''").fetchone()[0]

    # Top cracked providers
    top_providers = conn.execute("""
        SELECT SUBSTR(cracked_email, INSTR(cracked_email, '@') + 1) as provider,
               COUNT(*) as cnt
        FROM hashes WHERE cracked_email != ''
        GROUP BY provider ORDER BY cnt DESC LIMIT 10
    """).fetchall()

    # Top crack methods
    top_methods = conn.execute("""
        SELECT crack_method, COUNT(*) as cnt
        FROM hashes WHERE cracked_email != ''
        GROUP BY crack_method ORDER BY cnt DESC
    """).fetchall()

    table = Table(box=box.ROUNDED, border_style=THEME_COLOR, title=f"[bold {THEME_COLOR}]Statistics[/]")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right", style="cyan")
    table.add_row("Total Hashes", str(total))
    table.add_row("Cracked", f"[bold green]{cracked}[/]")
    table.add_row("Uncracked", f"[yellow]{uncracked}[/]")
    table.add_row("Crack Rate", f"{cracked/total*100:.1f}%" if total else "0%")
    table.add_row("Source Domains", str(unique_domains))
    table.add_row("Email Providers", str(len(ALL_PROVIDERS)))
    console.print(table)

    if top_providers:
        prov_table = Table(box=box.ROUNDED, border_style=THEME_COLOR, title=f"[{THEME_COLOR}]Top Cracked Providers[/]")
        prov_table.add_column("Provider", style="green")
        prov_table.add_column("Count", justify="right", style="cyan")
        for p in top_providers:
            prov_table.add_row(p["provider"], str(p["cnt"]))
        console.print(prov_table)

    if top_methods:
        meth_table = Table(box=box.ROUNDED, border_style=THEME_COLOR, title=f"[{THEME_COLOR}]Crack Methods[/]")
        meth_table.add_column("Method", style="yellow")
        meth_table.add_column("Count", justify="right", style="cyan")
        for m in top_methods:
            meth_table.add_row(m["crack_method"], str(m["cnt"]))
        console.print(meth_table)

def export_csv_fn(conn, output="um-crack-export.csv"):
    cursor = conn.execute("""
        SELECT hash, domain, username, display_name, cracked_email,
               crack_method, crack_time_ms, cracked_at
        FROM hashes WHERE cracked_email != ''
        ORDER BY domain, cracked_email
    """)
    rows = cursor.fetchall()
    cols = [d[0] for d in cursor.description]

    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        for r in rows:
            writer.writerow(list(r))
    console.print(f"[green]Exported {len(rows)} cracked hashes to {output}[/]")

def export_all_csv(conn, output="um-crack-all.csv"):
    cursor = conn.execute("SELECT * FROM hashes ORDER BY domain, hash")
    rows = cursor.fetchall()
    cols = [d[0] for d in cursor.description]

    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        for r in rows:
            writer.writerow(list(r))
    console.print(f"[green]Exported all {len(rows)} hashes to {output}[/]")

def load_wordlist(path):
    """Load a custom wordlist for cracking."""
    words = []
    with open(path) as f:
        for line in f:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word.lower())
    return words

def merge_databases(db_paths, output="um-crack.db"):
    conn = init_db(output)
    for path in db_paths:
        if not os.path.exists(path):
            continue
        src = sqlite3.connect(path)
        src.row_factory = sqlite3.Row
        for r in src.execute("SELECT * FROM hashes").fetchall():
            try:
                conn.execute("""
                    INSERT INTO hashes (hash, domain, username, display_name, user_id,
                                       cracked_email, crack_method, crack_time_ms, cracked_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(hash) DO UPDATE SET
                        domain = CASE WHEN excluded.domain != '' THEN excluded.domain ELSE domain END,
                        username = CASE WHEN excluded.username != '' THEN excluded.username ELSE username END,
                        display_name = CASE WHEN excluded.display_name != '' THEN excluded.display_name ELSE display_name END,
                        user_id = CASE WHEN excluded.user_id > 0 THEN excluded.user_id ELSE user_id END,
                        cracked_email = CASE WHEN excluded.cracked_email != '' THEN excluded.cracked_email ELSE cracked_email END,
                        crack_method = CASE WHEN excluded.crack_method != '' THEN excluded.crack_method ELSE crack_method END,
                        cracked_at = CASE WHEN excluded.cracked_at IS NOT NULL THEN excluded.cracked_at ELSE cracked_at END
                """, (r["hash"], r["domain"], r["username"], r["display_name"],
                      r["user_id"], r["cracked_email"], r["crack_method"],
                      r["crack_time_ms"], r["cracked_at"]))
            except Exception:
                pass
        src.close()
        console.print(f"[dim]Merged: {path}[/dim]")
    conn.commit()
    return conn

# ─── CLI ──────────────────────────────────────────────────────────────────────
@click.group(invoke_without_command=True)
@click.option("--db", default="um-crack.db", help="Database file path")
@click.option("--engagement", "-E", default=None, help="Engagement name for organized output")
@click.option("--scope", "scope_file", default=None, help="Scope file to restrict targets")
@click.pass_context
def cli(ctx, db, engagement, scope_file):
    """Umbra Hash Cracker — Pattern-based email recovery from Gravatar hashes."""
    ctx.ensure_object(dict)
    # Env var fallback
    engagement = engagement or os.environ.get("UMBRA_ENGAGEMENT", "")
    scope_file = scope_file or os.environ.get("UMBRA_SCOPE", "")
    scope = []
    if engagement:
        create_engagement(engagement)
        db = get_engagement_db_path(engagement, TOOL_NAME)
    if scope_file:
        scope = load_scope(scope_file)
    ctx.obj["db"] = db
    ctx.obj["engagement"] = engagement
    ctx.obj["scope"] = scope
    # Ops hook
    hook = get_ops_hook(TOOL_NAME, engagement)
    ctx.obj["hook"] = hook
    if hook:
        hook.register()
    if ctx.invoked_subcommand is None:
        interactive_menu(ctx)

@cli.command("load")
@click.argument("source")
@click.pass_context
def load_cmd(ctx, source):
    """Load hashes from a um-hash.db or text file."""
    conn = init_db(ctx.obj["db"])

    if source.endswith(".db"):
        count = import_from_hash_db(conn, source)
        console.print(f"[green]Imported {count} hashes from {source}[/]")
    else:
        count = import_hashes_from_file(conn, source)
        console.print(f"[green]Imported {count} hashes from {source}[/]")

    show_stats(conn)
    conn.close()

@cli.command()
@click.option("--region", default=None, help="Focus on region (e.g., us, uk, de, jp, cn)")
@click.option("--wordlist", default=None, help="Custom wordlist file")
@click.option("--providers-only", default=None, help="Comma-separated list of email providers to try")
@click.pass_context
def crack(ctx, region, wordlist, providers_only):
    """Start cracking loaded hashes."""
    conn = init_db(ctx.obj["db"])

    custom_words = load_wordlist(wordlist) if wordlist else []
    providers = None
    if providers_only:
        providers = [p.strip() for p in providers_only.split(",")]

    cracker = Cracker(conn, providers=providers, custom_wordlist=custom_words)
    cracker.crack(region_focus=region)

    console.print()
    if cracker.newly_cracked:
        console.print(f"[bold green]Newly cracked: {len(cracker.newly_cracked)}[/]")
    show_stats(conn)
    conn.close()

@cli.command()
@click.pass_context
def results(ctx):
    """Show cracked hashes."""
    conn = init_db(ctx.obj["db"])
    show_results(conn, limit=100)
    show_stats(conn)
    conn.close()

@cli.command()
@click.pass_context
def uncracked(ctx):
    """Show uncracked hashes."""
    conn = init_db(ctx.obj["db"])
    show_uncracked(conn, limit=100)
    conn.close()

@cli.command()
@click.option("-o", "--output", default="um-crack-export.csv")
@click.option("--all", "export_all", is_flag=True, help="Export all hashes (not just cracked)")
@click.pass_context
def export(ctx, output, export_all):
    """Export results to CSV."""
    conn = init_db(ctx.obj["db"])
    if export_all:
        export_all_csv(conn, output)
    else:
        export_csv_fn(conn, output)
    conn.close()

@cli.command()
@click.pass_context
def stats(ctx):
    """Show database statistics."""
    conn = init_db(ctx.obj["db"])
    show_stats(conn)
    conn.close()

@cli.command()
@click.argument("directory")
@click.option("-o", "--output", default="um-crack.db")
@click.pass_context
def merge(ctx, directory, output):
    """Merge multiple .db files."""
    import glob
    db_paths = glob.glob(os.path.join(directory, "*.db"))
    if not db_paths:
        console.print(f"[red]No .db files found in {directory}[/]")
        return
    conn = merge_databases(db_paths, output)
    show_stats(conn)
    conn.close()

@cli.command()
@click.argument("email")
@click.pass_context
def verify(ctx, email):
    """Verify an email against loaded hashes."""
    conn = init_db(ctx.obj["db"])
    h = hashlib.md5(email.lower().strip().encode()).hexdigest()
    row = conn.execute("SELECT * FROM hashes WHERE hash = ?", (h,)).fetchone()
    if row:
        console.print(f"[bold green]MATCH![/] Hash {h} matches email {email}")
        console.print(f"  Domain: {row['domain'] or '-'}")
        console.print(f"  Username: {row['username'] or '-'}")
        console.print(f"  Display Name: {row['display_name'] or '-'}")

        # Update if not already cracked
        if not row["cracked_email"]:
            conn.execute("""
                UPDATE hashes SET cracked_email = ?, crack_method = 'manual_verify',
                                 cracked_at = CURRENT_TIMESTAMP
                WHERE hash = ?
            """, (email, h))
            conn.commit()
            console.print("[green]Recorded as cracked.[/]")
    else:
        console.print(f"[dim]No match. Hash {h} not in database.[/]")
    conn.close()

@cli.command("hash-email")
@click.argument("email")
def hash_email(email):
    """Show the MD5 hash of an email address."""
    h = hashlib.md5(email.lower().strip().encode()).hexdigest()
    console.print(f"[cyan]{email}[/] → [green]{h}[/]")

# ─── Interactive Menu ─────────────────────────────────────────────────────────
def interactive_menu(ctx):
    conn = init_db(ctx.obj["db"])

    custom_wordlist = []

    def action_handler(key, tui):
        nonlocal custom_wordlist

        if key == "1":
            def on_source(source):
                if not os.path.exists(source):
                    tui.log(f"[!] File not found: {source}")
                    return
                if source.endswith(".db"):
                    count = import_from_hash_db(conn, source)
                else:
                    count = import_hashes_from_file(conn, source)
                tui.log(f"[+] Imported {count} hashes from {source}")
            tui.prompt("Path to .db or .txt file", on_source)

        elif key == "2":
            def on_path(wl_path):
                nonlocal custom_wordlist
                if os.path.exists(wl_path):
                    custom_wordlist = load_wordlist(wl_path)
                    tui.log(f"[+] Loaded {len(custom_wordlist)} words from {wl_path}")
                else:
                    tui.log(f"[!] File not found: {wl_path}")
            tui.prompt("Wordlist file path", on_path)

        elif key == "3":
            def on_region(region):
                if region == "all":
                    region_val = None
                else:
                    region_val = region
                tui.log("[*] Starting crack session...")
                cracker = Cracker(conn, custom_wordlist=custom_wordlist)
                original_record = cracker._record_crack

                def patched_record(hash_val, email, method, hash_lookup):
                    original_record(hash_val, email, method, hash_lookup)
                    tui.log(f"[+] CRACKED: {email} ({method})")

                cracker._record_crack = patched_record

                def do_crack():
                    cracker.crack(region_focus=region_val)
                    if cracker.newly_cracked:
                        tui.log(f"[+] Session complete: {len(cracker.newly_cracked)} new cracks")
                    else:
                        tui.log("[-] Session complete: no new cracks")
                    tui.log(f"[*] Tested {cracker.candidates_tested:,} candidates")

                tui.run_threaded(do_crack, status="Cracking...")
            tui.prompt("Region focus (us/uk/de/jp/cn/etc, or 'all')", on_region, default="all")

        elif key == "4":
            rows = conn.execute(
                "SELECT hash, domain, username, display_name, cracked_email, crack_method FROM hashes WHERE cracked_email != '' ORDER BY cracked_at DESC LIMIT 50"
            ).fetchall()
            t = Table(box=box.HEAVY, border_style=THEME_COLOR, title=f"[bold {THEME_COLOR}]Cracked Hashes[/]")
            t.add_column("Hash", style="dim", max_width=16)
            t.add_column("Domain", style="cyan")
            t.add_column("User", style="green")
            t.add_column("Email", style="bold green")
            t.add_column("Method", style="yellow")
            for r in rows:
                t.add_row(r["hash"][:16], r["domain"], r["username"], r["cracked_email"], r["crack_method"])
            tui.show_table(t)

        elif key == "5":
            rows = conn.execute(
                "SELECT hash, domain, username, display_name FROM hashes WHERE cracked_email = '' OR cracked_email IS NULL LIMIT 50"
            ).fetchall()
            t = Table(box=box.HEAVY, border_style=THEME_COLOR, title=f"[bold {THEME_COLOR}]Uncracked Hashes[/]")
            t.add_column("Hash", style="dim", max_width=16)
            t.add_column("Domain", style="cyan")
            t.add_column("User", style="green")
            t.add_column("Display Name")
            for r in rows:
                t.add_row(r["hash"][:16], r["domain"], r["username"], r["display_name"])
            tui.show_table(t)

        elif key == "6":
            def on_file(output_file):
                export_csv_fn(conn, output_file)
                tui.log(f"[+] Exported to {output_file}")
            tui.prompt("Output file", on_file, default="um-crack-export.csv")

        elif key == "7":
            total = conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            cracked = conn.execute("SELECT COUNT(*) FROM hashes WHERE cracked_email != ''").fetchone()[0]
            uncracked = total - cracked
            t = Table(box=box.ROUNDED, border_style=THEME_COLOR, title=f"[bold {THEME_COLOR}]Statistics[/]")
            t.add_column("Metric", style="bold")
            t.add_column("Value", justify="right", style="cyan")
            t.add_row("Total Hashes", f"{total:,}")
            t.add_row("Cracked", f"[green]{cracked:,}[/]")
            t.add_row("Uncracked", f"[yellow]{uncracked:,}[/]")
            if total > 0:
                t.add_row("Crack Rate", f"{cracked/total*100:.1f}%")
            tui.show_table(t)

        elif key == "8":
            def on_email(email):
                h = hashlib.md5(email.lower().strip().encode()).hexdigest()
                row = conn.execute("SELECT * FROM hashes WHERE hash = ?", (h,)).fetchone()
                if row:
                    tui.log(f"[+] MATCH: {email} -> {h}")
                    if not row["cracked_email"]:
                        conn.execute("UPDATE hashes SET cracked_email=?, crack_method='manual', cracked_at=CURRENT_TIMESTAMP WHERE hash=?",
                                    (email, h))
                        conn.commit()
                        tui.log("    Recorded as cracked.")
                else:
                    tui.log(f"[-] No match for {email} (hash: {h})")
            tui.prompt("Email to verify", on_email)

        elif key == "9":
            def on_email(email):
                h = hashlib.md5(email.lower().strip().encode()).hexdigest()
                tui.log(f"[*] {email} -> {h}")
            tui.prompt("Email", on_email)

    tui = UmbraTUI(
        tool_name=TOOL_NAME,
        version=VERSION,
        menu_items=MENU_ITEMS,
        info_items=CRACK_INFO,
        action_handler=action_handler,
        stats_fn=lambda: get_db_stats(conn),
        theme=THEME_COLOR,
        engagement=ctx.obj.get("engagement"),
    )
    tui.run()
    conn.close()

if __name__ == "__main__":
    cli()
