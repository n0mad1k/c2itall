#!/usr/bin/env python3
"""um-vault.py — Umbra Master Database Aggregator
10-table relational schema (countries→orgs→domains→hashes→cracked).
Imports from um-hash + um-crack databases, statistics dashboard.
"""

import csv
import glob
import json
import os
import sqlite3
import sys
import time
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich import box

# ─── Version ──────────────────────────────────────────────────────────────────
VERSION = "1.0.0"
TOOL_NAME = "um-vault"
THEME_COLOR = "bright_white"
BANNER = r"""
  _    _ __  __ ____  _____            __      __     _    _ _   _______
 | |  | |  \/  |  _ \|  __ \    /\     \ \    / /\   | |  | | | |__   __|
 | |  | | \  / | |_) | |__) |  /  \     \ \  / /  \  | |  | | |    | |
 | |  | | |\/| |  _ <|  _  /  / /\ \     \ \/ / /\ \ | |  | | |    | |
 | |__| | |  | | |_) | | \ \ / ____ \     \  / ____ \| |__| | |____| |
  \____/|_|  |_|____/|_|  \_\_/    \_\     \/_/    \_\\____/|______|_|
"""

# ─── Database Schema (10 tables) ─────────────────────────────────────────────
def init_db(path="um-vault.db"):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")

    # 1. Countries
    conn.execute("""
        CREATE TABLE IF NOT EXISTS countries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            name TEXT DEFAULT '',
            region TEXT DEFAULT '',
            total_orgs INTEGER DEFAULT 0,
            total_domains INTEGER DEFAULT 0
        )
    """)

    # 2. Organizations
    conn.execute("""
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            country_code TEXT DEFAULT '',
            industry TEXT DEFAULT '',
            total_domains INTEGER DEFAULT 0,
            total_hashes INTEGER DEFAULT 0,
            total_cracked INTEGER DEFAULT 0,
            FOREIGN KEY (country_code) REFERENCES countries(code)
        )
    """)

    # 3. Domains
    conn.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            org_id INTEGER DEFAULT 0,
            is_wordpress INTEGER DEFAULT 0,
            wp_version TEXT DEFAULT '',
            detection_methods TEXT DEFAULT '',
            total_hashes INTEGER DEFAULT 0,
            total_cracked INTEGER DEFAULT 0,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME,
            FOREIGN KEY (org_id) REFERENCES organizations(id)
        )
    """)

    # 4. Hashes
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT UNIQUE NOT NULL,
            domain_id INTEGER DEFAULT 0,
            domain TEXT DEFAULT '',
            username TEXT DEFAULT '',
            display_name TEXT DEFAULT '',
            user_id INTEGER DEFAULT 0,
            avatar_url TEXT DEFAULT '',
            cracked_email TEXT DEFAULT '',
            crack_method TEXT DEFAULT '',
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            cracked_at DATETIME,
            FOREIGN KEY (domain_id) REFERENCES domains(id)
        )
    """)

    # 5. Ports (from um-scan)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT DEFAULT 'open',
            service TEXT DEFAULT '',
            banner TEXT DEFAULT '',
            response_ms INTEGER DEFAULT 0,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(host, port)
        )
    """)

    # 6. Intel findings (from um-intel)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            source TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            value TEXT NOT NULL,
            extra TEXT DEFAULT '{}',
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(target, source, finding_type, value)
        )
    """)

    # 7. API endpoints (from um-api)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            url TEXT NOT NULL,
            path TEXT DEFAULT '',
            discovery_method TEXT NOT NULL,
            status_code INTEGER DEFAULT 0,
            description TEXT DEFAULT '',
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(target, url, discovery_method)
        )
    """)

    # 8. Fuzz results (from um-fuzz)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fuzz_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            base_url TEXT NOT NULL,
            path TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            content_length INTEGER DEFAULT 0,
            content_type TEXT DEFAULT '',
            redirect_url TEXT DEFAULT '',
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(base_url, path)
        )
    """)

    # 9. EXIF data (from um-exif)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS exif_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE NOT NULL,
            file_name TEXT DEFAULT '',
            camera_make TEXT DEFAULT '',
            camera_model TEXT DEFAULT '',
            datetime_original TEXT DEFAULT '',
            gps_coords TEXT DEFAULT '',
            artist TEXT DEFAULT '',
            copyright TEXT DEFAULT ''
        )
    """)

    # 10. Enum findings (from um-enum)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS enum_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            phase TEXT NOT NULL,
            command TEXT NOT NULL,
            value TEXT NOT NULL,
            url TEXT DEFAULT '',
            status_code INTEGER DEFAULT 0,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(domain, command, value)
        )
    """)

    # Indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hashes_hash ON hashes(hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hashes_domain ON hashes(domain)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_intel_target ON intel(target)")

    conn.commit()
    return conn

# ─── Import Functions ─────────────────────────────────────────────────────────
def import_wp_db(vault_conn, wp_db_path):
    """Import from um-wp.db."""
    if not os.path.exists(wp_db_path):
        return 0
    src = sqlite3.connect(wp_db_path)
    src.row_factory = sqlite3.Row
    count = 0
    for r in src.execute("SELECT * FROM sites").fetchall():
        vault_conn.execute("""
            INSERT INTO domains (domain, is_wordpress, wp_version, detection_methods, last_seen)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(domain) DO UPDATE SET
                is_wordpress = MAX(is_wordpress, excluded.is_wordpress),
                wp_version = CASE WHEN excluded.wp_version != '' THEN excluded.wp_version ELSE wp_version END,
                detection_methods = CASE WHEN excluded.detection_methods != '' THEN excluded.detection_methods ELSE detection_methods END,
                last_seen = CURRENT_TIMESTAMP
        """, (r["domain"], r["is_wordpress"], r["wp_version"], r["detection_methods"]))
        count += 1
    vault_conn.commit()
    src.close()
    return count

def import_hash_db(vault_conn, hash_db_path):
    """Import from um-hash.db."""
    if not os.path.exists(hash_db_path):
        return 0
    src = sqlite3.connect(hash_db_path)
    src.row_factory = sqlite3.Row
    count = 0
    for r in src.execute("SELECT * FROM hashes").fetchall():
        # Ensure domain exists
        vault_conn.execute("""
            INSERT OR IGNORE INTO domains (domain) VALUES (?)
        """, (r["domain"],))

        domain_row = vault_conn.execute(
            "SELECT id FROM domains WHERE domain=?", (r["domain"],)
        ).fetchone()
        domain_id = domain_row["id"] if domain_row else 0

        vault_conn.execute("""
            INSERT INTO hashes (hash, domain_id, domain, username, display_name,
                               user_id, avatar_url)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hash) DO UPDATE SET
                domain = CASE WHEN excluded.domain != '' THEN excluded.domain ELSE domain END,
                username = CASE WHEN excluded.username != '' THEN excluded.username ELSE username END,
                display_name = CASE WHEN excluded.display_name != '' THEN excluded.display_name ELSE display_name END
        """, (r["hash"], domain_id, r["domain"], r["username"],
              r["display_name"], r["user_id"], r["avatar_url"]))
        count += 1
    vault_conn.commit()
    src.close()
    return count

def import_crack_db(vault_conn, crack_db_path):
    """Import from um-crack.db."""
    if not os.path.exists(crack_db_path):
        return 0
    src = sqlite3.connect(crack_db_path)
    src.row_factory = sqlite3.Row
    count = 0
    for r in src.execute("SELECT * FROM hashes WHERE cracked_email != ''").fetchall():
        vault_conn.execute("""
            UPDATE hashes SET
                cracked_email = ?,
                crack_method = ?,
                cracked_at = ?
            WHERE hash = ? AND (cracked_email = '' OR cracked_email IS NULL)
        """, (r["cracked_email"], r["crack_method"], r["cracked_at"], r["hash"]))
        if vault_conn.execute("SELECT changes()").fetchone()[0] == 0:
            # Hash not in vault yet, insert it
            vault_conn.execute("""
                INSERT OR IGNORE INTO hashes (hash, domain, username, display_name,
                    cracked_email, crack_method, cracked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (r["hash"], r["domain"], r["username"], r["display_name"],
                  r["cracked_email"], r["crack_method"], r["cracked_at"]))
        count += 1
    vault_conn.commit()
    src.close()
    return count

def import_scan_db(vault_conn, scan_db_path):
    """Import from um-scan.db."""
    if not os.path.exists(scan_db_path):
        return 0
    src = sqlite3.connect(scan_db_path)
    src.row_factory = sqlite3.Row
    count = 0
    for r in src.execute("SELECT * FROM ports WHERE state='open'").fetchall():
        vault_conn.execute("""
            INSERT INTO ports (host, port, state, service, banner, response_ms)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(host, port) DO UPDATE SET
                service = CASE WHEN excluded.service != '' THEN excluded.service ELSE service END,
                banner = CASE WHEN excluded.banner != '' THEN excluded.banner ELSE banner END
        """, (r["host"], r["port"], r["state"], r["service"],
              r["banner"], r["response_ms"]))
        count += 1
    vault_conn.commit()
    src.close()
    return count

def import_intel_db(vault_conn, intel_db_path):
    """Import from um-intel.db."""
    if not os.path.exists(intel_db_path):
        return 0
    src = sqlite3.connect(intel_db_path)
    src.row_factory = sqlite3.Row
    count = 0
    for r in src.execute("SELECT * FROM findings").fetchall():
        vault_conn.execute("""
            INSERT OR IGNORE INTO intel (target, source, finding_type, value, extra)
            VALUES (?, ?, ?, ?, ?)
        """, (r["target"], r["source"], r["finding_type"], r["value"], r["extra"]))
        count += 1
    vault_conn.commit()
    src.close()
    return count

def import_api_db(vault_conn, api_db_path):
    """Import from um-api.db."""
    if not os.path.exists(api_db_path):
        return 0
    src = sqlite3.connect(api_db_path)
    src.row_factory = sqlite3.Row
    count = 0
    for r in src.execute("SELECT * FROM endpoints").fetchall():
        vault_conn.execute("""
            INSERT OR IGNORE INTO api_endpoints (target, url, path, discovery_method,
                                                 status_code, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (r["target"], r["url"], r["path"], r["discovery_method"],
              r["status_code"], r["description"]))
        count += 1
    vault_conn.commit()
    src.close()
    return count

def import_fuzz_db(vault_conn, fuzz_db_path):
    """Import from um-fuzz.db."""
    if not os.path.exists(fuzz_db_path):
        return 0
    src = sqlite3.connect(fuzz_db_path)
    src.row_factory = sqlite3.Row
    count = 0
    for r in src.execute("SELECT * FROM results").fetchall():
        vault_conn.execute("""
            INSERT OR IGNORE INTO fuzz_results (base_url, path, status_code,
                content_length, content_type, redirect_url)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (r["base_url"], r["path"], r["status_code"],
              r["content_length"], r["content_type"], r["redirect_url"]))
        count += 1
    vault_conn.commit()
    src.close()
    return count

def import_exif_db(vault_conn, exif_db_path):
    """Import from um-exif.db."""
    if not os.path.exists(exif_db_path):
        return 0
    src = sqlite3.connect(exif_db_path)
    src.row_factory = sqlite3.Row
    count = 0
    for r in src.execute("SELECT * FROM images WHERE has_exif=1").fetchall():
        vault_conn.execute("""
            INSERT OR IGNORE INTO exif_data (file_path, file_name, camera_make,
                camera_model, datetime_original, gps_coords, artist, copyright)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (r["file_path"], r["file_name"], r["camera_make"], r["camera_model"],
              r["datetime_original"], r["gps_coords"], r["artist"], r["copyright"]))
        count += 1
    vault_conn.commit()
    src.close()
    return count

def import_enum_db(vault_conn, enum_db_path):
    """Import from um-enum.db."""
    if not os.path.exists(enum_db_path):
        return 0
    src = sqlite3.connect(enum_db_path)
    src.row_factory = sqlite3.Row
    count = 0
    for r in src.execute("SELECT * FROM findings").fetchall():
        vault_conn.execute("""
            INSERT OR IGNORE INTO enum_findings (domain, phase, command, value, url, status_code)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (r["domain"], r["phase"], r["command"], r["value"],
              r["url"], r["status_code"]))
        count += 1
    vault_conn.commit()
    src.close()
    return count

# Map tool prefixes to import functions
IMPORT_MAP = {
    "um-wp": import_wp_db,
    "um-hash": import_hash_db,
    "um-crack": import_crack_db,
    "um-scan": import_scan_db,
    "um-intel": import_intel_db,
    "um-api": import_api_db,
    "um-fuzz": import_fuzz_db,
    "um-exif": import_exif_db,
    "um-enum": import_enum_db,
}

def detect_db_type(path):
    """Detect which Umbra tool created a .db file."""
    basename = os.path.basename(path).lower()
    for prefix in IMPORT_MAP:
        if basename.startswith(prefix):
            return prefix
    # Try detecting by table names
    try:
        conn = sqlite3.connect(path)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        conn.close()
        if "sites" in tables and "hashes" not in tables:
            return "um-wp"
        if "hashes" in tables and "sites" in tables:
            return "um-hash"
        if "hashes" in tables and "sites" not in tables:
            return "um-crack"
        if "ports" in tables:
            return "um-scan"
        if "findings" in tables and "targets" in tables:
            # Could be intel or enum — check columns
            try:
                conn = sqlite3.connect(path)
                cols = [r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
                conn.close()
                if "source" in cols:
                    return "um-intel"
                if "phase" in cols:
                    return "um-enum"
            except Exception:
                pass
        if "endpoints" in tables:
            return "um-api"
        if "results" in tables:
            return "um-fuzz"
        if "images" in tables:
            return "um-exif"
    except Exception:
        pass
    return None

# ─── Dashboard TUI ───────────────────────────────────────────────────────────
console = Console()
from um_tui import UmbraTUI
from um_ops import (create_engagement, get_engagement_db_path, list_engagements,
                    generate_engagement_summary, op_log, op_log_csv, get_ops_hook)

MENU_ITEMS = [
    ("1", "Import a tool database"),
    ("2", "Import all (auto-detect)"),
    ("3", "Merge from directory"),
    ("4", "Dashboard / statistics"),
    ("5", "Run SQL query"),
    ("6", "Export table to CSV"),
    ("7", "Create engagement"),
    ("8", "Switch engagement"),
    ("9", "Engagement summary"),
    ("Q", "Quit"),
]

VAULT_INFO = [
    "10-table relational schema",
    "Auto-detect DB type",
    "Import from all Umbra tools",
    "Custom SQL queries",
    "Per-table CSV export",
]

def get_db_stats(conn):
    try:
        tables_counts = []
        for tbl in ["domains", "hashes", "ports", "intel", "api_endpoints",
                     "fuzz_results", "exif_data", "enum_findings"]:
            try:
                c = conn.execute(f'SELECT COUNT(*) FROM "{tbl}"').fetchone()[0]
                if c > 0:
                    tables_counts.append(f"{tbl}:{c:,}")
            except Exception:
                pass
        return " | ".join(tables_counts) if tables_counts else "Vault: empty"
    except Exception:
        return "Vault: empty"

def show_dashboard(conn):
    """Show comprehensive statistics dashboard."""
    stats = {}

    tables = {
        "domains": "Domains",
        "hashes": "Hashes",
        "ports": "Open Ports",
        "intel": "Intel Findings",
        "api_endpoints": "API Endpoints",
        "fuzz_results": "Fuzz Results",
        "exif_data": "EXIF Images",
        "enum_findings": "Enum Findings",
        "countries": "Countries",
        "organizations": "Organizations",
    }

    for table, label in tables.items():
        try:
            count = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            stats[label] = count
        except Exception:
            stats[label] = 0

    # Main stats table
    main_table = Table(box=box.HEAVY, border_style=THEME_COLOR,
                       title=f"[bold {THEME_COLOR}]Umbra Vault — Master Database[/]")
    main_table.add_column("Table", style="bold", width=20)
    main_table.add_column("Records", justify="right", style="cyan", width=12)

    for label, count in stats.items():
        style = "[green]" if count > 0 else "[dim]"
        main_table.add_row(label, f"{style}{count:,}[/]")

    console.print(main_table)

    # Domain breakdown
    try:
        wp_count = conn.execute("SELECT COUNT(*) FROM domains WHERE is_wordpress=1").fetchone()[0]
        total_domains = stats.get("Domains", 0)
        if total_domains:
            console.print(f"\n[green]WordPress: {wp_count}/{total_domains} ({wp_count/total_domains*100:.1f}%)[/]")
    except Exception:
        pass

    # Hash breakdown
    try:
        total_hashes = stats.get("Hashes", 0)
        cracked = conn.execute("SELECT COUNT(*) FROM hashes WHERE cracked_email != ''").fetchone()[0]
        if total_hashes:
            console.print(f"[green]Cracked: {cracked}/{total_hashes} ({cracked/total_hashes*100:.1f}%)[/]")
    except Exception:
        pass

    # Top services
    try:
        top_services = conn.execute("""
            SELECT service, COUNT(*) as cnt FROM ports
            GROUP BY service ORDER BY cnt DESC LIMIT 5
        """).fetchall()
        if top_services:
            svc_table = Table(box=box.ROUNDED, border_style=THEME_COLOR,
                             title=f"[{THEME_COLOR}]Top Services[/]")
            svc_table.add_column("Service", style="cyan")
            svc_table.add_column("Count", justify="right")
            for s in top_services:
                svc_table.add_row(s["service"], str(s["cnt"]))
            console.print(svc_table)
    except Exception:
        pass

    # Top intel sources
    try:
        top_sources = conn.execute("""
            SELECT source, COUNT(*) as cnt FROM intel
            GROUP BY source ORDER BY cnt DESC LIMIT 5
        """).fetchall()
        if top_sources:
            src_table = Table(box=box.ROUNDED, border_style=THEME_COLOR,
                             title=f"[{THEME_COLOR}]Top Intel Sources[/]")
            src_table.add_column("Source", style="yellow")
            src_table.add_column("Count", justify="right")
            for s in top_sources:
                src_table.add_row(s["source"], str(s["cnt"]))
            console.print(src_table)
    except Exception:
        pass

def export_table_csv(conn, table_name, output):
    """Export a specific table to CSV."""
    try:
        cursor = conn.execute(f'SELECT * FROM "{table_name}"')
        rows = cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        with open(output, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(cols)
            for r in rows:
                writer.writerow(list(r))
        console.print(f"[green]Exported {len(rows)} rows from {table_name} to {output}[/]")
    except Exception as e:
        console.print(f"[red]Export error: {e}[/]")

# ─── CLI ──────────────────────────────────────────────────────────────────────
@click.group(invoke_without_command=True)
@click.option("--db", default="um-vault.db", help="Vault database path")
@click.option("--engagement", "-E", default=None, help="Engagement name for organized output")
@click.pass_context
def cli(ctx, db, engagement):
    """Umbra Vault — Master database aggregator for all Umbra tools."""
    ctx.ensure_object(dict)
    # Env var fallback
    engagement = engagement or os.environ.get("UMBRA_ENGAGEMENT", "")
    if engagement:
        create_engagement(engagement)
        db = get_engagement_db_path(engagement, TOOL_NAME)
    ctx.obj["db"] = db
    ctx.obj["engagement"] = engagement
    # Ops hook
    hook = get_ops_hook(TOOL_NAME, engagement)
    ctx.obj["hook"] = hook
    if hook:
        hook.register()
    if ctx.invoked_subcommand is None:
        interactive_menu(ctx)

@cli.command("import")
@click.argument("source")
@click.option("--type", "db_type", default=None,
              help="Database type (um-wp, um-hash, um-crack, um-scan, um-intel, um-api, um-fuzz, um-exif, um-enum)")
@click.pass_context
def import_cmd(ctx, source, db_type):
    """Import an Umbra tool database into the vault."""
    conn = init_db(ctx.obj["db"])

    if not db_type:
        db_type = detect_db_type(source)
    if not db_type:
        console.print(f"[red]Cannot detect database type for {source}. Use --type to specify.[/]")
        conn.close()
        return

    if db_type not in IMPORT_MAP:
        console.print(f"[red]Unknown type: {db_type}[/]")
        conn.close()
        return

    import_fn = IMPORT_MAP[db_type]
    count = import_fn(conn, source)
    console.print(f"[green]Imported {count} records from {source} ({db_type})[/]")
    show_dashboard(conn)
    conn.close()

@cli.command()
@click.argument("directory")
@click.pass_context
def merge(ctx, directory):
    """Merge all .db files from a directory into the vault."""
    conn = init_db(ctx.obj["db"])

    db_files = glob.glob(os.path.join(directory, "*.db"))
    if not db_files:
        console.print(f"[red]No .db files found in {directory}[/]")
        conn.close()
        return

    total_imported = 0
    for db_path in sorted(db_files):
        if os.path.basename(db_path) == os.path.basename(ctx.obj["db"]):
            continue  # Skip vault itself

        db_type = detect_db_type(db_path)
        if db_type and db_type in IMPORT_MAP:
            import_fn = IMPORT_MAP[db_type]
            count = import_fn(conn, db_path)
            console.print(f"[dim]  {os.path.basename(db_path)} ({db_type}): {count} records[/]")
            total_imported += count
        else:
            console.print(f"[yellow]  {os.path.basename(db_path)}: unknown type, skipped[/]")

    console.print(f"\n[green]Total imported: {total_imported} records from {len(db_files)} files[/]")
    show_dashboard(conn)
    conn.close()

@cli.command("import-all")
@click.pass_context
def import_all(ctx):
    """Auto-import all Umbra .db files from current directory."""
    conn = init_db(ctx.obj["db"])

    default_files = {
        "um-wp": "um-wp.db",
        "um-hash": "um-hash.db",
        "um-crack": "um-crack.db",
        "um-scan": "um-scan.db",
        "um-intel": "um-intel.db",
        "um-api": "um-api.db",
        "um-fuzz": "um-fuzz.db",
        "um-exif": "um-exif.db",
        "um-enum": "um-enum.db",
    }

    total = 0
    for db_type, filename in default_files.items():
        if os.path.exists(filename):
            import_fn = IMPORT_MAP[db_type]
            count = import_fn(conn, filename)
            console.print(f"[green]  {filename}: {count} records[/]")
            total += count
        else:
            console.print(f"[dim]  {filename}: not found[/]")

    console.print(f"\n[green]Total: {total} records imported[/]")
    show_dashboard(conn)
    conn.close()

@cli.command()
@click.pass_context
def dashboard(ctx):
    """Show the statistics dashboard."""
    conn = init_db(ctx.obj["db"])
    show_dashboard(conn)
    conn.close()

@cli.command()
@click.argument("table_name")
@click.option("-o", "--output", default=None)
@click.pass_context
def export(ctx, table_name, output):
    """Export a vault table to CSV."""
    conn = init_db(ctx.obj["db"])
    if not output:
        output = f"um-vault-{table_name}.csv"
    export_table_csv(conn, table_name, output)
    conn.close()

@cli.command()
@click.argument("sql_query")
@click.pass_context
def query(ctx, sql_query):
    """Run a custom SQL query on the vault."""
    conn = init_db(ctx.obj["db"])
    try:
        cursor = conn.execute(sql_query)
        rows = cursor.fetchall()
        if rows:
            cols = [d[0] for d in cursor.description]
            table = Table(box=box.ROUNDED, border_style=THEME_COLOR)
            for col in cols:
                table.add_column(col, style="cyan")
            for r in rows[:100]:
                table.add_row(*[str(v)[:50] for v in r])
            console.print(table)
            console.print(f"[dim]{len(rows)} rows[/]")
        else:
            console.print("[dim]No results.[/]")
    except Exception as e:
        console.print(f"[red]Query error: {e}[/]")
    conn.close()

# ─── Interactive Menu ─────────────────────────────────────────────────────────
def interactive_menu(ctx):
    conn = init_db(ctx.obj["db"])

    def action_handler(key, tui):
        if key == "1":
            def on_source(source):
                if os.path.exists(source):
                    db_type = detect_db_type(source)
                    if db_type:
                        tui.log(f"[*] Detected type: {db_type}")
                        import_fn = IMPORT_MAP[db_type]
                        count = import_fn(conn, source)
                        tui.log(f"[+] Imported {count} records from {source}")
                    else:
                        tui.log(f"[!] Cannot detect database type for {source}")
                else:
                    tui.log(f"[!] File not found: {source}")
            tui.prompt("Database file path", on_source)

        elif key == "2":
            default_files = {
                "um-wp": "um-wp.db", "um-hash": "um-hash.db",
                "um-crack": "um-crack.db", "um-scan": "um-scan.db",
                "um-intel": "um-intel.db", "um-api": "um-api.db",
                "um-fuzz": "um-fuzz.db", "um-exif": "um-exif.db",
                "um-enum": "um-enum.db",
            }
            total = 0
            for db_type, filename in default_files.items():
                if os.path.exists(filename):
                    count = IMPORT_MAP[db_type](conn, filename)
                    tui.log(f"[+] {filename}: {count} records")
                    total += count
                else:
                    tui.log(f"[-] {filename}: not found")
            tui.log(f"[*] Total imported: {total} records")

        elif key == "3":
            def on_dir(directory):
                db_files = glob.glob(os.path.join(directory, "*.db"))
                if not db_files:
                    tui.log(f"[!] No .db files found in {directory}")
                    return
                for db_path in db_files:
                    db_type = detect_db_type(db_path)
                    if db_type and db_type in IMPORT_MAP:
                        count = IMPORT_MAP[db_type](conn, db_path)
                        tui.log(f"[+] {os.path.basename(db_path)}: {count} records")
                    else:
                        tui.log(f"[-] {os.path.basename(db_path)}: unknown type, skipped")
            tui.prompt("Directory path", on_dir)

        elif key == "4":
            # Build dashboard as a Rich table for VIEW mode
            stats = {}
            tables_map = {
                "domains": "Domains", "hashes": "Hashes",
                "ports": "Open Ports", "intel": "Intel Findings",
                "api_endpoints": "API Endpoints", "fuzz_results": "Fuzz Results",
                "exif_data": "EXIF Images", "enum_findings": "Enum Findings",
                "countries": "Countries", "organizations": "Organizations",
            }
            for table, label in tables_map.items():
                try:
                    count = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                    stats[label] = count
                except Exception:
                    stats[label] = 0
            t = Table(box=box.HEAVY, border_style=THEME_COLOR,
                      title=f"[bold {THEME_COLOR}]Umbra Vault \u2014 Master Database[/]")
            t.add_column("Table", style="bold", width=20)
            t.add_column("Records", justify="right", style="cyan", width=12)
            for label, count in stats.items():
                style = "[green]" if count > 0 else "[dim]"
                t.add_row(label, f"{style}{count:,}[/]")
            tui.show_table(t)

        elif key == "5":
            def on_sql(sql):
                try:
                    cursor = conn.execute(sql)
                    rows = cursor.fetchall()
                    if rows:
                        cols = [d[0] for d in cursor.description]
                        t = Table(box=box.ROUNDED, border_style=THEME_COLOR)
                        for col in cols:
                            t.add_column(col)
                        for r in rows[:50]:
                            t.add_row(*[str(v)[:40] for v in r])
                        tui.log(f"[*] Query returned {len(rows)} rows")
                        tui.show_table(t)
                    else:
                        tui.log("[-] No results.")
                except Exception as e:
                    tui.log(f"[!] Query error: {e}")
            tui.prompt("SQL", on_sql)

        elif key == "6":
            def on_table(tname):
                def on_file(out):
                    export_table_csv(conn, tname, out)
                    tui.log(f"[+] Exported {tname} to {out}")
                tui.prompt("Output file", on_file, default=f"um-vault-{tname}.csv")
            tui.prompt("Table name", on_table)

        elif key == "7":
            def on_name(name):
                from um_ops import create_engagement
                eng_dir = create_engagement(name)
                tui.log(f"[+] Engagement created: {name}")
                tui.log(f"    Path: {eng_dir}")
                tui.log(f"    Edit scope: {eng_dir}/scope.txt")
            tui.prompt("Engagement name", on_name)

        elif key == "8":
            engagements = list_engagements()
            if not engagements:
                tui.log("[!] No engagements found. Create one first.")
            else:
                for i, eng in enumerate(engagements, 1):
                    tui.log(f"  {i}) {eng}")
                def on_choice(choice):
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(engagements):
                            eng_name = engagements[idx]
                            new_db = get_engagement_db_path(eng_name, TOOL_NAME)
                            nonlocal conn
                            conn.close()
                            conn = init_db(new_db)
                            tui.engagement = eng_name
                            ctx.obj["engagement"] = eng_name
                            tui.log(f"[+] Switched to engagement: {eng_name}")
                        else:
                            tui.log("[!] Invalid selection")
                    except ValueError:
                        tui.log("[!] Enter a number")
                tui.prompt("Select engagement #", on_choice)

        elif key == "9":
            eng = ctx.obj.get("engagement")
            if not eng:
                tui.log("[!] No engagement active. Use --engagement or switch first.")
            else:
                summary = generate_engagement_summary(eng)
                tui.log(summary)

    tui = UmbraTUI(
        tool_name=TOOL_NAME,
        version=VERSION,
        menu_items=MENU_ITEMS,
        info_items=VAULT_INFO,
        action_handler=action_handler,
        stats_fn=lambda: get_db_stats(conn),
        theme=THEME_COLOR,
        engagement=ctx.obj.get("engagement"),
    )
    tui.run()
    conn.close()

if __name__ == "__main__":
    cli()
