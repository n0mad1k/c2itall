"""um_ops.py — Engagement management, scope enforcement, operational logging,
and cross-tool import utilities for the Umbra reconnaissance suite.
"""

import atexit
import csv
import fcntl
import ipaddress
import json
import os
import re
import sqlite3
import sys
import time
from datetime import datetime
from fnmatch import fnmatch

# ─── Paths ───────────────────────────────────────────────────────────────────
UMBRA_HOME = os.path.expanduser("~/.umbra")
ENGAGEMENTS_DIR = os.path.join(UMBRA_HOME, "engagements")

# Sub-directories created per engagement
ENGAGEMENT_SUBDIRS = [
    "targets", "scans", "api", "intel", "enum", "fuzz",
    "hashes", "wordpress", "cracking", "exif", "exports",
]

# Tool name → engagement subdirectory mapping
TOOL_DIR_MAP = {
    "um-scan":  "scans",
    "um-api":   "api",
    "um-intel": "intel",
    "um-enum":  "enum",
    "um-fuzz":  "fuzz",
    "um-hash":  "hashes",
    "um-wp":    "wordpress",
    "um-crack": "cracking",
    "um-exif":  "exif",
    "um-vault": ".",
}

# ─── Ops Hook Bridge ────────────────────────────────────────────────────────

_ops_hook_cls = None

def get_ops_hook(tool_name, engagement=None):
    """Return an OpsHook instance (auto-imports from c2itall). Returns None if unavailable.

    Registers an atexit handler to call hook.complete() on clean exit.
    """
    global _ops_hook_cls
    engagement = engagement or os.environ.get("UMBRA_ENGAGEMENT", "")
    if not engagement:
        return None
    if _ops_hook_cls is None:
        try:
            c2_path = os.path.expanduser("~/tools/c2itall")
            if c2_path not in sys.path:
                sys.path.insert(0, c2_path)
            from utils.ops_hook import OpsHook
            _ops_hook_cls = OpsHook
        except ImportError:
            _ops_hook_cls = False  # sentinel: tried and failed
    if _ops_hook_cls is False:
        return None
    hook = _ops_hook_cls(tool_name, engagement)
    atexit.register(lambda h=hook: _safe_complete(h))
    return hook


def _safe_complete(hook):
    """atexit callback — mark tool completed if it's still running."""
    try:
        if hook and hook.active:
            hook.complete()
    except Exception:
        pass


# ─── Engagement Management ───────────────────────────────────────────────────

def create_engagement(name):
    """Create engagement directory structure. Idempotent — safe to call multiple times.

    Returns the engagement root path.
    """
    name = name.strip().replace(" ", "_")
    eng_dir = os.path.join(ENGAGEMENTS_DIR, name)
    os.makedirs(eng_dir, exist_ok=True)

    # Core files
    scope_file = os.path.join(eng_dir, "scope.txt")
    if not os.path.exists(scope_file):
        with open(scope_file, "w") as f:
            f.write("# Scope file — one target per line\n")
            f.write("# Supported: CIDR (10.0.0.0/24), IP ranges (10.0.0.1-10), single IPs, FQDNs, *.wildcard\n")

    log_file = os.path.join(eng_dir, "umbra.log")
    if not os.path.exists(log_file):
        with open(log_file, "w") as f:
            f.write(f"# Umbra engagement log — {name}\n")
            f.write(f"# Created: {datetime.now().isoformat()}\n\n")

    csv_file = os.path.join(eng_dir, "command_log.csv")
    if not os.path.exists(csv_file):
        with open(csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "tool", "action", "target", "result"])

    # Sub-directories
    for subdir in ENGAGEMENT_SUBDIRS:
        os.makedirs(os.path.join(eng_dir, subdir), exist_ok=True)

    return eng_dir


def list_engagements():
    """Return a sorted list of engagement names."""
    if not os.path.isdir(ENGAGEMENTS_DIR):
        return []
    return sorted(
        d for d in os.listdir(ENGAGEMENTS_DIR)
        if os.path.isdir(os.path.join(ENGAGEMENTS_DIR, d))
    )


def get_engagement_dir(name):
    """Return the engagement root directory (creates if needed)."""
    return create_engagement(name)


def get_tool_output_dir(engagement, tool_name):
    """Return the tool-specific subdirectory inside an engagement."""
    eng_dir = get_engagement_dir(engagement)
    subdir = TOOL_DIR_MAP.get(tool_name, "exports")
    path = os.path.join(eng_dir, subdir)
    os.makedirs(path, exist_ok=True)
    return path


def get_engagement_db_path(engagement, tool_name):
    """Return the path for a tool's database inside an engagement."""
    tool_dir = get_tool_output_dir(engagement, tool_name)
    return os.path.join(tool_dir, f"{tool_name}.db")


# ─── Scope Enforcement ──────────────────────────────────────────────────────

def load_scope(file_path):
    """Parse a scope file and return a list of scope entries.

    Supported formats:
    - CIDR: 10.0.0.0/24
    - IP range: 10.0.0.1-10 (expands last octet)
    - Single IP: 10.0.0.1
    - FQDN: example.com
    - Wildcard: *.example.com
    - Comment lines start with #
    """
    scope = []
    file_path = os.path.expanduser(file_path)
    if not os.path.exists(file_path):
        return scope

    with open(file_path) as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            scope.append(line)
    return scope


def _is_ip(s):
    """Check if string looks like an IP address."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _match_cidr(target_ip, cidr):
    """Check if an IP is within a CIDR range."""
    try:
        return ipaddress.ip_address(target_ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _match_ip_range(target_ip, range_str):
    """Match an IP range like 10.0.0.1-10."""
    m = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", range_str)
    if not m:
        return False
    prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
    try:
        last_octet = int(target_ip.split(".")[-1])
        ip_prefix = ".".join(target_ip.split(".")[:-1]) + "."
        return ip_prefix == prefix and start <= last_octet <= end
    except (ValueError, IndexError):
        return False


def check_scope(target, scope):
    """Check if a target is within scope.

    Returns True if allowed (in scope or scope is empty).
    Returns False if blocked (out of scope).
    """
    if not scope:
        return True  # Empty scope = allow all

    # Normalize target
    target = target.strip().lower()
    # Strip protocol/path if URL
    if "://" in target:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        target = parsed.hostname or target

    target_is_ip = _is_ip(target)

    for entry in scope:
        entry_lower = entry.lower().strip()

        # CIDR match
        if "/" in entry and target_is_ip:
            if _match_cidr(target, entry):
                return True
            continue

        # IP range match
        if re.match(r"^\d+\.\d+\.\d+\.\d+-\d+$", entry):
            if target_is_ip and _match_ip_range(target, entry):
                return True
            continue

        # Exact IP match
        if _is_ip(entry) and target_is_ip:
            if target == entry:
                return True
            continue

        # Wildcard FQDN match
        if entry_lower.startswith("*."):
            # *.example.com matches foo.example.com and example.com
            domain_part = entry_lower[2:]
            if target == domain_part or target.endswith("." + domain_part):
                return True
            continue

        # Exact FQDN match
        if target == entry_lower:
            return True

    return False


def get_scope_for_engagement(name):
    """Load scope from an engagement's scope.txt file."""
    eng_dir = os.path.join(ENGAGEMENTS_DIR, name.strip().replace(" ", "_"))
    scope_file = os.path.join(eng_dir, "scope.txt")
    return load_scope(scope_file)


# ─── Operational Logging ────────────────────────────────────────────────────

def op_log(engagement, message, level="info"):
    """Append a timestamped log entry to the engagement's umbra.log.

    Levels: info=[*], success=[+], warning=[!], error=[-]
    """
    prefixes = {
        "info": "[*]",
        "success": "[+]",
        "warning": "[!]",
        "error": "[-]",
    }
    prefix = prefixes.get(level, "[*]")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    eng_dir = os.path.join(ENGAGEMENTS_DIR, engagement.strip().replace(" ", "_"))
    log_path = os.path.join(eng_dir, "umbra.log")
    try:
        os.makedirs(eng_dir, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(f"{ts} {prefix} {message}\n")
    except OSError:
        pass


def op_log_csv(engagement, tool, action, target, result):
    """Append a structured CSV audit row to command_log.csv."""
    eng_dir = os.path.join(ENGAGEMENTS_DIR, engagement.strip().replace(" ", "_"))
    csv_path = os.path.join(eng_dir, "command_log.csv")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        os.makedirs(eng_dir, exist_ok=True)
        with open(csv_path, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([ts, tool, action, target, result])
    except OSError:
        pass


def generate_engagement_summary(name):
    """Generate a text summary of all tool activity within an engagement."""
    eng_dir = os.path.join(ENGAGEMENTS_DIR, name.strip().replace(" ", "_"))
    if not os.path.isdir(eng_dir):
        return f"Engagement '{name}' not found."

    lines = [
        f"Engagement Summary: {name}",
        f"{'=' * 50}",
        f"Path: {eng_dir}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]

    # Check each tool subdirectory for .db files
    for tool_name, subdir in TOOL_DIR_MAP.items():
        tool_dir = os.path.join(eng_dir, subdir)
        db_path = os.path.join(tool_dir, f"{tool_name}.db")
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                tables = [r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()]
                counts = {}
                for tbl in tables:
                    try:
                        c = conn.execute(f'SELECT COUNT(*) FROM "{tbl}"').fetchone()[0]
                        if c > 0:
                            counts[tbl] = c
                    except Exception:
                        pass
                conn.close()
                if counts:
                    lines.append(f"  {tool_name}:")
                    for tbl, cnt in counts.items():
                        lines.append(f"    {tbl}: {cnt:,} records")
            except Exception:
                lines.append(f"  {tool_name}: DB error")
        else:
            # Check if directory has any files at all
            if os.path.isdir(tool_dir) and os.listdir(tool_dir):
                lines.append(f"  {tool_name}: files present (no DB)")

    # Scope info
    scope = get_scope_for_engagement(name)
    if scope:
        lines.append(f"\nScope: {len(scope)} entries")
        for entry in scope[:10]:
            lines.append(f"  {entry}")
        if len(scope) > 10:
            lines.append(f"  ... and {len(scope) - 10} more")

    # Log stats
    log_path = os.path.join(eng_dir, "umbra.log")
    if os.path.exists(log_path):
        with open(log_path) as f:
            log_lines = f.readlines()
        # Count non-comment, non-empty lines
        entries = [l for l in log_lines if l.strip() and not l.startswith("#")]
        lines.append(f"\nLog entries: {len(entries)}")

    # CSV command log
    csv_path = os.path.join(eng_dir, "command_log.csv")
    if os.path.exists(csv_path):
        with open(csv_path) as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header
            commands = list(reader)
        lines.append(f"Commands logged: {len(commands)}")

    return "\n".join(lines)


# ─── State & Event Stream (for ops dashboard) ──────────────────────────────

def write_tool_state(engagement, tool_name, status, **extra):
    """Write tool status to state.json for dashboard consumption.

    Called automatically by op_log when level is 'success' (tool start/finish).
    Can also be called directly for fine-grained control.
    """
    eng_dir = os.path.join(ENGAGEMENTS_DIR, engagement.strip().replace(" ", "_"))
    state_path = os.path.join(eng_dir, "state.json")
    try:
        os.makedirs(eng_dir, exist_ok=True)
        fd = os.open(state_path, os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            raw = b""
            while True:
                chunk = os.read(fd, 8192)
                if not chunk:
                    break
                raw += chunk
            state = json.loads(raw) if raw.strip() else {"tools": {}}
            state.setdefault("tools", {})
            tool_entry = state["tools"].get(tool_name, {})
            tool_entry["status"] = status
            tool_entry.update(extra)
            state["tools"][tool_name] = tool_entry
            state["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            out = json.dumps(state, indent=2).encode()
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, out)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    except OSError:
        pass


def emit_event(engagement, tool_name, event_type, message):
    """Append event to events.jsonl for dashboard live feed."""
    eng_dir = os.path.join(ENGAGEMENTS_DIR, engagement.strip().replace(" ", "_"))
    events_path = os.path.join(eng_dir, "events.jsonl")
    try:
        os.makedirs(eng_dir, exist_ok=True)
        entry = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "tool": tool_name,
            "type": event_type,
            "msg": message,
        })
        with open(events_path, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(entry + "\n")
            fcntl.flock(f, fcntl.LOCK_UN)
    except OSError:
        pass


# ─── Cross-Tool Imports ─────────────────────────────────────────────────────

# Maps tool name to (table_name, target_column) for extracting targets
TOOL_TARGET_QUERIES = {
    "um-scan":  ("SELECT DISTINCT host FROM hosts", "host"),
    "um-api":   ("SELECT DISTINCT target FROM targets", "target"),
    "um-intel": ("SELECT DISTINCT target FROM targets", "target"),
    "um-enum":  ("SELECT DISTINCT domain FROM targets", "domain"),
    "um-fuzz":  ("SELECT DISTINCT base_url FROM results", "base_url"),
    "um-hash":  ("SELECT DISTINCT domain FROM sites", "domain"),
    "um-wp":    ("SELECT DISTINCT domain FROM sites WHERE is_wordpress=1", "domain"),
    "um-crack": ("SELECT DISTINCT domain FROM hashes WHERE cracked_email != ''", "domain"),
    "um-exif":  ("SELECT DISTINCT file_path FROM images WHERE has_exif=1", "file_path"),
}


def get_targets_from_tool_db(db_path, tool_name):
    """Query another tool's database to extract target list.

    Returns a list of target strings.
    """
    if not os.path.exists(db_path):
        return []

    query_info = TOOL_TARGET_QUERIES.get(tool_name)
    if not query_info:
        return []

    query = query_info[0]
    try:
        conn = sqlite3.connect(db_path)
        rows = conn.execute(query).fetchall()
        conn.close()
        return [str(r[0]) for r in rows if r[0]]
    except Exception:
        return []


def find_tool_db(tool_name, engagement=None):
    """Locate a tool's database file.

    Search order:
    1. Engagement directory (if provided)
    2. Current working directory
    """
    # Check engagement directory first
    if engagement:
        db_path = get_engagement_db_path(engagement, tool_name)
        if os.path.exists(db_path):
            return db_path

    # Fall back to current working directory
    cwd_path = os.path.join(os.getcwd(), f"{tool_name}.db")
    if os.path.exists(cwd_path):
        return cwd_path

    return None
