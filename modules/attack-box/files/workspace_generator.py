#!/usr/bin/env python3
"""
Workspace Structure Generator for Attack Box
Creates trashpanda-style penetration testing directory structure
"""

import os
import time
from pathlib import Path

def create_workspace_structure(base_name="/root/operator", operator="operator"):
    """Create a comprehensive penetration testing directory structure like trashpanda."""
    
    # Main engagement directory
    base_dir = os.path.abspath(base_name)
    
    # Primary directories (based on trashpanda structure)
    main_dirs = {
        "tools": "Downloaded/compiled tools and scripts",
        "scans": "All scan results organized by type",
        "logs": "Execution logs and debug output", 
        "loot": "Extracted credentials, hashes, and sensitive data",
        "payloads": "Custom payloads and exploit code",
        "targets": "Target lists and reconnaissance data",
        "screenshots": "Visual evidence and GUI captures",
        "reports": "Draft reports and documentation",
        "notes": "Manual notes and observations",
        "exploits": "Working exploits and proof-of-concepts",
        "wordlists": "Custom and downloaded wordlists",
        "pcaps": "Network captures and traffic analysis"
    }
    
    # Scan subdirectories (comprehensive enumeration structure)
    scan_subdirs = {
        "nmap": "Network discovery and port scanning",
        "dns": "DNS enumeration and zone transfers", 
        "snmp": "SNMP enumeration and community strings",
        "smb": "SMB/NetBIOS enumeration and shares",
        "web": "Web application scanning and enumeration",
        "ssl": "SSL/TLS certificate and cipher analysis",
        "vulns": "Vulnerability scanning and NSE scripts",
        "ldap": "LDAP enumeration and directory services",
        "ftp": "FTP enumeration and anonymous access",
        "ssh": "SSH enumeration and key analysis",
        "databases": "Database enumeration (MySQL, MSSQL, etc)",
        "custom": "Custom and manual scans",
        "reachability": "Network reachability test results"
    }
    
    # Loot subdirectories (for extracted data)
    loot_subdirs = {
        "credentials": "Usernames, passwords, and authentication data",
        "hashes": "Password hashes and cracking results",
        "keys": "SSH keys, certificates, and crypto material",
        "configs": "Configuration files and sensitive data",
        "databases": "Extracted database contents",
        "files": "Interesting files and documents"
    }
    
    print(f"[+] Creating penetration testing structure: {base_dir}")
    
    # Create main directories
    for dir_name, description in main_dirs.items():
        dir_path = os.path.join(base_dir, dir_name)
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        
        # Create README files for documentation
        readme_path = os.path.join(dir_path, "README.md")
        if not os.path.exists(readme_path):
            with open(readme_path, 'w') as f:
                f.write(f"# {dir_name.upper()}\n\n")
                f.write(f"{description}\n\n")
                f.write(f"Created by Attack Box on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Create scan subdirectories
    scans_dir = os.path.join(base_dir, "scans")
    for subdir, description in scan_subdirs.items():
        subdir_path = os.path.join(scans_dir, subdir)
        Path(subdir_path).mkdir(parents=True, exist_ok=True)
        
        readme_path = os.path.join(subdir_path, "README.md")
        if not os.path.exists(readme_path):
            with open(readme_path, 'w') as f:
                f.write(f"# {subdir.upper()} SCANS\n\n")
                f.write(f"{description}\n\n")
    
    # Create loot subdirectories
    loot_dir = os.path.join(base_dir, "loot")
    for subdir, description in loot_subdirs.items():
        subdir_path = os.path.join(loot_dir, subdir)
        Path(subdir_path).mkdir(parents=True, exist_ok=True)
        
        readme_path = os.path.join(subdir_path, "README.md")
        if not os.path.exists(readme_path):
            with open(readme_path, 'w') as f:
                f.write(f"# {subdir.upper()}\n\n")
                f.write(f"{description}\n\n")
    
    # Create engagement log
    engagement_log = os.path.join(base_dir, "logs", "engagement.log")
    with open(engagement_log, 'w') as f:
        f.write(f"Attack Box Engagement Log\n")
        f.write(f"=========================\n")
        f.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Operator: {operator}\n")
        f.write(f"Tool: Attack Box Manual Testing Interface\n\n")
    
    # Create initial target file
    target_template = os.path.join(base_dir, "targets", "targets.txt")
    if not os.path.exists(target_template):
        with open(target_template, 'w') as f:
            f.write("# Target List\n")
            f.write("# Add IPs, ranges, or hostnames (one per line)\n")
            f.write("# Examples:\n")
            f.write("# 192.168.1.1\n")
            f.write("# 192.168.1.0/24\n")
            f.write("# 192.168.1.1-50\n")
            f.write("# target.domain.com\n\n")
    
    # Create manual commands file
    manual_commands = os.path.join(base_dir, "scans", "_manual_commands.txt")
    with open(manual_commands, 'w') as f:
        f.write("# Manual Commands for Further Enumeration\n")
        f.write("# ======================================\n")
        f.write(f"# Generated by Attack Box on {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("# Example commands:\n")
        f.write("# nmap -sS -T4 --top-ports 1000 <target>\n")
        f.write("# gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt\n")
        f.write("# nikto -h http://<target>\n")
        f.write("# sqlmap -u http://<target>?id=1 --dbs\n\n")
    
    # Create notes template
    notes_template = os.path.join(base_dir, "notes", "engagement_notes.md")
    with open(notes_template, 'w') as f:
        f.write(f"# Engagement Notes\n\n")
        f.write(f"**Date:** {time.strftime('%Y-%m-%d')}\n")
        f.write(f"**Operator:** {operator}\n")
        f.write(f"**Engagement:** TBD\n\n")
        f.write(f"## Scope\n")
        f.write(f"- [ ] Define target scope\n")
        f.write(f"- [ ] Identify key assets\n")
        f.write(f"- [ ] Document rules of engagement\n\n")
        f.write(f"## Methodology\n")
        f.write(f"1. **Reconnaissance**\n")
        f.write(f"   - Passive information gathering\n")
        f.write(f"   - DNS enumeration\n")
        f.write(f"   - OSINT collection\n\n")
        f.write(f"2. **Scanning & Enumeration**\n")
        f.write(f"   - Network discovery\n")
        f.write(f"   - Port scanning\n")
        f.write(f"   - Service enumeration\n\n")
        f.write(f"3. **Vulnerability Assessment**\n")
        f.write(f"   - Automated scanning\n")
        f.write(f"   - Manual testing\n")
        f.write(f"   - Vulnerability validation\n\n")
        f.write(f"4. **Exploitation**\n")
        f.write(f"   - Proof of concept development\n")
        f.write(f"   - Privilege escalation\n")
        f.write(f"   - Lateral movement\n\n")
        f.write(f"## Key Findings\n")
        f.write(f"*Document critical findings here*\n\n")
        f.write(f"## Timeline\n")
        f.write(f"- **{time.strftime('%Y-%m-%d %H:%M')}:** Engagement started\n\n")
    
    # Create wordlist directory with common lists
    wordlist_dir = os.path.join(base_dir, "wordlists")
    common_wordlists = os.path.join(wordlist_dir, "common_lists.txt")
    with open(common_wordlists, 'w') as f:
        f.write("# Common Wordlist Locations\n")
        f.write("# =========================\n")
        f.write("# Directory enumeration:\n")
        f.write("/usr/share/wordlists/dirb/common.txt\n")
        f.write("/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt\n")
        f.write("/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt\n\n")
        f.write("# File enumeration:\n")
        f.write("/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt\n")
        f.write("/usr/share/seclists/Discovery/Web-Content/common.txt\n\n")
        f.write("# Subdomain enumeration:\n")
        f.write("/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt\n")
        f.write("/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt\n\n")
        f.write("# Password attacks:\n")
        f.write("/usr/share/wordlists/rockyou.txt\n")
        f.write("/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt\n")
    
    # Create scripts directory with useful scripts
    scripts_dir = os.path.join(base_dir, "tools", "scripts")
    Path(scripts_dir).mkdir(parents=True, exist_ok=True)
    
    quick_enum_script = os.path.join(scripts_dir, "quick_enum.sh")
    with open(quick_enum_script, 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("# Quick enumeration script\n")
        f.write("# Usage: ./quick_enum.sh <target_ip>\n\n")
        f.write("if [ $# -eq 0 ]; then\n")
        f.write('    echo "Usage: $0 <target_ip>"\n')
        f.write("    exit 1\n")
        f.write("fi\n\n")
        f.write("TARGET=$1\n")
        f.write("DATE=$(date +%Y%m%d_%H%M%S)\n")
        f.write("SCAN_DIR=\"../../scans\"\n\n")
        f.write("echo \"[+] Quick enumeration of $TARGET\"\n")
        f.write("echo \"[+] Results will be saved to $SCAN_DIR\"\n\n")
        f.write("# Quick nmap scan\n")
        f.write("echo \"[+] Running quick nmap scan...\"\n")
        f.write("nmap -sS -T4 --top-ports 1000 -oN \"$SCAN_DIR/nmap/quick_scan_${TARGET}_${DATE}.txt\" $TARGET\n\n")
        f.write("# Check for web services\n")
        f.write("echo \"[+] Checking for web services...\"\n")
        f.write("if nmap -p 80,443,8080,8443 --open $TARGET | grep -q open; then\n")
        f.write("    echo \"[+] Web services found, running quick web enum...\"\n")
        f.write("    gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -o \"$SCAN_DIR/web/gobuster_${TARGET}_${DATE}.txt\" -q\n")
        f.write("fi\n\n")
        f.write("echo \"[+] Quick enumeration complete\"\n")
    
    os.chmod(quick_enum_script, 0o755)
    
    print(f"[+] Penetration testing structure created successfully")
    print(f"[*] Add targets to: {target_template}")
    print(f"[*] Engagement log: {engagement_log}")
    print(f"[*] Quick enum script: {quick_enum_script}")
    
    return base_dir

if __name__ == "__main__":
    import sys
    import getpass
    
    if len(sys.argv) > 1:
        workspace_name = sys.argv[1]
    else:
        workspace_name = f"/root/operator"
    
    operator = getpass.getuser()
    create_workspace_structure(workspace_name, operator)
