#!/usr/bin/env python3

import os
import subprocess
import argparse
import sys
import re
import socket
import ipaddress
import threading
import time
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import json
import csv
import logging

# Global configuration
MAX_THREADS = 10
REACHABILITY_THREADS = 100
COMMON_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080"
TCPDUMP_DURATION = 300  # 5 minutes default
REACHABILITY_TIMEOUT = 3  # seconds for each connectivity test
REACHABILITY_PORTS = [22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5985, 5986, 8080, 8443]

# Global logging variables
csv_logger = None
verbose_logger = None

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def setup_logging(base_dir):
    """Setup comprehensive logging for TrashPanda operations."""
    global csv_logger, verbose_logger
    
    logs_dir = os.path.join(base_dir, "logs")
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    # Setup CSV command logging
    csv_file = os.path.join(logs_dir, f"trashpanda_commands_{timestamp}.csv")
    csv_fieldnames = ['start_time', 'end_time', 'hostname', 'command', 'exit_code', 'duration_seconds']
    
    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=csv_fieldnames)
        writer.writeheader()
    
    # Setup verbose console logging
    verbose_file = os.path.join(logs_dir, f"trashpanda_verbose_{timestamp}.log")
    verbose_logger = logging.getLogger('trashpanda_verbose')
    verbose_logger.setLevel(logging.DEBUG)
    
    # Create file handler for verbose log
    file_handler = logging.FileHandler(verbose_file)
    file_handler.setLevel(logging.DEBUG)
    
    # Create console handler that captures all output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    verbose_logger.addHandler(file_handler)
    verbose_logger.propagate = False  # Prevent duplicate console output
    
    print(f"{Colors.OKGREEN}[+] Logging initialized:{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] CSV commands log: {csv_file}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Verbose log: {verbose_file}{Colors.ENDC}")
    
    return csv_file, verbose_file

def log_command(command, start_time=None, end_time=None, exit_code=None, hostname=None):
    """Log command execution to CSV file."""
    global csv_logger
    
    if not hasattr(log_command, 'csv_file'):
        return  # Logging not initialized
    
    try:
        duration = (end_time - start_time) if start_time and end_time else None
        
        with open(log_command.csv_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['start_time', 'end_time', 'hostname', 'command', 'exit_code', 'duration_seconds'])
            writer.writerow({
                'start_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time)) if start_time else '',
                'end_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time)) if end_time else '',
                'hostname': hostname or socket.gethostname(),
                'command': command,
                'exit_code': exit_code,
                'duration_seconds': f"{duration:.2f}" if duration else ''
            })
    except Exception as e:
        print(f"{Colors.WARNING}[!] Logging error: {e}{Colors.ENDC}")

def log_verbose(message, level='INFO'):
    """Log message to verbose log file."""
    global verbose_logger
    
    if verbose_logger:
        if level == 'DEBUG':
            verbose_logger.debug(message)
        elif level == 'WARNING':
            verbose_logger.warning(message)
        elif level == 'ERROR':
            verbose_logger.error(message)
        else:
            verbose_logger.info(message)

class LoggingPrint:
    """Wrapper to capture and log all print statements."""
    def __init__(self, original_stdout):
        self.original_stdout = original_stdout
    
    def write(self, message):
        # Write to original stdout
        self.original_stdout.write(message)
        # Log to verbose log (strip ANSI colors for log file)
        if message.strip():
            clean_message = re.sub(r'\033\[[0-9;]*m', '', message.strip())
            log_verbose(clean_message)
    
    def flush(self):
        self.original_stdout.flush()

def is_public_ip(ip_str):
    """Check if an IP address is public (not private/reserved)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False

def filter_public_ips_from_targets(targets):
    """Filter out public IPs from target list and warn user."""
    filtered_targets = []
    public_ips = []
    
    for target in targets:
        # Handle CIDR ranges
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                if any(is_public_ip(str(ip)) for ip in list(network)[:5]):  # Check first 5 IPs
                    public_ips.append(target)
                    print(f"{Colors.WARNING}[!] Skipping public network range: {target}{Colors.ENDC}")
                else:
                    filtered_targets.append(target)
            except ValueError:
                filtered_targets.append(target)  # Keep if not valid CIDR
        # Handle IP ranges
        elif '-' in target and not target.count('.') > 3:
            try:
                base_ip = target.split('-')[0]
                if is_public_ip(base_ip):
                    public_ips.append(target)
                    print(f"{Colors.WARNING}[!] Skipping public IP range: {target}{Colors.ENDC}")
                else:
                    filtered_targets.append(target)
            except:
                filtered_targets.append(target)  # Keep if parsing fails
        # Handle single IPs
        else:
            try:
                # Try to parse as IP first
                ip = ipaddress.ip_address(target)
                if is_public_ip(str(ip)):
                    public_ips.append(target)
                    print(f"{Colors.WARNING}[!] Skipping public IP: {target}{Colors.ENDC}")
                else:
                    filtered_targets.append(target)
            except ValueError:
                # Not an IP, probably hostname - keep it
                filtered_targets.append(target)
    
    if public_ips:
        print(f"{Colors.WARNING}[!] Filtered out {len(public_ips)} public IP targets for safety{Colors.ENDC}")
        response = input(f"{Colors.WARNING}Continue with remaining {len(filtered_targets)} targets? [y/N]: {Colors.ENDC}")
        if response.lower() != 'y':
            print(f"{Colors.FAIL}[!] Scan aborted by user{Colors.ENDC}")
            sys.exit(0)
    
    return filtered_targets

def print_banner():
    banner = f"""
{Colors.HEADER}{Colors.BOLD}
████████╗██████╗  █████╗ ███████╗██╗  ██╗██████╗  █████╗ ███╗   ██╗██████╗  █████╗ 
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║  ██║██╔══██╗██╔══██╗████╗  ██║██╔══██╗██╔══██╗
   ██║   ██████╔╝███████║███████╗███████║██████╔╝███████║██╔██╗ ██║██║  ██║███████║
   ██║   ██╔══██╗██╔══██║╚════██║██╔══██║██╔═══╝ ██╔══██║██║╚██╗██║██║  ██║██╔══██║
   ██║   ██║  ██║██║  ██║███████║██║  ██║██║     ██║  ██║██║ ╚████║██████╔╝██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝
                                                                                      
                🦝 TrashPanda - Network Enumeration Tool v2.4 🦝
                   Professional Penetration Testing Framework
{Colors.ENDC}
    """
    print(banner)

def create_pentest_structure(base_name=None):
    if base_name is None:
        base_name = os.environ.get("WORK_DIR", os.environ.get("WORK_DIR", "/root/workspace"))
    """Create a comprehensive penetration testing directory structure."""
    
    # Main engagement directory
    base_dir = os.path.abspath(base_name)
    
    # Primary directories
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
    
    # Scan subdirectories
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
    
    # Loot subdirectories  
    loot_subdirs = {
        "credentials": "Usernames, passwords, and authentication data",
        "hashes": "Password hashes and cracking results",
        "keys": "SSH keys, certificates, and crypto material",
        "configs": "Configuration files and sensitive data",
        "databases": "Extracted database contents",
        "files": "Interesting files and documents"
    }
    
    print(f"{Colors.OKGREEN}[+] Creating penetration testing structure: {base_dir}{Colors.ENDC}")
    
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
                f.write(f"Created by TrashPanda on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
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
        f.write(f"TrashPanda Engagement Log\n")
        f.write(f"========================\n")
        f.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Operator: {os.environ.get('USER', 'operator')}\n")
        f.write(f"Tool: TrashPanda v2.4\n\n")

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
        f.write(f"# Generated by TrashPanda on {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    print(f"{Colors.OKGREEN}[+] Penetration testing structure created successfully{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Add targets to: {target_template}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Engagement log: {engagement_log}{Colors.ENDC}")
    
    return base_dir

def start_tcpdump(base_dir, duration=TCPDUMP_DURATION, interface="any"):
    """Start tcpdump for network capture, but only if not already running."""
    pcap_dir = os.path.join(base_dir, "pcaps")
    
    # Check if capture files already exist
    try:
        import glob
        existing_captures = glob.glob(os.path.join(pcap_dir, "capture_*.pcap"))
        if existing_captures:
            print(f"{Colors.WARNING}[!] Found {len(existing_captures)} existing capture file(s):{Colors.ENDC}")
            for capture in existing_captures[-3:]:  # Show last 3 files
                file_size = os.path.getsize(capture) / (1024*1024)  # MB
                mod_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(capture)))
                print(f"{Colors.WARNING}    - {os.path.basename(capture)} ({file_size:.1f}MB, {mod_time}){Colors.ENDC}")
            if len(existing_captures) > 3:
                print(f"{Colors.WARNING}    ... and {len(existing_captures)-3} more{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] Skipping new capture to avoid overwriting existing data{Colors.ENDC}")
            return None
    except Exception as e:
        print(f"{Colors.WARNING}[!] Error checking for existing captures: {e}{Colors.ENDC}")
        pass  # Continue with capture if check fails
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(pcap_dir, f"capture_{timestamp}.pcap")
    
    print(f"{Colors.OKBLUE}[*] Starting tcpdump capture for {duration} seconds...{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Capture file: {pcap_file}{Colors.ENDC}")
    
    # Build tcpdump command
    tcpdump_cmd = [
        "sudo", "tcpdump", 
        "-i", interface,
        "-U",  # Unbuffered output
        "-w", pcap_file,
        "-s", "65535",  # Capture full packets
        "not", "port", "22"  # Exclude SSH traffic to reduce noise
    ]
    
    try:
        # Start tcpdump process
        tcpdump_process = subprocess.Popen(
            tcpdump_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Log the process
        log_file = os.path.join(base_dir, "logs", "tcpdump.log")
        with open(log_file, 'a') as f:
            f.write(f"TCPDump started at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Command: {' '.join(tcpdump_cmd)}\n")
            f.write(f"PID: {tcpdump_process.pid}\n")
            f.write(f"Duration: {duration} seconds\n")
            f.write(f"Output: {pcap_file}\n\n")
        
        # Return process info for later termination
        return {
            'process': tcpdump_process,
            'start_time': time.time(),
            'duration': duration,
            'pcap_file': pcap_file,
            'log_file': log_file
        }
        
    except Exception as e:
        print(f"{Colors.FAIL}[!] Failed to start tcpdump: {e}{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Make sure you have sudo privileges{Colors.ENDC}")
        return None

def stop_tcpdump(tcpdump_info):
    """Stop tcpdump and log results."""
    if not tcpdump_info:
        return
    
    try:
        process = tcpdump_info['process']
        
        # Terminate gracefully
        process.terminate()
        
        # Wait for termination with timeout
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print(f"{Colors.WARNING}[!] TCPDump didn't terminate gracefully, killing...{Colors.ENDC}")
            process.kill()
            process.wait()
        
        # Log completion
        end_time = time.time()
        actual_duration = end_time - tcpdump_info['start_time']
        
        with open(tcpdump_info['log_file'], 'a') as f:
            f.write(f"TCPDump stopped at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Actual duration: {actual_duration:.2f} seconds\n")
            f.write(f"Exit code: {process.returncode}\n")
        
        # Check file size
        pcap_file = tcpdump_info['pcap_file']
        if os.path.exists(pcap_file):
            file_size = os.path.getsize(pcap_file)
            print(f"{Colors.OKGREEN}[+] TCPDump capture completed{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Capture file: {pcap_file} ({file_size:,} bytes){Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}[!] TCPDump capture file not found{Colors.ENDC}")
            
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error stopping tcpdump: {e}{Colors.ENDC}")

def run_command(command, output_file=None, debug=False, stealth=False):
    """Run a command with comprehensive logging."""
    start_time = time.time()
    hostname = socket.gethostname()
    
    if debug:
        print(f"{Colors.OKCYAN}[DEBUG] Running: {command}{Colors.ENDC}")
    
    log_verbose(f"COMMAND START: {command}", 'INFO')
    
    try:
        # Increase timeout for stealth mode (slower scans)
        timeout = 7200 if stealth else 3600
        result = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=timeout)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Log command to CSV
        log_command(command, start_time, end_time, result.returncode, hostname)
        
        # Log to verbose log
        log_verbose(f"COMMAND END: {command} (exit_code: {result.returncode}, duration: {duration:.2f}s)", 'INFO')
        
        if result.stdout:
            log_verbose(f"STDOUT: {result.stdout[:1000]}{'...' if len(result.stdout) > 1000 else ''}", 'DEBUG')
        if result.stderr:
            log_verbose(f"STDERR: {result.stderr[:1000]}{'...' if len(result.stderr) > 1000 else ''}", 'WARNING')
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(f"Command: {command}\n")
                f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}\n")
                f.write(f"Duration: {duration:.2f} seconds\n")
                f.write(f"Return Code: {result.returncode}\n")
                f.write(f"STDOUT:\n{result.stdout}\n")
                f.write(f"STDERR:\n{result.stderr}\n")
        
        if debug:
            print(f"{Colors.OKCYAN}[DEBUG] Return code: {result.returncode}, Duration: {duration:.2f}s{Colors.ENDC}")
            if result.stdout:
                print(f"{Colors.OKCYAN}[DEBUG] STDOUT: {result.stdout[:500]}...{Colors.ENDC}")
        
        return result
    except subprocess.TimeoutExpired:
        end_time = time.time()
        error_msg = f"Command timed out: {command}"
        print(f"{Colors.WARNING}[!] {error_msg}{Colors.ENDC}")
        log_command(command, start_time, end_time, -1, hostname)  # -1 for timeout
        log_verbose(f"TIMEOUT: {error_msg}", 'ERROR')
        return None
    except Exception as e:
        end_time = time.time()
        error_msg = f"Error running command: {e}"
        print(f"{Colors.FAIL}[!] {error_msg}{Colors.ENDC}")
        log_command(command, start_time, end_time, -2, hostname)  # -2 for error
        log_verbose(f"ERROR: {error_msg}", 'ERROR')
        return None

def add_manual_command(base_dir, service_name, commands):
    """Add manual commands to the manual commands file."""
    manual_file = os.path.join(base_dir, "scans", "_manual_commands.txt")
    
    with open(manual_file, 'a') as f:
        f.write(f"\n[*] {service_name}\n")
        f.write("=" * (len(service_name) + 4) + "\n\n")
        
        if isinstance(commands, str):
            commands = [commands]
        
        for cmd in commands:
            f.write(f"    {cmd}\n")
        f.write("\n")

def parse_targets(target_input):
    """Parse various target formats (IPs, ranges, CIDRs, hostnames)."""
    targets = []
    
    if os.path.isfile(target_input):
        with open(target_input, 'r') as f:
            lines = f.read().splitlines()
    else:
        lines = [target_input]
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        try:
            # Check if it's a CIDR range
            if '/' in line:
                network = ipaddress.ip_network(line, strict=False)
                targets.extend([str(ip) for ip in network.hosts()])
            # Check if it's an IP range (e.g., 192.168.1.1-50)
            elif '-' in line and not line.count('-') > 1:
                ip_parts = line.split('-')
                if len(ip_parts) == 2:
                    base_ip = ip_parts[0]
                    end_range = ip_parts[1]
                    
                    # Handle cases like 192.168.1.1-50
                    if '.' in base_ip and '.' not in end_range:
                        base_parts = base_ip.split('.')
                        start_num = int(base_parts[3])
                        end_num = int(end_range)
                        for i in range(start_num, end_num + 1):
                            targets.append(f"{'.'.join(base_parts[:3])}.{i}")
                    else:
                        targets.append(line)  # Add as-is if format not recognized
            else:
                # Single IP or hostname
                targets.append(line)
        except Exception as e:
            print(f"{Colors.WARNING}[!] Error parsing target {line}: {e}{Colors.ENDC}")
            targets.append(line)  # Add as-is and let tools handle it
    
    return list(set(targets))  # Remove duplicates

def classify_network_ranges(targets):
    """Intelligently classify and group IP targets into appropriate network ranges for scanning."""
    rfc1918_networks = {
        'class_a': set(),      # 10.0.0.0/8
        'class_b': set(),      # 172.16.0.0/12
        'class_c': set(),      # 192.168.0.0/16
    }
    
    non_rfc1918_ips = []
    hostnames = []
    
    for target in targets:
        try:
            ip_obj = ipaddress.ip_address(target)
            
            if ip_obj.is_private:
                ip_str = str(ip_obj)
                
                # Class A: 10.0.0.0/8
                if ip_str.startswith('10.'):
                    octets = ip_str.split('.')
                    # Group by /16 networks within Class A
                    network_prefix = f"{octets[0]}.{octets[1]}"
                    rfc1918_networks['class_a'].add(f"{network_prefix}.0.0/16")
                
                # Class B: 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
                elif ip_str.startswith('172.'):
                    octets = ip_str.split('.')
                    second_octet = int(octets[1])
                    if 16 <= second_octet <= 31:
                        network_prefix = f"{octets[0]}.{octets[1]}"
                        rfc1918_networks['class_b'].add(f"{network_prefix}.0.0/16")
                
                # Class C: 192.168.0.0/16
                elif ip_str.startswith('192.168.'):
                    octets = ip_str.split('.')
                    network_prefix = f"{octets[0]}.{octets[1]}.{octets[2]}"
                    rfc1918_networks['class_c'].add(f"{network_prefix}.0/24")
            else:
                non_rfc1918_ips.append(target)
                
        except ValueError:
            # Not an IP address, likely a hostname
            hostnames.append(target)
    
    return rfc1918_networks, non_rfc1918_ips, hostnames

def discover_services_from_nmap(base_dir):
    """Parse nmap results to discover services for enhanced enumeration."""
    services = {}
    nmap_dir = os.path.join(base_dir, "scans", "nmap")
    
    # Parse nmap gnmap files for services
    for nmap_file in Path(nmap_dir).glob("*.gnmap"):
        try:
            with open(nmap_file, 'r') as f:
                for line in f:
                    if "open" in line:
                        parts = line.split()
                        if len(parts) > 1:
                            ip = parts[1]
                            if ip not in services:
                                services[ip] = []
                            
                            # Extract port info
                            port_info = [p for p in parts if "open" in p]
                            for port_data in port_info:
                                port_match = re.search(r'(\d+)/(tcp|udp)', port_data)
                                service_match = re.search(r'//(.+?)/', port_data)
                                
                                if port_match:
                                    port = port_match.group(1)
                                    protocol = port_match.group(2)
                                    service = service_match.group(1) if service_match else "unknown"
                                    
                                    service_info = {
                                        'port': port,
                                        'protocol': protocol,
                                        'service': service,
                                        'ssl': 'ssl' in port_data or 'https' in port_data
                                    }
                                    
                                    if service_info not in services[ip]:
                                        services[ip].append(service_info)
        except Exception as e:
            print(f"{Colors.WARNING}[!] Error parsing {nmap_file}: {e}{Colors.ENDC}")
    
    return services

# Network Reachability Testing Functions
def test_icmp_connectivity(target, timeout=REACHABILITY_TIMEOUT):
    """Test ICMP connectivity using ping."""
    try:
        if sys.platform.startswith('win'):
            result = subprocess.run(['ping', '-n', '1', '-w', str(timeout*1000), target], 
                                  capture_output=True, text=True, timeout=timeout+2)
        else:
            result = subprocess.run(['ping', '-c', '1', '-W', str(timeout), target], 
                                  capture_output=True, text=True, timeout=timeout+2)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        return False

def test_dns_connectivity(dns_server, timeout=3):
    """Test DNS server connectivity with actual DNS query."""
    try:
        # Test UDP DNS first with a real DNS query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # DNS query for google.com (more realistic than generic UDP test)
        dns_query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
        sock.sendto(dns_query, (dns_server, 53))
        
        # Wait for response
        response, addr = sock.recvfrom(1024)
        sock.close()
        
        # Check if we got a valid DNS response
        if len(response) > 12:  # Minimum DNS response size
            return True
            
    except (socket.error, socket.timeout):
        pass
    
    # Fallback: test TCP connectivity to port 53
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((dns_server, 53))
        sock.close()
        return result == 0
    except (socket.error, socket.timeout):
        return False

def test_tcp_connectivity(target, port, timeout=REACHABILITY_TIMEOUT):
    """Test TCP connectivity to specific port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except (socket.error, socket.timeout):
        return False

def test_udp_connectivity(target, port=53, timeout=REACHABILITY_TIMEOUT):
    """Test UDP connectivity (primarily DNS)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Send a simple DNS query for connectivity test
        if port == 53:
            # Simple DNS query packet for google.com
            dns_query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
            sock.sendto(dns_query, (target, port))
            data, addr = sock.recvfrom(1024)
            sock.close()
            return True
        else:
            # For other UDP ports, just try to send a packet
            sock.sendto(b'test', (target, port))
            sock.close()
            return True
    except (socket.error, socket.timeout):
        return False

def test_comprehensive_connectivity(target, debug=False):
    """Run comprehensive connectivity tests for a single target."""
    results = {
        'target': target,
        'icmp': False,
        'tcp_ports': {},
        'udp_dns': False,
        'reachable': False,
        'response_time': 0,
        'best_ports': []
    }
    
    start_time = time.time()
    
    # Test ICMP first
    if debug:
        print(f"{Colors.OKCYAN}[DEBUG] Testing ICMP to {target}{Colors.ENDC}")
    
    results['icmp'] = test_icmp_connectivity(target)
    
    # Test common TCP ports
    tcp_results = {}
    for port in REACHABILITY_PORTS:
        if debug:
            print(f"{Colors.OKCYAN}[DEBUG] Testing TCP {target}:{port}{Colors.ENDC}")
        tcp_results[port] = test_tcp_connectivity(target, port)
        if tcp_results[port]:
            results['best_ports'].append(port)
    
    results['tcp_ports'] = tcp_results
    
    # Test UDP DNS
    if debug:
        print(f"{Colors.OKCYAN}[DEBUG] Testing UDP DNS to {target}{Colors.ENDC}")
    results['udp_dns'] = test_udp_connectivity(target, 53)
    
    # Determine overall reachability
    results['reachable'] = (results['icmp'] or 
                           any(tcp_results.values()) or 
                           results['udp_dns'])
    
    results['response_time'] = round(time.time() - start_time, 2)
    
    return results

def analyze_network_infrastructure(targets, debug=False):
    """Analyze targets and identify key network infrastructure to test."""
    infrastructure = {
        'subnets': {},  # Changed from 'enclaves' to 'subnets'
        'individual_hosts': [],
        'dns_servers': set(),
        'analysis_summary': {},
        'total_original_targets': 0  # Track original scope
    }
    
    print(f"{Colors.OKGREEN}[+] Analyzing Target Infrastructure{Colors.ENDC}")
    
    # Count original targets for reduction metrics
    total_original = 0
    for target in targets:
        try:
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                total_original += network.num_addresses - 2  # Exclude network and broadcast
            else:
                total_original += 1
        except ValueError:
            total_original += 1
    
    infrastructure['total_original_targets'] = total_original
    print(f"{Colors.OKBLUE}[*] Original scope: ~{total_original:,} potential targets{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Performing intelligent analysis to avoid brute force scanning...{Colors.ENDC}")
    
    subnet_count = 0
    
    for target in targets:
        try:
            # Try to parse as IP address
            ip_obj = ipaddress.ip_address(target)
            
            # Determine which subnet/network this belongs to
            if ip_obj.is_private:
                octets = str(ip_obj).split('.')
                
                # Group by /24 networks for now (can be adjusted)
                if octets[0] == '10':
                    # For 10.x networks, group by /16
                    subnet_key = f"{octets[0]}.{octets[1]}.0.0/16"
                elif octets[0] == '172' and 16 <= int(octets[1]) <= 31:
                    # For 172.16-31 networks, group by /16  
                    subnet_key = f"{octets[0]}.{octets[1]}.0.0/16"
                elif octets[0] == '192' and octets[1] == '168':
                    # For 192.168 networks, group by /24
                    subnet_key = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                else:
                    # Other private ranges, group by /24
                    subnet_key = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
            else:
                # Public IP - each gets its own "subnet"
                subnet_key = f"public_{str(ip_obj)}"
            
            # Initialize subnet if not seen before
            if subnet_key not in infrastructure['subnets']:
                subnet_count += 1
                infrastructure['subnets'][subnet_key] = {
                    'network': subnet_key,
                    'targets': [],
                    'sample_targets': [],
                    'key_infrastructure': [],
                    'subnet_id': subnet_count
                }
                
                # Add key infrastructure for this subnet
                try:
                    network = ipaddress.ip_network(subnet_key, strict=False)
                    if network.is_private and network.num_addresses > 2:
                        # Add potential gateways and key servers
                        base_ip = str(network.network_address).split('.')
                        key_ips = [
                            f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.1",      # Common gateway
                            f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.254",    # Alt gateway
                            f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.10",     # Common server IP
                            f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.53",     # DNS server
                            f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.100",    # Common server range
                        ]
                        
                        # Only add IPs that are actually in the network
                        for key_ip in key_ips:
                            try:
                                if ipaddress.ip_address(key_ip) in network:
                                    infrastructure['subnets'][subnet_key]['key_infrastructure'].append(key_ip)
                            except ValueError:
                                pass
                except ValueError:
                    pass
            
            # Add target to subnet
            infrastructure['subnets'][subnet_key]['targets'].append(str(ip_obj))
            
        except ValueError:
            # Handle CIDR ranges
            if '/' in target:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    subnet_key = str(network)
                    
                    if subnet_key not in infrastructure['subnets']:
                        subnet_count += 1
                        infrastructure['subnets'][subnet_key] = {
                            'network': subnet_key,
                            'targets': [],
                            'sample_targets': [],
                            'key_infrastructure': [],
                            'subnet_id': subnet_count,
                            'is_full_network': True
                        }
                    
                    # For full networks, we'll sample them intelligently (not all hosts)
                    all_hosts = list(network.hosts())
                    if len(all_hosts) > 50:
                        # Large network - take strategic samples
                        sample_hosts = all_hosts[:10] + all_hosts[-10:] + all_hosts[len(all_hosts)//2:len(all_hosts)//2+10]
                        infrastructure['subnets'][subnet_key]['targets'] = [str(h) for h in sample_hosts[:30]]
                    else:
                        # Small network - include all
                        infrastructure['subnets'][subnet_key]['targets'] = [str(h) for h in all_hosts]
                    
                except ValueError:
                    infrastructure['individual_hosts'].append(target)
            else:
                # Hostname or IP range
                infrastructure['individual_hosts'].append(target)
    
    # Generate sample targets for each subnet (for testing) - SMALL samples only
    for subnet_key, subnet_data in infrastructure['subnets'].items():
        targets_in_subnet = subnet_data['targets']
        
        if len(targets_in_subnet) <= 5:
            # Very small subnet - test all targets
            subnet_data['sample_targets'] = targets_in_subnet.copy()
        else:
            # Larger subnet - SMALL intelligent sampling (max 8 targets)
            sample_size = min(8, max(3, len(targets_in_subnet) // 20))  # Much smaller sample
            
            # Always include first, last, and some middle targets
            samples = []
            samples.append(targets_in_subnet[0])  # First
            if len(targets_in_subnet) > 1:
                samples.append(targets_in_subnet[-1])  # Last
            
            # Add evenly distributed samples
            remaining = sample_size - len(samples)
            if remaining > 0 and len(targets_in_subnet) > 2:
                step = len(targets_in_subnet) // (remaining + 1)
                for i in range(remaining):
                    idx = (i + 1) * step
                    if idx < len(targets_in_subnet):
                        samples.append(targets_in_subnet[idx])
            
            subnet_data['sample_targets'] = list(set(samples))
        
        # Add key infrastructure to samples
        subnet_data['sample_targets'].extend(subnet_data['key_infrastructure'])
        subnet_data['sample_targets'] = list(set(subnet_data['sample_targets']))
    
    # Discover system DNS servers
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns_ip = line.split()[1]
                    try:
                        ipaddress.ip_address(dns_ip)
                        infrastructure['dns_servers'].add(dns_ip)
                    except ValueError:
                        pass
    except FileNotFoundError:
        pass
    
    # Add common external DNS if none found
    if not infrastructure['dns_servers']:
        infrastructure['dns_servers'].update(['8.8.8.8', '1.1.1.1'])
    
    # Generate summary
    total_samples = sum(len(e['sample_targets']) for e in infrastructure['subnets'].values())
    infrastructure['analysis_summary'] = {
        'total_subnets': len(infrastructure['subnets']),
        'total_targets': sum(len(e['targets']) for e in infrastructure['subnets'].values()),
        'total_samples': total_samples,
        'individual_hosts': len(infrastructure['individual_hosts']),
        'dns_servers': len(infrastructure['dns_servers']),
        'reduction_ratio': total_original / max(total_samples, 1)
    }
    
    # Print detailed analysis
    print(f"{Colors.OKGREEN}[+] Infrastructure Analysis Complete{Colors.ENDC}")
    reduction_pct = (1 - total_samples / total_original) * 100
    print(f"{Colors.OKGREEN}[+] Smart sampling: {total_samples:,} tests vs {total_original:,} original ({reduction_pct:.1f}% reduction){Colors.ENDC}")
    
    print(f"{Colors.OKBLUE}[*] Identified {len(infrastructure['subnets'])} network subnets:{Colors.ENDC}")
    
    for subnet_key, subnet_data in infrastructure['subnets'].items():
        subnet_id = subnet_data['subnet_id']
        target_count = len(subnet_data['targets'])
        sample_count = len(subnet_data['sample_targets'])
        
        print(f"{Colors.OKCYAN}    [{subnet_id}] {subnet_key}: {target_count} targets → {sample_count} samples{Colors.ENDC}")
    
    return infrastructure

def test_subnet_reachability(infrastructure, debug=False, timeout=3):
    """Test each subnet independently to determine reachability."""
    results = {
        'reachable_subnets': {},
        'unreachable_subnets': {},
        'dns_servers': {'reachable': [], 'unreachable': []},
        'individual_hosts': {'reachable': [], 'unreachable': []},
        'testing_summary': {}
    }
    
    print(f"\n{Colors.OKGREEN}[+] Testing Subnet Reachability{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Strategy: ANY response from subnet = entire subnet reachable{Colors.ENDC}")
    
    # Test DNS servers first
    dns_servers_list = list(infrastructure['dns_servers'])
    total_dns = len(dns_servers_list)
    
    if total_dns > 0:
        print(f"{Colors.OKBLUE}[*] Step 1: Testing DNS connectivity ({total_dns} servers){Colors.ENDC}")
        
        for dns_idx, dns_server in enumerate(dns_servers_list, 1):
            print(f"{Colors.OKCYAN}    [{dns_idx}/{total_dns}] Testing DNS server {dns_server}...{Colors.ENDC}", end=' ')
            
            is_reachable = test_dns_connectivity(dns_server, timeout)
            
            if is_reachable:
                results['dns_servers']['reachable'].append(dns_server)
                print(f"{Colors.OKGREEN}✓ REACHABLE{Colors.ENDC}")
            else:
                results['dns_servers']['unreachable'].append(dns_server)
                print(f"{Colors.FAIL}✗ UNREACHABLE{Colors.ENDC}")
        
        print(f"{Colors.OKBLUE}[*] DNS Summary: {len(results['dns_servers']['reachable'])}/{total_dns} reachable{Colors.ENDC}")
    
    # Test each subnet - handle both 'subnets' and 'enclaves' keys for compatibility
    subnet_dict = infrastructure.get('subnets', infrastructure.get('enclaves', {}))
    total_subnets = len(subnet_dict)
    
    print(f"\n{Colors.OKBLUE}[*] Step 2: Testing Network Subnet Reachability ({total_subnets} subnets){Colors.ENDC}")
    
    subnet_counter = 0
    for subnet_key, subnet_data in subnet_dict.items():
        subnet_counter += 1
        subnet_id = subnet_data['subnet_id']
        sample_targets = subnet_data['sample_targets']
        
        print(f"\n{Colors.OKCYAN}[{subnet_counter}/{total_subnets}] Testing subnet: {subnet_key} (ID: {subnet_id}){Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Sample size: {len(sample_targets)} targets{Colors.ENDC}")
        
        # Test samples in parallel
        subnet_results = []
        reachable_count = 0
        
        with ThreadPoolExecutor(max_workers=min(20, len(sample_targets))) as executor:
            future_to_target = {
                executor.submit(test_basic_connectivity, target, timeout): target 
                for target in sample_targets
            }
            
            target_counter = 0
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                target_counter += 1
                try:
                    is_reachable = future.result()
                    subnet_results.append((target, is_reachable))
                    
                    if is_reachable:
                        reachable_count += 1
                        if debug:
                            print(f"{Colors.OKGREEN}      [{target_counter}/{len(sample_targets)}] ✓ {target}{Colors.ENDC}")
                    else:
                        if debug:
                            print(f"{Colors.FAIL}      [{target_counter}/{len(sample_targets)}] ✗ {target}{Colors.ENDC}")
                            
                except Exception as e:
                    subnet_results.append((target, False))
                    if debug:
                        print(f"{Colors.WARNING}      [{target_counter}/{len(sample_targets)}] ! {target} (error: {e}){Colors.ENDC}")
        
        # Calculate reachability
        reachability_percentage = (reachable_count / len(sample_targets)) * 100 if sample_targets else 0
        
        print(f"{Colors.OKCYAN}    Results: {reachable_count}/{len(sample_targets)} samples reachable ({reachability_percentage:.1f}%){Colors.ENDC}")
        
        # New logic: ANY response means subnet is reachable
        if reachable_count > 0:
            results['reachable_subnets'][subnet_key] = {
                'subnet_data': subnet_data,
                'sample_results': subnet_results,
                'reachable_count': reachable_count,
                'total_tested': len(sample_targets),
                'reachability_percentage': reachability_percentage,
                'confidence': 'high' if reachability_percentage >= 50 else 'medium' if reachable_count >= 3 else 'low'
            }
            confidence = results['reachable_subnets'][subnet_key]['confidence']
            print(f"{Colors.OKGREEN}    → Subnet REACHABLE (confidence: {confidence.upper()}){Colors.ENDC}")
        else:
            results['unreachable_subnets'][subnet_key] = {
                'subnet_data': subnet_data,
                'sample_results': subnet_results,
                'reachable_count': reachable_count,
                'total_tested': len(sample_targets),
                'reachability_percentage': reachability_percentage
            }
            print(f"{Colors.FAIL}    → Subnet UNREACHABLE (zero response - no routing){Colors.ENDC}")
        
        # Show overall progress
        remaining_subnets = total_subnets - subnet_counter
        if remaining_subnets > 0:
            print(f"{Colors.OKBLUE}    Progress: {subnet_counter}/{total_subnets} subnets completed ({remaining_subnets} remaining){Colors.ENDC}")
    
    # Test individual hosts
    individual_hosts = infrastructure['individual_hosts']
    total_individual = len(individual_hosts)
    
    if total_individual > 0:
        print(f"\n{Colors.OKBLUE}[*] Step 3: Testing Individual Hosts ({total_individual} hosts){Colors.ENDC}")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_host = {
                executor.submit(test_basic_connectivity, host, timeout): host 
                for host in individual_hosts
            }
            
            host_counter = 0
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                host_counter += 1
                try:
                    is_reachable = future.result()
                    if is_reachable:
                        results['individual_hosts']['reachable'].append(host)
                        print(f"{Colors.OKGREEN}    [{host_counter}/{total_individual}] ✓ {host}{Colors.ENDC}")
                    else:
                        results['individual_hosts']['unreachable'].append(host)
                        print(f"{Colors.FAIL}    [{host_counter}/{total_individual}] ✗ {host}{Colors.ENDC}")
                except Exception as e:
                    results['individual_hosts']['unreachable'].append(host)
                    print(f"{Colors.WARNING}    [{host_counter}/{total_individual}] ! {host} (error){Colors.ENDC}")
    
    # Generate testing summary
    results['testing_summary'] = {
        'total_subnets_tested': total_subnets,
        'reachable_subnets_count': len(results['reachable_subnets']),
        'unreachable_subnets_count': len(results['unreachable_subnets']),
        'subnet_reachability_percentage': len(results['reachable_subnets']) / max(total_subnets, 1) * 100,
        'dns_reachability_percentage': len(results['dns_servers']['reachable']) / max(total_dns, 1) * 100 if total_dns > 0 else 0
    }
    
    return results

def test_basic_connectivity(target, timeout=3):
    """Test basic connectivity using multiple methods quickly."""
    # Method 1: ICMP ping (fastest)
    try:
        if sys.platform.startswith('win'):
            result = subprocess.run(['ping', '-n', '1', '-w', str(timeout*1000), target], 
                                  capture_output=True, text=True, timeout=timeout+1)
        else:
            result = subprocess.run(['ping', '-c', '1', '-W', str(timeout), target], 
                                  capture_output=True, text=True, timeout=timeout+1)
        
        if result.returncode == 0:
            return True
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Method 2: ARP ping for local networks (often more reliable than ICMP)
    try:
        # Check if target appears to be in local network (basic check)
        target_ip = ipaddress.ip_address(target)
        if target_ip.is_private:
            # Use nmap ARP ping for local networks
            result = subprocess.run(['nmap', '-PR', '-sn', '--max-retries', '1', 
                                   '--max-rtt-timeout', f'{timeout}s', target], 
                                  capture_output=True, text=True, timeout=timeout+2)
            if result.returncode == 0 and "Host is up" in result.stdout:
                return True
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, ValueError):
        pass
    
    # Method 3: Quick TCP tests on common ports
    common_ports = [22, 80, 443, 135, 139, 445, 3389]
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout / len(common_ports))
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return True
        except (socket.error, socket.timeout):
            continue
    
    return False

def test_optimized_connectivity(targets, timeout=3, debug=False):
    """Optimized connectivity testing with fastest methods first and verified host tracking."""
    verified_hosts = set()
    unverified_hosts = set(targets)
    
    print(f"{Colors.OKBLUE}[*] Optimized connectivity testing: fastest methods first{Colors.ENDC}")
    
    # Phase 1: ICMP ping sweep (fastest method) 
    print(f"{Colors.OKCYAN}[*] Phase 1: ICMP ping sweep (fastest)...{Colors.ENDC}")
    icmp_verified = 0
    for target in list(unverified_hosts):
        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['ping', '-n', '1', '-w', str(timeout*1000), target], 
                                      capture_output=True, text=True, timeout=timeout+1)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', str(timeout), target], 
                                      capture_output=True, text=True, timeout=timeout+1)
            
            if result.returncode == 0:
                verified_hosts.add(target)
                unverified_hosts.remove(target)
                icmp_verified += 1
                if debug:
                    print(f"{Colors.OKGREEN}[+] ICMP: {target} verified{Colors.ENDC}")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            continue
    
    print(f"{Colors.OKGREEN}[+] ICMP verified: {icmp_verified} hosts, {len(unverified_hosts)} remaining{Colors.ENDC}")
    
    if not unverified_hosts:
        return list(verified_hosts), []
    
    # Phase 2: ARP ping for local networks (often catches hosts that don't respond to ICMP)
    print(f"{Colors.OKCYAN}[*] Phase 2: ARP ping for remaining local network hosts...{Colors.ENDC}")
    arp_verified = 0
    for target in list(unverified_hosts):
        try:
            target_ip = ipaddress.ip_address(target)
            if target_ip.is_private:
                result = subprocess.run(['nmap', '-PR', '-sn', '--max-retries', '1', 
                                       '--max-rtt-timeout', f'{timeout}s', target], 
                                      capture_output=True, text=True, timeout=timeout+2)
                if result.returncode == 0 and "Host is up" in result.stdout:
                    verified_hosts.add(target)
                    unverified_hosts.remove(target)
                    arp_verified += 1
                    if debug:
                        print(f"{Colors.OKGREEN}[+] ARP: {target} verified{Colors.ENDC}")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, ValueError):
            continue
    
    print(f"{Colors.OKGREEN}[+] ARP verified: {arp_verified} hosts, {len(unverified_hosts)} remaining{Colors.ENDC}")
    
    if not unverified_hosts:
        return list(verified_hosts), []
    
    # Phase 3: TCP port checks for remaining hosts (thorough but slower)
    print(f"{Colors.OKCYAN}[*] Phase 3: TCP port checks for remaining {len(unverified_hosts)} hosts...{Colors.ENDC}")
    tcp_verified = 0
    common_ports = [22, 80, 443, 135, 139, 445, 3389]
    
    for target in list(unverified_hosts):
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout / len(common_ports))
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    verified_hosts.add(target)
                    unverified_hosts.remove(target)
                    tcp_verified += 1
                    if debug:
                        print(f"{Colors.OKGREEN}[+] TCP: {target}:{port} verified{Colors.ENDC}")
                    break  # Host verified, no need to test other ports
            except (socket.error, socket.timeout):
                continue
    
    print(f"{Colors.OKGREEN}[+] TCP verified: {tcp_verified} hosts, {len(unverified_hosts)} remaining{Colors.ENDC}")
    
    # Note: DNS testing is handled separately as it's already optimized but slow
    # DNS testing should be done last if all other methods fail
    
    print(f"{Colors.OKGREEN}[+] Fast connectivity testing complete: {len(verified_hosts)} verified, {len(unverified_hosts)} for DNS testing{Colors.ENDC}")
    
    return list(verified_hosts), list(unverified_hosts)

def generate_conservative_target_list(infrastructure, subnet_results, debug=False):
    """Generate a realistic target list based on actual reachability testing."""
    
    print(f"\n{Colors.OKGREEN}[+] Generating Realistic Target List{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Logic: ANY reachable host in subnet = entire subnet is reachable{Colors.ENDC}")
    
    final_targets = []
    decision_log = []
    
    # Add reachable DNS servers
    dns_targets = subnet_results['dns_servers']['reachable']
    if dns_targets:
        final_targets.extend(dns_targets)
        decision_log.append(f"Added {len(dns_targets)} reachable DNS servers")
        print(f"{Colors.OKCYAN}[+] DNS Servers: Added {len(dns_targets)} confirmed reachable{Colors.ENDC}")
    
    # Process ALL subnets - if ANY sample responds, include the whole subnet
    all_subnets = {**subnet_results['reachable_subnets'], **subnet_results['unreachable_subnets']}
    
    for subnet_key, subnet_info in all_subnets.items():
        subnet_data = subnet_info['subnet_data']
        reachable_count = subnet_info['reachable_count']
        total_tested = subnet_info['total_tested']
        reachability_pct = subnet_info['reachability_percentage']
        
        print(f"\n{Colors.OKCYAN}[{subnet_data['subnet_id']}] Processing subnet: {subnet_key}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Test Results: {reachable_count}/{total_tested} samples responded ({reachability_pct:.1f}%){Colors.ENDC}")
        
        if reachable_count > 0:
            # ANY response means the network is reachable
            targets_to_add = subnet_data['targets']
            final_targets.extend(targets_to_add)
            
            # Determine confidence level for user awareness
            if reachability_pct >= 50:
                confidence = "HIGH"
                reason = "majority of samples responded"
            elif reachable_count >= 3:
                confidence = "MEDIUM" 
                reason = "multiple samples responded"
            else:
                confidence = "LOW"
                reason = "minimal samples responded, but network is routable"
            
            decision_log.append(f"subnet {subnet_key}: added all {len(targets_to_add)} targets (confidence: {confidence})")
            print(f"{Colors.OKGREEN}    → INCLUDED all {len(targets_to_add)} targets{Colors.ENDC}")
            print(f"{Colors.OKGREEN}    → Confidence: {confidence} ({reason}){Colors.ENDC}")
            
        else:
            # Absolutely no response - likely not routable
            decision_log.append(f"subnet {subnet_key}: excluded - zero response from all {total_tested} samples")
            print(f"{Colors.FAIL}    → EXCLUDED (zero response from all samples - likely not routable){Colors.ENDC}")
    
    # Add individual reachable hosts
    individual_reachable = subnet_results['individual_hosts']['reachable']
    if individual_reachable:
        final_targets.extend(individual_reachable)
        decision_log.append(f"Added {len(individual_reachable)} individual reachable hosts")
        print(f"{Colors.OKCYAN}[+] Individual Hosts: Added {len(individual_reachable)} confirmed reachable{Colors.ENDC}")
    
    # Remove duplicates while preserving order
    seen = set()
    unique_targets = []
    for target in final_targets:
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)
    
    print(f"\n{Colors.OKGREEN}[+] Realistic Target List Summary:{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Total unique targets: {len(unique_targets)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Original target count: {infrastructure['analysis_summary']['total_targets']}{Colors.ENDC}")
    
    if infrastructure['analysis_summary']['total_targets'] > 0:
        reduction_pct = (1 - len(unique_targets) / infrastructure['analysis_summary']['total_targets']) * 100
        if reduction_pct > 0:
            print(f"{Colors.OKBLUE}[*] Filtered out: {reduction_pct:.1f}% (unreachable networks){Colors.ENDC}")
        else:
            print(f"{Colors.OKBLUE}[*] No networks filtered - all appear reachable{Colors.ENDC}")
    
    return unique_targets, decision_log

def run_dns_intelligence_gathering(targets, base_dir=None, debug=False, timeout=5):
    """Run comprehensive DNS intelligence gathering as first phase of reachability testing."""
    
    if base_dir:
        dns_dir = os.path.join(base_dir, "scans", "dns")
        os.makedirs(dns_dir, exist_ok=True)
    else:
        dns_dir = "./dns_intelligence"
        os.makedirs(dns_dir, exist_ok=True)
    
    print(f"{Colors.OKGREEN}[+] DNS Intelligence Gathering Phase{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Strategy: Extract reachable hosts from DNS before connectivity testing{Colors.ENDC}")
    
    start_time = time.time()
    
    # Phase 1: Discover DNS servers
    dns_servers = discover_dns_servers(targets, debug)
    print(f"{Colors.OKBLUE}[*] Found {len(dns_servers)} DNS servers to query{Colors.ENDC}")
    
    # Phase 2: Attempt zone transfers
    zone_transfer_results = attempt_zone_transfers(dns_servers, debug, timeout)
    
    # Phase 3: Reverse DNS sweeps 
    reverse_dns_results = perform_reverse_dns_sweeps(targets, dns_servers, debug, timeout)
    
    # Phase 4: Forward DNS brute forcing
    forward_dns_results = perform_forward_dns_enumeration(targets, dns_servers, debug, timeout)
    
    # Phase 5: Compile intelligence
    dns_intelligence = compile_dns_intelligence(
        zone_transfer_results, reverse_dns_results, forward_dns_results, debug
    )
    
    total_time = time.time() - start_time
    
    # Generate reports
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    generate_dns_intelligence_reports(dns_intelligence, dns_dir, timestamp, total_time)
    
    return dns_intelligence

def discover_dns_servers(targets, debug=False):
    """Discover all potential DNS servers from targets and system config."""
    dns_servers = set()
    
    print(f"{Colors.OKBLUE}[*] Phase 1: DNS Server Discovery{Colors.ENDC}")
    
    # Get system DNS servers
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns_ip = line.split()[1]
                    try:
                        ipaddress.ip_address(dns_ip)
                        dns_servers.add(dns_ip)
                        if debug:
                            print(f"{Colors.OKCYAN}    Found system DNS: {dns_ip}{Colors.ENDC}")
                    except ValueError:
                        pass
    except FileNotFoundError:
        pass
    
    # Extract potential DNS servers from target networks
    for target in targets:
        try:
            if '/' in target:
                # CIDR network
                network = ipaddress.ip_network(target, strict=False)
                if network.is_private and network.num_addresses > 2:
                    # Common DNS server positions in networks
                    common_dns_positions = [1, 2, 10, 53, 100]
                    base_ip = str(network.network_address)
                    
                    for pos in common_dns_positions:
                        try:
                            dns_candidate = str(list(network.hosts())[pos-1])
                            dns_servers.add(dns_candidate)
                        except (IndexError, ValueError):
                            pass
            else:
                # Individual IP - check if it could be a DNS server
                try:
                    ip_obj = ipaddress.ip_address(target)
                    if ip_obj.is_private:
                        octets = str(ip_obj).split('.')
                        # Add likely DNS servers in same subnet
                        subnet_dns = [
                            f"{octets[0]}.{octets[1]}.{octets[2]}.1",
                            f"{octets[0]}.{octets[1]}.{octets[2]}.2", 
                            f"{octets[0]}.{octets[1]}.{octets[2]}.10",
                            f"{octets[0]}.{octets[1]}.{octets[2]}.53"
                        ]
                        dns_servers.update(subnet_dns)
                except ValueError:
                    pass
        except ValueError:
            continue
    
    # Add common external DNS servers
    dns_servers.update(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'])
    
    # Test which DNS servers actually respond
    working_dns = []
    print(f"{Colors.OKCYAN}    Testing {len(dns_servers)} potential DNS servers...{Colors.ENDC}")
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_dns = {
            executor.submit(test_dns_connectivity, dns_server, 3): dns_server 
            for dns_server in dns_servers
        }
        
        for future in as_completed(future_to_dns):
            dns_server = future_to_dns[future]
            try:
                if future.result():
                    working_dns.append(dns_server)
                    if debug:
                        print(f"{Colors.OKGREEN}      ✓ {dns_server}{Colors.ENDC}")
            except Exception:
                pass
    
    print(f"{Colors.OKGREEN}    → {len(working_dns)} working DNS servers found{Colors.ENDC}")
    return working_dns

def attempt_zone_transfers(dns_servers, debug=False, timeout=10):
    """Attempt DNS zone transfers (AXFR) from discovered domains."""
    print(f"\n{Colors.OKBLUE}[*] Phase 2: DNS Zone Transfer Attempts{Colors.ENDC}")
    
    zone_results = {
        'successful_transfers': {},
        'failed_transfers': [],
        'discovered_domains': set(),
        'discovered_hosts': set()
    }
    
    # Common internal domain patterns to try
    common_domains = [
        'local', 'internal', 'corp', 'company', 'domain', 'ad', 'lan',
        'intranet', 'office', 'net', 'priv', 'private'
    ]
    
    # Also try reverse zones for common private networks
    reverse_zones = [
        '10.in-addr.arpa', '168.192.in-addr.arpa', 
        '16.172.in-addr.arpa', '17.172.in-addr.arpa', '18.172.in-addr.arpa'
    ]
    
    all_zones_to_try = common_domains + reverse_zones
    
    print(f"{Colors.OKCYAN}    Attempting zone transfers for {len(all_zones_to_try)} common zones...{Colors.ENDC}")
    
    for dns_server in dns_servers[:5]:  # Limit to first 5 DNS servers
        for zone in all_zones_to_try:
            try:
                if debug:
                    print(f"{Colors.OKCYAN}      Trying {zone} from {dns_server}...{Colors.ENDC}")
                
                # Use dig for zone transfer
                cmd = f"dig @{dns_server} {zone} AXFR +time={timeout}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
                
                if result.returncode == 0 and len(result.stdout) > 100:
                    # Successful transfer
                    zone_results['successful_transfers'][f"{dns_server}_{zone}"] = result.stdout
                    zone_results['discovered_domains'].add(zone)
                    
                    # Parse hosts from zone transfer
                    for line in result.stdout.split('\n'):
                        if '\tA\t' in line or '\tAAAA\t' in line:
                            parts = line.split()
                            if len(parts) >= 5:
                                hostname = parts[0].rstrip('.')
                                ip = parts[4]
                                zone_results['discovered_hosts'].add(ip)
                                if debug:
                                    print(f"{Colors.OKGREEN}        Found: {hostname} -> {ip}{Colors.ENDC}")
                    
                    print(f"{Colors.OKGREEN}    ✓ Zone transfer successful: {zone} from {dns_server}{Colors.ENDC}")
                else:
                    zone_results['failed_transfers'].append(f"{dns_server}_{zone}")
                    
            except subprocess.TimeoutExpired:
                if debug:
                    print(f"{Colors.WARNING}      Timeout: {zone} from {dns_server}{Colors.ENDC}")
            except Exception as e:
                if debug:
                    print(f"{Colors.WARNING}      Error: {zone} from {dns_server} - {e}{Colors.ENDC}")
    
    success_count = len(zone_results['successful_transfers'])
    host_count = len(zone_results['discovered_hosts'])
    
    if success_count > 0:
        print(f"{Colors.OKGREEN}    → {success_count} successful zone transfers, {host_count} hosts discovered{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}    → No successful zone transfers (transfers likely disabled){Colors.ENDC}")
    
    return zone_results

def perform_reverse_dns_sweeps(targets, dns_servers, debug=False, timeout=3):
    """Perform SMART reverse DNS sampling - not brute force sweeps."""
    print(f"\n{Colors.OKBLUE}[*] Phase 3: Smart Reverse DNS Sampling{Colors.ENDC}")
    
    reverse_results = {
        'networks_with_dns': {},
        'discovered_hosts': set(),
        'hostname_patterns': set(),
        'networks_with_no_dns': set()
    }
    
    # Extract IP networks from targets
    networks_to_sample = []
    for target in targets:
        try:
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                networks_to_sample.append(network)
            else:
                ip = ipaddress.ip_address(target)
                if ip.version == 4:
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                    networks_to_sample.append(network)
        except ValueError:
            continue
    
    total_networks = len(networks_to_sample)
    print(f"{Colors.OKCYAN}    Smart sampling {total_networks} networks (not brute forcing){Colors.ENDC}")
    
    network_counter = 0
    for network in networks_to_sample:
        network_counter += 1
        print(f"{Colors.OKCYAN}    [{network_counter}/{total_networks}] Sampling network: {network}...{Colors.ENDC}", end=' ')
        
        # SMART SAMPLING: Only test a few strategic IPs per network
        all_hosts = list(network.hosts())
        if len(all_hosts) == 0:
            print(f"{Colors.WARNING}No hosts{Colors.ENDC}")
            continue
        
        # Sample strategy: Test 5-8 strategic IPs to determine if reverse DNS exists
        sample_ips = []
        
        # Always test first few IPs (common for infrastructure)
        sample_ips.extend(all_hosts[:3])
        
        # Test some IPs from the middle
        if len(all_hosts) > 10:
            mid_point = len(all_hosts) // 2
            sample_ips.extend(all_hosts[mid_point:mid_point+2])
        
        # Test last few IPs
        if len(all_hosts) > 5:
            sample_ips.extend(all_hosts[-2:])
        
        # Remove duplicates and limit to max 8 samples
        sample_ips = list(dict.fromkeys(sample_ips))[:8]
        
        # Test samples quickly
        network_has_reverse_dns = False
        found_hosts = []
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            future_to_ip = {
                executor.submit(reverse_dns_lookup, str(ip), dns_servers[0] if dns_servers else '8.8.8.8', timeout): str(ip) 
                for ip in sample_ips
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    hostname = future.result()
                    if hostname:
                        network_has_reverse_dns = True
                        found_hosts.append((ip, hostname))
                        reverse_results['discovered_hosts'].add(ip)
                        reverse_results['hostname_patterns'].add(hostname)
                        
                        if debug:
                            print(f"\n{Colors.OKGREEN}        {ip} -> {hostname}{Colors.ENDC}")
                            
                except Exception:
                    pass
        
        if network_has_reverse_dns:
            reverse_results['networks_with_dns'][str(network)] = found_hosts
            print(f"{Colors.OKGREEN}✓ HAS REVERSE DNS ({len(found_hosts)} found){Colors.ENDC}")
            
            # If we found reverse DNS in samples, it's worth checking a few more strategic IPs
            if len(found_hosts) >= 2:
                print(f"{Colors.OKCYAN}      Network appears to use reverse DNS - checking key infrastructure IPs...{Colors.ENDC}")
                
                # Check common infrastructure IPs that might have DNS
                key_infrastructure_ips = []
                base_octets = str(network.network_address).split('.')
                
                # Common server/infrastructure IPs
                common_endings = [1, 2, 10, 25, 53, 100, 200, 250, 254]
                for ending in common_endings:
                    try:
                        potential_ip = f"{base_octets[0]}.{base_octets[1]}.{base_octets[2]}.{ending}"
                        if ipaddress.ip_address(potential_ip) in network:
                            key_infrastructure_ips.append(potential_ip)
                    except ValueError:
                        pass
                
                # Test infrastructure IPs (max 10)
                with ThreadPoolExecutor(max_workers=10) as executor:
                    infra_futures = {
                        executor.submit(reverse_dns_lookup, ip, dns_servers[0] if dns_servers else '8.8.8.8', timeout): ip 
                        for ip in key_infrastructure_ips[:10]
                    }
                    
                    for future in as_completed(infra_futures):
                        ip = infra_futures[future]
                        try:
                            hostname = future.result()
                            if hostname and ip not in [h[0] for h in found_hosts]:
                                found_hosts.append((ip, hostname))
                                reverse_results['discovered_hosts'].add(ip)
                                reverse_results['hostname_patterns'].add(hostname)
                                if debug:
                                    print(f"{Colors.OKGREEN}        Infrastructure: {ip} -> {hostname}{Colors.ENDC}")
                        except Exception:
                            pass
                
                reverse_results['networks_with_dns'][str(network)] = found_hosts
        else:
            reverse_results['networks_with_no_dns'].add(str(network))
            print(f"{Colors.FAIL}✗ No reverse DNS{Colors.ENDC}")
        
        # Show progress
        remaining = total_networks - network_counter
        if remaining > 0 and network_counter % 5 == 0:  # Show progress every 5 networks
            print(f"{Colors.OKBLUE}    Progress: {network_counter}/{total_networks} networks completed ({remaining} remaining){Colors.ENDC}")
    
    total_hosts = len(reverse_results['discovered_hosts'])
    networks_with_dns = len(reverse_results['networks_with_dns'])
    networks_without_dns = len(reverse_results['networks_with_no_dns'])
    
    print(f"{Colors.OKGREEN}    → {total_hosts} hosts with reverse DNS across {networks_with_dns} networks{Colors.ENDC}")
    print(f"{Colors.OKCYAN}    → {networks_without_dns} networks have no reverse DNS configured{Colors.ENDC}")
    
    return reverse_results

def analyze_network_infrastructure(targets, debug=False):
    """Analyze targets and identify key network infrastructure to test."""
    infrastructure = {
        'subnets': {},  # Use 'subnets' consistently
        'individual_hosts': [],
        'dns_servers': set(),
        'analysis_summary': {},
        'total_original_targets': 0
    }
    
    print(f"{Colors.OKGREEN}[+] Analyzing Target Infrastructure{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Processing {len(targets)} targets to identify network segments...{Colors.ENDC}")
    
    # Count original targets for reduction metrics
    total_original = 0
    for target in targets:
        try:
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                total_original += network.num_addresses - 2
            else:
                total_original += 1
        except ValueError:
            total_original += 1
    
    infrastructure['total_original_targets'] = total_original
    print(f"{Colors.OKBLUE}[*] Original scope: ~{total_original:,} potential targets{Colors.ENDC}")
    
    subnet_count = 0
    
    for target in targets:
        try:
            ip_obj = ipaddress.ip_address(target)
            
            if ip_obj.is_private:
                octets = str(ip_obj).split('.')
                
                if octets[0] == '10':
                    subnet_key = f"{octets[0]}.{octets[1]}.0.0/16"
                elif octets[0] == '172' and 16 <= int(octets[1]) <= 31:
                    subnet_key = f"{octets[0]}.{octets[1]}.0.0/16"
                elif octets[0] == '192' and octets[1] == '168':
                    subnet_key = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                else:
                    subnet_key = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
            else:
                subnet_key = f"public_{str(ip_obj)}"
            
            if subnet_key not in infrastructure['subnets']:
                subnet_count += 1
                infrastructure['subnets'][subnet_key] = {
                    'network': subnet_key,
                    'targets': [],
                    'sample_targets': [],
                    'key_infrastructure': [],
                    'subnet_id': subnet_count
                }
                
                try:
                    network = ipaddress.ip_network(subnet_key, strict=False)
                    if network.is_private and network.num_addresses > 2:
                        base_ip = str(network.network_address).split('.')
                        key_ips = [
                            f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.1",
                            f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.254",
                            f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.10",
                            f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.53",
                            f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.100",
                        ]
                        
                        for key_ip in key_ips:
                            try:
                                if ipaddress.ip_address(key_ip) in network:
                                    infrastructure['subnets'][subnet_key]['key_infrastructure'].append(key_ip)
                            except ValueError:
                                pass
                except ValueError:
                    pass
            
            infrastructure['subnets'][subnet_key]['targets'].append(str(ip_obj))
            
        except ValueError:
            if '/' in target:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    subnet_key = str(network)
                    
                    if subnet_key not in infrastructure['subnets']:
                        subnet_count += 1
                        infrastructure['subnets'][subnet_key] = {
                            'network': subnet_key,
                            'targets': [],
                            'sample_targets': [],
                            'key_infrastructure': [],
                            'subnet_id': subnet_count,
                            'is_full_network': True
                        }
                    
                    all_hosts = list(network.hosts())
                    if len(all_hosts) > 50:
                        sample_hosts = all_hosts[:10] + all_hosts[-10:] + all_hosts[len(all_hosts)//2:len(all_hosts)//2+10]
                        infrastructure['subnets'][subnet_key]['targets'] = [str(h) for h in sample_hosts[:30]]
                    else:
                        infrastructure['subnets'][subnet_key]['targets'] = [str(h) for h in all_hosts]
                    
                except ValueError:
                    infrastructure['individual_hosts'].append(target)
            else:
                infrastructure['individual_hosts'].append(target)
    
    # Generate sample targets for each subnet
    for subnet_key, subnet_data in infrastructure['subnets'].items():
        targets_in_subnet = subnet_data['targets']
        
        if len(targets_in_subnet) <= 5:
            subnet_data['sample_targets'] = targets_in_subnet.copy()
        else:
            sample_size = min(8, max(3, len(targets_in_subnet) // 20))
            
            samples = []
            samples.append(targets_in_subnet[0])
            if len(targets_in_subnet) > 1:
                samples.append(targets_in_subnet[-1])
            
            remaining = sample_size - len(samples)
            if remaining > 0 and len(targets_in_subnet) > 2:
                step = len(targets_in_subnet) // (remaining + 1)
                for i in range(remaining):
                    idx = (i + 1) * step
                    if idx < len(targets_in_subnet):
                        samples.append(targets_in_subnet[idx])
            
            subnet_data['sample_targets'] = list(set(samples))
        
        subnet_data['sample_targets'].extend(subnet_data['key_infrastructure'])
        subnet_data['sample_targets'] = list(set(subnet_data['sample_targets']))
    
    # Discover system DNS servers
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns_ip = line.split()[1]
                    try:
                        ipaddress.ip_address(dns_ip)
                        infrastructure['dns_servers'].add(dns_ip)
                    except ValueError:
                        pass
    except FileNotFoundError:
        pass
    
    if not infrastructure['dns_servers']:
        infrastructure['dns_servers'].update(['8.8.8.8', '1.1.1.1'])
    
    # Generate summary
    infrastructure['analysis_summary'] = {
        'total_subnets': len(infrastructure['subnets']),
        'total_targets': sum(len(e['targets']) for e in infrastructure['subnets'].values()),
        'total_samples': sum(len(e['sample_targets']) for e in infrastructure['subnets'].values()),
        'individual_hosts': len(infrastructure['individual_hosts']),
        'dns_servers': len(infrastructure['dns_servers'])
    }
    
    print(f"{Colors.OKGREEN}[+] Infrastructure Analysis Complete{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Identified {len(infrastructure['subnets'])} network subnets:{Colors.ENDC}")
    
    for subnet_key, subnet_data in infrastructure['subnets'].items():
        subnet_id = subnet_data['subnet_id']
        target_count = len(subnet_data['targets'])
        sample_count = len(subnet_data['sample_targets'])
        
        print(f"{Colors.OKCYAN}    [{subnet_id}] {subnet_key}: {target_count} targets → {sample_count} samples{Colors.ENDC}")
        
        if debug:
            print(f"{Colors.OKCYAN}        Sample IPs: {', '.join(subnet_data['sample_targets'][:5])}{'...' if len(subnet_data['sample_targets']) > 5 else ''}{Colors.ENDC}")
    
    if infrastructure['individual_hosts']:
        print(f"{Colors.OKCYAN}    Individual hosts: {len(infrastructure['individual_hosts'])}{Colors.ENDC}")
    
    print(f"{Colors.OKBLUE}[*] Total testing targets: {infrastructure['analysis_summary']['total_samples']} (vs {infrastructure['analysis_summary']['total_targets']} original){Colors.ENDC}")
    
    return infrastructure

def perform_forward_dns_enumeration(targets, dns_servers, debug=False, timeout=3):
    """Perform forward DNS enumeration using common hostname patterns."""
    print(f"\n{Colors.OKBLUE}[*] Phase 4: Forward DNS Enumeration{Colors.ENDC}")
    
    forward_results = {
        'discovered_hosts': set(),
        'successful_queries': {},
        'domain_patterns': set()
    }
    
    # Common hostname patterns for internal networks
    common_hostnames = [
        'dc', 'dc1', 'dc2', 'dc01', 'dc02', 'domain', 'ad', 'ldap',
        'dns', 'dns1', 'dns2', 'ns', 'ns1', 'ns2',
        'mail', 'exchange', 'smtp', 'pop', 'imap',
        'web', 'www', 'intranet', 'portal', 'sharepoint',
        'db', 'database', 'sql', 'mysql', 'oracle',
        'file', 'files', 'fs', 'nas', 'share', 'fileserver',
        'backup', 'bkp', 'archive',
        'fw', 'firewall', 'gw', 'gateway', 'router',
        'monitor', 'nagios', 'zabbix', 'snmp',
        'print', 'printer', 'cups',
        'vm', 'vmware', 'vcenter', 'esxi',
        'admin', 'mgmt', 'management', 'console'
    ]
    
    # Extract potential domains from any hostname patterns we found
    potential_domains = set(['local', 'internal', 'corp', 'domain', 'ad'])
    
    # If we have DNS servers, try to extract domain from their configuration
    for dns_server in dns_servers[:3]:
        try:
            # Try to get the DNS server's domain
            cmd = f"dig @{dns_server} . NS +short +time=3"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if '.' in line:
                        domain_parts = line.strip('.').split('.')
                        if len(domain_parts) >= 2:
                            potential_domains.add('.'.join(domain_parts[-2:]))
        except:
            pass
    
    print(f"{Colors.OKCYAN}    Testing {len(common_hostnames)} hostnames across {len(potential_domains)} domains...{Colors.ENDC}")
    
    queries_to_test = []
    for domain in potential_domains:
        for hostname in common_hostnames:
            fqdn = f"{hostname}.{domain}"
            queries_to_test.append(fqdn)
    
    # Limit total queries to reasonable number
    if len(queries_to_test) > 200:
        queries_to_test = queries_to_test[:200]
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_query = {
            executor.submit(forward_dns_lookup, query, dns_servers[0] if dns_servers else '8.8.8.8', timeout): query 
            for query in queries_to_test
        }
        
        successful_count = 0
        for future in as_completed(future_to_query):
            query = future_to_query[future]
            try:
                ip = future.result()
                if ip:
                    forward_results['discovered_hosts'].add(ip)
                    forward_results['successful_queries'][query] = ip
                    forward_results['domain_patterns'].add(query.split('.', 1)[1])
                    successful_count += 1
                    
                    if debug:
                        print(f"{Colors.OKGREEN}      {query} -> {ip}{Colors.ENDC}")
                        
            except Exception:
                pass
    
    print(f"{Colors.OKGREEN}    → {successful_count} successful DNS queries, {len(forward_results['discovered_hosts'])} unique hosts{Colors.ENDC}")
    
    return forward_results

def reverse_dns_lookup(ip, dns_server, timeout=3):
    """Perform reverse DNS lookup for an IP address."""
    try:
        cmd = f"dig @{dns_server} -x {ip} +short +time={timeout}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout+1)
        
        if result.returncode == 0 and result.stdout.strip():
            hostname = result.stdout.strip().split('\n')[0].rstrip('.')
            if hostname and not hostname.startswith(';'):
                return hostname
    except:
        pass
    
    return None

def forward_dns_lookup(hostname, dns_server, timeout=3):
    """Perform forward DNS lookup for a hostname."""
    try:
        cmd = f"dig @{dns_server} {hostname} A +short +time={timeout}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout+1)
        
        if result.returncode == 0 and result.stdout.strip():
            ip = result.stdout.strip().split('\n')[0]
            # Validate it's actually an IP
            try:
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                pass
    except:
        pass
    
    return None

def compile_dns_intelligence(zone_results, reverse_results, forward_results, debug=False):
    """Compile all DNS intelligence into actionable target list."""
    print(f"\n{Colors.OKBLUE}[*] Phase 5: Compiling DNS Intelligence{Colors.ENDC}")
    
    intelligence = {
        'high_value_targets': set(),    # Hosts from DNS that likely exist
        'medium_value_targets': set(),  # Hosts from patterns/inference
        'discovered_domains': set(),
        'dns_summary': {},
        'recommendations': []
    }
    
    # Compile all discovered hosts
    all_discovered_hosts = set()
    
    # Zone transfer results (highest confidence)
    if zone_results['discovered_hosts']:
        all_discovered_hosts.update(zone_results['discovered_hosts'])
        intelligence['high_value_targets'].update(zone_results['discovered_hosts'])
        intelligence['recommendations'].append(f"Zone transfers revealed {len(zone_results['discovered_hosts'])} hosts")
    
    # Reverse DNS results (high confidence - these hosts have DNS records)
    if reverse_results['discovered_hosts']:
        all_discovered_hosts.update(reverse_results['discovered_hosts'])
        intelligence['high_value_targets'].update(reverse_results['discovered_hosts'])
        intelligence['recommendations'].append(f"Reverse DNS found {len(reverse_results['discovered_hosts'])} hosts")
    
    # Forward DNS results (high confidence - these hosts resolve)
    if forward_results['discovered_hosts']:
        all_discovered_hosts.update(forward_results['discovered_hosts'])
        intelligence['high_value_targets'].update(forward_results['discovered_hosts'])
        intelligence['recommendations'].append(f"Forward DNS enumeration found {len(forward_results['discovered_hosts'])} hosts")
    
    # Compile discovered domains
    intelligence['discovered_domains'].update(zone_results['discovered_domains'])
    intelligence['discovered_domains'].update(forward_results['domain_patterns'])
    
    # Generate summary
    intelligence['dns_summary'] = {
        'total_discovered_hosts': len(all_discovered_hosts),
        'zone_transfer_hosts': len(zone_results['discovered_hosts']),
        'reverse_dns_hosts': len(reverse_results['discovered_hosts']),
        'forward_dns_hosts': len(forward_results['discovered_hosts']),
        'discovered_domains': len(intelligence['discovered_domains']),
        'successful_zone_transfers': len(zone_results['successful_transfers'])
    }
    
    print(f"{Colors.OKGREEN}[+] DNS Intelligence Summary:{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Total hosts discovered via DNS: {len(all_discovered_hosts)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] High-value targets (DNS confirmed): {len(intelligence['high_value_targets'])}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Domains discovered: {len(intelligence['discovered_domains'])}{Colors.ENDC}")
    
    if len(all_discovered_hosts) > 0:
        intelligence['recommendations'].append("Focus initial scanning on DNS-discovered hosts")
        print(f"{Colors.OKGREEN}[+] Recommendation: Prioritize the {len(all_discovered_hosts)} DNS-confirmed targets{Colors.ENDC}")
    else:
        intelligence['recommendations'].append("No DNS intelligence gathered - proceed with standard reachability testing")
        print(f"{Colors.WARNING}[!] No hosts discovered via DNS - proceeding with connectivity testing{Colors.ENDC}")
    
    return intelligence

def generate_dns_intelligence_reports(intelligence, dns_dir, timestamp, total_time):
    """Generate DNS intelligence reports."""
    
    # Main DNS targets file
    dns_targets_file = os.path.join(dns_dir, f"dns_discovered_targets_{timestamp}.txt")
    with open(dns_targets_file, 'w') as f:
        f.write(f"# DNS Intelligence Gathering Results\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Duration: {total_time:.2f} seconds\n")
        f.write(f"# Total DNS-confirmed targets: {len(intelligence['high_value_targets'])}\n\n")
        
        for target in sorted(intelligence['high_value_targets'], 
                           key=lambda x: ipaddress.ip_address(x) if x.replace('.','').isdigit() else x):
            f.write(f"{target}\n")
    
    # Detailed intelligence report
    intel_report = os.path.join(dns_dir, f"dns_intelligence_report_{timestamp}.txt")
    with open(intel_report, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("DNS INTELLIGENCE GATHERING REPORT\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Duration: {total_time:.2f} seconds\n\n")
        
        summary = intelligence['dns_summary']
        f.write("DISCOVERY SUMMARY:\n")
        f.write("-" * 17 + "\n")
        f.write(f"Total Hosts Discovered: {summary['total_discovered_hosts']}\n")
        f.write(f"Zone Transfer Hosts: {summary['zone_transfer_hosts']}\n")
        f.write(f"Reverse DNS Hosts: {summary['reverse_dns_hosts']}\n")
        f.write(f"Forward DNS Hosts: {summary['forward_dns_hosts']}\n")
        f.write(f"Domains Discovered: {summary['discovered_domains']}\n")
        f.write(f"Successful Zone Transfers: {summary['successful_zone_transfers']}\n\n")
        
        f.write("RECOMMENDATIONS:\n")
        f.write("-" * 15 + "\n")
        for rec in intelligence['recommendations']:
            f.write(f"• {rec}\n")
    
    print(f"{Colors.OKBLUE}[*] DNS targets file: {dns_targets_file}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Intelligence report: {intel_report}{Colors.ENDC}")

def run_smart_network_reachability_test(targets, base_dir=None, standalone=False, debug=False, 
                                       threads=None, timeout=None):
    """Run comprehensive reachability assessment: DNS intelligence + connectivity testing."""
    
    test_timeout = timeout if timeout is not None else REACHABILITY_TIMEOUT
    
    if base_dir:
        reachability_dir = os.path.join(base_dir, "scans", "reachability")
        os.makedirs(reachability_dir, exist_ok=True)
    else:
        reachability_dir = "./reachability_results"
        os.makedirs(reachability_dir, exist_ok=True)
    
    print(f"{Colors.OKGREEN}[+] Comprehensive Network Reachability Assessment{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Strategy: DNS intelligence + connectivity testing for maximum coverage{Colors.ENDC}")
    
    start_time = time.time()
    
    # Phase 1: DNS Intelligence Gathering
    print(f"\n{Colors.OKGREEN}=== PHASE 1: DNS INTELLIGENCE GATHERING ==={Colors.ENDC}")
    dns_intelligence = run_dns_intelligence_gathering(targets, base_dir, debug, test_timeout)
    
    # Phase 2: Infrastructure Analysis and Connectivity Testing
    print(f"\n{Colors.OKGREEN}=== PHASE 2: NETWORK CONNECTIVITY TESTING ==={Colors.ENDC}")
    infrastructure = analyze_network_infrastructure(targets, debug)
    subnet_results = test_subnet_reachability(infrastructure, debug, test_timeout)
    connectivity_targets, decision_log = generate_conservative_target_list(infrastructure, subnet_results, debug)
    
    # Phase 3: Combine and Validate Results
    print(f"\n{Colors.OKGREEN}=== PHASE 3: RESULTS INTEGRATION ==={Colors.ENDC}")
    final_results = integrate_dns_and_connectivity_results(
        dns_intelligence, connectivity_targets, debug, test_timeout
    )
    
    total_time = time.time() - start_time
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    # Generate comprehensive reports
    return generate_comprehensive_reachability_reports(
        final_results, dns_intelligence, infrastructure, subnet_results, 
        decision_log, reachability_dir, timestamp, total_time, standalone, debug
    )

def integrate_dns_and_connectivity_results(dns_intelligence, connectivity_targets, debug=False, timeout=3):
    """Integrate DNS intelligence with connectivity test results."""
    print(f"{Colors.OKBLUE}[*] Integrating DNS intelligence with connectivity results...{Colors.ENDC}")
    
    results = {
        'dns_confirmed': list(dns_intelligence['high_value_targets']),
        'connectivity_confirmed': connectivity_targets,
        'validated_targets': [],  # DNS targets that also pass connectivity
        'dns_only_targets': [],   # DNS targets that don't respond to connectivity
        'connectivity_only_targets': [],  # Connectivity targets not in DNS
        'final_target_list': [],
        'validation_summary': {}
    }
    
    dns_targets = set(dns_intelligence['high_value_targets'])
    conn_targets = set(connectivity_targets)
    
    # Find overlaps and differences
    overlap_targets = dns_targets.intersection(conn_targets)
    dns_only = dns_targets - conn_targets
    connectivity_only = conn_targets - dns_targets
    
    print(f"{Colors.OKCYAN}    DNS-discovered targets: {len(dns_targets)}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}    Connectivity-confirmed targets: {len(conn_targets)}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}    Overlap (DNS + connectivity): {len(overlap_targets)}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}    DNS-only targets: {len(dns_only)}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}    Connectivity-only targets: {len(connectivity_only)}{Colors.ENDC}")
    
    # Validate DNS-only targets with quick connectivity test
    if dns_only:
        print(f"{Colors.OKBLUE}[*] Validating {len(dns_only)} DNS-only targets...{Colors.ENDC}")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_target = {
                executor.submit(test_basic_connectivity, target, timeout): target 
                for target in dns_only
            }
            
            validated_count = 0
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    is_reachable = future.result()
                    if is_reachable:
                        results['validated_targets'].append(target)
                        validated_count += 1
                        if debug:
                            print(f"{Colors.OKGREEN}      ✓ {target} (DNS + validated){Colors.ENDC}")
                    else:
                        results['dns_only_targets'].append(target)
                        if debug:
                            print(f"{Colors.WARNING}      - {target} (DNS only, no connectivity){Colors.ENDC}")
                except Exception:
                    results['dns_only_targets'].append(target)
        
        print(f"{Colors.OKGREEN}    → {validated_count}/{len(dns_only)} DNS targets validated via connectivity{Colors.ENDC}")
    
    # Build final target list with prioritization
    results['connectivity_confirmed'] = list(conn_targets)
    results['connectivity_only_targets'] = list(connectivity_only)
    
    # Priority order for final list:
    # 1. Overlap targets (DNS + connectivity confirmed) - HIGHEST priority
    # 2. Validated DNS targets (DNS + newly validated) - HIGH priority  
    # 3. Connectivity-only targets - MEDIUM priority
    # 4. DNS-only targets (DNS but no connectivity) - LOW priority
    
    final_targets = []
    
    # Add overlap targets (highest confidence)
    final_targets.extend(sorted(overlap_targets))
    
    # Add validated DNS targets
    final_targets.extend(sorted(results['validated_targets']))
    
    # Add connectivity-only targets
    final_targets.extend(sorted(connectivity_only))
    
    # Add DNS-only targets (might be offline but worth trying)
    final_targets.extend(sorted(results['dns_only_targets']))
    
    results['final_target_list'] = final_targets
    
    # Generate summary
    results['validation_summary'] = {
        'total_unique_targets': len(final_targets),
        'dns_discovered': len(dns_targets),
        'connectivity_confirmed': len(conn_targets),
        'high_confidence': len(overlap_targets) + len(results['validated_targets']),
        'medium_confidence': len(connectivity_only),
        'low_confidence': len(results['dns_only_targets']),
        'coverage_improvement': len(final_targets) - max(len(dns_targets), len(conn_targets))
    }
    
    print(f"\n{Colors.OKGREEN}[+] Integration Complete:{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Final target list: {len(final_targets)} unique targets{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[*] High confidence: {results['validation_summary']['high_confidence']} targets (DNS + connectivity){Colors.ENDC}")
    print(f"{Colors.WARNING}[*] Medium confidence: {results['validation_summary']['medium_confidence']} targets (connectivity only){Colors.ENDC}")
    print(f"{Colors.OKCYAN}[*] Low confidence: {results['validation_summary']['low_confidence']} targets (DNS only){Colors.ENDC}")
    
    coverage_improvement = results['validation_summary']['coverage_improvement']
    if coverage_improvement > 0:
        print(f"{Colors.OKGREEN}[+] Combined approach found {coverage_improvement} additional targets vs single method{Colors.ENDC}")
    
    return results

def generate_comprehensive_reachability_reports(final_results, dns_intelligence, infrastructure, 
                                              subnet_results, decision_log, reachability_dir, 
                                              timestamp, total_time, standalone, debug):
    """Generate comprehensive reports combining DNS and connectivity intelligence."""
    
    final_targets = final_results['final_target_list']
    
    # 1. Main reachable targets file (prioritized)
    reachable_file = os.path.join(reachability_dir, f"reachable_targets_{timestamp}.txt")
    with open(reachable_file, 'w') as f:
        f.write(f"# Comprehensive Network Reachability Assessment Results\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Assessment Duration: {total_time:.2f} seconds\n")
        f.write(f"# Method: DNS Intelligence + Connectivity Testing\n")
        f.write(f"# Total Targets: {len(final_targets)}\n")
        f.write(f"# High Confidence: {final_results['validation_summary']['high_confidence']}\n")
        f.write(f"# Medium Confidence: {final_results['validation_summary']['medium_confidence']}\n")
        f.write(f"# Low Confidence: {final_results['validation_summary']['low_confidence']}\n\n")
        f.write(f"# Target Priority Order:\n")
        f.write(f"# 1. DNS + Connectivity confirmed (lines 1-{len(final_results['validated_targets']) + len(set(final_results['dns_confirmed']).intersection(set(final_results['connectivity_confirmed'])))})\n")
        f.write(f"# 2. Connectivity-only confirmed\n") 
        f.write(f"# 3. DNS-only targets\n\n")
        
        for target in final_targets:
            f.write(f"{target}\n")
    
    # 2. High confidence targets only
    high_confidence_file = os.path.join(reachability_dir, f"high_confidence_targets_{timestamp}.txt")
    high_conf_targets = (set(final_results['dns_confirmed']).intersection(set(final_results['connectivity_confirmed'])) | 
                        set(final_results['validated_targets']))
    
    with open(high_confidence_file, 'w') as f:
        f.write(f"# High Confidence Targets Only (DNS + Connectivity Confirmed)\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Count: {len(high_conf_targets)}\n\n")
        for target in sorted(high_conf_targets):
            f.write(f"{target}\n")
    
    # 3. Comprehensive assessment report
    assessment_report = os.path.join(reachability_dir, f"comprehensive_assessment_{timestamp}.txt")
    with open(assessment_report, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("COMPREHENSIVE NETWORK REACHABILITY ASSESSMENT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Assessment Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Duration: {total_time:.2f} seconds\n")
        f.write(f"Assessment Method: DNS Intelligence + Network Connectivity Testing\n\n")
        
        f.write("METHODOLOGY:\n")
        f.write("-" * 12 + "\n")
        f.write("1. DNS Intelligence Gathering:\n")
        f.write("   - Zone transfer attempts\n")
        f.write("   - Reverse DNS sweeps\n")
        f.write("   - Forward DNS enumeration\n")
        f.write("2. Network Connectivity Testing:\n")
        f.write("   - Subnet-based reachability\n")
        f.write("   - Infrastructure validation\n")
        f.write("3. Results Integration and Validation\n\n")
        
        f.write("DNS INTELLIGENCE RESULTS:\n")
        f.write("-" * 25 + "\n")
        dns_summary = dns_intelligence['dns_summary']
        f.write(f"Total DNS-discovered hosts: {dns_summary['total_discovered_hosts']}\n")
        f.write(f"Zone transfer hosts: {dns_summary['zone_transfer_hosts']}\n")
        f.write(f"Reverse DNS hosts: {dns_summary['reverse_dns_hosts']}\n")
        f.write(f"Forward DNS hosts: {dns_summary['forward_dns_hosts']}\n")
        f.write(f"Discovered domains: {dns_summary['discovered_domains']}\n\n")
        
        f.write("CONNECTIVITY TESTING RESULTS:\n")
        f.write("-" * 29 + "\n")
        f.write(f"Reachable subnets: {len(subnet_results['reachable_subnets'])}\n")
        f.write(f"Unreachable subnets: {len(subnet_results['unreachable_subnets'])}\n")
        f.write(f"Connectivity-confirmed targets: {len(final_results['connectivity_confirmed'])}\n\n")
        
        f.write("FINAL ASSESSMENT SUMMARY:\n")
        f.write("-" * 25 + "\n")
        summary = final_results['validation_summary']
        f.write(f"Total Unique Targets: {summary['total_unique_targets']}\n")
        f.write(f"High Confidence (DNS + Connectivity): {summary['high_confidence']}\n")
        f.write(f"Medium Confidence (Connectivity only): {summary['medium_confidence']}\n")
        f.write(f"Low Confidence (DNS only): {summary['low_confidence']}\n")
        f.write(f"Coverage Improvement: +{summary['coverage_improvement']} targets vs single method\n\n")
        
        f.write("RECOMMENDATIONS:\n")
        f.write("-" * 15 + "\n")
        f.write("1. Prioritize high-confidence targets for initial scanning\n")
        f.write("2. Use medium-confidence targets for comprehensive coverage\n")
        f.write("3. Test low-confidence targets last (may be offline)\n")
        if dns_summary['zone_transfer_hosts'] > 0:
            f.write("4. Zone transfers were successful - high intelligence value\n")
        if summary['coverage_improvement'] > 0:
            f.write(f"5. Combined approach provided {summary['coverage_improvement']} additional targets\n")
    
    # Print final summary
    print(f"\n{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Comprehensive Network Reachability Assessment Complete!{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Assessment Duration: {total_time:.2f} seconds{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Total Targets Found: {len(final_targets)}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] High Confidence Targets: {final_results['validation_summary']['high_confidence']}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] All targets: {reachable_file}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] High confidence only: {high_confidence_file}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Full assessment report: {assessment_report}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
    
    return final_targets, [], []  # Compatible with existing code

def run_nmap_discovery(base_dir, targets, stealth=False, quick=False, enhanced=False, debug=False):
    """Run comprehensive port scanning with enhanced options."""
    nmap_dir = os.path.join(base_dir, "scans", "nmap")
    target_file = os.path.join(nmap_dir, "targets.txt")
    
    # Write targets to file
    with open(target_file, 'w') as f:
        f.write('\n'.join(targets))
    
    print(f"{Colors.OKGREEN}[+] Starting {'Enhanced ' if enhanced else ''}Nmap Port Scanning{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Targets already validated by reachability testing{Colors.ENDC}")
    
    # Use targets directly since they've been validated by reachability testing
    alive_hosts = targets
    
    # Write alive hosts file for consistency with existing structure
    alive_file = os.path.join(nmap_dir, "alive_hosts.txt")
    with open(alive_file, 'w') as f:
        f.write('\n'.join(alive_hosts))
    
    # Copy to targets directory for reference
    alive_copy = os.path.join(base_dir, "targets", "alive_hosts.txt")
    with open(alive_copy, 'w') as f:
        f.write('\n'.join(alive_hosts))
    
    print(f"{Colors.OKGREEN}[+] Scanning {len(alive_hosts)} validated targets{Colors.ENDC}")
    
    # For large target lists, break into smaller chunks to avoid timeouts
    chunk_size = 200 if len(alive_hosts) > 500 else len(alive_hosts)
    target_chunks = [alive_hosts[i:i + chunk_size] for i in range(0, len(alive_hosts), chunk_size)]
    
    if len(target_chunks) > 1:
        print(f"{Colors.OKBLUE}[*] Breaking {len(alive_hosts)} targets into {len(target_chunks)} chunks of ~{chunk_size} for efficiency{Colors.ENDC}")
    
    # Enhanced scanning modes
    timing = "-T2" if stealth else "-T3"
    
    # Adjust timeouts based on target count for efficiency
    if len(alive_hosts) > 500:
        # Very large scan - use shorter timeouts
        host_timeout = "120s"
        max_retries = "1"
        print(f"{Colors.OKBLUE}[*] Large target set detected - using shorter timeouts for efficiency{Colors.ENDC}")
    elif len(alive_hosts) > 200:
        # Medium scan - moderate timeouts
        host_timeout = "240s"
        max_retries = "1"
    else:
        # Small scan - normal timeouts
        host_timeout = "300s"
        max_retries = "2"
    
    if quick:
        # Quick mode: Low hanging fruit ports only, skip UDP for speed
        print(f"{Colors.OKBLUE}[*] Running Quick Mode: Low hanging fruit TCP ports (no UDP){Colors.ENDC}")
        
        # Focus on most common services for quick wins
        quick_ports = "21,22,23,25,53,80,110,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080,8443"
        
        # Process chunks for quick scan
        for i, chunk in enumerate(target_chunks, 1):
            chunk_file = os.path.join(nmap_dir, f"chunk_{i}_targets.txt")
            with open(chunk_file, 'w') as f:
                f.write('\n'.join(chunk))
                
            print(f"{Colors.OKCYAN}[*] Quick scan chunk {i}/{len(target_chunks)} ({len(chunk)} targets)...{Colors.ENDC}")
            tcp_cmd = f"nmap -sSV -Pn -n -p {quick_ports} {timing} --max-parallelism 50 --max-retries {max_retries} --host-timeout {host_timeout} -iL {chunk_file} -oA {os.path.join(nmap_dir, f'tcp_quick_chunk_{i}')}"
            
            result = run_command(tcp_cmd, debug=debug, stealth=stealth)
            if result is None:
                print(f"{Colors.WARNING}[!] Quick scan chunk {i} timed out, continuing with next chunk...{Colors.ENDC}")
        
    else:
        # Standard mode: Top 1000 TCP + 500 UDP, then enhanced scans
        print(f"{Colors.OKBLUE}[*] Running Standard Mode: Progressive scanning for fast results{Colors.ENDC}")
        
        # Phase 1: TCP top 1000 ports in chunks
        print(f"{Colors.OKBLUE}[*] Phase 1: Running TCP top 1000 ports...{Colors.ENDC}")
        for i, chunk in enumerate(target_chunks, 1):
            chunk_file = os.path.join(nmap_dir, f"chunk_{i}_targets.txt")
            with open(chunk_file, 'w') as f:
                f.write('\n'.join(chunk))
                
            print(f"{Colors.OKCYAN}[*] TCP scan chunk {i}/{len(target_chunks)} ({len(chunk)} targets)...{Colors.ENDC}")
            tcp_cmd = f"nmap -sSV -Pn -n --top-ports 1000 {timing} --max-parallelism 50 --max-retries {max_retries} --host-timeout {host_timeout} -iL {chunk_file} -oA {os.path.join(nmap_dir, f'tcp_top1000_chunk_{i}')}"
            
            tcp_result = run_command(tcp_cmd, debug=debug, stealth=stealth)
            if tcp_result is None:
                print(f"{Colors.WARNING}[!] TCP chunk {i} timed out, continuing with next chunk...{Colors.ENDC}")
        
        # Phase 2: UDP top 500 ports in chunks
        print(f"{Colors.OKBLUE}[*] Phase 2: Running UDP top 500 ports...{Colors.ENDC}")
        for i, chunk in enumerate(target_chunks, 1):
            chunk_file = os.path.join(nmap_dir, f"chunk_{i}_targets.txt")
            
            print(f"{Colors.OKCYAN}[*] UDP scan chunk {i}/{len(target_chunks)} ({len(chunk)} targets)...{Colors.ENDC}")
            udp_cmd = f"nmap -sU --top-ports 500 {timing} --max-parallelism 25 --max-retries 1 -iL {chunk_file} -oA {os.path.join(nmap_dir, f'udp_top500_chunk_{i}')}"
            
            udp_result = run_command(udp_cmd, debug=debug, stealth=stealth)
            if udp_result is None:
                print(f"{Colors.WARNING}[!] UDP chunk {i} timed out, continuing with next chunk...{Colors.ENDC}")
        
        # Phase 3: Enhanced scans if enhanced mode enabled
        if enhanced:
            print(f"{Colors.OKBLUE}[*] Phase 3: Running Enhanced Comprehensive Scans{Colors.ENDC}")
            
            for i, chunk in enumerate(target_chunks, 1):
                chunk_file = os.path.join(nmap_dir, f"chunk_{i}_targets.txt")
                
                # Full TCP port scan with comprehensive service detection
                print(f"{Colors.OKCYAN}[*] Enhanced TCP scan chunk {i}/{len(target_chunks)}...{Colors.ENDC}")
                tcp_full_cmd = f"nmap -sT -sV -sC -A --version-all {timing} -p- --max-parallelism 50 --max-retries {max_retries} --host-timeout 600s -iL {chunk_file} -oA {os.path.join(nmap_dir, f'tcp_full_enhanced_chunk_{i}')}"
                
                tcp_full_result = run_command(tcp_full_cmd, debug=debug, stealth=stealth)
                if tcp_full_result is None:
                    print(f"{Colors.WARNING}[!] Enhanced TCP chunk {i} timed out, continuing...{Colors.ENDC}")
                
                # Comprehensive UDP scan
                print(f"{Colors.OKCYAN}[*] Enhanced UDP scan chunk {i}/{len(target_chunks)}...{Colors.ENDC}")
                udp_enhanced_cmd = f"nmap -sU -sV --top-ports 1000 {timing} --max-parallelism 25 --max-retries 1 -iL {chunk_file} -oA {os.path.join(nmap_dir, f'udp_top1000_enhanced_chunk_{i}')}"
                
                udp_enhanced_result = run_command(udp_enhanced_cmd, debug=debug, stealth=stealth)
                if udp_enhanced_result is None:
                    print(f"{Colors.WARNING}[!] Enhanced UDP chunk {i} timed out, continuing...{Colors.ENDC}")
    
    # Phase 4: Additional scanning phases (post-discovery enumeration)
    print(f"{Colors.OKBLUE}[*] Phase 4: Post-Discovery Service Enumeration{Colors.ENDC}")
    
    # DNS enumeration
    print(f"{Colors.OKCYAN}[*] Running DNS enumeration...{Colors.ENDC}")
    run_enhanced_dns_enumeration(base_dir, alive_hosts, debug)
    
    # SMB enumeration  
    print(f"{Colors.OKCYAN}[*] Running SMB enumeration...{Colors.ENDC}")
    run_enhanced_smb_enumeration(base_dir, alive_hosts, debug)
    
    # Web enumeration
    print(f"{Colors.OKCYAN}[*] Running web enumeration...{Colors.ENDC}")
    run_enhanced_web_enumeration(base_dir, alive_hosts, stealth, debug)
    
    # Final summary
    print(f"\n{Colors.OKGREEN}[+] Nmap Discovery Phase Complete{Colors.ENDC}")
    if len(target_chunks) > 1:
        print(f"{Colors.OKBLUE}[*] Processed {len(target_chunks)} chunks covering {len(alive_hosts)} targets{Colors.ENDC}")
    
    # Count completed scan files
    scan_files = list(Path(nmap_dir).glob("*.gnmap"))
    print(f"{Colors.OKBLUE}[*] Generated {len(scan_files)} nmap result files{Colors.ENDC}")
    
    # Parse and summarize discovered services
    discovered_services = discover_services_from_nmap(base_dir)
    total_services = sum(len(services) for services in discovered_services.values())
    hosts_with_services = len(discovered_services)
    
    if hosts_with_services > 0:
        print(f"{Colors.OKGREEN}[*] Discovered {total_services} services across {hosts_with_services} responsive hosts{Colors.ENDC}")
        
        # Show top service types
        service_counts = {}
        for host_services in discovered_services.values():
            for service in host_services:
                service_name = service['service']
                service_counts[service_name] = service_counts.get(service_name, 0) + 1
        
        top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_services:
            print(f"{Colors.OKBLUE}[*] Top services found: {', '.join([f'{svc}({count})' for svc, count in top_services])}{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}[!] No responsive hosts with open ports discovered{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] This could be due to: firewalls, timeouts, or network filtering{Colors.ENDC}")
    
    return alive_hosts

def run_enhanced_web_enumeration(base_dir, targets, stealth=False, debug=False):
    """Enhanced web enumeration with multiple tools."""
    web_dir = os.path.join(base_dir, "scans", "web")
    
    print(f"{Colors.OKGREEN}[+] Starting Enhanced Web Enumeration{Colors.ENDC}")
    
    # Discover web services from nmap results
    services = discover_services_from_nmap(base_dir)
    web_services = []
    
    for ip, service_list in services.items():
        for service in service_list:
            if (service['service'] in ['http', 'https', 'http-proxy', 'ssl/http'] or 
                service['port'] in ['80', '443', '8080', '8443', '8000', '8888']):
                
                protocol = "https" if service['ssl'] or service['port'] in ['443', '8443'] else "http"
                web_services.append({
                    'ip': ip,
                    'port': service['port'],
                    'protocol': protocol,
                    'service': service['service']
                })
    
    if not web_services:
        print(f"{Colors.WARNING}[!] No web services identified{Colors.ENDC}")
        return
    
    print(f"{Colors.OKGREEN}[+] Found {len(web_services)} web services for enhanced enumeration{Colors.ENDC}")
    
    for web_service in web_services:
        ip = web_service['ip']
        port = web_service['port']
        protocol = web_service['protocol']
        base_url = f"{protocol}://{ip}:{port}"
        
        print(f"{Colors.OKCYAN}[*] Enhanced enumeration of {base_url}{Colors.ENDC}")
        
        # Create service-specific directory
        service_dir = os.path.join(web_dir, f"{protocol}_{port}")
        os.makedirs(service_dir, exist_ok=True)
        
        # 1. Basic HTTP Information
        print(f"{Colors.OKCYAN}[*] Gathering basic HTTP information...{Colors.ENDC}")
        
        # Curl for headers and basic info
        curl_cmd = f"curl -sSikL --max-time 10 {base_url}/"
        curl_output = os.path.join(service_dir, f"curl_headers_{ip}_{port}.txt")
        run_command(curl_cmd, curl_output, debug=debug, stealth=stealth)
        
        # Curl robots.txt
        robots_cmd = f"curl -sSik --max-time 10 {base_url}/robots.txt"
        robots_output = os.path.join(service_dir, f"robots_{ip}_{port}.txt")
        run_command(robots_cmd, robots_output, debug=debug, stealth=stealth)
        
        # 2. WhatWeb for technology identification
        which_whatweb = run_command("which whatweb", debug=debug)
        if which_whatweb and which_whatweb.returncode == 0:
            print(f"{Colors.OKCYAN}[*] Running WhatWeb technology identification...{Colors.ENDC}")
            whatweb_cmd = f"whatweb --color=never --no-errors -a 3 -v {base_url}"
            whatweb_output = os.path.join(service_dir, f"whatweb_{ip}_{port}.txt")
            run_command(whatweb_cmd, whatweb_output, debug=debug, stealth=stealth)
        
        # 3. Nikto vulnerability scanning
        which_nikto = run_command("which nikto", debug=debug)
        if which_nikto and which_nikto.returncode == 0:
            print(f"{Colors.OKCYAN}[*] Running Nikto vulnerability scan...{Colors.ENDC}")
            nikto_cmd = f"nikto -ask=no -h {base_url}"
            if stealth:
                nikto_cmd += " -T 2"
            nikto_output = os.path.join(service_dir, f"nikto_{ip}_{port}.txt")
            run_command(nikto_cmd, nikto_output, debug=debug, stealth=stealth)
        
        # 4. Directory brute forcing with gobuster (prioritized) and feroxbuster
        print(f"{Colors.OKCYAN}[*] Running directory enumeration...{Colors.ENDC}")
        
        # Primary wordlists to try (in order of preference)
        wordlists = [
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
        ]
        
        # Find the first available wordlist
        wordlist_to_use = None
        for wordlist in wordlists:
            if os.path.exists(wordlist):
                wordlist_to_use = wordlist
                break
        
        if not wordlist_to_use:
            print(f"{Colors.WARNING}[!] No wordlists found for directory enumeration{Colors.ENDC}")
            wordlist_to_use = "/usr/share/wordlists/dirb/common.txt"  # fallback
        
        # Try directory enumeration tools in priority order
        dir_tools = [
            ("gobuster", f"gobuster dir -u {base_url}/ -w {wordlist_to_use} -x txt,html,php,asp,aspx,jsp,xml,js,css,zip,tar,gz,bak,old,log -t 10 -k --no-error -q -o"),
            ("feroxbuster", f"feroxbuster -u {base_url}/ -t 10 -w {wordlist_to_use} -x txt,html,php,asp,aspx,jsp,xml,js,css,zip,tar,gz,bak,old,log -v -k -q -o")
        ]
        
        # Adjust for stealth mode
        if stealth:
            dir_tools = [
                ("gobuster", f"gobuster dir -u {base_url}/ -w {wordlist_to_use} -x txt,html,php,asp,aspx,jsp,xml,js,css,zip,tar,gz,bak,old,log -t 5 -k --no-error -q --delay 200ms -o"),
                ("feroxbuster", f"feroxbuster -u {base_url}/ -t 5 -w {wordlist_to_use} -x txt,html,php,asp,aspx,jsp,xml,js,css,zip,tar,gz,bak,old,log -v -k -q --rate-limit 10 -o")
            ]
        
        for tool_name, tool_cmd in dir_tools:
            which_tool = run_command(f"which {tool_name}", debug=debug)
            if which_tool and which_tool.returncode == 0:
                print(f"{Colors.OKCYAN}[*] Running {tool_name} directory enumeration...{Colors.ENDC}")
                tool_output = os.path.join(service_dir, f"{tool_name}_{ip}_{port}.txt")
                full_cmd = f"{tool_cmd} {tool_output}"
                run_command(full_cmd, debug=debug, stealth=stealth)
                break
        
        # 5. SSL/TLS Analysis if HTTPS
        if protocol == "https":
            print(f"{Colors.OKCYAN}[*] Running SSL/TLS analysis...{Colors.ENDC}")
            
            # SSLScan
            which_sslscan = run_command("which sslscan", debug=debug)
            if which_sslscan and which_sslscan.returncode == 0:
                sslscan_cmd = f"sslscan --show-certificate --no-colour {ip}:{port}"
                sslscan_output = os.path.join(service_dir, f"sslscan_{ip}_{port}.txt")
                run_command(sslscan_cmd, sslscan_output, debug=debug, stealth=stealth)
            
            # TestSSL.sh if available
            which_testssl = run_command("which testssl.sh", debug=debug)
            if which_testssl and which_testssl.returncode == 0:
                testssl_cmd = f"testssl.sh {ip}:{port}"
                testssl_output = os.path.join(service_dir, f"testssl_{ip}_{port}.txt")
                run_command(testssl_cmd, testssl_output, debug=debug, stealth=stealth)
        
        # 6. Add manual commands for further testing
        manual_commands = [
            f"# Manual enumeration commands for {base_url}",
            f"wpscan --url {base_url}/ --enumerate vp,vt,tt,cb,dbe,u,m",
            f"cmsmap -t {base_url}/",
            f"python3 /opt/dirsearch/dirsearch.py -u {base_url}/ -e *",
            f"ffuf -u {base_url}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
            f"gobuster dir -u {base_url}/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x txt,html,php,asp,aspx,jsp -t 50",
            f"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/darkweb2017-top100.txt {ip} http-post-form '/login.php:username=^USER^&password=^PASS^:invalid'",
            f"sqlmap -u '{base_url}/?id=1' --batch --banner",
            f"nuclei -u {base_url} -t /root/nuclei-templates/"
        ]
        
        add_manual_command(base_dir, f"Web Service {base_url}", manual_commands)

def run_enhanced_smb_enumeration(base_dir, targets, debug=False):
    """Enhanced SMB enumeration with multiple tools and techniques."""
    smb_dir = os.path.join(base_dir, "scans", "smb")
    
    print(f"{Colors.OKGREEN}[+] Starting Enhanced SMB Enumeration{Colors.ENDC}")
    
    # Discover SMB services
    services = discover_services_from_nmap(base_dir)
    smb_targets = []
    
    for ip, service_list in services.items():
        for service in service_list:
            if (service['service'] in ['microsoft-ds', 'smb', 'netbios-ssn'] or 
                service['port'] in ['139', '445']):
                if ip not in smb_targets:
                    smb_targets.append(ip)
    
    if not smb_targets:
        print(f"{Colors.WARNING}[!] No SMB services identified{Colors.ENDC}")
        return
    
    print(f"{Colors.OKGREEN}[+] Found {len(smb_targets)} SMB targets for enhanced enumeration{Colors.ENDC}")
    
    for target in smb_targets:
        print(f"{Colors.OKCYAN}[*] Enhanced SMB enumeration of {target}{Colors.ENDC}")
        
        # 1. Enum4Linux comprehensive enumeration
        which_enum4linux = run_command("which enum4linux", debug=debug)
        if which_enum4linux and which_enum4linux.returncode == 0:
            print(f"{Colors.OKCYAN}[*] Running enum4linux comprehensive scan...{Colors.ENDC}")
            enum4linux_cmd = f"enum4linux -a -M -l -d {target}"
            enum4linux_output = os.path.join(smb_dir, f"enum4linux_{target}.txt")
            run_command(enum4linux_cmd, enum4linux_output, debug=debug)
        
        # 2. SMBClient share enumeration
        which_smbclient = run_command("which smbclient", debug=debug)
        if which_smbclient and which_smbclient.returncode == 0:
            print(f"{Colors.OKCYAN}[*] Running smbclient share enumeration...{Colors.ENDC}")
            smbclient_cmd = f"smbclient -L //{target} -N -I {target}"
            smbclient_output = os.path.join(smb_dir, f"smbclient_{target}.txt")
            run_command(smbclient_cmd, smbclient_output, debug=debug)
        
        # 3. SMBMap detailed enumeration
        which_smbmap = run_command("which smbmap", debug=debug)
        if which_smbmap and which_smbmap.returncode == 0:
            print(f"{Colors.OKCYAN}[*] Running smbmap detailed enumeration...{Colors.ENDC}")
            
            # Share permissions
            smbmap_cmd1 = f"smbmap -H {target} -u null -p ''"
            smbmap_output1 = os.path.join(smb_dir, f"smbmap_shares_{target}.txt")
            run_command(smbmap_cmd1, smbmap_output1, debug=debug)
            
            # Recursive listing
            smbmap_cmd2 = f"smbmap -H {target} -u null -p '' -r"
            smbmap_output2 = os.path.join(smb_dir, f"smbmap_recursive_{target}.txt")
            run_command(smbmap_cmd2, smbmap_output2, debug=debug)
        
        # 4. NBTScan NetBIOS enumeration
        which_nbtscan = run_command("which nbtscan", debug=debug)
        if which_nbtscan and which_nbtscan.returncode == 0:
            print(f"{Colors.OKCYAN}[*] Running nbtscan NetBIOS enumeration...{Colors.ENDC}")
            nbtscan_cmd = f"nbtscan -rvh {target}"
            nbtscan_output = os.path.join(smb_dir, f"nbtscan_{target}.txt")
            run_command(nbtscan_cmd, nbtscan_output, debug=debug)
        
        # 5. RPCClient enumeration
        which_rpcclient = run_command("which rpcclient", debug=debug)
        if which_rpcclient and which_rpcclient.returncode == 0:
            print(f"{Colors.OKCYAN}[*] Running rpcclient enumeration...{Colors.ENDC}")
            rpcclient_cmd = f'echo "enumdomusers; enumdomgroups; querydominfo; exit" | rpcclient -U "" {target}'
            rpcclient_output = os.path.join(smb_dir, f"rpcclient_{target}.txt")
            run_command(rpcclient_cmd, rpcclient_output, debug=debug)
        
        # 6. Advanced Nmap SMB scripts
        print(f"{Colors.OKCYAN}[*] Running advanced Nmap SMB scripts...{Colors.ENDC}")
        nmap_smb_cmd = f"nmap -p 139,445 --script 'smb-os-discovery,smb-security-mode,smb-enum-shares,smb-enum-users,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-server-stats' {target}"
        nmap_smb_output = os.path.join(smb_dir, f"nmap_smb_advanced_{target}.txt")
        run_command(nmap_smb_cmd, nmap_smb_output, debug=debug)
        
        # 7. Add manual commands
        manual_commands = [
            f"# Manual SMB enumeration commands for {target}",
            f"crackmapexec smb {target} --shares",
            f"crackmapexec smb {target} --users",
            f"crackmapexec smb {target} --groups",
            f"crackmapexec smb {target} --pass-pol",
            f"impacket-samrdump {target}",
            f"impacket-rpcdump {target}",
            f"smbclient //{target}/SHARE -U username%password",
            f"mount -t cifs //{target}/SHARE /mnt/smb -o username=,password=",
            f"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/darkweb2017-top100.txt {target} smb"
        ]
        
        add_manual_command(base_dir, f"SMB Service {target}", manual_commands)

def run_enhanced_database_enumeration(base_dir, targets, debug=False):
    """Enhanced database enumeration for various database services."""
    db_dir = os.path.join(base_dir, "scans", "databases")
    os.makedirs(db_dir, exist_ok=True)
    
    print(f"{Colors.OKGREEN}[+] Starting Enhanced Database Enumeration{Colors.ENDC}")
    
    # Discover database services
    services = discover_services_from_nmap(base_dir)
    db_services = {}
    
    for ip, service_list in services.items():
        for service in service_list:
            service_name = service['service'].lower()
            port = service['port']
            
            # Identify database services
            if any(db in service_name for db in ['mysql', 'mssql', 'postgresql', 'oracle', 'mongodb', 'redis']):
                if ip not in db_services:
                    db_services[ip] = []
                db_services[ip].append({
                    'service': service_name,
                    'port': port,
                    'protocol': service['protocol']
                })
    
    if not db_services:
        print(f"{Colors.WARNING}[!] No database services identified{Colors.ENDC}")
        return
    
    print(f"{Colors.OKGREEN}[+] Found database services on {len(db_services)} hosts{Colors.ENDC}")
    
    for ip, services in db_services.items():
        for service in services:
            service_name = service['service']
            port = service['port']
            
            print(f"{Colors.OKCYAN}[*] Enhanced enumeration of {service_name} on {ip}:{port}{Colors.ENDC}")
            
            # MySQL enumeration
            if 'mysql' in service_name:
                print(f"{Colors.OKCYAN}[*] Running MySQL enumeration...{Colors.ENDC}")
                
                # Nmap MySQL scripts
                mysql_nmap_cmd = f"nmap -p {port} --script 'mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122' {ip}"
                mysql_output = os.path.join(db_dir, f"mysql_nmap_{ip}_{port}.txt")
                run_command(mysql_nmap_cmd, mysql_output, debug=debug)
                
                # Manual commands
                mysql_manual = [
                    f"# MySQL enumeration for {ip}:{port}",
                    f"mysql -h {ip} -P {port} -u root -p",
                    f"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/darkweb2017-top100.txt {ip} mysql",
                    f"ncrack -v --user root -P /usr/share/seclists/Passwords/darkweb2017-top100.txt {ip}:{port}"
                ]
                add_manual_command(base_dir, f"MySQL {ip}:{port}", mysql_manual)
            
            # MSSQL enumeration
            elif 'mssql' in service_name or 'ms-sql' in service_name:
                print(f"{Colors.OKCYAN}[*] Running MSSQL enumeration...{Colors.ENDC}")
                
                # Nmap MSSQL scripts
                mssql_nmap_cmd = f"nmap -p {port} --script 'ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-query' {ip}"
                mssql_output = os.path.join(db_dir, f"mssql_nmap_{ip}_{port}.txt")
                run_command(mssql_nmap_cmd, mssql_output, debug=debug)
                
                # Manual commands
                mssql_manual = [
                    f"# MSSQL enumeration for {ip}:{port}",
                    f"impacket-mssqlclient sa@{ip} -port {port}",
                    f"sqsh -S {ip}:{port} -U sa -P",
                    f"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/darkweb2017-top100.txt {ip} mssql"
                ]
                add_manual_command(base_dir, f"MSSQL {ip}:{port}", mssql_manual)
            
            # PostgreSQL enumeration
            elif 'postgresql' in service_name:
                print(f"{Colors.OKCYAN}[*] Running PostgreSQL enumeration...{Colors.ENDC}")
                
                # Nmap PostgreSQL scripts
                pgsql_nmap_cmd = f"nmap -p {port} --script 'pgsql-brute' {ip}"
                pgsql_output = os.path.join(db_dir, f"postgresql_nmap_{ip}_{port}.txt")
                run_command(pgsql_nmap_cmd, pgsql_output, debug=debug)
                
                # Manual commands
                pgsql_manual = [
                    f"# PostgreSQL enumeration for {ip}:{port}",
                    f"psql -h {ip} -p {port} -U postgres",
                    f"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/darkweb2017-top100.txt {ip} postgres"
                ]
                add_manual_command(base_dir, f"PostgreSQL {ip}:{port}", pgsql_manual)
            
            # MongoDB enumeration
            elif 'mongodb' in service_name or 'mongod' in service_name:
                print(f"{Colors.OKCYAN}[*] Running MongoDB enumeration...{Colors.ENDC}")
                
                # Nmap MongoDB scripts
                mongo_nmap_cmd = f"nmap -p {port} --script 'mongodb-databases,mongodb-info' {ip}"
                mongo_output = os.path.join(db_dir, f"mongodb_nmap_{ip}_{port}.txt")
                run_command(mongo_nmap_cmd, mongo_output, debug=debug)
                
                # Manual commands
                mongo_manual = [
                    f"# MongoDB enumeration for {ip}:{port}",
                    f"mongo {ip}:{port}",
                    f"mongo {ip}:{port}/admin --eval 'db.runCommand(\"listCollections\")'",
                    f"mongo {ip}:{port} --eval 'show dbs'"
                ]
                add_manual_command(base_dir, f"MongoDB {ip}:{port}", mongo_manual)
            
            # Redis enumeration
            elif 'redis' in service_name:
                print(f"{Colors.OKCYAN}[*] Running Redis enumeration...{Colors.ENDC}")
                
                # Nmap Redis scripts
                redis_nmap_cmd = f"nmap -p {port} --script 'redis-info' {ip}"
                redis_output = os.path.join(db_dir, f"redis_nmap_{ip}_{port}.txt")
                run_command(redis_nmap_cmd, redis_output, debug=debug)
                
                # Redis-cli enumeration
                which_redis = run_command("which redis-cli", debug=debug)
                if which_redis and which_redis.returncode == 0:
                    redis_info_cmd = f"redis-cli -h {ip} -p {port} INFO"
                    redis_info_output = os.path.join(db_dir, f"redis_info_{ip}_{port}.txt")
                    run_command(redis_info_cmd, redis_info_output, debug=debug)
                
                # Manual commands
                redis_manual = [
                    f"# Redis enumeration for {ip}:{port}",
                    f"redis-cli -h {ip} -p {port}",
                    f"redis-cli -h {ip} -p {port} CONFIG GET '*'",
                    f"redis-cli -h {ip} -p {port} INFO",
                    f"redis-cli -h {ip} -p {port} CLIENT LIST"
                ]
                add_manual_command(base_dir, f"Redis {ip}:{port}", redis_manual)

def run_enhanced_dns_enumeration(base_dir, targets, debug=False):
    """Enhanced DNS enumeration with subdomain discovery and zone transfers."""
    dns_dir = os.path.join(base_dir, "scans", "dns")
    
    print(f"{Colors.OKGREEN}[+] Starting Enhanced DNS Enumeration{Colors.ENDC}")
    
    # Classify targets and discover domains
    rfc1918_networks, non_rfc1918_ips, hostnames = classify_network_ranges(targets)
    
    # Discover additional domains from reverse lookups
    discovered_domains = set(hostnames)
    
    # Parse DNS output files for additional domains
    for dns_file in Path(dns_dir).glob("*.txt"):
        try:
            with open(dns_file, 'r') as f:
                content = f.read()
                domain_patterns = [
                    r'([a-zA-Z0-9-]+\.(?:[a-zA-Z]{2,})+)',
                    r'([a-zA-Z0-9-]+\.(?:local|corp|internal|lan|domain|ad))',
                ]
                
                for pattern in domain_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if '.' in match and not match.startswith('.'):
                            domain = match.strip('.')
                            if len(domain.split('.')) >= 2:
                                discovered_domains.add(domain)
        except Exception as e:
            if debug:
                print(f"{Colors.WARNING}[!] Error parsing {dns_file}: {e}{Colors.ENDC}")
    
    # Enhanced subdomain enumeration
    if discovered_domains:
        print(f"{Colors.OKBLUE}[*] Enhanced subdomain enumeration for {len(discovered_domains)} domains{Colors.ENDC}")
        
        subdomain_dir = os.path.join(dns_dir, "subdomains")
        os.makedirs(subdomain_dir, exist_ok=True)
        
        for domain in discovered_domains:
            if len(domain.split('.')) >= 2:
                print(f"{Colors.OKCYAN}[*] Comprehensive subdomain enumeration for {domain}{Colors.ENDC}")
                safe_domain = domain.replace('.', '_')
                
                # Multiple subdomain enumeration techniques
                subdomain_tools = [
                    ("sublist3r", f"sublist3r -d {domain} -o"),
                    ("amass", f"amass enum -d {domain} -o"),
                    ("subfinder", f"subfinder -d {domain} -o"),
                    ("assetfinder", f"assetfinder --subs-only {domain}")
                ]
                
                for tool_name, tool_cmd in subdomain_tools:
                    which_tool = run_command(f"which {tool_name}", debug=debug)
                    if which_tool and which_tool.returncode == 0:
                        print(f"{Colors.OKCYAN}[*] Running {tool_name} subdomain enumeration...{Colors.ENDC}")
                        tool_output = os.path.join(subdomain_dir, f"{tool_name}_{safe_domain}.txt")
                        full_cmd = f"{tool_cmd} {tool_output}"
                        run_command(full_cmd, debug=debug)
                
                # Add manual subdomain commands
                subdomain_manual = [
                    f"# Advanced subdomain enumeration for {domain}",
                    f"gobuster dns -d {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50",
                    f"python3 /opt/Sublist3r/sublist3r.py -d {domain} -b -t 100",
                    f"amass enum -passive -d {domain}",
                    f"curl -s 'https://dns.bufferover.run/dns?q=.{domain}' | jq -r .FDNS_A[]",
                    f"theHarvester -d {domain} -b all",
                    f"subfinder -d {domain} -all -recursive",
                    f"assetfinder --subs-only {domain} | sort -u"
                ]
                add_manual_command(base_dir, f"Subdomain Enumeration {domain}", subdomain_manual)

def run_quick_reconnaissance(base_dir, targets, debug=False):
    """Run quick reconnaissance scans for immediate results on pre-verified targets."""
    print(f"{Colors.OKGREEN}[+] Phase 1: Quick Reconnaissance (Fast Results){Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Skipping connectivity checks - targets already verified by reachability testing{Colors.ENDC}")
    
    # Since targets are already verified as reachable, jump straight to port scanning
    # Fast top ports scan on verified hosts
    print(f"{Colors.OKBLUE}[*] Running fast top ports scan on {len(targets)} verified hosts...{Colors.ENDC}")
    
    # Limit to first 10 targets for quick results
    quick_targets = targets[:10] if len(targets) > 10 else targets
    
    fast_ports_cmd = ["nmap", "-n", "--top-ports", "100", "--max-retries", "1", 
                     "--max-rtt-timeout", "500ms", "--max-scan-delay", "5ms", "-Pn"] + quick_targets
    try:
        result = subprocess.run(fast_ports_cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            # Parse for open ports
            current_host = None
            quick_results = []
            for line in result.stdout.split('\n'):
                if "Nmap scan report for" in line:
                    current_host = line.split()[-1]
                    quick_results.append(current_host)
                elif "/tcp" in line and "open" in line:
                    port = line.split('/')[0]
                    service = line.split()[-1] if len(line.split()) > 2 else "unknown"
                    print(f"{Colors.OKGREEN}[+] Quick service found: {current_host}:{port} ({service}){Colors.ENDC}")
            return quick_results
    except subprocess.TimeoutExpired:
        print(f"{Colors.WARNING}[!] Fast port scan timed out, continuing...{Colors.ENDC}")
    
    return targets  # Return original targets if scan fails

def run_enhanced_enumeration(base_dir, targets, stealth=False, debug=False):
    """Run comprehensive enhanced enumeration across all discovered services."""
    print(f"{Colors.OKGREEN}[+] Starting Enhanced Service Enumeration{Colors.ENDC}")
    
    # Enhanced enumeration modules
    enumeration_modules = [
        ("Enhanced Web Enumeration", run_enhanced_web_enumeration),
        ("Enhanced SMB Enumeration", run_enhanced_smb_enumeration),
        ("Enhanced Database Enumeration", run_enhanced_database_enumeration),
        ("Enhanced DNS Enumeration", run_enhanced_dns_enumeration),
    ]
    
    for module_name, module_func in enumeration_modules:
        try:
            print(f"\n{Colors.OKBLUE}[*] Running {module_name}...{Colors.ENDC}")
            if module_name == "Enhanced DNS Enumeration":
                module_func(base_dir, targets, debug=debug)
            else:
                module_func(base_dir, targets, debug=debug)
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error in {module_name}: {e}{Colors.ENDC}")
            if debug:
                import traceback
                traceback.print_exc()

def generate_summary_report(base_dir):
    """Generate a comprehensive summary report of all findings."""
    reports_dir = os.path.join(base_dir, "reports")
    report_file = os.path.join(reports_dir, "trashpanda_summary.txt")
    
    print(f"{Colors.OKGREEN}[+] Generating comprehensive summary report: {report_file}{Colors.ENDC}")
    
    with open(report_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("TRASHPANDA COMPREHENSIVE PENETRATION TESTING REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Operator: {os.environ.get('USER', 'operator')}\n")
        f.write(f"Engagement Directory: {base_dir}\n\n")

        # Enhanced directory structure overview
        f.write("DIRECTORY STRUCTURE:\n")
        f.write("-" * 20 + "\n")
        main_dirs = ["tools", "scans", "logs", "loot", "payloads", "targets", 
                    "screenshots", "reports", "notes", "exploits", "wordlists", "pcaps"]
        
        for main_dir in main_dirs:
            dir_path = os.path.join(base_dir, main_dir)
            if os.path.exists(dir_path):
                file_count = len([f for f in os.listdir(dir_path) 
                                if os.path.isfile(os.path.join(dir_path, f))])
                subdir_count = len([d for d in os.listdir(dir_path) 
                                  if os.path.isdir(os.path.join(dir_path, d))])
                f.write(f"├── {main_dir:15} ({file_count} files, {subdir_count} subdirs)\n")
        
        f.write("\n")
        
        # Enhanced scan results summary
        f.write("SCAN RESULTS SUMMARY:\n")
        f.write("-" * 21 + "\n")
        scans_dir = os.path.join(base_dir, "scans")
        if os.path.exists(scans_dir):
            scan_types = ["nmap", "dns", "snmp", "smb", "web", "ssl", "vulns", 
                         "databases", "ldap", "ftp", "ssh", "reachability"]
            for scan_type in scan_types:
                scan_dir = os.path.join(scans_dir, scan_type)
                if os.path.exists(scan_dir):
                    file_count = len([f for f in os.listdir(scan_dir) 
                                    if os.path.isfile(os.path.join(scan_dir, f))])
                    f.write(f"├── {scan_type.upper():12} scans: {file_count} files\n")
        
        f.write("\n")
        
        # Service discovery summary
        services = discover_services_from_nmap(base_dir)
        if services:
            f.write("DISCOVERED SERVICES:\n")
            f.write("-" * 20 + "\n")
            for ip, service_list in services.items():
                f.write(f"Target: {ip}\n")
                for service in service_list:
                    ssl_indicator = " (SSL)" if service['ssl'] else ""
                    f.write(f"  ├── {service['protocol']}/{service['port']} - {service['service']}{ssl_indicator}\n")
                f.write("\n")
        
        # Key files inventory
        f.write("KEY FILES:\n")
        f.write("-" * 10 + "\n")
        
        key_files = [
            ("targets/alive_hosts.txt", "Live hosts discovered"),
            ("scans/reachability/reachable_targets_*.txt", "Network reachability results"),
            ("scans/nmap/*.gnmap", "Nmap scan results"),
            ("scans/dns/dns_enumeration_summary.txt", "DNS enumeration summary"),
            ("scans/snmp/snmp_enumeration_summary.txt", "SNMP enumeration summary"),
            ("scans/_manual_commands.txt", "Manual commands for further testing"),
            ("pcaps/capture_*.pcap", "Network traffic capture"),
            ("logs/engagement.log", "Engagement activity log")
        ]
        
        for file_pattern, description in key_files:
            file_path = os.path.join(base_dir, file_pattern.replace("*", ""))
            if "*" in file_pattern:
                import glob
                matches = glob.glob(os.path.join(base_dir, file_pattern))
                if matches:
                    f.write(f"✓ {description}: {len(matches)} file(s)\n")
                else:
                    f.write(f"✗ {description}: Not found\n")
            elif os.path.exists(file_path):
                f.write(f"✓ {description}: Available\n")
            else:
                f.write(f"✗ {description}: Not found\n")
        
        f.write("\n" + "=" * 80 + "\n")
        f.write("RECOMMENDED NEXT STEPS:\n")
        f.write("1. Review manual commands in scans/_manual_commands.txt\n")
        f.write("2. Analyze discovered services for vulnerabilities\n")
        f.write("3. Check web services for common web application vulnerabilities\n")
        f.write("4. Review SMB shares for sensitive information\n")
        f.write("5. Test discovered databases for default credentials\n")
        f.write("6. Perform credential stuffing attacks if usernames discovered\n")
        f.write("7. Document all findings in notes/ directory\n")
        f.write("8. Store any discovered credentials in loot/ directory\n")
        f.write("=" * 80 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="TrashPanda - Professional Penetration Testing Framework v2.4",
        epilog="""
Examples:
  %(prog)s targets.txt                    # Standard scan with reachability test
  %(prog)s -e targets.txt                 # Enhanced comprehensive enumeration
  %(prog)s -r targets.txt                 # Reachability testing only
  %(prog)s -c                             # Just create directory structure
  %(prog)s -n targets.txt                 # Only run Nmap scans
  %(prog)s targets.txt -s                 # Stealth mode scanning
  %(prog)s 192.168.1.0/24 -q             # Quick scan mode
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target specification
    parser.add_argument("targets", nargs='?', help="Target file, IP, IP range, or CIDR")
    
    # Directory options
    parser.add_argument("-d", "--directory", help="Engagement directory name",
                        default=os.environ.get("WORK_DIR", os.environ.get("WORK_DIR", "/root/workspace")))
    parser.add_argument("-c", "--create-dirs", action="store_true", help="Only create directory structure and exit")
    
    # Scan modes
    parser.add_argument("-e", "--enhanced", action="store_true", help="Enable enhanced comprehensive enumeration mode")
    parser.add_argument("-s", "--stealth", action="store_true", help="Enable stealth mode")
    parser.add_argument("-q", "--quick", action="store_true", help="Quick mode")
    parser.add_argument("-f", "--full-tcp", action="store_true", help="Include full TCP port scan")
    
    # Reachability testing
    parser.add_argument("-r", "--reachability-only", action="store_true", help="Only run network reachability testing")
    parser.add_argument("--skip-reachability", action="store_true", help="Skip initial reachability testing")
    parser.add_argument("--reachability-threads", type=int, default=REACHABILITY_THREADS, help="Threads for reachability testing")
    parser.add_argument("--reachability-timeout", type=int, default=REACHABILITY_TIMEOUT, help="Timeout for reachability tests")
    
    # Individual module flags
    parser.add_argument("-n", "--nmap-only", action="store_true", help="Only run Nmap scans")
    parser.add_argument("--dns-only", action="store_true", help="Only run DNS enumeration")
    parser.add_argument("--snmp-only", action="store_true", help="Only run SNMP enumeration")
    parser.add_argument("--smb-only", action="store_true", help="Only run SMB enumeration")
    parser.add_argument("-w", "--web-only", action="store_true", help="Only run web enumeration")
    parser.add_argument("--ssl-only", action="store_true", help="Only run SSL enumeration")
    parser.add_argument("-v", "--vulns-only", action="store_true", help="Only run vulnerability scripts")
    
    # Module exclusions
    parser.add_argument("--no-dns", action="store_true", help="Skip DNS enumeration")
    parser.add_argument("--no-snmp", action="store_true", help="Skip SNMP enumeration")
    parser.add_argument("--no-smb", action="store_true", help="Skip SMB enumeration")
    parser.add_argument("--no-web", action="store_true", help="Skip web enumeration")
    parser.add_argument("--no-ssl", action="store_true", help="Skip SSL enumeration")
    parser.add_argument("--no-vulns", action="store_true", help="Skip vulnerability scripts")
    
    # Packet capture options
    parser.add_argument("--no-pcap", action="store_true", help="Skip tcpdump packet capture")
    parser.add_argument("-p", "--pcap-duration", type=int, default=TCPDUMP_DURATION, help=f"TCPDump capture duration in seconds")
    parser.add_argument("-i", "--pcap-interface", default="any", help="Network interface for packet capture")
    
    # Debug options
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    
    args = parser.parse_args()
    
    print_banner()
    
    # Create penetration testing structure
    base_dir = create_pentest_structure(args.directory)
    
    # Initialize comprehensive logging
    csv_log_file, verbose_log_file = setup_logging(base_dir)
    log_command.csv_file = csv_log_file  # Store for log_command function
    
    # Setup console output logging if not in debug mode
    if not args.debug:
        original_stdout = sys.stdout
        sys.stdout = LoggingPrint(original_stdout)
    
    log_verbose("TrashPanda session started", 'INFO')
    log_verbose(f"Arguments: {' '.join(sys.argv)}", 'INFO')
    
    # If only creating directories, exit here
    if args.create_dirs:
        print(f"{Colors.OKGREEN}[+] Directory structure created. Exiting as requested.{Colors.ENDC}")
        log_verbose("Directory creation only mode - exiting", 'INFO')
        sys.exit(0)
    
    # Parse targets
    if args.targets:
        print(f"{Colors.OKBLUE}[*] Parsing targets...{Colors.ENDC}")
        targets = parse_targets(args.targets)
    else:
        # Use default target file
        default_targets = os.path.join(base_dir, "targets", "targets.txt")
        if os.path.exists(default_targets):
            with open(default_targets, 'r') as f:
                content = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if content:
                print(f"{Colors.OKBLUE}[*] Using default target file: {default_targets}{Colors.ENDC}")
                targets = parse_targets(default_targets)
            else:
                print(f"{Colors.FAIL}[!] Default target file is empty{Colors.ENDC}")
                sys.exit(1)
        else:
            print(f"{Colors.FAIL}[!] No targets specified and no default target file found{Colors.ENDC}")
            sys.exit(1)
    
    if not targets:
        print(f"{Colors.FAIL}[!] No valid targets found{Colors.ENDC}")
        sys.exit(1)
    
    print(f"{Colors.OKGREEN}[+] Loaded {len(targets)} targets{Colors.ENDC}")
    
    # Apply public IP safety filter
    targets = filter_public_ips_from_targets(targets)
    
    if not targets:
        print(f"{Colors.FAIL}[!] No valid targets remaining after filtering{Colors.ENDC}")
        sys.exit(1)
    
    print(f"{Colors.OKGREEN}[+] Proceeding with {len(targets)} filtered targets{Colors.ENDC}")
    
    # Reachability-only mode
    if args.reachability_only:
        print(f"{Colors.OKBLUE}[*] Running standalone smart network reachability assessment{Colors.ENDC}")
        reachable, unreachable, detailed = run_smart_network_reachability_test(
            targets, base_dir, standalone=True, debug=args.debug,
            threads=args.reachability_threads, timeout=args.reachability_timeout
        )
        sys.exit(0)
    
    if args.enhanced:
        print(f"{Colors.WARNING}[!] Enhanced mode enabled - comprehensive enumeration will take significantly longer{Colors.ENDC}")
    if args.stealth:
        print(f"{Colors.WARNING}[!] Stealth mode enabled - scans will be slower and quieter{Colors.ENDC}")
    
    # Determine which modules to run
    modules_selected = any([
        args.nmap_only, args.dns_only, args.snmp_only, args.smb_only,
        args.web_only, args.ssl_only, args.vulns_only
    ])
    
    # Start tcpdump if requested
    tcpdump_info = None
    if not args.no_pcap and not modules_selected:
        tcpdump_info = start_tcpdump(base_dir, args.pcap_duration, args.pcap_interface)
    
    # Log start time and parameters
    start_time = time.time()
    engagement_log = os.path.join(base_dir, "logs", "engagement.log")
    
    with open(engagement_log, 'a') as f:
        f.write(f"\n=== SCAN SESSION ===\n")
        f.write(f"Start Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target Count: {len(targets)}\n")
        f.write(f"Enhanced Mode: {args.enhanced}\n")
        f.write(f"Stealth Mode: {args.stealth}\n")
        f.write(f"Quick Mode: {args.quick}\n")
        f.write(f"Reachability Testing: {not args.skip_reachability}\n")
        f.write(f"Arguments: {' '.join(sys.argv)}\n\n")
    
    try:
        # Phase 0: Network Reachability Testing (unless skipped)
        if not args.skip_reachability:
            print(f"{Colors.OKBLUE}[*] Phase 0: Smart Network Reachability Assessment{Colors.ENDC}")
            reachable_targets, unreachable_targets, detailed_results = run_smart_network_reachability_test(
                targets, base_dir, standalone=False, debug=args.debug,
                threads=args.reachability_threads, timeout=args.reachability_timeout
            )
            
            if not reachable_targets:
                print(f"{Colors.FAIL}[!] No targets are reachable from current network position{Colors.ENDC}")
                print(f"{Colors.WARNING}[!] Check network connectivity or try from different location{Colors.ENDC}")
                sys.exit(1)
            
            # Use only reachable targets for further scanning
            targets = reachable_targets
            print(f"{Colors.OKGREEN}[+] Proceeding with {len(targets)} reachable targets{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}[!] Skipping reachability testing as requested{Colors.ENDC}")
        
        alive_hosts = targets  # Default to all targets
        
        # Run individual modules if specified
        if args.nmap_only:
            alive_hosts = run_nmap_discovery(base_dir, targets, args.stealth, args.quick, args.enhanced, args.debug)
        elif args.dns_only:
            run_enhanced_dns_enumeration(base_dir, targets, args.debug)
        elif args.snmp_only:
            print(f"{Colors.OKBLUE}[*] SNMP enumeration module not implemented yet{Colors.ENDC}")
        elif args.smb_only:
            run_enhanced_smb_enumeration(base_dir, targets, args.debug)
        elif args.web_only:
            run_enhanced_web_enumeration(base_dir, targets, args.stealth, args.debug)
        elif args.ssl_only:
            print(f"{Colors.OKBLUE}[*] SSL enumeration module not implemented yet{Colors.ENDC}")
        elif args.vulns_only:
            print(f"{Colors.OKBLUE}[*] Vulnerability scanning module not implemented yet{Colors.ENDC}")
        else:
            # Progressive scan mode - reorganized for quicker results
            scan_mode = "Enhanced" if args.enhanced else ("Quick" if args.quick else "Standard")
            print(f"{Colors.OKGREEN}[+] Starting {scan_mode} progressive enumeration scan{Colors.ENDC}")
            
            # Phase 1: Quick Reconnaissance (fast results first)
            quick_hits = run_quick_reconnaissance(base_dir, targets, args.debug)
            
            # Phase 2: Comprehensive Nmap Discovery and Port Scanning  
            alive_hosts = run_nmap_discovery(base_dir, targets, args.stealth, args.quick, args.enhanced, args.debug)
            
            # Phase 3: Enhanced enumeration if requested
            if args.enhanced:
                run_enhanced_enumeration(base_dir, alive_hosts, args.stealth, args.debug)
        
        # Stop tcpdump before generating report
        if tcpdump_info:
            print(f"{Colors.OKBLUE}[*] Stopping packet capture...{Colors.ENDC}")
            stop_tcpdump(tcpdump_info)
        
        # Generate comprehensive summary report
        generate_summary_report(base_dir)
        
        # Calculate runtime
        end_time = time.time()
        runtime = end_time - start_time
        hours = int(runtime // 3600)
        minutes = int((runtime % 3600) // 60)
        seconds = int(runtime % 60)
        
        # Log completion
        with open(engagement_log, 'a') as f:
            f.write(f"End Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Runtime: {hours:02d}:{minutes:02d}:{seconds:02d}\n")
            f.write(f"Status: Completed Successfully\n")
        
        print(f"\n{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] TrashPanda enumeration completed!{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Runtime: {hours:02d}:{minutes:02d}:{seconds:02d}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Results saved to: {base_dir}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Manual commands: {os.path.join(base_dir, 'scans', '_manual_commands.txt')}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Summary report: {os.path.join(base_dir, 'reports', 'trashpanda_summary.txt')}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] CSV commands log: {csv_log_file}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Verbose log: {verbose_log_file}{Colors.ENDC}")
        if tcpdump_info:
            print(f"{Colors.OKGREEN}[+] Packet capture: {tcpdump_info['pcap_file']}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
        
        log_verbose(f"TrashPanda session completed successfully in {runtime:.2f} seconds", 'INFO')
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
        log_verbose("Scan interrupted by user (KeyboardInterrupt)", 'WARNING')
        if 'tcpdump_info' in locals() and tcpdump_info:
            stop_tcpdump(tcpdump_info)
        generate_summary_report(base_dir)
        sys.exit(1)
        
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Unexpected error: {e}{Colors.ENDC}")
        log_verbose(f"Unexpected error: {e}", 'ERROR')
        if 'tcpdump_info' in locals() and tcpdump_info:
            stop_tcpdump(tcpdump_info)
        if args.debug:
            import traceback
            traceback.print_exc()
            log_verbose(f"Traceback: {traceback.format_exc()}", 'ERROR')
        sys.exit(1)

if __name__ == "__main__":
    main()