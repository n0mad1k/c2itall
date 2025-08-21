#!/bin/bash
# Automated Port Scanning Script for Attack Box
# Usage: ./port_scan_automation.sh <target> [quick|full|stealth]

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target> [quick|full|stealth]"
    echo "Example: $0 192.168.1.1 full"
    echo "         $0 example.com quick"
    exit 1
fi

TARGET="$1"
SCAN_TYPE="${2:-quick}"
WORKSPACE="/root/operator/scans/nmap/$TARGET"
DATE=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}[+] Starting port scan for: $TARGET${NC}"
echo -e "${BLUE}[*] Scan type: $SCAN_TYPE${NC}"

# Create workspace
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"

# Create log file
LOG_FILE="portscan_$DATE.log"
echo "Port scan started at $(date)" > "$LOG_FILE"

# Function to log and execute
log_and_run() {
    echo -e "${YELLOW}[*] $1${NC}"
    echo "[$(date)] $1" >> "$LOG_FILE"
    eval "$2" 2>&1 | tee -a "$LOG_FILE"
}

case $SCAN_TYPE in
    "quick")
        echo -e "${GREEN}[+] Quick Port Scan (Top 1000 ports)${NC}"
        log_and_run "Nmap quick scan" "nmap -T4 -F $TARGET -oA nmap_quick_$DATE"
        log_and_run "Rustscan quick" "rustscan -a $TARGET --ulimit 5000 -- -A"
        ;;
    
    "full")
        echo -e "${GREEN}[+] Full Port Scan (All 65535 ports)${NC}"
        log_and_run "Nmap SYN scan all ports" "nmap -sS -T4 -p- $TARGET -oA nmap_syn_all_$DATE"
        log_and_run "Nmap service detection on open ports" "nmap -sV -sC -T4 $TARGET -oA nmap_services_$DATE"
        log_and_run "Nmap UDP scan top ports" "nmap -sU --top-ports 1000 $TARGET -oA nmap_udp_$DATE"
        log_and_run "Masscan all ports" "masscan -p1-65535 $TARGET --rate=1000 -e tun0 2>/dev/null || echo 'Masscan failed - check interface'"
        ;;
    
    "stealth")
        echo -e "${GREEN}[+] Stealth Port Scan${NC}"
        log_and_run "Nmap stealth SYN scan" "nmap -sS -T2 -f --source-port 53 $TARGET -oA nmap_stealth_$DATE"
        log_and_run "Nmap decoy scan" "nmap -D RND:10 -T2 $TARGET -oA nmap_decoy_$DATE"
        ;;
    
    *)
        echo -e "${RED}[-] Invalid scan type. Use: quick, full, or stealth${NC}"
        exit 1
        ;;
esac

# Additional enumeration for common services
echo -e "${GREEN}[+] Service-specific enumeration${NC}"

# Check for common vulnerabilities
log_and_run "Nmap vulnerability scripts" "nmap --script vuln $TARGET -oA nmap_vulns_$DATE"

# Extract open ports for further enumeration
if [ -f "nmap_*.gnmap" ]; then
    OPEN_PORTS=$(grep "open" nmap_*.gnmap | grep -oP '\d+/open' | cut -d'/' -f1 | sort -n | uniq | tr '\n' ',')
    echo -e "${BLUE}[*] Open ports found: $OPEN_PORTS${NC}"
    
    # Service-specific scans
    if echo "$OPEN_PORTS" | grep -q "21"; then
        log_and_run "FTP enumeration" "nmap --script ftp-* -p 21 $TARGET"
    fi
    
    if echo "$OPEN_PORTS" | grep -q "22"; then
        log_and_run "SSH enumeration" "nmap --script ssh-* -p 22 $TARGET"
    fi
    
    if echo "$OPEN_PORTS" | grep -q "53"; then
        log_and_run "DNS enumeration" "nmap --script dns-* -p 53 $TARGET"
        if command -v dig &> /dev/null; then
            log_and_run "DNS zone transfer attempt" "dig @$TARGET axfr"
        fi
    fi
    
    if echo "$OPEN_PORTS" | grep -E "(80|443|8080|8443)" &> /dev/null; then
        log_and_run "HTTP enumeration" "nmap --script http-* -p 80,443,8080,8443 $TARGET"
    fi
    
    if echo "$OPEN_PORTS" | grep -q "139\|445"; then
        log_and_run "SMB enumeration" "nmap --script smb-* -p 139,445 $TARGET"
        if command -v enum4linux &> /dev/null; then
            log_and_run "enum4linux scan" "enum4linux $TARGET"
        fi
    fi
    
    if echo "$OPEN_PORTS" | grep -q "1433"; then
        log_and_run "MSSQL enumeration" "nmap --script ms-sql-* -p 1433 $TARGET"
    fi
    
    if echo "$OPEN_PORTS" | grep -q "3306"; then
        log_and_run "MySQL enumeration" "nmap --script mysql-* -p 3306 $TARGET"
    fi
fi

# Generate summary
echo -e "${GREEN}[+] Port Scan Complete!${NC}"
echo -e "${BLUE}[*] Results saved in: $WORKSPACE${NC}"
echo -e "${BLUE}[*] Log file: $LOG_FILE${NC}"

# Count open ports
if ls nmap_*.gnmap 1> /dev/null 2>&1; then
    TOTAL_OPEN=$(grep -h "open" nmap_*.gnmap | wc -l)
    echo -e "${BLUE}[*] Total open ports found: $TOTAL_OPEN${NC}"
fi

# Generate simple report
cat > "portscan_report.txt" << EOF
Port Scan Report for $TARGET
=============================
Scan Type: $SCAN_TYPE
Date: $(date)
Workspace: $WORKSPACE

Open Ports:
$(grep -h "open" nmap_*.gnmap 2>/dev/null | head -20 || echo "No open ports found in gnmap files")

Summary:
- Scan completed successfully
- Results saved in multiple formats (.nmap, .xml, .gnmap)
- Log file: $LOG_FILE

Next Steps:
1. Review service versions for known vulnerabilities
2. Run targeted service enumeration
3. Check for default credentials
4. Look for misconfigurations
EOF

echo -e "${GREEN}[+] Report generated: portscan_report.txt${NC}"
echo "Port scan completed at $(date)" >> "$LOG_FILE"
