#!/bin/bash
# Automated Reconnaissance Script for Attack Box
# Usage: ./recon_automation.sh <target_domain>

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_domain>"
    echo "Example: $0 example.com"
    exit 1
fi

TARGET="$1"
WORKSPACE="/root/operator/scans/reachability/$TARGET"
DATE=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}[+] Starting reconnaissance for: $TARGET${NC}"
echo -e "${BLUE}[*] Creating workspace directory: $WORKSPACE${NC}"

# Create workspace
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"

# Create log file
LOG_FILE="recon_$DATE.log"
echo "Reconnaissance started at $(date)" > "$LOG_FILE"

# Function to log and execute
log_and_run() {
    echo -e "${YELLOW}[*] $1${NC}"
    echo "[$(date)] $1" >> "$LOG_FILE"
    eval "$2" 2>&1 | tee -a "$LOG_FILE"
}

# Subdomain enumeration
echo -e "${GREEN}[+] Phase 1: Subdomain Enumeration${NC}"
log_and_run "Running Subfinder" "subfinder -d $TARGET -o subdomains_subfinder.txt"
log_and_run "Running Assetfinder" "assetfinder --subs-only $TARGET > subdomains_assetfinder.txt"
log_and_run "Running Amass" "amass enum -passive -d $TARGET -o subdomains_amass.txt"

# Combine and deduplicate subdomains
log_and_run "Combining subdomain lists" "cat subdomains_*.txt | sort -u > all_subdomains.txt"

# Check which subdomains are alive
echo -e "${GREEN}[+] Phase 2: Checking Live Subdomains${NC}"
log_and_run "Checking live subdomains with httprobe" "cat all_subdomains.txt | httprobe -c 50 > live_subdomains.txt"

# Port scanning on live subdomains
echo -e "${GREEN}[+] Phase 3: Port Scanning${NC}"
log_and_run "Running Nmap on live subdomains" "nmap -T4 -iL live_subdomains.txt -oA nmap_scan"

# Web technology detection
echo -e "${GREEN}[+] Phase 4: Web Technology Detection${NC}"
log_and_run "Running whatweb" "whatweb -i live_subdomains.txt -a 3 > whatweb_results.txt"

# Screenshot and visual recon
echo -e "${GREEN}[+] Phase 5: Visual Reconnaissance${NC}"
if command -v aquatone &> /dev/null; then
    log_and_run "Taking screenshots with Aquatone" "cat live_subdomains.txt | aquatone -out aquatone_report"
fi

# Directory bruteforcing
echo -e "${GREEN}[+] Phase 6: Directory Enumeration${NC}"
mkdir -p directory_enum
while IFS= read -r url; do
    if [[ $url == http* ]]; then
        clean_url=$(echo "$url" | sed 's|http://||g' | sed 's|https://||g' | tr '/' '_')
        log_and_run "Running gobuster on $url" "gobuster dir -u $url -w /usr/share/wordlists/dirb/common.txt -o directory_enum/gobuster_$clean_url.txt -q"
    fi
done < live_subdomains.txt

# Vulnerability scanning with Nuclei
echo -e "${GREEN}[+] Phase 7: Vulnerability Scanning${NC}"
log_and_run "Running Nuclei" "nuclei -l live_subdomains.txt -t ~/nuclei-templates/ -o nuclei_results.txt"

# Summary
echo -e "${GREEN}[+] Reconnaissance Complete!${NC}"
echo -e "${BLUE}[*] Results saved in: $WORKSPACE${NC}"
echo -e "${BLUE}[*] Total subdomains found: $(wc -l < all_subdomains.txt)${NC}"
echo -e "${BLUE}[*] Live subdomains: $(wc -l < live_subdomains.txt)${NC}"
echo -e "${BLUE}[*] Log file: $LOG_FILE${NC}"

# Generate simple HTML report
cat > "recon_report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Reconnaissance Report - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        h2 { color: #666; }
        .stats { background: #f0f0f0; padding: 10px; margin: 10px 0; }
        pre { background: #f8f8f8; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>Reconnaissance Report for $TARGET</h1>
    <div class="stats">
        <h2>Statistics</h2>
        <p>Total Subdomains Found: $(wc -l < all_subdomains.txt)</p>
        <p>Live Subdomains: $(wc -l < live_subdomains.txt)</p>
        <p>Scan Date: $(date)</p>
    </div>
    
    <h2>Live Subdomains</h2>
    <pre>$(cat live_subdomains.txt)</pre>
    
    <h2>Port Scan Results</h2>
    <pre>$(cat nmap_scan.nmap 2>/dev/null || echo "Nmap results not available")</pre>
</body>
</html>
EOF

echo -e "${GREEN}[+] HTML report generated: recon_report.html${NC}"
echo "Reconnaissance completed at $(date)" >> "$LOG_FILE"
