#!/bin/bash
# Web Application Enumeration Script for Attack Box
# Usage: ./web_enum_automation.sh <target_url>

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_url>"
    echo "Example: $0 https://example.com"
    echo "         $0 http://10.0.0.100:8080"
    exit 1
fi

TARGET_URL="$1"
# Extract domain/IP for workspace naming
TARGET_CLEAN=$(echo "$TARGET_URL" | sed 's|https\?://||g' | sed 's|/.*||g' | tr ':' '_')
BASE_DIR="${WORK_DIR:-${WORK_DIR:-/root/workspace}}"
WORKSPACE="$BASE_DIR/scans/web/$TARGET_CLEAN"
DATE=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}[+] Starting web enumeration for: $TARGET_URL${NC}"

# Create workspace
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"

# Create log file
LOG_FILE="web_enum_$DATE.log"
echo "Web enumeration started at $(date)" > "$LOG_FILE"

# Function to log and execute
log_and_run() {
    echo -e "${YELLOW}[*] $1${NC}"
    echo "[$(date)] $1" >> "$LOG_FILE"
    eval "$2" 2>&1 | tee -a "$LOG_FILE"
}

# Basic web info gathering
echo -e "${GREEN}[+] Phase 1: Basic Information Gathering${NC}"
log_and_run "Getting HTTP headers" "curl -I $TARGET_URL"
log_and_run "Checking robots.txt" "curl -s $TARGET_URL/robots.txt"
log_and_run "Checking sitemap.xml" "curl -s $TARGET_URL/sitemap.xml"

# Technology detection
echo -e "${GREEN}[+] Phase 2: Technology Detection${NC}"
log_and_run "Running whatweb" "whatweb -a 3 $TARGET_URL"
if command -v wappalyzer &> /dev/null; then
    log_and_run "Running Wappalyzer" "wappalyzer $TARGET_URL"
fi

# Directory and file enumeration
echo -e "${GREEN}[+] Phase 3: Directory and File Enumeration${NC}"

# Gobuster with common wordlist
log_and_run "Gobuster directory enumeration (common)" "gobuster dir -u $TARGET_URL -w /usr/share/wordlists/dirb/common.txt -o gobuster_common.txt -q"

# Gobuster with bigger wordlist
if [ -f "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" ]; then
    log_and_run "Gobuster directory enumeration (medium)" "gobuster dir -u $TARGET_URL -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -o gobuster_medium.txt -q --timeout 10s"
fi

# File extension enumeration
log_and_run "Gobuster file enumeration" "gobuster dir -u $TARGET_URL -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,js,xml,json,bak,old -o gobuster_files.txt -q"

# Alternative directory tools
if command -v dirb &> /dev/null; then
    log_and_run "Dirb enumeration" "dirb $TARGET_URL -o dirb_results.txt"
fi

if command -v ffuf &> /dev/null; then
    log_and_run "FFUF enumeration" "ffuf -w /usr/share/wordlists/dirb/common.txt -u $TARGET_URL/FUZZ -o ffuf_results.json -of json -s"
fi

# Subdomain enumeration (if it's a domain)
if [[ $TARGET_URL == *"."* ]] && [[ $TARGET_URL != *[0-9]* ]]; then
    echo -e "${GREEN}[+] Phase 4: Subdomain Enumeration${NC}"
    DOMAIN=$(echo "$TARGET_URL" | sed 's|https\?://||g' | sed 's|/.*||g' | cut -d':' -f1)
    log_and_run "Gobuster subdomain enumeration" "gobuster dns -d $DOMAIN -w /usr/share/wordlists/dirb/common.txt -o gobuster_subdomains.txt -q"
fi

# Web vulnerability scanning
echo -e "${GREEN}[+] Phase 5: Vulnerability Scanning${NC}"
log_and_run "Nikto scan" "nikto -h $TARGET_URL -o nikto_results.txt"

# Nuclei web templates
if command -v nuclei &> /dev/null; then
    log_and_run "Nuclei web vulnerability scan" "nuclei -u $TARGET_URL -H 'User-Agent: homelab-security-scan/nuclei' -t ~/nuclei-templates/http/ -o nuclei_web_results.txt"
fi

# SSL/TLS testing (for HTTPS)
if [[ $TARGET_URL == https* ]]; then
    echo -e "${GREEN}[+] Phase 6: SSL/TLS Testing${NC}"
    DOMAIN=$(echo "$TARGET_URL" | sed 's|https://||g' | sed 's|/.*||g')
    log_and_run "SSL certificate information" "openssl s_client -connect $DOMAIN:443 -servername $DOMAIN < /dev/null 2>/dev/null | openssl x509 -text -noout"
    
    if command -v sslscan &> /dev/null; then
        log_and_run "SSLScan" "sslscan $DOMAIN"
    fi
    
    if command -v testssl.sh &> /dev/null; then
        log_and_run "TestSSL" "testssl.sh $TARGET_URL"
    fi
fi

# Web application firewall detection
echo -e "${GREEN}[+] Phase 7: WAF Detection${NC}"
if command -v wafw00f &> /dev/null; then
    log_and_run "WAF detection" "wafw00f $TARGET_URL"
fi

# Content discovery and analysis
echo -e "${GREEN}[+] Phase 8: Content Analysis${NC}"

# Find interesting files and directories
echo -e "${BLUE}[*] Analyzing discovered content...${NC}"
if [ -f "gobuster_common.txt" ]; then
    echo "Interesting directories found:" >> content_analysis.txt
    grep -E "(admin|login|api|config|backup|test|dev)" gobuster_common.txt >> content_analysis.txt 2>/dev/null || echo "No interesting directories found" >> content_analysis.txt
fi

# Parameter discovery
if command -v arjun &> /dev/null; then
    log_and_run "Parameter discovery with Arjun" "arjun -u $TARGET_URL -o arjun_params.txt"
fi

# JavaScript analysis
log_and_run "Finding JavaScript files" "curl -s $TARGET_URL | grep -oP '(?<=src=\")[^\"]*\.js(?=\")' | head -10 > js_files.txt"

# Generate summary report
echo -e "${GREEN}[+] Web Enumeration Complete!${NC}"
echo -e "${BLUE}[*] Results saved in: $WORKSPACE${NC}"
echo -e "${BLUE}[*] Log file: $LOG_FILE${NC}"

# Count discovered items
DIRS_FOUND=0
FILES_FOUND=0
if [ -f "gobuster_common.txt" ]; then
    DIRS_FOUND=$(wc -l < gobuster_common.txt)
fi
if [ -f "gobuster_files.txt" ]; then
    FILES_FOUND=$(wc -l < gobuster_files.txt)
fi

echo -e "${BLUE}[*] Directories found: $DIRS_FOUND${NC}"
echo -e "${BLUE}[*] Files found: $FILES_FOUND${NC}"

# Generate HTML report
cat > "web_enum_report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Web Enumeration Report - $TARGET_URL</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        h2 { color: #666; }
        .stats { background: #f0f0f0; padding: 10px; margin: 10px 0; }
        pre { background: #f8f8f8; padding: 10px; overflow-x: auto; }
        .finding { background: #ffffcc; padding: 5px; margin: 5px 0; }
    </style>
</head>
<body>
    <h1>Web Enumeration Report</h1>
    <p><strong>Target:</strong> $TARGET_URL</p>
    
    <div class="stats">
        <h2>Statistics</h2>
        <p>Directories Found: $DIRS_FOUND</p>
        <p>Files Found: $FILES_FOUND</p>
        <p>Scan Date: $(date)</p>
    </div>
    
    <h2>Discovered Directories</h2>
    <pre>$(cat gobuster_common.txt 2>/dev/null | head -20 || echo "No directories file found")</pre>
    
    <h2>Discovered Files</h2>
    <pre>$(cat gobuster_files.txt 2>/dev/null | head -20 || echo "No files found")</pre>
    
    <h2>Technology Stack</h2>
    <pre>$(grep -A 10 "Running whatweb" $LOG_FILE 2>/dev/null | tail -n +2 | head -10 || echo "Technology detection results not available")</pre>
    
    <h2>Security Findings</h2>
    <pre>$(cat nikto_results.txt 2>/dev/null | head -20 || echo "Nikto results not available")</pre>
</body>
</html>
EOF

echo -e "${GREEN}[+] HTML report generated: web_enum_report.html${NC}"

# Next steps suggestions
cat > "next_steps.txt" << EOF
Next Steps for $TARGET_URL:
===========================

1. Manual Testing:
   - Browse discovered directories manually
   - Test for authentication bypasses
   - Look for file upload functionality
   - Check for SQL injection points

2. Focused Scanning:
   - Run OWASP ZAP or Burp Suite
   - Test for XSS vulnerabilities
   - Check for CSRF tokens
   - Test API endpoints if found

3. Exploitation:
   - Research CVEs for identified technologies
   - Test default credentials
   - Look for configuration files with sensitive data
   - Check for local file inclusion vulnerabilities

4. Further Enumeration:
   - Use custom wordlists for your target
   - Check for backup files (.bak, .old, .swp)
   - Look for version control directories (.git, .svn)
   - Test for subdomain takeover

Files to review:
$(ls -la *.txt *.html *.json 2>/dev/null || echo "No additional files found")
EOF

echo -e "${GREEN}[+] Next steps guide generated: next_steps.txt${NC}"
echo "Web enumeration completed at $(date)" >> "$LOG_FILE"
