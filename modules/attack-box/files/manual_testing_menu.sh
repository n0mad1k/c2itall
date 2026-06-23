#!/bin/bash
# Manual Testing Menu for Attack Box
# Interactive interface for manual penetration testing tasks

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ASCII Banner
show_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
    ╔═══════════════════════════════════════╗
    ║           ATTACK BOX MENU             ║
    ║        Manual Testing Interface       ║
    ╚═══════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Main menu
show_main_menu() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}    Attack Box Manual Testing Menu     ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    echo -e "${BLUE}1.${NC}  Target Reconnaissance"
    echo -e "${BLUE}2.${NC}  Network Scanning"
    echo -e "${BLUE}3.${NC}  Web Application Testing"
    echo -e "${BLUE}4.${NC}  Vulnerability Assessment"
    echo -e "${BLUE}5.${NC}  Exploitation Framework"
    echo -e "${BLUE}6.${NC}  Post-Exploitation"
    echo -e "${BLUE}7.${NC}  Password Attacks"
    echo -e "${BLUE}8.${NC}  Wireless Testing"
    echo -e "${BLUE}9.${NC}  Social Engineering"
    echo -e "${BLUE}10.${NC} OSINT Tools"
    echo -e "${BLUE}11.${NC} Custom Scripts"
    echo -e "${BLUE}12.${NC} Tool Status & Updates"
    echo -e "${BLUE}13.${NC} Generate Reports"
    echo -e "${BLUE}0.${NC}  Exit"
    echo
    echo -ne "${YELLOW}Select an option [0-13]: ${NC}"
}

# Reconnaissance menu
recon_menu() {
    clear
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}       Reconnaissance Tools             ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    echo -e "${BLUE}1.${NC}  Domain Enumeration (theHarvester)"
    echo -e "${BLUE}2.${NC}  Subdomain Discovery (Subfinder + Amass)"
    echo -e "${BLUE}3.${NC}  DNS Enumeration (dnsrecon)"
    echo -e "${BLUE}4.${NC}  WHOIS Lookup"
    echo -e "${BLUE}5.${NC}  Shodan Search"
    echo -e "${BLUE}6.${NC}  Google Dorking (Pagodo)"
    echo -e "${BLUE}7.${NC}  Certificate Transparency"
    echo -e "${BLUE}8.${NC}  Automated Recon Script"
    echo -e "${BLUE}0.${NC}  Back to Main Menu"
    echo
    echo -ne "${YELLOW}Select an option [0-8]: ${NC}"
    
    read -r choice
    case $choice in
        1) domain_enum ;;
        2) subdomain_discovery ;;
        3) dns_enum ;;
        4) whois_lookup ;;
        5) shodan_search ;;
        6) google_dorking ;;
        7) cert_transparency ;;
        8) automated_recon ;;
        0) return ;;
        *) echo -e "${RED}Invalid option!${NC}"; sleep 2; recon_menu ;;
    esac
}

# Network scanning menu
network_menu() {
    clear
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}        Network Scanning Tools          ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    echo -e "${BLUE}1.${NC}  Nmap Host Discovery"
    echo -e "${BLUE}2.${NC}  Nmap Port Scan (Top 1000)"
    echo -e "${BLUE}3.${NC}  Nmap Full Port Scan"
    echo -e "${BLUE}4.${NC}  Nmap Service Detection"
    echo -e "${BLUE}5.${NC}  Nmap Vulnerability Scripts"
    echo -e "${BLUE}6.${NC}  Masscan Fast Scan"
    echo -e "${BLUE}7.${NC}  Automated Port Scan Script"
    echo -e "${BLUE}8.${NC}  Network Mapper (netdiscover)"
    echo -e "${BLUE}0.${NC}  Back to Main Menu"
    echo
    echo -ne "${YELLOW}Select an option [0-8]: ${NC}"
    
    read -r choice
    case $choice in
        1) nmap_discovery ;;
        2) nmap_port_scan ;;
        3) nmap_full_scan ;;
        4) nmap_service_detection ;;
        5) nmap_vuln_scripts ;;
        6) masscan_scan ;;
        7) automated_port_scan ;;
        8) network_discovery ;;
        0) return ;;
        *) echo -e "${RED}Invalid option!${NC}"; sleep 2; network_menu ;;
    esac
}

# Web application testing menu
web_menu() {
    clear
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}     Web Application Testing Tools      ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    echo -e "${BLUE}1.${NC}  Directory/File Enumeration (Gobuster)"
    echo -e "${BLUE}2.${NC}  Technology Detection (WhatWeb)"
    echo -e "${BLUE}3.${NC}  Vulnerability Scanner (Nikto)"
    echo -e "${BLUE}4.${NC}  Web Crawler (Hakrawler)"
    echo -e "${BLUE}5.${NC}  Parameter Discovery (Arjun)"
    echo -e "${BLUE}6.${NC}  SQL Injection (SQLMap)"
    echo -e "${BLUE}7.${NC}  XSS Testing (XSStrike)"
    echo -e "${BLUE}8.${NC}  Automated Web Enum Script"
    echo -e "${BLUE}9.${NC}  Launch Burp Suite"
    echo -e "${BLUE}0.${NC}  Back to Main Menu"
    echo
    echo -ne "${YELLOW}Select an option [0-9]: ${NC}"
    
    read -r choice
    case $choice in
        1) directory_enum ;;
        2) tech_detection ;;
        3) web_vuln_scan ;;
        4) web_crawler ;;
        5) param_discovery ;;
        6) sql_injection ;;
        7) xss_testing ;;
        8) automated_web_enum ;;
        9) launch_burp ;;
        0) return ;;
        *) echo -e "${RED}Invalid option!${NC}"; sleep 2; web_menu ;;
    esac
}

# Vulnerability assessment menu
vuln_menu() {
    clear
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}     Vulnerability Assessment Tools     ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    echo -e "${BLUE}1.${NC}  Nuclei Scanner"
    echo -e "${BLUE}2.${NC}  OpenVAS Scan"
    echo -e "${BLUE}3.${NC}  SearchSploit (ExploitDB)"
    echo -e "${BLUE}4.${NC}  CVE Search"
    echo -e "${BLUE}5.${NC}  Vulnerability Database Lookup"
    echo -e "${BLUE}6.${NC}  Custom Vulnerability Scripts"
    echo -e "${BLUE}0.${NC}  Back to Main Menu"
    echo
    echo -ne "${YELLOW}Select an option [0-6]: ${NC}"
    
    read -r choice
    case $choice in
        1) nuclei_scan ;;
        2) openvas_scan ;;
        3) searchsploit_search ;;
        4) cve_search ;;
        5) vuln_db_lookup ;;
        6) custom_vuln_scripts ;;
        0) return ;;
        *) echo -e "${RED}Invalid option!${NC}"; sleep 2; vuln_menu ;;
    esac
}

# Functions for each tool category
domain_enum() {
    echo -e "${YELLOW}[*] Domain Enumeration with theHarvester${NC}"
    echo -ne "Enter target domain: "
    read -r domain
    echo -e "${GREEN}[+] Running theHarvester against $domain${NC}"
    theHarvester -d "$domain" -b all -l 500
    echo -e "${BLUE}[*] Press Enter to continue...${NC}"
    read -r
    recon_menu
}

subdomain_discovery() {
    echo -e "${YELLOW}[*] Subdomain Discovery${NC}"
    echo -ne "Enter target domain: "
    read -r domain
    echo -e "${GREEN}[+] Running Subfinder...${NC}"
    subfinder -d "$domain" -o "subdomains_$domain.txt"
    echo -e "${GREEN}[+] Running Amass...${NC}"
    amass enum -d "$domain" -o "amass_$domain.txt"
    echo -e "${BLUE}[*] Results saved to subdomains_$domain.txt and amass_$domain.txt${NC}"
    echo -e "${BLUE}[*] Press Enter to continue...${NC}"
    read -r
    recon_menu
}

nmap_port_scan() {
    echo -e "${YELLOW}[*] Nmap Port Scan (Top 1000)${NC}"
    echo -ne "Enter target IP/range: "
    read -r target
    echo -e "${GREEN}[+] Scanning $target...${NC}"
    nmap -sS -T4 --top-ports 1000 -oN "nmap_top1000_$target.txt" "$target"
    echo -e "${BLUE}[*] Results saved to nmap_top1000_$target.txt${NC}"
    echo -e "${BLUE}[*] Press Enter to continue...${NC}"
    read -r
    network_menu
}

directory_enum() {
    echo -e "${YELLOW}[*] Directory/File Enumeration${NC}"
    echo -ne "Enter target URL: "
    read -r url
    echo -e "${GREEN}[+] Running Gobuster against $url${NC}"
    gobuster dir -u "$url" -w /usr/share/wordlists/dirb/common.txt -o "gobuster_$(echo $url | sed 's|https\?://||g' | tr '/' '_').txt"
    echo -e "${BLUE}[*] Press Enter to continue...${NC}"
    read -r
    web_menu
}

automated_recon() {
    echo -e "${YELLOW}[*] Running Automated Reconnaissance Script${NC}"
    echo -ne "Enter target domain/IP: "
    read -r target
    echo -e "${GREEN}[+] Executing recon automation script...${NC}"
    if [ -f "/root/operator/tools/scripts/recon_automation.sh" ]; then
        /root/operator/tools/scripts/recon_automation.sh "$target"
    else
        echo -e "${RED}[-] Recon automation script not found!${NC}"
    fi
    echo -e "${BLUE}[*] Press Enter to continue...${NC}"
    read -r
    recon_menu
}

automated_port_scan() {
    echo -e "${YELLOW}[*] Running Automated Port Scan Script${NC}"
    echo -ne "Enter target IP/range: "
    read -r target
    echo -e "${GREEN}[+] Executing port scan automation script...${NC}"
    if [ -f "/root/operator/tools/scripts/port_scan_automation.sh" ]; then
        /root/operator/tools/scripts/port_scan_automation.sh "$target"
    else
        echo -e "${RED}[-] Port scan automation script not found!${NC}"
    fi
    echo -e "${BLUE}[*] Press Enter to continue...${NC}"
    read -r
    network_menu
}

automated_web_enum() {
    echo -e "${YELLOW}[*] Running Automated Web Enumeration Script${NC}"
    echo -ne "Enter target URL: "
    read -r url
    echo -e "${GREEN}[+] Executing web enumeration automation script...${NC}"
    if [ -f "/root/operator/tools/scripts/web_enum_automation.sh" ]; then
        /root/operator/tools/scripts/web_enum_automation.sh "$url"
    else
        echo -e "${RED}[-] Web enumeration automation script not found!${NC}"
    fi
    echo -e "${BLUE}[*] Press Enter to continue...${NC}"
    read -r
    web_menu
}

# Tool status and updates
tool_status() {
    clear
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}        Tool Status & Updates           ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    
    # Check key tools
    tools=("nmap" "gobuster" "nuclei" "subfinder" "amass" "sqlmap" "nikto" "whatweb")
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}[✓]${NC} $tool - Installed"
        else
            echo -e "${RED}[✗]${NC} $tool - Not Found"
        fi
    done
    
    echo
    echo -e "${BLUE}[*] Press Enter to continue...${NC}"
    read -r
}

# Generate reports
generate_reports() {
    clear
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}         Generate Reports               ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    
    WORKSPACE="/root/operator"
    DATE=$(date +%Y%m%d_%H%M%S)
    REPORT_DIR="$WORKSPACE/reports/manual_testing_$DATE"
    
    mkdir -p "$REPORT_DIR"
    
    echo -e "${YELLOW}[*] Generating comprehensive report...${NC}"
    
    # Collect all scan results
    find "$WORKSPACE" -name "*.txt" -type f -exec cp {} "$REPORT_DIR/" \; 2>/dev/null
    find "$WORKSPACE" -name "*.html" -type f -exec cp {} "$REPORT_DIR/" \; 2>/dev/null
    find "$WORKSPACE" -name "*.json" -type f -exec cp {} "$REPORT_DIR/" \; 2>/dev/null
    
    # Create summary report
    cat > "$REPORT_DIR/summary_report.md" << EOF
# Manual Testing Report
**Generated:** $(date)
**Operator:** $(whoami)

## Engagement Summary
This report contains results from manual penetration testing activities.

## Files Included
$(ls -la "$REPORT_DIR" | grep -v "^total")

## Key Findings
- Review individual tool outputs for detailed findings
- Cross-reference results across multiple tools
- Validate findings manually before reporting

## Next Steps
1. Analyze all collected data
2. Prioritize findings by severity
3. Prepare client deliverables
4. Archive results securely
EOF
    
    echo -e "${GREEN}[+] Report generated: $REPORT_DIR${NC}"
    echo -e "${BLUE}[*] Press Enter to continue...${NC}"
    read -r
}

# Main execution loop
main() {
    while true; do
        clear
        show_banner
        show_main_menu
        read -r choice
        
        case $choice in
            1) recon_menu ;;
            2) network_menu ;;
            3) web_menu ;;
            4) vuln_menu ;;
            5) echo -e "${YELLOW}[*] Exploitation Framework - Launch Metasploit${NC}"; msfconsole ;;
            6) echo -e "${YELLOW}[*] Post-Exploitation - Launch custom shells/tools${NC}"; sleep 2 ;;
            7) echo -e "${YELLOW}[*] Password Attacks - Hydra, John, Hashcat${NC}"; sleep 2 ;;
            8) echo -e "${YELLOW}[*] Wireless Testing - Aircrack-ng suite${NC}"; sleep 2 ;;
            9) echo -e "${YELLOW}[*] Social Engineering - SET toolkit${NC}"; setoolkit ;;
            10) echo -e "${YELLOW}[*] OSINT Tools - Various intelligence gathering tools${NC}"; sleep 2 ;;
            11) echo -e "${YELLOW}[*] Custom Scripts - Run user-defined scripts${NC}"; sleep 2 ;;
            12) tool_status ;;
            13) generate_reports ;;
            0) echo -e "${GREEN}[+] Goodbye!${NC}"; exit 0 ;;
            *) echo -e "${RED}Invalid option! Please try again.${NC}"; sleep 2 ;;
        esac
    done
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}[!] Running as root - be careful!${NC}"
    sleep 2
fi

# Create operator structure if it doesn't exist
mkdir -p "/root/operator/"{tools,scans,logs,loot,payloads,targets,screenshots,reports,notes,exploits,wordlists,pcaps}

# Start the main menu
main
