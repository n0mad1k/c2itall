#!/bin/bash
# Attack Box - Python Tools Installation Script
# Installs security tools via pipx with enhanced feedback

export PATH="/root/.local/bin:$PATH"

echo "================================================================"
echo "PYTHON TOOLS INSTALLATION STARTED"
echo "================================================================"
echo "Total tools to install: 29"
echo "Each tool has a 5-minute timeout"
echo "================================================================"

TOOLS=(
  "impacket"
  "bloodhound"
  "crackmapexec"
  "netexec"
  "droopescan"
  "wpscan"
  "arjun"
  "subjack"
  "sublist3r"
  "theharvester"
  "feroxbuster"
  "dirsearch"
  "sqlmap"
  "wafw00f"
  "dnsrecon"
  "dnsgen"
  "massdns"
  "altdns"
  "paramspider"
  "linkfinder"
  "xsstrike"
  "scapy"
  "pwntools"
  "volatility3"
  "ldapdomaindump"
  "ldap3"
  "responder"
  "mitm6"
  "enum4linux-ng"
  "smbmap"
)

TOTAL=${#TOOLS[@]}
CURRENT=0
FAILED=0
SUCCESS=0

for tool in "${TOOLS[@]}"; do
  CURRENT=$((CURRENT + 1))
  echo ""
  echo "[$CURRENT/$TOTAL] Installing $tool..."
  echo "Progress: $(( CURRENT * 100 / TOTAL ))%"
  echo "Started: $(date '+%H:%M:%S')"
  
  if timeout 300 pipx install --verbose "$tool" 2>&1; then
    SUCCESS=$((SUCCESS + 1))
    echo "✓ $tool installed successfully"
  else
    FAILED=$((FAILED + 1))
    echo "✗ $tool installation failed or timed out"
  fi
  
  echo "Completed: $(date '+%H:%M:%S')"
  echo "Status: $SUCCESS successful, $FAILED failed"
  echo "Remaining: $(( TOTAL - CURRENT )) tools"
  echo "================================================================"
done

echo ""
echo "PYTHON TOOLS INSTALLATION SUMMARY:"
echo "=================================="
echo "Total attempted: $TOTAL"
echo "Successful: $SUCCESS"
echo "Failed: $FAILED"
echo "Success rate: $(( SUCCESS * 100 / TOTAL ))%"
echo ""
echo "Installed pipx tools:"
pipx list

exit 0
