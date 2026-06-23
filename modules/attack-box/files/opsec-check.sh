#!/bin/bash
# OPSEC Status Check Script
# Monitors operational security status for red team operations

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== OPERATIONAL SECURITY STATUS ===${NC}"
echo ""

# Check VPN Status
echo -e "${BLUE}[*] VPN Status:${NC}"
if pgrep openvpn > /dev/null 2>&1; then
    echo -e "${GREEN}  ✓ OpenVPN is running${NC}"
    VPN_INTERFACES=$(ip link show | grep -E "tun|tap" | awk -F: '{print $2}' | xargs)
    if [ ! -z "$VPN_INTERFACES" ]; then
        echo -e "${GREEN}  ✓ VPN interfaces active: $VPN_INTERFACES${NC}"
    fi
else
    echo -e "${RED}  ✗ OpenVPN not detected${NC}"
fi

# Check Tor Status
echo -e "\n${BLUE}[*] Tor Status:${NC}"
if systemctl is-active tor >/dev/null 2>&1; then
    echo -e "${GREEN}  ✓ Tor service is active${NC}"
    if netstat -tuln 2>/dev/null | grep -q ":9050"; then
        echo -e "${GREEN}  ✓ SOCKS proxy listening on 9050${NC}"
    fi
else
    echo -e "${YELLOW}  - Tor service not active${NC}"
fi

# Check External IP
echo -e "\n${BLUE}[*] External IP Check:${NC}"
EXTERNAL_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null)
if [ ! -z "$EXTERNAL_IP" ]; then
    echo -e "${GREEN}  ✓ External IP: $EXTERNAL_IP${NC}"
else
    echo -e "${RED}  ✗ Could not determine external IP${NC}"
fi

# Check DNS
echo -e "\n${BLUE}[*] DNS Configuration:${NC}"
DNS_SERVERS=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | xargs)
echo -e "${GREEN}  ✓ DNS servers: $DNS_SERVERS${NC}"

# Check for DNS leaks
echo -e "\n${BLUE}[*] DNS Leak Test:${NC}"
DNS_LEAK=$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null)
if [ ! -z "$DNS_LEAK" ]; then
    if [ "$DNS_LEAK" = "$EXTERNAL_IP" ]; then
        echo -e "${GREEN}  ✓ No DNS leak detected${NC}"
    else
        echo -e "${YELLOW}  ! Potential DNS leak: $DNS_LEAK vs $EXTERNAL_IP${NC}"
    fi
else
    echo -e "${YELLOW}  - DNS leak test failed${NC}"
fi

# Check Active Connections
echo -e "\n${BLUE}[*] Active Network Connections:${NC}"
ACTIVE_CONS=$(ss -tupln 2>/dev/null | grep -E "LISTEN|ESTAB" | wc -l)
echo -e "${GREEN}  ✓ $ACTIVE_CONS active connections${NC}"

# Check Suspicious Processes
echo -e "\n${BLUE}[*] Process Security Check:${NC}"
SUSPICIOUS_PROCS=$(ps aux | grep -iE "wireshark|tcpdump|ettercap" | grep -v grep | wc -l)
if [ $SUSPICIOUS_PROCS -gt 0 ]; then
    echo -e "${YELLOW}  ! $SUSPICIOUS_PROCS monitoring processes detected${NC}"
else
    echo -e "${GREEN}  ✓ No obvious monitoring processes${NC}"
fi

# Check SSH Keys
echo -e "\n${BLUE}[*] SSH Key Security:${NC}"
SSH_KEYS=$(find ~/.ssh -name "*.pub" 2>/dev/null | wc -l)
echo -e "${GREEN}  ✓ $SSH_KEYS SSH public keys found${NC}"

# Check System Logs
echo -e "\n${BLUE}[*] Log Security:${NC}"
AUTH_LOG_SIZE=$(wc -l /var/log/auth.log 2>/dev/null | awk '{print $1}')
if [ ! -z "$AUTH_LOG_SIZE" ]; then
    echo -e "${GREEN}  ✓ Auth log has $AUTH_LOG_SIZE entries${NC}"
fi

# Check Firewall Status
echo -e "\n${BLUE}[*] Firewall Status:${NC}"
if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)
    echo -e "${GREEN}  ✓ UFW: $UFW_STATUS${NC}"
fi

if command -v iptables >/dev/null 2>&1; then
    IPTABLES_RULES=$(iptables -L 2>/dev/null | grep -c "Chain")
    echo -e "${GREEN}  ✓ iptables: $IPTABLES_RULES chains configured${NC}"
fi

echo ""
echo -e "${BLUE}=== OPSEC CHECK COMPLETE ===${NC}"
echo ""

# Provide recommendations based on findings
echo -e "${BLUE}[*] Recommendations:${NC}"
if ! pgrep openvpn > /dev/null 2>&1; then
    echo -e "${YELLOW}  • Consider using VPN for enhanced anonymity${NC}"
fi

if ! systemctl is-active tor >/dev/null 2>&1; then
    echo -e "${YELLOW}  • Consider enabling Tor for additional anonymity${NC}"
fi

echo -e "${GREEN}  • Regularly monitor external IP changes${NC}"
echo -e "${GREEN}  • Clear logs periodically during operations${NC}"
echo -e "${GREEN}  • Use proxychains for sensitive network operations${NC}"
