#!/bin/bash
# Emergency Wipe Script for OPSEC
# Quickly sanitizes system for emergency situations

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}=== EMERGENCY SANITIZATION PROTOCOL ===${NC}"
echo -e "${YELLOW}This will clear sensitive data and logs${NC}"
echo ""

# Confirm emergency wipe
read -p "Are you sure you want to proceed? (type YES): " CONFIRM
if [ "$CONFIRM" != "YES" ]; then
    echo -e "${GREEN}Emergency wipe cancelled${NC}"
    exit 0
fi

echo -e "${RED}[*] Beginning emergency sanitization...${NC}"

# Clear command history
echo -e "${YELLOW}[*] Clearing command history${NC}"
history -c
> ~/.bash_history
> ~/.zsh_history
> ~/.python_history
> ~/.mysql_history
> ~/.psql_history

# Clear system logs
echo -e "${YELLOW}[*] Clearing system logs${NC}"
sudo find /var/log -type f -exec truncate -s 0 {} \; 2>/dev/null
sudo truncate -s 0 /var/log/auth.log 2>/dev/null
sudo truncate -s 0 /var/log/syslog 2>/dev/null
sudo truncate -s 0 /var/log/kern.log 2>/dev/null

# Clear temporary files
echo -e "${YELLOW}[*] Clearing temporary files${NC}"
sudo rm -rf /tmp/* 2>/dev/null
sudo rm -rf /var/tmp/* 2>/dev/null
rm -rf ~/.cache/* 2>/dev/null

# Clear SSH known hosts
echo -e "${YELLOW}[*] Clearing SSH artifacts${NC}"
> ~/.ssh/known_hosts
sudo truncate -s 0 /var/log/btmp 2>/dev/null
sudo truncate -s 0 /var/log/wtmp 2>/dev/null
sudo truncate -s 0 /var/log/lastlog 2>/dev/null

# Clear network traces
echo -e "${YELLOW}[*] Clearing network artifacts${NC}"
sudo ip neigh flush all 2>/dev/null

# Clear DNS cache
echo -e "${YELLOW}[*] Clearing DNS cache${NC}"
sudo systemctl restart systemd-resolved 2>/dev/null

# Clear browser data if present
echo -e "${YELLOW}[*] Clearing browser data${NC}"
rm -rf ~/.mozilla/firefox/*/sessionstore* 2>/dev/null
rm -rf ~/.mozilla/firefox/*/cookies.sqlite 2>/dev/null
rm -rf ~/.config/google-chrome/Default/History 2>/dev/null
rm -rf ~/.config/google-chrome/Default/Cookies 2>/dev/null

# Secure delete free space (optional - takes time)
read -p "Perform secure free space wipe? (y/N): " WIPE_FREE
if [ "$WIPE_FREE" = "y" ] || [ "$WIPE_FREE" = "Y" ]; then
    echo -e "${YELLOW}[*] Securely wiping free space (this may take a while)${NC}"
    dd if=/dev/urandom of=/tmp/wipe_file bs=1M 2>/dev/null || true
    rm -f /tmp/wipe_file 2>/dev/null
fi

# Clear systemd journal
echo -e "${YELLOW}[*] Clearing systemd journal${NC}"
sudo journalctl --vacuum-time=1s 2>/dev/null

# Final cleanup
echo -e "${YELLOW}[*] Final cleanup${NC}"
sync
sudo updatedb 2>/dev/null

echo ""
echo -e "${GREEN}=== EMERGENCY SANITIZATION COMPLETE ===${NC}"
echo -e "${YELLOW}Consider rebooting the system for maximum effectiveness${NC}"
echo -e "${RED}WARNING: This does not guarantee complete data removal${NC}"
