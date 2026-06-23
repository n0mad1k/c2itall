#!/bin/bash
# Trash Cleanup Script
# Safely removes operational artifacts and cleans system

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== OPERATIONAL CLEANUP ===${NC}"
echo ""

# Get working directory
if [ -n "$1" ]; then
    WORK_DIR="$1"
else
    # Auto-detect working directory
    if [ -d "/root/operator" ]; then
        WORK_DIR="/root/operator"
    else
        # Find deployment-named directory
        WORK_DIR=$(find /root -maxdepth 1 -type d -name "*[a-z]*[a-z]*" 2>/dev/null | head -1)
        if [ -z "$WORK_DIR" ]; then
            WORK_DIR="/root"
        fi
    fi
fi

echo -e "${BLUE}[*] Working directory: $WORK_DIR${NC}"

# Clean scan results older than 7 days
if [ -d "$WORK_DIR/scans" ]; then
    echo -e "${YELLOW}[*] Cleaning old scan results (>7 days)${NC}"
    find "$WORK_DIR/scans" -type f -mtime +7 -name "*.xml" -delete 2>/dev/null
    find "$WORK_DIR/scans" -type f -mtime +7 -name "*.txt" -delete 2>/dev/null
    find "$WORK_DIR/scans" -type f -mtime +7 -name "*.log" -delete 2>/dev/null
fi

# Clean temporary loot
if [ -d "$WORK_DIR/loot" ]; then
    echo -e "${YELLOW}[*] Cleaning temporary loot files${NC}"
    find "$WORK_DIR/loot" -name "*.tmp" -delete 2>/dev/null
    find "$WORK_DIR/loot" -name "temp_*" -delete 2>/dev/null
fi

# Clean logs older than 30 days
if [ -d "$WORK_DIR/logs" ]; then
    echo -e "${YELLOW}[*] Cleaning old logs (>30 days)${NC}"
    find "$WORK_DIR/logs" -type f -mtime +30 -delete 2>/dev/null
fi

# Clean empty directories
echo -e "${YELLOW}[*] Removing empty directories${NC}"
find "$WORK_DIR" -type d -empty -delete 2>/dev/null

# Clean system temp files
echo -e "${YELLOW}[*] Cleaning system temporary files${NC}"
rm -f /tmp/nmap_* 2>/dev/null
rm -f /tmp/scan_* 2>/dev/null
rm -f /tmp/exploit_* 2>/dev/null
rm -f /tmp/*.tmp 2>/dev/null

# Rotate command history
echo -e "${YELLOW}[*] Rotating command history${NC}"
if [ -f ~/.bash_history ]; then
    tail -n 100 ~/.bash_history > /tmp/hist_tmp && mv /tmp/hist_tmp ~/.bash_history
fi

# Clean network artifacts
echo -e "${YELLOW}[*] Clearing network artifacts${NC}"
> ~/.ssh/known_hosts

# Update file permissions
echo -e "${YELLOW}[*] Updating file permissions${NC}"
if [ -d "$WORK_DIR" ]; then
    chmod -R 750 "$WORK_DIR" 2>/dev/null
    find "$WORK_DIR" -name "*.sh" -exec chmod +x {} \; 2>/dev/null
fi

# Compress old files
echo -e "${YELLOW}[*] Compressing old files${NC}"
if [ -d "$WORK_DIR/reports" ]; then
    find "$WORK_DIR/reports" -name "*.txt" -mtime +7 -exec gzip {} \; 2>/dev/null
fi

echo ""
echo -e "${GREEN}=== CLEANUP COMPLETE ===${NC}"
echo -e "${BLUE}Summary:${NC}"
echo -e "${GREEN}  ✓ Old scan results cleaned${NC}"
echo -e "${GREEN}  ✓ Temporary files removed${NC}"
echo -e "${GREEN}  ✓ Logs rotated${NC}"
echo -e "${GREEN}  ✓ Permissions updated${NC}"
echo -e "${GREEN}  ✓ Network artifacts cleared${NC}"
