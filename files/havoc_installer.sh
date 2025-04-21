#!/bin/bash
# Havoc C2 Framework installer with EDR evasion features

set -e
TEMP_DIR=$(mktemp -d)
LOG_FILE="/root/Tools/havoc_installer.log"
HAVOC_DIR="/root/Tools/havoc"
HAVOC_DATA_DIR="/root/Tools/havoc/data"
HAVOC_VERSION="0.5.0"
HAVOC_GITHUB="https://github.com/HavocFramework/Havoc"
GO_VERSION="1.19"

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
apt-get install -y git golang-go make build-essential mingw-w64 nasm cmake \
    ninja-build python3-pip libfontconfig1 libglu1-mesa-dev libgtest-dev \
    libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev \
    libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev \
    qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 \
    libqt5websockets5-dev >/dev/null 2>&1

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

# Generate unique identifiers for EDR evasion
RANDOMIZED_BUILD_ID=$(random_string 16)
log "Using randomized build ID: $RANDOMIZED_BUILD_ID"

# Build Havoc teamserver
log "Building Havoc teamserver..."
cd $HAVOC_DIR/Teamserver
go mod download
sed -i "s/const Version = \".*\"/const Version = \"${HAVOC_VERSION}-${RANDOMIZED_BUILD_ID}\"/" pkg/common/metadata.go
make

# Build Havoc client 
log "Building Havoc client..."
cd $HAVOC_DIR/Client
mkdir -p build
cd build
cmake -GNinja ..
ninja

# Generate self-signed SSL certificates for Teamserver
mkdir -p $HAVOC_DATA_DIR/certs
cd $HAVOC_DATA_DIR/certs

if [ ! -f havoc.key ] || [ ! -f havoc.crt ]; then
    log "Generating self-signed SSL certificates..."
    
    # Generate random values for certificate
    COUNTRY="US"
    STATE=$(random_string 8)
    LOCALITY=$(random_string 8)
    ORGANIZATION=$(random_string 10)
    COMMON_NAME=$(random_string 12).com
    
    # Create OpenSSL config
    cat > openssl.cnf << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $LOCALITY
O = $ORGANIZATION
CN = $COMMON_NAME

[v3_req]
keyUsage = critical, digitalSignature, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $COMMON_NAME
DNS.2 = localhost
EOF
    
    # Generate certificate
    openssl req -x509 -newkey rsa:4096 -keyout havoc.key -out havoc.crt -days 3650 -nodes -config openssl.cnf
    chmod 600 havoc.key
    chmod 644 havoc.crt
    
    log "Generated SSL certificates with CN=$COMMON_NAME"
fi

# Create systemd service for Havoc Teamserver
log "Creating systemd service for Havoc Teamserver..."
cat > /etc/systemd/system/havoc.service << EOF
[Unit]
Description=Havoc C2 Teamserver
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

# Create default Havoc profile directory
mkdir -p $HAVOC_DATA_DIR/profiles

# Create default Havoc profile
log "Creating default Havoc profile..."
cat > $HAVOC_DATA_DIR/profiles/default.yaotl << EOF
Teamserver {
    Host = "0.0.0.0"
    Port = 40056
    
    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    admin {
        Password = "$(random_string 12)"
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
        Port         = 8080
        PortBind     = 8080
        UserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        Headers      = ["Accept: */*"]
        Uris         = ["/api/v1", "/dashboard"]
        Secure       = false
    }
    
    https {
        Name         = "https"
        KillDate     = "2030-01-01"
        WorkingHours = "0:00-23:59"
        Hosts        = ["0.0.0.0"]
        HostBind     = "0.0.0.0"
        HostRotation = "round-robin"
        Port         = 443
        PortBind     = 443
        UserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        Headers      = ["Accept: */*"]
        Uris         = ["/api/v2", "/content"]
        Secure       = true
        Cert         = "$HAVOC_DATA_DIR/certs/havoc.crt"
        Key          = "$HAVOC_DATA_DIR/certs/havoc.key"
    }
}

Demon {
    Sleep        = 2
    SleepJitter  = 50
    
    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}
EOF

# Set proper permissions
log "Setting proper permissions..."
chmod 755 $HAVOC_DIR/Teamserver/teamserver
chmod 755 $HAVOC_DIR/Client/havoc

# Create symlinks to executables in /usr/local/bin
ln -sf $HAVOC_DIR/Teamserver/teamserver /usr/local/bin/havoc-teamserver
ln -sf $HAVOC_DIR/Client/havoc /usr/local/bin/havoc-client

# Enable and start Havoc service
log "Enabling and starting Havoc service..."
systemctl daemon-reload
systemctl enable havoc
systemctl start havoc

log "Havoc C2 installation completed!"