#!/bin/bash
# randomize_ports.sh - Generate and set random ports for C2 services

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}   C2ingRed Port Randomization                     ${NC}"
echo -e "${BLUE}==================================================${NC}"

# Define port range (avoid well-known and commonly monitored ports)
MIN_PORT=10000
MAX_PORT=60000

# Define list of ports to avoid (commonly used services and monitoring tools)
AVOID_PORTS=(22 80 443 3389 5985 5986 3306 5432 1433 8080 8443 9090 9091 8008 4444 5555 1234 4321 31337 50051)

# Function to check if a port is in the avoid list
is_port_avoided() {
    local port=$1
    for avoid_port in "${AVOID_PORTS[@]}"; do
        if [ "$port" -eq "$avoid_port" ]; then
            return 0  # Port should be avoided
        fi
    done
    return 1  # Port is fine to use
}

# Function to check if a port is already in use
is_port_in_use() {
    local port=$1
    if ss -tuln | grep -q ":$port "; then
        return 0  # Port is in use
    fi
    return 1  # Port is not in use
}

# Function to generate a random port number
generate_random_port() {
    local attempts=0
    local max_attempts=20
    local port
    
    while [ $attempts -lt $max_attempts ]; do
        port=$((RANDOM % (MAX_PORT - MIN_PORT) + MIN_PORT))
        
        # Check if port is in avoid list or already in use
        if ! is_port_avoided $port && ! is_port_in_use $port; then
            echo $port
            return 0
        fi
        
        attempts=$((attempts + 1))
    done
    
    # If we reach here, we couldn't find a suitable port
    echo "Error: Could not find a suitable random port after $max_attempts attempts" >&2
    return 1
}

# Generate random ports for different services
HTTP_C2_PORT=$(generate_random_port)
HTTPS_C2_PORT=$(generate_random_port)
MTLS_C2_PORT=$(generate_random_port)
SHELL_HANDLER_PORT=$(generate_random_port)
BEACON_SERVER_PORT=$(generate_random_port)
ADMIN_PORT=$(generate_random_port)

# Print the generated ports
echo -e "\n${GREEN}Generated random ports:${NC}"
echo -e "HTTP C2 Port: ${YELLOW}$HTTP_C2_PORT${NC}"
echo -e "HTTPS C2 Port: ${YELLOW}$HTTPS_C2_PORT${NC}"
echo -e "MTLS C2 Port: ${YELLOW}$MTLS_C2_PORT${NC}"
echo -e "Shell Handler Port: ${YELLOW}$SHELL_HANDLER_PORT${NC}"
echo -e "Beacon Server Port: ${YELLOW}$BEACON_SERVER_PORT${NC}"
echo -e "Admin Port: ${YELLOW}$ADMIN_PORT${NC}"

# Create a port configuration file
PORT_CONFIG="/root/Tools/port_config.json"
cat > $PORT_CONFIG << EOF
{
    "http_c2_port": $HTTP_C2_PORT,
    "https_c2_port": $HTTPS_C2_PORT,
    "mtls_c2_port": $MTLS_C2_PORT,
    "shell_handler_port": $SHELL_HANDLER_PORT,
    "beacon_server_port": $BEACON_SERVER_PORT,
    "admin_port": $ADMIN_PORT
}
EOF

echo -e "\n${GREEN}Port configuration saved to $PORT_CONFIG${NC}"

# Function to update Sliver configuration
update_sliver_config() {
    local sliver_config="/root/.sliver/configs/daemon.json"
    
    if [ -f "$sliver_config" ]; then
        echo -e "\n${BLUE}Updating Sliver daemon configuration...${NC}"
        cp "$sliver_config" "${sliver_config}.bak"
        
        # Check if jq is installed
        if ! command -v jq &> /dev/null; then
            echo -e "${YELLOW}jq not found, installing...${NC}"
            apt-get update && apt-get install -y jq
        fi
        
        # Update the configuration with jq
        jq ".daemon_port = $MTLS_C2_PORT | .daemon_http_port = $HTTP_C2_PORT | .daemon_https_port = $HTTPS_C2_PORT" "${sliver_config}.bak" > "$sliver_config"
        
        echo -e "${GREEN}Sliver configuration updated successfully${NC}"
        
        # Restart Sliver service
        echo -e "${BLUE}Restarting Sliver service...${NC}"
        systemctl restart sliver
    else
        echo -e "${YELLOW}Sliver configuration file not found at $sliver_config${NC}"
    fi
}

# Function to update shell handler configuration
update_shell_handler() {
    local handler_script="/root/Tools/shell-handler/persistent-listener.sh"
    
    if [ -f "$handler_script" ]; then
        echo -e "\n${BLUE}Updating shell handler configuration...${NC}"
        
        # Update the port in the script
        sed -i "s/LISTEN_PORT=.*/LISTEN_PORT=$SHELL_HANDLER_PORT/" "$handler_script"
        
        # Update the service if it exists
        local service_file="/etc/systemd/system/shell-handler.service"
        if [ -f "$service_file" ]; then
            # Add environment variable to service file if not already present
            if ! grep -q "Environment=\"LISTEN_PORT=" "$service_file"; then
                sed -i "/\[Service\]/a Environment=\"LISTEN_PORT=$SHELL_HANDLER_PORT\"" "$service_file"
            else
                sed -i "s/Environment=\"LISTEN_PORT=.*/Environment=\"LISTEN_PORT=$SHELL_HANDLER_PORT\"/" "$service_file"
            fi
            
            # Reload systemd and restart the service
            systemctl daemon-reload
            systemctl restart shell-handler
        fi
        
        echo -e "${GREEN}Shell handler updated to use port $SHELL_HANDLER_PORT${NC}"
    else
        echo -e "${YELLOW}Shell handler script not found at $handler_script${NC}"
    fi
}

# Function to update beacon server configuration
update_beacon_server() {
    local beacon_script="/root/Tools/serve-beacons.sh"
    
    if [ -f "$beacon_script" ]; then
        echo -e "\n${BLUE}Updating beacon server configuration...${NC}"
        
        # Update the port in the script
        sed -i "s/LISTEN_PORT=.*/LISTEN_PORT=$BEACON_SERVER_PORT/" "$beacon_script"
        
        # Restart the beacon server if it's running
        if pgrep -f "serve-beacons.sh" > /dev/null; then
            echo -e "${YELLOW}Stopping running beacon server...${NC}"
            pkill -f "serve-beacons.sh"
            
            echo -e "${GREEN}Starting beacon server with new port...${NC}"
            nohup "$beacon_script" > /dev/null 2>&1 &
        fi
        
        echo -e "${GREEN}Beacon server updated to use port $BEACON_SERVER_PORT${NC}"
    else
        echo -e "${YELLOW}Beacon server script not found at $beacon_script${NC}"
    fi
}

# Function to update NGINX configuration for the redirector
update_nginx_redirector() {
    local nginx_config="/etc/nginx/sites-available/default"
    
    if [ -f "$nginx_config" ]; then
        echo -e "\n${BLUE}Updating NGINX redirector configuration...${NC}"
        
        # Update configuration to use new ports
        # Note: This assumes standard format used in the C2ingRed templates
        if grep -q "proxy_pass http://.*:" "$nginx_config"; then
            sed -i "s|proxy_pass http://.*:8888;|proxy_pass http://{{ c2_ip }}:$HTTP_C2_PORT;|g" "$nginx_config"
            sed -i "s|proxy_pass https://.*:443;|proxy_pass https://{{ c2_ip }}:$HTTPS_C2_PORT;|g" "$nginx_config"
            
            # Update stream configuration if it exists
            local stream_config="/etc/nginx/modules-enabled/stream.conf"
            if [ -f "$stream_config" ]; then
                sed -i "s|proxy_pass .*:31337;|proxy_pass {{ c2_ip }}:$MTLS_C2_PORT;|g" "$stream_config"
                sed -i "s|proxy_pass .*:50051;|proxy_pass {{ c2_ip }}:$HTTP_C2_PORT;|g" "$stream_config"
            fi
            
            # Reload NGINX
            systemctl reload nginx
            
            echo -e "${GREEN}NGINX configuration updated to use new ports${NC}"
        else
            echo -e "${YELLOW}Could not find proxy_pass directives in NGINX config${NC}"
        fi
    else
        echo -e "${YELLOW}NGINX configuration file not found at $nginx_config${NC}"
    fi
}

# Apply the configuration updates
update_sliver_config
update_shell_handler
update_beacon_server
update_nginx_redirector

echo -e "\n${GREEN}Port randomization complete!${NC}"
echo -e "${YELLOW}Remember to update any firewall rules to allow traffic on these ports.${NC}"
echo -e "${YELLOW}You should also update your DNS records if they contain SRV records that specify ports.${NC}"

# Display the new port configuration again for reference
echo -e "\n${BLUE}New Port Configuration:${NC}"
cat $PORT_CONFIG | jq