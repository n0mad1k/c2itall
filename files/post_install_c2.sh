#!/bin/bash
# post_install_redirector.sh - Post-installation setup for redirector

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Debug mode flag
DEBUG=false

# Show usage information
function show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -d, --debug    Enable debug/verbose output"
    echo "  -h, --help     Show this help message"
    echo ""
}

# Process command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Debug function - only prints if DEBUG is true
function debug() {
    if [ "$DEBUG" = true ]; then
        echo -e "${BLUE}[DEBUG] $1${NC}"
    fi
}

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}   C2ingRed Post-Installation Setup - Redirector    ${NC}"
echo -e "${BLUE}==================================================${NC}"

# Function to check if domain resolves to current IP
check_dns() {
    domain=$1
    current_ip=$(curl -s ifconfig.me)
    resolved_ip=$(dig +short $domain)
    
    debug "Checking DNS for $domain"
    debug "Current IP: $current_ip"
    debug "Resolved IP: $resolved_ip"
    
    if [ "$resolved_ip" = "$current_ip" ]; then
        echo -e "${GREEN}DNS check passed for $domain!${NC}"
        return 0
    else
        echo -e "${YELLOW}DNS check failed for $domain${NC}"
        echo -e "Current IP: $current_ip"
        echo -e "Resolved IP: $resolved_ip or not set"
        return 1
    fi
}

# Function to set up Let's Encrypt
setup_letsencrypt() {
    domain=$1
    email=$2
    
    echo -e "\n${BLUE}Setting up Let's Encrypt for $domain${NC}"
    debug "Domain: $domain, Email: $email"
    
    # Check if certificate already exists
    if [ -d "/etc/letsencrypt/live/$domain" ]; then
        echo -e "${YELLOW}Certificate already exists for $domain${NC}"
        read -p "Do you want to renew it? (y/n): " renew
        if [ "$renew" != "y" ]; then
            echo -e "${YELLOW}Skipping certificate renewal${NC}"
            return 0
        fi
    fi
    
    # Stop nginx if running to free up port 80
    debug "Stopping nginx to free port 80"
    systemctl stop nginx 2>/dev/null
    
    # Get certificate
    debug "Running certbot to obtain certificate"
    if [ "$DEBUG" = true ]; then
        certbot certonly --standalone -d $domain -m $email --agree-tos --non-interactive
    else
        certbot certonly --standalone -d $domain -m $email --agree-tos --non-interactive >/dev/null 2>&1
    fi
    
    cert_result=$?
    debug "Certbot result code: $cert_result"
    
    if [ $cert_result -eq 0 ]; then
        echo -e "${GREEN}Successfully obtained certificate for $domain${NC}"
        return 0
    else
        echo -e "${RED}Failed to obtain certificate for $domain${NC}"
        return 1
    fi
}

# Function to update NGINX configuration
update_nginx_config() {
    domain=$1
    
    debug "Updating NGINX configuration for $domain"
    
    # Check if NGINX config exists and contains the domain
    if [ -f "/etc/nginx/sites-available/default" ]; then
        if grep -q "$domain" "/etc/nginx/sites-available/default"; then
            echo -e "\n${BLUE}Updating NGINX configuration to use SSL certificate${NC}"
            
            # Update SSL certificate paths
            debug "Updating SSL certificate paths in NGINX config"
            sed -i "s|ssl_certificate .*|ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;|" /etc/nginx/sites-available/default
            sed -i "s|ssl_certificate_key .*|ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;|" /etc/nginx/sites-available/default
            
            echo -e "${GREEN}NGINX configuration updated${NC}"
        else
            echo -e "${YELLOW}Domain $domain not found in NGINX configuration${NC}"
            debug "Searched for '$domain' in NGINX config but did not find it"
        fi
    else
        echo -e "${RED}NGINX configuration file not found${NC}"
    fi
}

# Function to start services
start_services() {
    echo -e "\n${BLUE}Starting required services${NC}"
    
    # Start nginx
    debug "Starting NGINX"
    systemctl start nginx
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}NGINX started successfully${NC}"
        systemctl enable nginx
    else
        echo -e "${RED}Failed to start NGINX${NC}"
    fi
    
    # Start shell handler
    debug "Starting shell handler"
    systemctl start shell-handler
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Shell handler started successfully${NC}"
        systemctl enable shell-handler
    else
        echo -e "${RED}Failed to start shell handler${NC}"
    fi
}

# Function to display port information
show_port_info() {
    # Display shell handler port
    debug "Collecting port information"
    
    if [ -f "/etc/systemd/system/shell-handler.service" ]; then
        debug "Found shell-handler.service, extracting port information"
        SHELL_PORT=$(grep "LISTEN_PORT=" /root/Tools/shell-handler/persistent-listener.sh | cut -d'=' -f2)
        echo -e "\n${BLUE}Shell Handler Port Information:${NC}"
        echo -e "Shell Handler is using port: ${GREEN}$SHELL_PORT${NC}"
    fi
    
    # Display nginx listening ports
    echo -e "\n${BLUE}NGINX Listening Ports:${NC}"
    if [ "$DEBUG" = true ]; then
        netstat -tulnp | grep nginx
    else
        netstat -tulnp | grep nginx | grep -v "127.0.0.1"
    fi
}

# Main execution
debug "Starting redirector post-installation process with debug mode: $DEBUG"

echo -e "\n${BLUE}Beginning redirector setup process...${NC}"

# Get domain information
read -p "Enter redirector domain (e.g., cdn.example.com): " redirector_domain
read -p "Enter email for Let's Encrypt: " email

# Check if DNS is properly configured
echo -e "\n${BLUE}Checking DNS configuration...${NC}"
check_dns $redirector_domain

# Confirm proceeding even if DNS check fails
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}DNS check failed but we can proceed anyway.${NC}"
    echo -e "${YELLOW}Make sure to set up DNS records before trying to obtain certificates.${NC}"
    read -p "Do you want to proceed anyway? (y/n): " proceed
    if [ "$proceed" != "y" ]; then
        echo -e "${RED}Setup aborted.${NC}"
        exit 1
    fi
fi

# Set up Let's Encrypt
setup_letsencrypt $redirector_domain $email

# Update NGINX configuration
update_nginx_config $redirector_domain

# Start services
start_services

# Show port information
show_port_info

echo -e "\n${GREEN}Redirector setup complete!${NC}"
echo -e "${YELLOW}Make sure DNS records are properly configured for continued operation.${NC}"