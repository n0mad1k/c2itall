#!/bin/bash
# post_install_c2.sh - Post-installation setup for C2 server

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default settings
DEBUG=false
RUN_ON_REDIRECTOR=false

# Show usage information
function show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -d, --debug              Enable debug/verbose output"
    echo "  -r, --run-on-redirector  Run post-install script on redirector"
    echo "  -h, --help               Show this help message"
    echo ""
}

# Process command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -r|--run-on-redirector)
            RUN_ON_REDIRECTOR=true
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
echo -e "${BLUE}   C2ingRed Post-Installation Setup - C2 Server    ${NC}"
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
    
    # Stop Havoc service temporarily to free port 80
    systemctl stop havoc 2>/dev/null
    debug "Stopped Havoc service"
    
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
        
        # Configure applications to use the certificate if needed
        if [ -f "/etc/postfix/main.cf" ]; then
            debug "Updating Postfix configuration with new certificate"
            sed -i "s|^smtpd_tls_cert_file =.*|smtpd_tls_cert_file = /etc/letsencrypt/live/$domain/fullchain.pem|" /etc/postfix/main.cf
            sed -i "s|^smtpd_tls_key_file =.*|smtpd_tls_key_file = /etc/letsencrypt/live/$domain/privkey.pem|" /etc/postfix/main.cf
        fi
        
        # Restart Havoc
        debug "Restarting Havoc service"
        systemctl start havoc
        
        return 0
    else
        echo -e "${RED}Failed to obtain certificate for $domain${NC}"
        
        # Restart Havoc
        debug "Restarting Havoc service"
        systemctl start havoc
        
        return 1
    fi
}

# Function to display DKIM/DMARC records
show_dns_records() {
    domain=$1
    
    debug "Showing DNS records for $domain"
    
    if [ -f "/etc/opendkim/keys/$domain/mail.txt" ]; then
        echo -e "\n${BLUE}DKIM DNS Record Information for $domain${NC}"
        echo -e "${YELLOW}Add the following TXT record to your DNS:${NC}"
        echo -e "${GREEN}=================================================${NC}"
        echo -e "Name: mail._domainkey.$domain"
        echo -e "Value:"
        cat /etc/opendkim/keys/$domain/mail.txt | grep -v "^;" | tr -d '\n'
        echo -e "\n${GREEN}=================================================${NC}"
    fi
    
    echo -e "\n${BLUE}DMARC Record Recommendation for $domain${NC}"
    echo -e "${YELLOW}Add the following TXT record to your DNS:${NC}"
    echo -e "${GREEN}=================================================${NC}"
    echo -e "Name: _dmarc.$domain"
    echo -e "Value: v=DMARC1; p=reject; rua=mailto:admin@$domain; ruf=mailto:admin@$domain; pct=100"
    echo -e "${GREEN}=================================================${NC}"
}

# Function to test redirector connection
test_redirector() {
    # Check if SSH to redirector is configured
    debug "Testing redirector connection"
    
    if [ -f "/root/.ssh/config" ] && grep -q "Host redirector" /root/.ssh/config; then
        echo -e "\n${BLUE}Testing SSH connection to redirector...${NC}"
        if [ "$DEBUG" = true ]; then
            ssh -o ConnectTimeout=5 redirector "echo 'Connection successful'"
        else
            ssh -o ConnectTimeout=5 redirector "echo 'Connection successful'" >/dev/null 2>&1
        fi
        
        ssh_result=$?
        debug "SSH connection result: $ssh_result"
        
        if [ $ssh_result -eq 0 ]; then
            echo -e "${GREEN}SSH connection to redirector successful!${NC}"
            echo -e "You can access the redirector with: ${YELLOW}ssh redirector${NC}"
            return 0
        else
            echo -e "${RED}Could not connect to redirector.${NC}"
            echo -e "${YELLOW}Please verify SSH configuration and firewall rules.${NC}"
            return 1
        fi
    else
        echo -e "\n${YELLOW}Redirector SSH configuration not found.${NC}"
        echo -e "If you need to access the redirector, please check deployment logs."
        return 1
    fi
}

# Function to synchronize payloads with redirector
sync_payloads() {
    # Check if sync script exists
    debug "Attempting to synchronize payloads with redirector"
    
    if [ -f "/root/Tools/secure_payload_sync.sh" ]; then
        echo -e "\n${BLUE}Synchronizing payloads with redirector...${NC}"
        if [ "$DEBUG" = true ]; then
            /root/Tools/secure_payload_sync.sh
        else
            /root/Tools/secure_payload_sync.sh >/dev/null 2>&1
        fi
        
        sync_result=$?
        debug "Payload sync result: $sync_result"
        
        if [ $sync_result -eq 0 ]; then
            echo -e "${GREEN}Payload synchronization successful${NC}"
            return 0
        else
            echo -e "${RED}Payload synchronization failed${NC}"
            echo -e "${YELLOW}Check /root/Tools/logs/payload_sync.log for details${NC}"
            return 1
        fi
    else
        echo -e "\n${YELLOW}Payload sync script not found${NC}"
        return 1
    fi
}

# Function to run redirector post-install script
run_redirector_setup() {
    echo -e "\n${BLUE}Running post-installation setup on redirector...${NC}"
    debug "Checking if we can connect to redirector"
    
    # First, test the connection
    if [ -f "/root/.ssh/config" ] && grep -q "Host redirector" /root/.ssh/config; then
        # Check if post_install_redirector.sh exists on the redirector
        debug "Checking for post_install_redirector.sh on redirector"
        ssh -o ConnectTimeout=5 redirector "test -f /root/Tools/post_install_redirector.sh" >/dev/null 2>&1
        
        check_result=$?
        debug "Script check result: $check_result"
        
        if [ $check_result -eq 0 ]; then
            echo -e "${BLUE}Running post-install script on redirector...${NC}"
            # Pass the debug flag if it's enabled here
            if [ "$DEBUG" = true ]; then
                ssh -o ConnectTimeout=10 redirector "/root/Tools/post_install_redirector.sh --debug"
            else
                ssh -o ConnectTimeout=10 redirector "/root/Tools/post_install_redirector.sh"
            fi
            
            redir_setup_result=$?
            debug "Redirector setup result: $redir_setup_result"
            
            if [ $redir_setup_result -eq 0 ]; then
                echo -e "${GREEN}Redirector post-installation completed successfully${NC}"
                return 0
            else
                echo -e "${RED}Redirector post-installation failed${NC}"
                return 1
            fi
        else
            echo -e "${RED}post_install_redirector.sh not found on redirector${NC}"
            return 1
        fi
    else
        echo -e "${RED}SSH configuration for redirector not found${NC}"
        echo -e "${YELLOW}Cannot run post-installation on redirector${NC}"
        return 1
    fi
}

# Main execution
debug "Starting post-installation process with debug mode: $DEBUG"
debug "Run on redirector flag: $RUN_ON_REDIRECTOR"

echo -e "\n${BLUE}Running post-installation checks...${NC}"

# Get domain information
read -p "Enter primary domain: " domain
read -p "Enter email for Let's Encrypt: " email

# Check DNS configuration
echo -e "\n${BLUE}Checking DNS configuration...${NC}"
check_dns $domain

# Ask if user wants to set up Let's Encrypt certificates
read -p "Set up Let's Encrypt SSL certificate? (y/n): " setup_ssl
if [ "$setup_ssl" = "y" ]; then
    setup_letsencrypt $domain $email
fi

# Show DNS records to configure
show_dns_records $domain

# Test redirector connection
test_redirector

# Ask if user wants to sync payloads
read -p "Synchronize payloads with redirector? (y/n): " sync_payload
if [ "$sync_payload" = "y" ]; then
    sync_payloads
fi

# Ask if user wants to run post-install on redirector
if [ "$RUN_ON_REDIRECTOR" = true ] || test_redirector; then
    read -p "Run post-installation setup on redirector? (y/n): " run_on_redir
    if [ "$run_on_redir" = "y" ]; then
        run_redirector_setup
    fi
fi

echo -e "\n${GREEN}Post-installation checks complete!${NC}"
echo -e "${YELLOW}Ensure your DNS records are properly configured.${NC}"
echo -e "${YELLOW}See your deployment log for complete infrastructure details.${NC}"