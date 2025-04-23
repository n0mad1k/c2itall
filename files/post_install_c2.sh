#!/bin/bash
# post_install_c2.sh - Post-installation setup for C2 server

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}   C2ingRed Post-Installation Setup - C2 Server    ${NC}"
echo -e "${BLUE}==================================================${NC}"

# Function to check if domain resolves to current IP
check_dns() {
    domain=$1
    current_ip=$(curl -s ifconfig.me)
    resolved_ip=$(dig +short $domain)
    
    if [ "$resolved_ip" = "$current_ip" ]; then
        echo -e "${GREEN}DNS check passed for $domain!${NC}"
        return 0
    else
        echo -e "${YELLOW}DNS check failed for $domain${NC}"
        echo -e "Current IP: $current_ip"
        echo -e "Resolved IP: $resolved_ip"
        return 1
    fi
}

# Function to set up Let's Encrypt
setup_letsencrypt() {
    domain=$1
    email=$2
    
    echo -e "\n${BLUE}Setting up Let's Encrypt for $domain${NC}"
    
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
    systemctl stop nginx 2>/dev/null
    
    # Get certificate
    certbot certonly --standalone -d $domain -m $email --agree-tos --non-interactive
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Successfully obtained certificate for $domain${NC}"
        return 0
    else
        echo -e "${RED}Failed to obtain certificate for $domain${NC}"
        return 1
    fi
}

# Function to set up mail subdomain
setup_mail_subdomain() {
    domain=$1
    mail_domain="mail.$domain"
    email=$2
    
    echo -e "\n${BLUE}Setting up Let's Encrypt for mail subdomain $mail_domain${NC}"
    
    if [ -d "/etc/letsencrypt/live/$mail_domain" ]; then
        echo -e "${YELLOW}Certificate already exists for $mail_domain${NC}"
        read -p "Do you want to renew it? (y/n): " renew
        if [ "$renew" != "y" ]; then
            echo -e "${YELLOW}Skipping certificate renewal${NC}"
            return 0
        fi
    fi
    
    certbot certonly --standalone -d $mail_domain -m $email --agree-tos --non-interactive
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Successfully obtained certificate for $mail_domain${NC}"
        return 0
    else
        echo -e "${RED}Failed to obtain certificate for $mail_domain${NC}"
        return 1
    fi
}

# Function to start services
start_services() {
    echo -e "\n${BLUE}Starting required services${NC}"
    
    # Restart Sliver
    systemctl restart havoc
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Havoc C2 started successfully${NC}"
    else
        echo -e "${RED}Failed to start Havoc C2${NC}"
    fi
    
    # Start nginx
    systemctl start nginx
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}NGINX started successfully${NC}"
    else
        echo -e "${RED}Failed to start NGINX${NC}"
    fi
    
    # Start Postfix
    systemctl start postfix
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Postfix started successfully${NC}"
    else
        echo -e "${RED}Failed to start Postfix${NC}"
    fi
    
    # Start Dovecot
    systemctl start dovecot
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Dovecot started successfully${NC}"
    else
        echo -e "${RED}Failed to start Dovecot${NC}"
    fi
    
    # Start the beacon server
    if pgrep -f "serve-beacons.sh" > /dev/null; then
        echo -e "${YELLOW}Beacon server already running${NC}"
    else
        nohup /root/Tools/serve-beacons.sh > /dev/null 2>&1 &
        echo -e "${GREEN}Started beacon server${NC}"
    fi
    
    # If tracker is installed, start it
    if [ -d "/root/Tools/tracker" ]; then
        systemctl start tracker
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Email tracker started successfully${NC}"
        else
            echo -e "${RED}Failed to start email tracker${NC}"
        fi
    fi
}

# Function to generate DKIM DNS records
generate_dkim_records() {
    domain=$1
    
    if [ -f "/etc/opendkim/keys/$domain/mail.txt" ]; then
        echo -e "\n${BLUE}DKIM DNS Record Information for $domain${NC}"
        echo -e "${YELLOW}Add the following TXT record to your DNS:${NC}"
        echo -e "${GREEN}=================================================${NC}"
        echo -e "Name: mail._domainkey.$domain"
        echo -e "Value:"
        cat /etc/opendkim/keys/$domain/mail.txt | grep -v "^;" | tr -d '\n'
        echo -e "\n${GREEN}=================================================${NC}"
    else
        echo -e "${RED}DKIM key file not found at /etc/opendkim/keys/$domain/mail.txt${NC}"
    fi
}

# Function to create DMARC record recommendation
recommend_dmarc() {
    domain=$1
    
    echo -e "\n${BLUE}DMARC Record Recommendation for $domain${NC}"
    echo -e "${YELLOW}Add the following TXT record to your DNS:${NC}"
    echo -e "${GREEN}=================================================${NC}"
    echo -e "Name: _dmarc.$domain"
    echo -e "Value: v=DMARC1; p=reject; rua=mailto:admin@$domain; ruf=mailto:admin@$domain; pct=100"
    echo -e "${GREEN}=================================================${NC}"
}

# Function to test SSH connection to redirector
test_redirector_ssh() {
    redirector_ip=$1
    ssh_key=$2
    ssh_user=${3:-"root"}
    
    echo -e "\n${BLUE}Testing SSH connection to redirector at $redirector_ip${NC}"
    
    if [ -f "$ssh_key" ]; then
        # Try SSH with 5-second timeout
        ssh -i "$ssh_key" -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$ssh_user@$redirector_ip" "echo 'SSH connection successful'" >/dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}SSH connection to redirector successful${NC}"
            return 0
        else
            echo -e "${RED}SSH connection to redirector failed${NC}"
            echo -e "${YELLOW}Please check the redirector IP and SSH key${NC}"
            return 1
        fi
    else
        echo -e "${RED}SSH key file not found at $ssh_key${NC}"
        return 1
    fi
}

# Function to execute post-install on redirector
setup_redirector() {
    redirector_ip=$1
    ssh_key=$2
    ssh_user=${3:-"root"}
    
    echo -e "\n${BLUE}Preparing to set up redirector at $redirector_ip${NC}"
    
    # Check if redirector post-install script exists, copy if not
    ssh -i "$ssh_key" -o StrictHostKeyChecking=no "$ssh_user@$redirector_ip" "test -f /root/Tools/post_install_redirector.sh" >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}Copying post-install script to redirector...${NC}"
        
        # Create the script first
        cat > /tmp/post_install_redirector.sh << 'EOF'
#!/bin/bash
# post_install_redirector.sh - Post-installation setup for redirector

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}   C2ingRed Post-Installation Setup - Redirector    ${NC}"
echo -e "${BLUE}==================================================${NC}"

# Function to check if domain resolves to current IP
check_dns() {
    domain=$1
    current_ip=$(curl -s ifconfig.me)
    resolved_ip=$(dig +short $domain)
    
    if [ "$resolved_ip" = "$current_ip" ]; then
        echo -e "${GREEN}DNS check passed for $domain!${NC}"
        return 0
    else
        echo -e "${YELLOW}DNS check failed for $domain${NC}"
        echo -e "Current IP: $current_ip"
        echo -e "Resolved IP: $resolved_ip"
        return 1
    fi
}

# Function to set up Let's Encrypt
setup_letsencrypt() {
    domain=$1
    email=$2
    
    echo -e "\n${BLUE}Setting up Let's Encrypt for $domain${NC}"
    
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
    systemctl stop nginx 2>/dev/null
    
    # Get certificate
    certbot certonly --standalone -d $domain -m $email --agree-tos --non-interactive
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Successfully obtained certificate for $domain${NC}"
        return 0
    else
        echo -e "${RED}Failed to obtain certificate for $domain${NC}"
        return 1
    fi
}

# Function to start services
start_services() {
    echo -e "\n${BLUE}Starting required services${NC}"
    
    # Start nginx
    systemctl start nginx
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}NGINX started successfully${NC}"
    else
        echo -e "${RED}Failed to start NGINX${NC}"
    fi
    
    # Start shell handler
    systemctl start shell-handler
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Shell handler started successfully${NC}"
    else
        echo -e "${RED}Failed to start shell handler${NC}"
    fi
}

# Main execution
echo -e "\n${BLUE}Beginning redirector setup process...${NC}"

# Get domain information
read -p "Enter redirector domain (e.g., cdn.example.com): " redirector_domain
read -p "Enter email for Let's Encrypt: " email

# Check if DNS is properly configured
echo -e "\n${BLUE}Checking DNS configuration...${NC}"
check_dns $redirector_domain

# Set up Let's Encrypt
setup_letsencrypt $redirector_domain $email

# Start services
start_services

echo -e "\n${GREEN}Redirector setup complete!${NC}"
echo -e "${YELLOW}Make sure to check the logs if you encounter any issues.${NC}"
EOF
        
        # Make the script executable
        chmod +x /tmp/post_install_redirector.sh
        
        # Copy to redirector
        scp -i "$ssh_key" -o StrictHostKeyChecking=no /tmp/post_install_redirector.sh "$ssh_user@$redirector_ip:/root/Tools/"
        
        # Make executable on redirector
        ssh -i "$ssh_key" -o StrictHostKeyChecking=no "$ssh_user@$redirector_ip" "chmod +x /root/Tools/post_install_redirector.sh"
        
        echo -e "${GREEN}Post-install script copied to redirector${NC}"
    else
        echo -e "${GREEN}Post-install script already exists on redirector${NC}"
    fi
    
    # Ask to run the script
    read -p "Run redirector setup now? (y/n): " run_setup
    
    if [ "$run_setup" = "y" ]; then
        echo -e "${BLUE}Connecting to redirector and running setup script...${NC}"
        ssh -i "$ssh_key" -o StrictHostKeyChecking=no -t "$ssh_user@$redirector_ip" "cd /root/Tools && ./post_install_redirector.sh"
    else
        echo -e "${YELLOW}Skipping redirector setup${NC}"
        echo -e "You can run it later by SSHing to the redirector and executing /root/Tools/post_install_redirector.sh"
    fi
}

# Main execution
echo -e "\n${BLUE}Beginning C2 server setup process...${NC}"

# Get domain information
read -p "Enter primary domain: " domain
read -p "Enter email for Let's Encrypt: " email

# Check if DNS is properly configured
echo -e "\n${BLUE}Checking DNS configuration...${NC}"
check_dns $domain
check_dns "mail.$domain" 

# Set up Let's Encrypt
setup_letsencrypt $domain $email
setup_mail_subdomain $domain $email

# Configure applications to use the certificates
if [ -f "/etc/postfix/main.cf" ]; then
    echo -e "\n${BLUE}Configuring Postfix to use the certificates...${NC}"
    sed -i "s|^smtpd_tls_cert_file =.*|smtpd_tls_cert_file = /etc/letsencrypt/live/$domain/fullchain.pem|" /etc/postfix/main.cf
    sed -i "s|^smtpd_tls_key_file =.*|smtpd_tls_key_file = /etc/letsencrypt/live/$domain/privkey.pem|" /etc/postfix/main.cf
fi

if [ -f "/root/Tools/gophish/config.json" ]; then
    echo -e "\n${BLUE}Configuring GoPhish to use the certificates...${NC}"
    sed -i "s|\"cert_path\":.*|\"cert_path\": \"/etc/letsencrypt/live/$domain/fullchain.pem\",|" /root/Tools/gophish/config.json
    sed -i "s|\"key_path\":.*|\"key_path\": \"/etc/letsencrypt/live/$domain/privkey.pem\",|" /root/Tools/gophish/config.json
fi

# Start services
start_services

# Generate DKIM and DMARC recommendations
generate_dkim_records $domain
recommend_dmarc $domain

# Ask for redirector information
echo -e "\n${BLUE}Do you want to set up the redirector now?${NC}"
read -p "Enter redirector IP (leave empty to skip): " redirector_ip

if [ -n "$redirector_ip" ]; then
    read -p "Enter SSH key path: " ssh_key
    read -p "Enter SSH user (default: root): " ssh_user
    
    if [ -z "$ssh_user" ]; then
        ssh_user="root"
    fi
    
    if test_redirector_ssh "$redirector_ip" "$ssh_key" "$ssh_user"; then
        setup_redirector "$redirector_ip" "$ssh_key" "$ssh_user"
    fi
else
    echo -e "${YELLOW}Skipping redirector setup${NC}"
fi

echo -e "\n${GREEN}C2 server setup complete!${NC}"
echo -e "${YELLOW}Make sure to set up DNS records as described above if you haven't already.${NC}"