#!/bin/bash
# V2Ray + TLS + WebSocket + Nginx Setup Script
# This script sets up a complete V2Ray proxy with TLS, WebSocket, and Nginx
# with optimized performance configurations using certbot for SSL.

set -e

# Color codes for better readability
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
RED="\033[0;31m"
NC="\033[0m" # No Color

# Configuration variables (you should modify these)
DOMAIN="example.com"             # Your domain
EMAIL="admin@example.com"                 # Email for Let's Encrypt
UUID=$(cat /proc/sys/kernel/random/uuid)  # Random UUID for V2Ray
WS_PATH="/ray"                            # WebSocket path
PORT="443"                                # HTTPS port
NGINX_PORT="8080"                         # Nginx listener port for V2Ray WebSocket
# Try multiple services to detect server IP
get_server_ip() {
    local ip=""
    # Try multiple IP detection services
    for service in "ifconfig.me" "ipinfo.io/ip" "api.ipify.org" "icanhazip.com"; do
        ip=$(curl -s -4 --connect-timeout 5 $service 2>/dev/null)
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    # If auto-detection fails, prompt for manual entry
    echo -e "${YELLOW}Could not automatically detect server IP.${NC}"
    read -p "Please enter your server's public IP address: " manual_ip
    if [[ $manual_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$manual_ip"
        return 0
    else
        echo -e "${RED}Invalid IP format. Using localhost for testing.${NC}"
        echo "127.0.0.1"
        return 1
    fi
}

SERVER_IP=$(get_server_ip)       # Auto-detect or manually enter server IP

echo -e "${BLUE}V2Ray + TLS + WebSocket + Nginx Setup Script${NC}"
echo "Domain: $DOMAIN"
echo "Server IP: $SERVER_IP"
echo "UUID: $UUID"
echo "WebSocket Path: $WS_PATH"

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}Error: This script must be run as root!${NC}"
    exit 1
fi

# Update system
echo -e "\n${YELLOW}Updating system packages...${NC}"
apt update && apt upgrade -y

# Install necessary tools
echo -e "\n${YELLOW}Installing required packages...${NC}"
apt install -y curl wget unzip lsof git socat cron dnsutils ufw

# Ensure firewall allows necessary ports
configure_firewall() {
    echo -e "\n${YELLOW}Configuring firewall...${NC}"
    # Check if UFW is active
    if systemctl is-active --quiet ufw; then
        echo -e "${YELLOW}Ensuring ports 80, 443, and 22 are open...${NC}"
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow 22/tcp
        ufw status
    else
        echo -e "${YELLOW}UFW is not active. Consider enabling it with proper rules.${NC}"
        echo -e "${YELLOW}Command: ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 22/tcp && ufw enable${NC}"
    fi
}

# Verify DNS resolution
check_dns() {
    echo -e "\n${YELLOW}Checking DNS resolution for $DOMAIN...${NC}"
    local resolved_ip=$(dig +short $DOMAIN A | head -n 1)
    
    if [ -z "$resolved_ip" ]; then
        echo -e "${RED}Error: Domain $DOMAIN does not resolve to any IP address.${NC}"
        echo -e "${YELLOW}Please ensure your DNS settings are correct before continuing.${NC}"
        echo -e "${YELLOW}You can continue anyway, but certificate issuance will likely fail.${NC}"
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    elif [ "$resolved_ip" != "$SERVER_IP" ]; then
        echo -e "${RED}Warning: Domain $DOMAIN resolves to $resolved_ip, but your server IP is $SERVER_IP${NC}"
        
        # Ask if the user wants to update the SERVER_IP variable
        echo -e "${YELLOW}Would you like to use the resolved IP ($resolved_ip) as your server IP?${NC}"
        read -p "Update server IP to match DNS? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            SERVER_IP=$resolved_ip
            echo -e "${GREEN}Updated server IP to $SERVER_IP${NC}"
        else
            echo -e "${YELLOW}Certificate issuance may fail unless this is a proxy/CDN setup.${NC}"
            read -p "Continue anyway? (y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    else
        echo -e "${GREEN}DNS check passed. Domain $DOMAIN correctly resolves to $SERVER_IP${NC}"
    fi
}

# Check external connectivity
check_connectivity() {
    echo -e "\n${YELLOW}Checking external connectivity...${NC}"
    
    # First ensure nginx is running and port 80 is open
    systemctl restart nginx
    sleep 2
    
    # Create a test file
    local test_filename="connectivity_test_$(date +%s).html"
    echo "<html><body>Connectivity test</body></html>" > /var/www/html/$test_filename
    
    # Try to fetch it (try multiple methods)
    local http_code=0
    
    # Method 1: Standard curl request
    http_code=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN/$test_filename -m 10 2>/dev/null || echo "0")
    
    # Method 2: Try with explicit DNS resolution if Method 1 fails
    if [ "$http_code" = "0" ] || [ "$http_code" = "000" ]; then
        echo -e "${YELLOW}Standard connectivity test failed. Trying with explicit IP...${NC}"
        resolved_ip=$(dig +short $DOMAIN A | head -n 1)
        if [ ! -z "$resolved_ip" ]; then
            http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-to $DOMAIN:80:$resolved_ip:80 http://$DOMAIN/$test_filename -m 10 2>/dev/null || echo "0")
        fi
    fi
    
    # Method 3: Try with direct IP if all else fails
    if [ "$http_code" = "0" ] || [ "$http_code" = "000" ]; then
        echo -e "${YELLOW}Explicit IP test failed. Trying direct server IP connection...${NC}"
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $DOMAIN" http://$SERVER_IP/$test_filename -m 10 2>/dev/null || echo "0")
    fi
    
    # Clean up
    rm -f /var/www/html/$test_filename
    
    if [ "$http_code" = "200" ]; then
        echo -e "${GREEN}Connectivity check passed. Your server is accessible from the internet.${NC}"
    else
        echo -e "${RED}Warning: Could not verify external connectivity to http://$DOMAIN/${NC}"
        echo -e "${YELLOW}This might cause problems with certificate issuance.${NC}"
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Install BBR for TCP optimization
install_bbr() {
    echo -e "\n${YELLOW}Installing TCP BBR for better performance...${NC}"
    if grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf && grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo -e "${GREEN}BBR is already enabled!${NC}"
    else
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo -e "${GREEN}BBR has been enabled!${NC}"
    fi
}

# Install Nginx
install_nginx() {
    echo -e "\n${YELLOW}Installing Nginx...${NC}"
    apt install -y nginx
    systemctl enable nginx
    systemctl start nginx
    
    # Create basic HTML page for connectivity tests
    cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
        h1 { color: #444; }
        .container { max-width: 800px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to my website!</h1>
        <p>This is a sample page. Here you'll find information about our services and products.</p>
        <p>Please check back later for updates.</p>
    </div>
</body>
</html>
EOF
    
    echo -e "${GREEN}Nginx installed!${NC}"
}

# Install Certbot for SSL certificates
install_certbot() {
    echo -e "\n${YELLOW}Installing Certbot...${NC}"
    apt install -y certbot python3-certbot-nginx python3-certbot-apache
    echo -e "${GREEN}Certbot installed!${NC}"
}

# Configure Nginx for initial setup
configure_nginx_initial() {
    echo -e "\n${YELLOW}Configuring Nginx for initial setup...${NC}"
    
    # Create server block for the domain
    cat > /etc/nginx/sites-available/$DOMAIN.conf << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    
    root /var/www/html;
    index index.html;
    
    location /.well-known/acme-challenge/ {
        allow all;
        root /var/www/html;
    }
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    # Enable the site
    ln -sf /etc/nginx/sites-available/$DOMAIN.conf /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Test Nginx configuration
    nginx -t
    
    # Reload Nginx
    systemctl restart nginx
    
    echo -e "${GREEN}Nginx initial configuration complete!${NC}"
}

# Issue SSL certificate with multiple methods
issue_ssl() {
    echo -e "\n${YELLOW}Attempting to issue SSL certificate for ${DOMAIN}...${NC}"
    
    # Test if port 80 is open and accessible from the internet
    echo -e "${YELLOW}Testing if port 80 is accessible...${NC}"
    PORT_80_TEST=$(curl -s -I -m 10 http://$DOMAIN | grep -q "HTTP/" && echo "success" || echo "failed")
    
    if [ "$PORT_80_TEST" = "failed" ]; then
        echo -e "${RED}Warning: Port 80 does not appear to be accessible.${NC}"
        echo -e "${YELLOW}This may be due to:${NC}"
        echo -e "  ${YELLOW}- Firewall blocking port 80${NC}"
        echo -e "  ${YELLOW}- DNS not properly pointing to this server${NC}"
        echo -e "  ${YELLOW}- Network issues between the internet and this server${NC}"
        
        # Check if port 80 is listening locally
        if ! netstat -tuln | grep -q ":80 "; then
            echo -e "${RED}Port 80 is not listening on this server. Check if Nginx is running.${NC}"
            systemctl restart nginx
            sleep 2
            if ! netstat -tuln | grep -q ":80 "; then
                echo -e "${RED}Failed to start Nginx on port 80.${NC}"
            fi
        fi
        
        # Check if UFW is blocking port 80
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
            if ! ufw status | grep -q "80/tcp.*ALLOW"; then
                echo -e "${RED}Port 80 may be blocked by UFW. Attempting to allow it...${NC}"
                ufw allow 80/tcp
            fi
        fi
        
        echo -e "${YELLOW}Proceeding with certificate issuance, but it may fail...${NC}"
    else
        echo -e "${GREEN}Port 80 is accessible!${NC}"
    fi
    
    # Setup proper permissions for webroot
    mkdir -p /var/www/html/.well-known/acme-challenge
    chmod -R 755 /var/www/html
    chown -R www-data:www-data /var/www/html
    
    # Reset failed flags
    NGINX_FAILED=false
    STANDALONE_FAILED=false
    WEBROOT_FAILED=false
    
    # Method 1: Try with Nginx plugin (with more verbose output)
    echo -e "${YELLOW}Trying Nginx plugin method...${NC}"
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m $EMAIL --keep-until-expiring --verbose || NGINX_FAILED=true
    
    # If Nginx plugin fails, try standalone method
    if [ "$NGINX_FAILED" = "true" ]; then
        echo -e "${YELLOW}Nginx plugin failed. Checking Nginx status before proceeding...${NC}"
        systemctl status nginx
        echo -e "${YELLOW}Trying standalone method...${NC}"
        
        # Stop Nginx temporarily
        systemctl stop nginx
        sleep 2
        
        # Verify port 80 is free
        if netstat -tuln | grep -q ":80 "; then
            echo -e "${RED}Warning: Port 80 is still in use by another process. Attempting to find it...${NC}"
            fuser -v 80/tcp
            echo -e "${YELLOW}You may need to stop this process manually.${NC}"
        else
            echo -e "${GREEN}Port 80 is free for standalone mode.${NC}"
        fi
        
        # Try standalone method with more debugging
        certbot certonly --standalone -d $DOMAIN --non-interactive --agree-tos -m $EMAIL --verbose || STANDALONE_FAILED=true
        
        # Start Nginx again
        systemctl start nginx
    fi
    
    # If both methods fail, try webroot with more debugging
    if [ "$STANDALONE_FAILED" = "true" ]; then
        echo -e "${YELLOW}Standalone method failed. Trying webroot method...${NC}"
        
        # Double check webroot permissions
        mkdir -p /var/www/html/.well-known/acme-challenge
        chmod -R 755 /var/www/html
        chown -R www-data:www-data /var/www/html
        
        # Create test file to ensure webroot is working
        echo "Test file" > /var/www/html/.well-known/acme-challenge/test.txt
        WEBROOT_TEST=$(curl -s -m 5 http://$DOMAIN/.well-known/acme-challenge/test.txt)
        if [ "$WEBROOT_TEST" = "Test file" ]; then
            echo -e "${GREEN}Webroot access is working correctly.${NC}"
        else
            echo -e "${RED}Warning: Cannot access test file via webroot. Nginx may not be configured correctly.${NC}"
            # Show Nginx config
            echo -e "${YELLOW}Current Nginx server blocks:${NC}"
            grep -r "server {" /etc/nginx/sites-enabled/
        fi
        
        # Remove test file
        rm -f /var/www/html/.well-known/acme-challenge/test.txt
        
        # Try webroot method with more debugging
        certbot certonly --webroot -w /var/www/html -d $DOMAIN --non-interactive --agree-tos -m $EMAIL --verbose || WEBROOT_FAILED=true
    fi
    
    # If all methods fail, try manual DNS verification or use self-signed
    if [ "$WEBROOT_FAILED" = "true" ]; then
        echo -e "${RED}All automatic certificate issuance methods failed.${NC}"
        echo -e "${YELLOW}Options:${NC}"
        echo -e "  ${YELLOW}1. Try manual DNS verification method${NC}"
        echo -e "  ${YELLOW}2. Continue with self-signed certificate${NC}"
        read -p "Choose option (1/2): " cert_option
        
        if [ "$cert_option" = "1" ]; then
            echo -e "${YELLOW}Starting DNS verification method...${NC}"
            certbot certonly --manual --preferred-challenges dns -d $DOMAIN --agree-tos -m $EMAIL || DNS_FAILED=true
            
            if [ "$DNS_FAILED" = "true" ]; then
                echo -e "${RED}DNS verification method failed. Using self-signed certificate.${NC}"
                # Create directory for certs
                mkdir -p /etc/letsencrypt/live/$DOMAIN
                
                # Generate self-signed certificate
                openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                    -keyout /etc/letsencrypt/live/$DOMAIN/privkey.pem \
                    -out /etc/letsencrypt/live/$DOMAIN/fullchain.pem \
                    -subj "/CN=$DOMAIN" -addext "subjectAltName = DNS:$DOMAIN"
            else
                echo -e "${GREEN}SSL certificate issued successfully via DNS verification!${NC}"
            fi
        else
            echo -e "${YELLOW}Continuing with self-signed certificate...${NC}"
            
            # Create directory for certs
            mkdir -p /etc/letsencrypt/live/$DOMAIN
            
            # Generate self-signed certificate
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout /etc/letsencrypt/live/$DOMAIN/privkey.pem \
                -out /etc/letsencrypt/live/$DOMAIN/fullchain.pem \
                -subj "/CN=$DOMAIN" -addext "subjectAltName = DNS:$DOMAIN"
        fi
    else
        echo -e "${GREEN}SSL certificate issued successfully!${NC}"
    fi
    
    # Create directory for V2Ray and set up symbolic links if needed
    mkdir -p /etc/v2ray/cert
    if [ ! -f /etc/v2ray/cert/fullchain.crt ] && [ -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]; then
        ln -sf /etc/letsencrypt/live/$DOMAIN/fullchain.pem /etc/v2ray/cert/fullchain.crt
    fi
    if [ ! -f /etc/v2ray/cert/private.key ] && [ -f /etc/letsencrypt/live/$DOMAIN/privkey.pem ]; then
        ln -sf /etc/letsencrypt/live/$DOMAIN/privkey.pem /etc/v2ray/cert/private.key
    fi
}

# Install V2Ray using official script
install_v2ray() {
    echo -e "\n${YELLOW}Installing V2Ray using official installation script...${NC}"
    
    # Check if V2Ray is already installed
    if [ -f /usr/local/bin/v2ray ]; then
        echo -e "${GREEN}V2Ray is already installed!${NC}"
        return
    fi
    
    # Install necessary dependencies for the script
    apt-get install -y curl wget unzip
    
    # Create a temporary directory for the installation script
    mkdir -p /tmp/v2ray-install
    cd /tmp/v2ray-install
    
    # Download the official installation script
    echo -e "${YELLOW}Downloading official V2Ray installation script...${NC}"
    if ! curl -L -o install-release.sh https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh; then
        echo -e "${RED}Failed to download the official installation script.${NC}"
        echo -e "${YELLOW}Attempting alternative download method...${NC}"
        
        if ! wget -O install-release.sh https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh; then
            echo -e "${RED}All download attempts failed. Please check your internet connection.${NC}"
            echo -e "${YELLOW}Trying final fallback installation method...${NC}"
            
            # Final fallback - direct installation command
            if ! bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh); then
                echo -e "${RED}All installation methods failed. Exiting.${NC}"
                exit 1
            else
                echo -e "${GREEN}V2Ray installed successfully using direct installation!${NC}"
                return
            fi
        fi
    fi
    
    # Make the script executable
    chmod +x install-release.sh
    
    # Run the installation script
    echo -e "${YELLOW}Running V2Ray installation script...${NC}"
    if ! ./install-release.sh; then
        echo -e "${RED}Official installation script failed.${NC}"
        exit 1
    fi
    
    # Verify installation
    if [ -f /usr/local/bin/v2ray ]; then
        echo -e "${GREEN}V2Ray has been successfully installed!${NC}"
    else
        echo -e "${RED}V2Ray installation seems to have failed. Binary not found at expected location.${NC}"
        exit 1
    fi
    
    # Clean up
    cd -
    rm -rf /tmp/v2ray-install
    
    # Create v2ray config directory if it doesn't exist
    mkdir -p /etc/v2ray
    
    echo -e "${GREEN}V2Ray installation completed!${NC}"
}

# Configure V2Ray
configure_v2ray() {
    echo -e "\n${YELLOW}Configuring V2Ray...${NC}"
    cat > /usr/local/etc/v2ray/config.json << EOF
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": $NGINX_PORT,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "alterId": 0,
            "security": "auto"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$WS_PATH",
          "headers": {}
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked"
      }
    ]
  },
  "policy": {
    "levels": {
      "0": {
        "handshake": 4,
        "connIdle": 300,
        "uplinkOnly": 5,
        "downlinkOnly": 30,
        "statsUserUplink": false,
        "statsUserDownlink": false,
        "bufferSize": 4096
      }
    },
    "system": {
      "statsInboundUplink": false,
      "statsInboundDownlink": false,
      "statsOutboundUplink": false,
      "statsOutboundDownlink": false
    }
  }
}
EOF

    # Create directory for logs
    mkdir -p /var/log/v2ray
    
    # Enable and start V2Ray service
    systemctl daemon-reload
    systemctl enable v2ray
    systemctl restart v2ray
    
    echo -e "${GREEN}V2Ray configured and started!${NC}"
}

# Configure Nginx for final setup
configure_nginx_final() {
    echo -e "\n${YELLOW}Configuring Nginx for V2Ray proxy...${NC}"
    
    # Create optimized Nginx config
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

# Optimized worker connections
events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # MIME
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    # SSL
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Buffer size
    client_body_buffer_size 128k;
    client_max_body_size 10m;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;
    
    # File cache
    open_file_cache max=1000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
    
    # Include site configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    # Create HTTPS configuration for the domain
    cat > /etc/nginx/sites-available/$DOMAIN.conf << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    
    # For Let's Encrypt certificate renewal
    location /.well-known/acme-challenge/ {
        allow all;
        root /var/www/html;
    }
    
    # Redirect all HTTP to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen $PORT ssl http2;
    listen [::]:$PORT ssl http2;
    server_name $DOMAIN;

    root /var/www/html;
    index index.html;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    # WebSocket proxy
    location $WS_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$NGINX_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        
        # Optimized WebSocket settings
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }
    
    # Default location
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    # Test Nginx configuration
    nginx -t
    
    # Reload Nginx
    systemctl restart nginx
    
    echo -e "${GREEN}Nginx configured for V2Ray proxy!${NC}"
}

# Optimize system settings
optimize_system() {
    echo -e "\n${YELLOW}Optimizing system settings...${NC}"
    
    # Create sysctl config for networking optimization
    cat > /etc/sysctl.d/99-network-performance.conf << 'EOF'
# Maximum receive socket buffer size
net.core.rmem_max = 16777216

# Maximum send socket buffer size
net.core.wmem_max = 16777216

# Default receive socket buffer size
net.core.rmem_default = 262144

# Default send socket buffer size
net.core.wmem_default = 262144

# Maximum number of backlog packets
net.core.netdev_max_backlog = 4096

# Maximum number of incoming connections
net.core.somaxconn = 4096

# Increase the TCP max buffer size
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# TCP time wait
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30

# TCP keepalive
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5

# Avoid falling back to slow start after a connection goes idle
net.ipv4.tcp_slow_start_after_idle = 0

# Increase the maximum length of processor input queues
net.core.netdev_max_backlog = 8192

# Increase system file descriptor limit
fs.file-max = 1000000

# Allow a high number of timewait sockets
net.ipv4.tcp_max_tw_buckets = 65536

# Allowed local port range
net.ipv4.ip_local_port_range = 1024 65535

# Maximum number of packets queued on the INPUT side
net.core.netdev_budget = 300

# Use SYN cookies when syn backlog is overflowed
net.ipv4.tcp_syncookies = 1
EOF

    # Apply sysctl settings
    sysctl --system
    
    # Increase file descriptor limits for all users
    cat > /etc/security/limits.d/99-file-descriptors.conf << 'EOF'
*       soft    nofile  1048576
*       hard    nofile  1048576
root    soft    nofile  1048576
root    hard    nofile  1048576
EOF

    echo -e "${GREEN}System optimized for better networking performance!${NC}"
}

# Print a summary of the installation
print_summary() {
    echo -e "\n${GREEN}V2Ray with TLS, WebSocket, and Nginx has been set up successfully!${NC}"
    echo -e "${YELLOW}-----------------------------------------------------------${NC}"
    echo -e "${YELLOW}V2Ray Client Configuration:${NC}"
    echo -e "${BLUE}Address:${NC} $DOMAIN"
    echo -e "${BLUE}Port:${NC} $PORT"
    echo -e "${BLUE}UUID:${NC} $UUID"
    echo -e "${BLUE}AlterID:${NC} 0"
    echo -e "${BLUE}Security:${NC} auto"
    echo -e "${BLUE}Network:${NC} ws"
    echo -e "${BLUE}Path:${NC} $WS_PATH"
    echo -e "${BLUE}TLS:${NC} tls"
    echo -e "${YELLOW}-----------------------------------------------------------${NC}"
    
    # Save client config to file
    cat > v2ray_client_config.json << EOF
{
  "inbounds": [
    {
      "port": 1080,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      },
      "settings": {
        "auth": "noauth",
        "udp": true
      }
    },
    {
      "port": 1081,
      "listen": "127.0.0.1",
      "protocol": "http",
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": "$DOMAIN",
            "port": $PORT,
            "users": [
              {
                "id": "$UUID",
                "alterId": 0,
                "security": "auto"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "serverName": "$DOMAIN",
          "allowInsecure": false
        },
        "wsSettings": {
          "path": "$WS_PATH",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      },
      "mux": {
        "enabled": true,
        "concurrency": 8
      }
    },
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "direct"
      }
    ]
  }
}
EOF
    echo -e "${GREEN}Client configuration saved to v2ray_client_config.json${NC}"
    echo -e "${YELLOW}-----------------------------------------------------------${NC}"
    echo -e "${GREEN}Your V2Ray service is running and configured for optimal performance!${NC}"
    
    # Check services status
    echo -e "\n${YELLOW}Service Status:${NC}"
    systemctl status nginx --no-pager -l | grep "Active:"
    systemctl status v2ray --no-pager -l | grep "Active:"
}

# Error handler
handle_error() {
    echo -e "${RED}An error occurred during setup. Error on line $1${NC}"
    exit 1
}

# Set up error handling
trap 'handle_error $LINENO' ERR

# Main setup flow with pre-checks
configure_firewall
install_nginx
install_certbot
configure_nginx_initial
check_dns
check_connectivity
issue_ssl
install_bbr
install_v2ray
configure_v2ray
configure_nginx_final
optimize_system
print_summary

echo -e "\n${GREEN}Setup completed successfully!${NC}"
