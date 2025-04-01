#!/bin/bash
# V2Ray + WebSocket + Nginx + Cloudflare Setup Script
# This script sets up V2Ray with WebSocket protocol compatible with Cloudflare CDN

set -e

# Color codes for better readability
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
RED="\033[0;31m"
NC="\033[0m" # No Color

# Configuration variables (you should modify these)
DOMAIN="example.com"                     # Your domain (must be added to Cloudflare)
EMAIL="admin@example.com"                # Email for Let's Encrypt
UUID=$(cat /proc/sys/kernel/random/uuid) # Random UUID for V2Ray
WS_PATH="/ray"                           # WebSocket path
NGINX_PORT="8080"                        # Nginx listener port for V2Ray WebSocket

echo -e "${BLUE}V2Ray + WebSocket + Nginx + Cloudflare Setup Script${NC}"
echo "Domain: $DOMAIN"
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
apt install -y curl wget unzip lsof git socat cron dnsutils ufw certbot python3-certbot-nginx

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

# Verify Cloudflare DNS configuration
check_cloudflare_dns() {
    echo -e "\n${YELLOW}Checking Cloudflare DNS configuration for $DOMAIN...${NC}"
    
    # Get the server's IP address
    SERVER_IP=$(curl -s -4 ifconfig.me)
    
    # Get the domain's resolved IP
    DOMAIN_IP=$(dig +short $DOMAIN A)
    
    # Check if the domain resolves to a Cloudflare IP
    if [[ $(curl -s -4 https://www.cloudflare.com/ips-v4 | grep -c $DOMAIN_IP) -eq 0 ]]; then
        echo -e "${RED}Warning: Domain $DOMAIN does not resolve to a Cloudflare IP.${NC}"
        echo -e "${YELLOW}Please ensure your domain is properly configured with Cloudflare:${NC}"
        echo -e "1. Make sure DNS records point to your server IP: ${SERVER_IP}"
        echo -e "2. Ensure the Cloudflare proxy is enabled (orange cloud icon)"
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        echo -e "${GREEN}Domain $DOMAIN is correctly proxied through Cloudflare.${NC}"
    fi
}

# Install Nginx
install_nginx() {
    echo -e "\n${YELLOW}Installing Nginx...${NC}"
    apt install -y nginx
    systemctl enable nginx
    systemctl start nginx
    
    # Create fake website for cover
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
    
    # For certbot validation
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

# Issue SSL certificate
issue_ssl() {
    echo -e "\n${YELLOW}Issuing SSL certificate for ${DOMAIN}...${NC}"
    
    # Setup proper permissions for webroot
    mkdir -p /var/www/html/.well-known/acme-challenge
    chmod -R 755 /var/www/html
    chown -R www-data:www-data /var/www/html
    
    # Temporarily disable Cloudflare proxy for certificate issuance
    echo -e "${YELLOW}Important: For certificate issuance, you need to:${NC}"
    echo -e "1. Temporarily set Cloudflare DNS record for $DOMAIN to 'DNS only' (gray cloud)"
    echo -e "2. Wait a few minutes for DNS changes to propagate"
    echo -e "3. After certificate issuance, set it back to 'Proxied' (orange cloud)"
    read -p "Press enter once you have set Cloudflare to 'DNS only'..."
    
    # Wait for DNS propagation
    echo -e "${YELLOW}Waiting for DNS changes to propagate (30 seconds)...${NC}"
    sleep 30
    
    # Issue certificate
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m $EMAIL --redirect
    
    # Create directory for V2Ray if needed
    mkdir -p /etc/v2ray/cert
    
    echo -e "${GREEN}SSL certificate issued successfully!${NC}"
    echo -e "${YELLOW}Important: Remember to set your Cloudflare DNS record back to 'Proxied' (orange cloud)${NC}"
    read -p "Press enter once you have set Cloudflare back to 'Proxied'..."
}

# Install V2Ray using official script
install_v2ray() {
    echo -e "\n${YELLOW}Installing V2Ray using official installation script...${NC}"
    
    # Check if V2Ray is already installed
    if [ -f /usr/local/bin/v2ray ]; then
        echo -e "${GREEN}V2Ray is already installed!${NC}"
        return
    fi
    
    # Install dependencies
    apt-get install -y curl wget unzip
    
    # Download and run official installation script
    echo -e "${YELLOW}Downloading and running official V2Ray installation script...${NC}"
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
    # Verify installation
    if [ -f /usr/local/bin/v2ray ]; then
        echo -e "${GREEN}V2Ray has been successfully installed!${NC}"
    else
        echo -e "${RED}V2Ray installation failed. Exiting.${NC}"
        exit 1
    fi
    
    # Create v2ray config directory if it doesn't exist
    mkdir -p /etc/v2ray
    
    echo -e "${GREEN}V2Ray installation completed!${NC}"
}

# Configure V2Ray for Cloudflare
configure_v2ray() {
    echo -e "\n${YELLOW}Configuring V2Ray for Cloudflare...${NC}"
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
    
    # Set appropriate permissions
    chmod 644 /etc/v2ray/config.json
    
    # Enable and start V2Ray service
    systemctl daemon-reload
    systemctl enable v2ray
    systemctl restart v2ray
    
    echo -e "${GREEN}V2Ray configured for Cloudflare!${NC}"
}

# Configure Nginx for Cloudflare
configure_nginx_final() {
    echo -e "\n${YELLOW}Configuring Nginx for Cloudflare and V2Ray proxy...${NC}"
    
    # Get Cloudflare IP ranges
    echo -e "${YELLOW}Fetching Cloudflare IP ranges...${NC}"
    CF_IPV4=$(curl -s https://www.cloudflare.com/ips-v4)
    CF_IPV6=$(curl -s https://www.cloudflare.com/ips-v6)
    
    # Create Cloudflare IP whitelist file
    mkdir -p /etc/nginx/conf.d
    cat > /etc/nginx/conf.d/cloudflare.conf << EOF
# Cloudflare IP Ranges
EOF

    # Add IPv4 ranges
    for ip in $CF_IPV4; do
        echo "set_real_ip_from $ip;" >> /etc/nginx/conf.d/cloudflare.conf
    done
    
    # Add IPv6 ranges
    for ip in $CF_IPV6; do
        echo "set_real_ip_from $ip;" >> /etc/nginx/conf.d/cloudflare.conf
    done
    
    # Set real IP header
    echo "real_ip_header CF-Connecting-IP;" >> /etc/nginx/conf.d/cloudflare.conf
    
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
    
    # Include Cloudflare IP configuration
    include /etc/nginx/conf.d/cloudflare.conf;
    
    # Include site configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    # Create server config for Cloudflare
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
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    root /var/www/html;
    index index.html;

    # SSL certificates (managed by Certbot)
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    # Optimized SSL
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 1.0.0.1 valid=300s;
    resolver_timeout 5s;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    # WebSocket proxy - V2Ray
    location $WS_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$NGINX_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        
        # Pass Cloudflare real IP
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
    
    echo -e "${GREEN}Nginx configured for Cloudflare proxy!${NC}"
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

# Create Cloudflare client configuration
create_cloudflare_client_config() {
    echo -e "\n${YELLOW}Creating client configuration for Cloudflare setup...${NC}"
    
    cat > v2ray_cloudflare_client_config.json << EOF
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
            "port": 443,
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

    echo -e "${GREEN}Client configuration saved to v2ray_cloudflare_client_config.json${NC}"
}

# Print a summary and QR code
print_summary() {
    echo -e "\n${GREEN}V2Ray with WebSocket + Nginx + Cloudflare has been set up successfully!${NC}"
    echo -e "${YELLOW}-----------------------------------------------------------${NC}"
    echo -e "${YELLOW}V2Ray Client Configuration:${NC}"
    echo -e "${BLUE}Address:${NC} $DOMAIN"
    echo -e "${BLUE}Port:${NC} 443"
    echo -e "${BLUE}UUID:${NC} $UUID"
    echo -e "${BLUE}AlterID:${NC} 0"
    echo -e "${BLUE}Security:${NC} auto"
    echo -e "${BLUE}Network:${NC} ws"
    echo -e "${BLUE}Path:${NC} $WS_PATH"
    echo -e "${BLUE}TLS:${NC} tls"
    echo -e "${YELLOW}-----------------------------------------------------------${NC}"
    echo -e "${YELLOW}Cloudflare Settings:${NC}"
    echo -e "${BLUE}SSL/TLS:${NC} Full (strict)"
    echo -e "${BLUE}Always Use HTTPS:${NC} On"
    echo -e "${BLUE}WebSockets:${NC} On"
    echo -e "${YELLOW}-----------------------------------------------------------${NC}"
    echo -e "${GREEN}A client configuration file was saved to: v2ray_cloudflare_client_config.json${NC}"
    
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

# Main setup flow
echo -e "\n${YELLOW}Starting Cloudflare-compatible V2Ray setup...${NC}"

# Verify DNS is properly configured with Cloudflare
check_cloudflare_dns

# Install components
install_bbr
install_nginx
configure_nginx_initial
issue_ssl
install_v2ray
configure_v2ray
configure_nginx_final
optimize_system
create_cloudflare_client_config
print_summary

echo -e "\n${GREEN}Setup completed successfully!${NC}"
echo -e "${YELLOW}Important Cloudflare settings to verify:${NC}"
echo -e "1. SSL/TLS encryption mode: Set to 'Full (strict)'"
echo -e "2. Edge Certificates: Enable 'Always Use HTTPS'"
echo -e "3. Network: Enable 'WebSockets'"
echo -e "4. Ensure your domain has the 'Proxied' status (orange cloud)"
echo -e "\n${GREEN}Enjoy your V2Ray setup behind Cloudflare CDN!${NC}"
