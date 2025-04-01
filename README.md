# V2Ray + TLS + WebSocket + Nginx Setup Script

This script automates the setup of a V2Ray proxy server with TLS encryption, WebSocket protocol, and Nginx as a reverse proxy. The setup includes performance optimizations for better speed and reliability.

## Features

- **Full automation**: One-script setup for V2Ray, TLS, WebSocket, and Nginx
- **Security**: TLS encryption with automatic certificate handling
- **Performance optimization**: System-level, Nginx, and V2Ray configurations optimized for speed
- **Robust implementation**: Multiple fallback mechanisms for IP detection and certificate issuance
- **Self-diagnostic**: Pre-checks for DNS, connectivity, and firewall settings
- **Multiple certificate options**: Supports automatic and manual certificate issuance methods

## Requirements

- A fresh server running Debian 10/11 or Ubuntu 18.04/20.04/22.04
- A registered domain name with DNS properly configured to point to your server's IP
- Port 80 and 443 open on your server's firewall
- Root access to your server

## Installation

1. Download the setup script:

```bash
curl -O https://raw.githubusercontent.com/zweineu/fanq/main/v2ray-setup.sh
```

2. Make the script executable:

```bash
chmod +x v2ray-setup.sh
```

3. Edit the script to set your configuration:

```bash
nano v2ray-setup.sh
```

Modify the following variables at the top of the script:
```bash
DOMAIN="your-domain.com"             # Your domain
EMAIL="your-email@example.com"       # Email for Let's Encrypt
WS_PATH="/ray"                       # WebSocket path
```

4. Run the script:

```bash
sudo ./v2ray-setup.sh
```

5. Follow the on-screen prompts to complete the installation.

## Configuration

### Custom Settings

You can customize the following parameters in the script:

- `DOMAIN`: Your domain name
- `EMAIL`: Your email address for Let's Encrypt
- `UUID`: Automatically generated, but you can set it manually
- `WS_PATH`: WebSocket path for V2Ray
- `PORT`: HTTPS port (default: 443)
- `NGINX_PORT`: Internal port for V2Ray WebSocket (default: 8080)

### Client Configuration

After installation, the script generates a client configuration file named `v2ray_client_config.json`. You can use this file with V2Ray clients such as:

- V2Ray official client
- v2rayN (Windows)
- V2RayX (macOS)
- v2rayNG (Android)
- Shadowrocket (iOS)

## Troubleshooting

### Certificate Issuance Failed

If certificate issuance fails, the script offers multiple fallback methods:

1. First attempts via Nginx plugin
2. If that fails, tries standalone mode
3. If standalone fails, tries webroot method
4. As a last resort, offers manual DNS verification or self-signed certificate

Common issues:
- DNS not properly configured
- Port 80 blocked by firewall
- Network issues preventing Let's Encrypt validation

### Connection Issues

If you experience connection issues:

1. Check the status of V2Ray and Nginx:
```bash
systemctl status v2ray
systemctl status nginx
```

2. Verify the certificate is valid:
```bash
certbot certificates
```

3. Check Nginx configuration:
```bash
nginx -t
```

4. Examine the logs:
```bash
tail -f /var/log/v2ray/access.log
tail -f /var/log/v2ray/error.log
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```

## Security Considerations

This setup implements several security best practices:

- TLS 1.2/1.3 only (older protocols disabled)
- Strong cipher suites
- HSTS and other security headers
- WebSocket path obfuscation
- Regular certificate renewal via Certbot

For additional security:
- Consider changing the default WebSocket path
- Set up fail2ban for brute force protection
- Keep your system updated

## Performance Optimization Details

The script includes the following performance optimizations:

### V2Ray Optimizations
- Efficient buffer sizes
- Connection idle timeouts
- Optimized sniffing configuration

### Nginx Optimizations
- Worker process auto-scaling
- Epoll event model
- WebSocket-specific settings
- File cache configuration
- Gzip compression

### System-level Optimizations
- TCP BBR congestion control
- Increased socket buffer sizes
- Optimized TCP parameters
- Higher file descriptor limits

## Automatic Updates

The script configures automatic certificate renewal through Certbot's timer service. 

To manually renew certificates:
```bash
certbot renew
```

## License

This script is provided "as is", without warranty of any kind. Use at your own risk.

## Acknowledgements

This setup script incorporates best practices from:
- V2Ray official documentation
- Nginx performance guides
- Let's Encrypt/Certbot documentation
- Various Linux networking optimization resources
