# CrowdSec DDNS Monitor

A Docker solution that automatically manages CrowdSec AllowLists for Dynamic DNS domains and Cloudflare-proxied services. This eliminates the performance penalties of CrowdSec's native DNS resolution while providing intelligent change detection and updates.

## ⚠️ Security Considerations

- __Claude Code planned and wrote 99% of this repo. I chose ease-of-setup vs. ultimate security. See [Security Considerations](https://github.com/trial123Zel/crowdsec-ddns-monitor#%EF%B8%8F-security-considerations) and [Important Deviations from Standard Deployments](https://github.com/trial123Zel/crowdsec-ddns-monitor?tab=readme-ov-file#-important-deviations-from-standard-deployments) for details and do not deploy on production server/exposed services server without understanding the repercussions.__
- **Docker Socket Access**: The container requires Docker socket access. Ensure your host security policies allow this.
- **Cloudflare Headers**: Never trust Cloudflare headers without validating the source IP is actually from Cloudflare.
- **Webhook URLs**: Keep webhook URLs secure and rotate them regularly.
- **Network Access**: The monitor requires outbound internet access for DNS resolution and Cloudflare API calls.

### 🚀 Features

- **Automated DDNS Monitoring**: Continuously monitors your dynamic DNS domains and updates CrowdSec AllowLists when IP addresses change
- **Cloudflare Integration**: Manages Cloudflare proxy IP ranges with proper header validation for secure authentication
- **Multi-ISP Support**: Handles primary/failover ISP configurations with separate domain tracking
- **Zero-Latency Operation**: Uses CrowdSec AllowLists instead of real-time DNS lookups for optimal performance
- **Health Monitoring**: Built-in health checks and status endpoints for monitoring integration
- **Webhook Alerts**: Optional Slack/Discord/HTTP webhook notifications for IP changes and system events
- **Homelab Ready**: Comprehensive error handling, logging, and Docker health checks

## 🏗️ Architecture

<details>

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   DDNS Monitor  │──▶│    CrowdSec     │───▶│   Your Apps     │
│                 │    │                 │    │                 │
│ • DNS Resolution│    │ • AllowLists    │    │ • Protected by  │
│ • Change Detection   │ • Decision Engine    │   CrowdSec      │
│ • Health Checks │    │ • Log Analysis  │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│  Cloudflare API │    │   Log Sources   │
│                 │    │                 │
│ • IP Ranges     │    │ • Caddy/Nginx   │
│ • Auto-Update   │    │ • Application   │
└─────────────────┘    └─────────────────┘
```

</details>

### 📋 Prerequisites

<details>

- Docker and Docker Compose v2
- Dynamic DNS domains (from providers like DuckDNS, No-IP, etc.)
- Basic understanding of CrowdSec concepts
- (Optional) Cloudflare account for proxy features
- Currently includes the now-deprecated Cloudflare Bouncer for Crowdsec. Consider upgrading to
  the new [Cloudflare Worker Bouncer by Crowdsec](https://docs.crowdsec.net/u/bouncers/cloudflare-workers)

</details>

### 🚦 Quick Start

#### 1. Clone and Setup

```bash
git clone https://github.com/yourusername/crowdsec-ddns-monitor.git
cd crowdsec-ddns-monitor

# Copy and edit configuration
touch .env
```

#### 2. Configure Environment

Edit `.env` with your settings:

```bash
# Required: Your dynamic DNS domains
DDNS_DOMAINS=ip1.example.com,ip2.example.com

# Optional: Cloudflare-proxied domains
CF_PROXIED_DOMAINS=your-cf-domain.com

# Server identification
HOSTNAME=production-server-1

# Optional: Webhook alerts
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

#### 3. Deploy

```bash
# Build and start services
docker compose --env-file .env up -d

# Verify deployment
curl http://localhost:8081/health
docker compose logs -f ddns-monitor
```

#### 4. Verify CrowdSec Integration

```bash
# Check that allowlists are created
docker exec crowdsec cscli allowlists list ddns-whitelist

# Monitor for IP changes
docker compose logs -f ddns-monitor | grep "DNS changes"
```

### ⚙️ Configuration

<details>

#### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DDNS_DOMAINS` | Yes* | - | Comma-separated list of dynamic DNS domains |
| `CF_PROXIED_DOMAINS` | Yes* | - | Comma-separated list of Cloudflare-proxied domains |
| `CHECK_INTERVAL` | No | 300 | DNS check interval in seconds |
| `ALLOWLIST_NAME` | No | ddns-whitelist | CrowdSec allowlist name for DDNS IPs |
| `CF_ALLOWLIST_NAME` | No | cloudflare-proxy | CrowdSec allowlist name for CF ranges |
| `DNS_SERVERS` | No | 1.1.1.1,8.8.8.8,9.9.9.9 | DNS servers for resolution |
| `LOG_LEVEL` | No | INFO | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `ALERT_WEBHOOK_URL` | No | - | Webhook URL for alerts |
| `HOSTNAME` | No | crowdsec-host | Server identifier for alerts |

*At least one of `DDNS_DOMAINS` or `CF_PROXIED_DOMAINS` must be specified.

</details>

### Advanced Configuration

<details>

#### DNS Settings
```bash
# Custom DNS servers and timeouts
DNS_SERVERS=8.8.8.8,1.1.1.1,your-isp-dns
DNS_TIMEOUT=5
DNS_RETRIES=3
```

#### Cloudflare Settings
```bash
# Cloudflare IP range refresh (daily by default)
CF_IP_REFRESH_INTERVAL=86400
```
</details>

### 🔧 Multi-Server Deployment

<details>

For environments with multiple CrowdSec instances:

#### Server 1 Configuration
```bash
# config/.env
HOSTNAME=production-server-1
DDNS_DOMAINS=ip1.example.com,ip2.example.com
ALERT_WEBHOOK_URL=https://your-webhook-url
```

#### Server 2 Configuration
```bash
# config/.env
HOSTNAME=production-server-2
DDNS_DOMAINS=ip1.example.com,ip2.example.com
ALERT_WEBHOOK_URL=https://your-webhook-url
```

Each server runs independently but monitors the same domains, ensuring consistent protection.

</details>

## 🔒 Cloudflare Integration

<details>

### Why Not Whitelist All Cloudflare IPs?

**⚠️ Security Warning**: This solution does NOT whitelist all Cloudflare proxy IPs, which would create a massive security vulnerability. Instead, it provides proper Cloudflare header validation.

### How It Works

1. **Cloudflare Proxy IPs**: Managed in a separate allowlist for visibility
2. **Header Validation**: Your application validates `CF-Connecting-IP` headers
3. **Real IP Analysis**: CrowdSec analyzes the actual client IP, not the proxy IP

</details>

## Application Integration

<details>

For applications behind Cloudflare:

```nginx
# nginx.conf example
server {
    # Trust Cloudflare IPs for real IP extraction
    set_real_ip_from 103.21.244.0/22;
    # ... (other CF ranges managed automatically)
    real_ip_header CF-Connecting-IP;
    
    # Log real client IP for CrowdSec analysis
    access_log /var/log/nginx/access.log combined;
}
```

For Python Application Code
```python
from flask import Flask, request
import ipaddress

app = Flask(__name__)

# Initialize Cloudflare manager (from your monitor)
cf_manager = CloudflareManager()

@app.before_request
def extract_real_client_ip():
    """Extract and validate real client IP from Cloudflare headers"""
    
    # Get the source IP (Cloudflare proxy IP)
    source_ip = request.environ.get('REMOTE_ADDR')
    
    # Check if this request came through Cloudflare
    if cf_manager.is_cloudflare_ip(source_ip):
        # Validate Cloudflare headers and get real client IP
        real_ip = cf_manager.validate_cloudflare_headers(
            dict(request.headers), 
            source_ip
        )
        
        if real_ip:
            # Store real client IP for use by CrowdSec and your app
            request.real_client_ip = real_ip
            # Log for CrowdSec to analyze
            app.logger.info(f"Real client IP: {real_ip} via CF proxy {source_ip}")
        else:
            # Invalid Cloudflare request - potential attack
            app.logger.warning(f"Invalid CF headers from {source_ip}")
            request.real_client_ip = source_ip
    else:
        # Direct connection (not through Cloudflare)
        request.real_client_ip = source_ip

@app.route('/')
def home():
    # Use the real client IP for any security decisions
    client_ip = getattr(request, 'real_client_ip', request.remote_addr)
    return f"Your real IP is: {client_ip}"
```

</details>

## 🎯 API Endpoints

<details>

The monitor exposes health and status endpoints:

### Health Check
```bash
curl http://localhost:8081/health
```

Response:
```json
{
  "status": "healthy",
  "last_check": "2025-01-01T12:00:00",
  "error_count": 0,
  "ddns_domains": ["ip1.example.com"],
  "cf_ranges_count": 156
}
```

### Detailed Status
```bash
curl http://localhost:8081/status
```

### Cloudflare Validation Test
```bash
curl -X POST http://localhost:8081/validate-cf-request \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "104.16.1.1",
    "headers": {
      "CF-Connecting-IP": "203.0.113.1",
      "CF-Ray": "7d7f8c9e5bf81234-SJC"
    }
  }'
```

</details>

## 📊 Monitoring and Alerting

<details>

### Health Monitoring

The service provides health endpoints suitable for:
- Docker health checks
- Kubernetes liveness/readiness probes
- External monitoring systems (Prometheus, etc.)

### Webhook Alerts

Configure webhooks for important events:
- New IP addresses added
- Old IP addresses removed
- System failures
- Cloudflare range updates

Supported formats:
- Slack webhooks
- Discord webhooks
- Generic HTTP POST endpoints

</details>

## 🔍 Troubleshooting

<details>

### Common Issues

#### Debug Mode

Enable debug logging:
```bash
# Add to config/.env
LOG_LEVEL=DEBUG

# Restart monitor
docker compose restart ddns-monitor
```

</details>

## 🚨 Important Deviations from Standard Deployments

<details>

### Docker Socket Access
This solution mounts the Docker socket (`/var/run/docker.sock`) to enable communication with CrowdSec. This is necessary for `cscli` command execution but requires:
- Container runs with elevated privileges
- Host Docker socket access
- Standard security practice in monitoring containers

### CrowdSec Configuration
The solution creates and manages AllowLists automatically. Unlike standard CrowdSec deployments:
- AllowLists are managed programmatically, not manually
- Two separate allowlists are maintained (DDNS and Cloudflare)
- Configuration changes don't require manual cscli commands

### Cloudflare Integration
This is NOT a standard CrowdSec pattern. The integration:
- Does NOT blindly whitelist Cloudflare IPs
- Requires application-level header validation
- Provides IP ranges for reference, not blanket whitelisting

</details>

## 🔄 Maintenance

<details>

### Regular Tasks

#### Update Cloudflare Ranges
Ranges update automatically every 24 hours, but you can force an update:
```bash
# Check current status
curl http://localhost:8081/status

# Monitor for updates in logs
docker compose logs ddns-monitor | grep "Cloudflare"
```

#### Monitor AllowList Growth
```bash
# Check allowlist sizes
docker exec crowdsec cscli allowlists list ddns-whitelist
docker exec crowdsec cscli allowlists list cloudflare-proxy

# Clean up if needed (manual process)
docker exec crowdsec cscli allowlists remove ddns-whitelist --value OLD_IP
```

#### Health Monitoring
Set up monitoring for the health endpoint:
```bash
# Simple monitoring script
*/5 * * * * curl -f http://localhost:8081/health || echo "DDNS Monitor unhealthy"
```

### Updates

To update the monitor:
```bash
git pull
docker compose build ddns-monitor
docker compose --env-file .env up -d
```

</details>

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [CrowdSec](https://crowdsec.net/) for the excellent security platform
- [Cloudflare](https://cloudflare.com/) for global CDN infrastructure
- The open-source community for inspiration and feedback