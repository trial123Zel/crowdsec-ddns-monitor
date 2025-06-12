import os
import logging
from typing import List

class Config:
    """Configuration management for DDNS monitor and Cloudflare Proxied Traffic support"""
    
    def __init__(self):
        # Core settings
        self.ddns_domains = self._parse_domains(os.getenv('DDNS_DOMAINS', ''))
        self.check_interval = int(os.getenv('CHECK_INTERVAL', '300'))
        self.crowdsec_api_url = os.getenv('CROWDSEC_API_URL', 'http://crowdsec:8080')
        self.allowlist_name = os.getenv('ALLOWLIST_NAME', 'ddns-whitelist')

        # Cloudflare settings
        self.cf_proxied_domains = self._parse_domains(os.getenv('CF_PROXIED_DOMAINS', ''))
        self.cf_ip_refresh_interval = int(os.getenv('CF_IP_REFRESH_INTERVAL', '86400'))  # 24 hours
        self.cf_allowlist_name = os.getenv('CF_ALLOWLIST_NAME', 'cloudflare-proxy')

        # DNS settings
        self.dns_servers = self._parse_dns_servers(os.getenv('DNS_SERVERS', '1.1.1.1,8.8.8.8,9.9.9.9'))
        self.dns_timeout = int(os.getenv('DNS_TIMEOUT', '5'))
        self.dns_retries = int(os.getenv('DNS_RETRIES', '3'))
        
        # Logging
        self.log_level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper())
        self.log_file = '/app/logs/ddns-monitor.log'
        
        # Alerting
        self.alert_webhook_url = os.getenv('ALERT_WEBHOOK_URL', '')
        
        # Validation
        self._validate_config()
    
    def _parse_domains(self, domains_str: str) -> List[str]:
        """Parse comma-separated domain list"""
        if not domains_str:
            raise ValueError("DDNS_DOMAINS environment variable is required")
        return [domain.strip() for domain in domains_str.split(',') if domain.strip()]
    
    def _parse_dns_servers(self, servers_str: str) -> List[str]:
        """Parse comma-separated DNS server list"""
        return [server.strip() for server in servers_str.split(',') if server.strip()]
    
    def _validate_config(self):
        """Validate configuration values"""
        if not self.ddns_domains:
            raise ValueError("At least one DDNS domain must be specified")
        
        if self.check_interval < 60:
            raise ValueError("Check interval must be at least 60 seconds")
        
        if not self.dns_servers:
            raise ValueError("At least one DNS server must be specified")

# Global config instance
config = Config()
