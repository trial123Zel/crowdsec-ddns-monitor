#!/usr/bin/env python3

import sys
import time
import json
import logging
import ipaddress
import threading
import requests
import dns.resolver
import schedule
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from flask import Flask, jsonify, request
from config import config

# Configure logging
logging.basicConfig(
    level=config.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class DNSResolver:
    """Robust DNS resolver with multiple server fallback"""
    
    def __init__(self, dns_servers: List[str], timeout: int = 5, retries: int = 3):
        self.dns_servers = dns_servers
        self.timeout = timeout
        self.retries = retries
        
    def resolve_domain(self, domain: str) -> Set[str]:
        """Resolve domain to set of IP addresses"""
        for server in self.dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [server]
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout * self.retries
                
                result = resolver.resolve(domain, 'A')
                ips = {str(rdata) for rdata in result}
                
                if ips:
                    logger.debug(f"Resolved {domain} to {ips} via {server}")
                    return ips
                    
            except Exception as e:
                logger.warning(f"DNS resolution failed for {domain} via {server}: {e}")
                continue
        
        logger.error(f"Failed to resolve {domain} using all DNS servers")
        return set()

class CrowdSecAPI:
    """CrowdSec API client for managing AllowLists"""
    
    def __init__(self, api_url: str):
        self.api_url = api_url.rstrip('/')
        self.session = None  # Not using requests session, using cscli instead
        
    def execute_cscli_command(self, command: list) -> tuple[bool, str]:
        """Execute cscli command via docker exec"""
        try:
            import subprocess
            full_command = ['docker', 'exec', 'crowdsec', 'cscli'] + command
            
            result = subprocess.run(
                full_command, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            return result.returncode == 0, result.stdout if result.returncode == 0 else result.stderr
            
        except Exception as e:
            logger.error(f"Error executing cscli command: {e}")
            return False, str(e)
        
    def get_allowlist_entries(self, list_name: str) -> Set[str]:
        """Get current AllowList entries"""
        try:
            success, output = self.execute_cscli_command(['allowlists', 'list', list_name, '-o', 'json'])
            
            if success and output.strip():
                data = json.loads(output)
                return {entry.get('value', '') for entry in data if entry.get('value')}
            else:
                logger.debug(f"No entries found for allowlist {list_name} or list doesn't exist")
                return set()
                
        except Exception as e:
            logger.error(f"Error getting allowlist entries: {e}")
            return set()
    
    def add_allowlist_entry(self, list_name: str, ip: str, reason: str) -> bool:
        """Add IP to AllowList"""
        try:
            success, output = self.execute_cscli_command([
                'allowlists', 'add', list_name,
                ip, '-d', reason
            ])
            
            if success:
                logger.info(f"Added {ip} to allowlist {list_name}")
            else:
                logger.error(f"Failed to add {ip} to allowlist: {output}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error adding allowlist entry: {e}")
            return False
    
    def remove_allowlist_entry(self, list_name: str, ip: str) -> bool:
        """Remove IP from AllowList"""
        try:
            success, output = self.execute_cscli_command([
                'allowlists', 'remove', list_name, ip
            ])
            
            if success:
                logger.info(f"Removed {ip} from allowlist {list_name}")
            else:
                logger.error(f"Failed to remove {ip} from allowlist: {output}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error removing allowlist entry: {e}")
            return False

class DDNSMonitor:
    """Enhanced DDNS monitoring with Cloudflare support"""
    
    def __init__(self):
        self.dns_resolver = DNSResolver(config.dns_servers, config.dns_timeout, config.dns_retries)
        self.crowdsec_api = CrowdSecAPI(config.crowdsec_api_url)
        self.cloudflare_manager = CloudflareManager()
        
        # Tracking state
        self.current_ips: Dict[str, Set[str]] = {}
        self.current_cf_ranges: Set[str] = set()
        self.last_check = None
        self.error_count = 0
        self.max_errors = 5
        
        # Health check app
        self.app = Flask(__name__)
        self.setup_health_endpoints()
        
    def setup_health_endpoints(self):
        """Setup Flask health check endpoints with Cloudflare info"""
        
        @self.app.route('/health')
        def health():
            """Health check endpoint"""
            healthy = (
                self.last_check and 
                (datetime.now() - self.last_check) < timedelta(minutes=10) and
                self.error_count < self.max_errors
            )
            
            status = 200 if healthy else 503
            return jsonify({
                'status': 'healthy' if healthy else 'unhealthy',
                'last_check': self.last_check.isoformat() if self.last_check else None,
                'error_count': self.error_count,
                'ddns_domains': list(self.current_ips.keys()),
                'cf_domains': config.cf_proxied_domains,
                'cf_ranges_count': len(self.current_cf_ranges),
                'cf_last_update': self.cloudflare_manager.last_update.isoformat() if self.cloudflare_manager.last_update else None
            }), status
        
        @self.app.route('/status')
        def status():
            """Detailed status endpoint"""
            return jsonify({
                'ddns_domains': {domain: list(ips) for domain, ips in self.current_ips.items()},
                'cloudflare': {
                    'proxied_domains': config.cf_proxied_domains,
                    'ip_ranges_count': len(self.current_cf_ranges),
                    'last_update': self.cloudflare_manager.last_update.isoformat() if self.cloudflare_manager.last_update else None,
                    'ipv4_ranges': len(self.cloudflare_manager.cf_ipv4_ranges),
                    'ipv6_ranges': len(self.cloudflare_manager.cf_ipv6_ranges)
                },
                'last_check': self.last_check.isoformat() if self.last_check else None,
                'config': {
                    'check_interval': config.check_interval,
                    'dns_servers': config.dns_servers,
                    'ddns_allowlist': config.allowlist_name,
                    'cf_allowlist': config.cf_allowlist_name
                }
            })
        
        @self.app.route('/validate-cf-request', methods=['POST'])
        def validate_cf_request():
            """Endpoint to validate Cloudflare requests (for testing)"""
            try:
                data = request.get_json()
                source_ip = data.get('source_ip')
                headers = data.get('headers', {})
                
                real_ip = self.cloudflare_manager.validate_cloudflare_headers(headers, source_ip)
                
                return jsonify({
                    'valid': real_ip is not None,
                    'real_client_ip': real_ip,
                    'cloudflare_source': self.cloudflare_manager.is_cloudflare_ip(source_ip)
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 400
    
    def send_alert(self, message: str, level: str = 'warning'):
        """Send alert via webhook if configured"""
        if not config.alert_webhook_url:
            return
            
        try:
            payload = {
                'text': f"DDNS Monitor Alert: {message}",
                'level': level,
                'timestamp': datetime.now().isoformat(),
                'hostname': config.crowdsec_api_url
            }
            
            response = requests.post(config.alert_webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
    
    def check_dns_changes(self):
        """Enhanced DNS check with Cloudflare range updates"""
        logger.info("Starting DNS check cycle")
        self.last_check = datetime.now()
        
        try:
            changes_detected = False
            
            # Check if we need to update Cloudflare ranges
            if config.cf_proxied_domains and self.cloudflare_manager.should_update_ranges():
                if self.cloudflare_manager.update_cloudflare_ranges():
                    changes_detected = True
            
            # Check DDNS domains (existing logic)
            if config.ddns_domains:
                new_ips = {}
                
                for domain in config.ddns_domains:
                    logger.debug(f"Resolving DDNS domain {domain}")
                    resolved_ips = self.dns_resolver.resolve_domain(domain)
                    
                    if not resolved_ips:
                        logger.warning(f"No IPs resolved for {domain}")
                        self.error_count += 1
                        continue
                    
                    new_ips[domain] = resolved_ips
                    
                    # Check for changes
                    if domain not in self.current_ips or self.current_ips[domain] != resolved_ips:
                        changes_detected = True
                        old_ips = self.current_ips.get(domain, set())
                        
                        added_ips = resolved_ips - old_ips
                        removed_ips = old_ips - resolved_ips
                        
                        if added_ips:
                            logger.info(f"New IPs for {domain}: {added_ips}")
                        if removed_ips:
                            logger.info(f"Removed IPs for {domain}: {removed_ips}")
                
                if changes_detected and new_ips:
                    self.update_ddns_allowlists(new_ips)
                    self.current_ips = new_ips
            
            # Update Cloudflare allowlists if needed
            if config.cf_proxied_domains and changes_detected:
                self.update_cloudflare_allowlists()
            
            if not changes_detected:
                logger.debug("No DNS or Cloudflare changes detected")
            
            self.error_count = 0  # Reset error count on successful update
                
        except Exception as e:
            logger.error(f"Error during DNS check: {e}")
            self.error_count += 1
            
            if self.error_count >= self.max_errors:
                self.send_alert(f"DDNS monitor has failed {self.error_count} times", 'critical')
    
    def update_ddns_allowlists(self, new_ips: Dict[str, Set[str]]):
        """Update DDNS AllowLists"""
        logger.info("Updating DDNS AllowLists")
        
        current_allowlist = self.crowdsec_api.get_allowlist_entries(config.allowlist_name)
        
        desired_ips = set()
        for domain, ips in new_ips.items():
            desired_ips.update(ips)
        
        # Add new IPs
        for ip in desired_ips - current_allowlist:
            reason = f"DDNS auto-whitelist ({datetime.now().strftime('%Y-%m-%d %H:%M')})"
            if self.crowdsec_api.add_allowlist_entry(config.allowlist_name, ip, reason):
                self.send_alert(f"Added new DDNS IP: {ip}", 'info')
        
        # Remove old IPs
        for ip in current_allowlist - desired_ips:
            if self.crowdsec_api.remove_allowlist_entry(config.allowlist_name, ip):
                self.send_alert(f"Removed old DDNS IP: {ip}", 'info')
    
    def update_cloudflare_allowlists(self):
        """Update Cloudflare proxy IP ranges in allowlist"""
        logger.info("Updating Cloudflare proxy AllowLists")
        
        # Get current Cloudflare allowlist
        current_cf_allowlist = self.crowdsec_api.get_allowlist_entries(config.cf_allowlist_name)
        
        # Get desired Cloudflare ranges
        desired_cf_ranges = self.cloudflare_manager.get_cloudflare_ips_for_allowlist()
        
        # Add new ranges
        for cf_range in desired_cf_ranges - current_cf_allowlist:
            reason = f"Cloudflare proxy range ({datetime.now().strftime('%Y-%m-%d')})"
            if self.crowdsec_api.add_allowlist_entry(config.cf_allowlist_name, cf_range, reason):
                logger.info(f"Added Cloudflare range: {cf_range}")
        
        # Remove old ranges
        for cf_range in current_cf_allowlist - desired_cf_ranges:
            if self.crowdsec_api.remove_allowlist_entry(config.cf_allowlist_name, cf_range):
                logger.info(f"Removed old Cloudflare range: {cf_range}")
        
        self.current_cf_ranges = desired_cf_ranges
    
    def run_scheduler(self):
        """Run the scheduled DNS checks"""
        schedule.every(config.check_interval).seconds.do(self.check_dns_changes)
        
        # Initial check
        self.check_dns_changes()
        
        logger.info(f"Starting scheduler with {config.check_interval}s interval")
        while True:
            schedule.run_pending()
            time.sleep(10)  # Check every 10 seconds for new scheduled jobs
    
    def run(self):
        """Start the monitor with health check server"""
        logger.info("Starting Enhanced DDNS Monitor with Cloudflare support")
        logger.info(f"Monitoring DDNS domains: {config.ddns_domains}")
        logger.info(f"Monitoring CF domains: {config.cf_proxied_domains}")
        logger.info(f"Check interval: {config.check_interval}s")
        logger.info(f"DDNS AllowList: {config.allowlist_name}")
        logger.info(f"CF AllowList: {config.cf_allowlist_name}")
        
        # Initial Cloudflare range update if CF domains configured
        if config.cf_proxied_domains:
            logger.info("Performing initial Cloudflare IP range update")
            self.cloudflare_manager.update_cloudflare_ranges()
        
        # Start scheduler in background thread
        scheduler_thread = threading.Thread(target=self.run_scheduler, daemon=True)
        scheduler_thread.start()
        
        # Start health check server
        self.app.run(host='0.0.0.0', port=8081, debug=False)

class CloudflareManager:
    """Manages Cloudflare IP ranges and authentication"""
    
    def __init__(self):
        self.cf_ipv4_ranges: Set[ipaddress.IPv4Network] = set()
        self.cf_ipv6_ranges: Set[ipaddress.IPv6Network] = set()
        self.last_update: Optional[datetime] = None
        self.cf_ips_url_v4 = "https://www.cloudflare.com/ips-v4"
        self.cf_ips_url_v6 = "https://www.cloudflare.com/ips-v6"
        
    def update_cloudflare_ranges(self) -> bool:
        """Update Cloudflare IP ranges from official sources"""
        try:
            logger.info("Updating Cloudflare IP ranges")
            
            # Get IPv4 ranges
            response_v4 = requests.get(self.cf_ips_url_v4, timeout=30)
            response_v4.raise_for_status()
            
            # Get IPv6 ranges  
            response_v6 = requests.get(self.cf_ips_url_v6, timeout=30)
            response_v6.raise_for_status()
            
            # Parse IPv4 ranges
            new_ipv4_ranges = set()
            for line in response_v4.text.strip().split('\n'):
                if line.strip():
                    new_ipv4_ranges.add(ipaddress.IPv4Network(line.strip()))
            
            # Parse IPv6 ranges
            new_ipv6_ranges = set()
            for line in response_v6.text.strip().split('\n'):
                if line.strip():
                    new_ipv6_ranges.add(ipaddress.IPv6Network(line.strip()))
            
            # Update if we got valid data
            if new_ipv4_ranges:
                self.cf_ipv4_ranges = new_ipv4_ranges
                self.cf_ipv6_ranges = new_ipv6_ranges
                self.last_update = datetime.now()
                
                logger.info(f"Updated Cloudflare ranges: {len(self.cf_ipv4_ranges)} IPv4, {len(self.cf_ipv6_ranges)} IPv6")
                return True
            
        except Exception as e:
            logger.error(f"Failed to update Cloudflare IP ranges: {e}")
            
        return False
    
    def is_cloudflare_ip(self, ip_str: str) -> bool:
        """Check if an IP belongs to Cloudflare"""
        try:
            ip = ipaddress.ip_address(ip_str)
            
            if isinstance(ip, ipaddress.IPv4Address):
                return any(ip in network for network in self.cf_ipv4_ranges)
            else:
                return any(ip in network for network in self.cf_ipv6_ranges)
                
        except ValueError:
            return False
    
    def get_cloudflare_ips_for_allowlist(self) -> Set[str]:
        """Get all Cloudflare IP ranges as strings for allowlist"""
        ips = set()
        
        # Add IPv4 ranges
        for network in self.cf_ipv4_ranges:
            ips.add(str(network))
            
        # Add IPv6 ranges
        for network in self.cf_ipv6_ranges:
            ips.add(str(network))
            
        return ips
    
    def should_update_ranges(self) -> bool:
        """Check if Cloudflare ranges need updating"""
        if not self.last_update:
            return True
            
        return (datetime.now() - self.last_update) > timedelta(seconds=config.cf_ip_refresh_interval)

    def validate_cloudflare_headers(self, headers: Dict[str, str], source_ip: str) -> Optional[str]:
        """
        Validate that a request with Cloudflare headers actually came from Cloudflare
        Returns the real client IP if valid, None if invalid
        """
        # First check: Is this request coming from a Cloudflare IP?
        if not self.is_cloudflare_ip(source_ip):
            logger.warning(f"Request with CF headers from non-Cloudflare IP: {source_ip}")
            return None
        
        # Second check: Does it have the required Cloudflare headers?
        cf_connecting_ip = headers.get('CF-Connecting-IP')
        cf_ray = headers.get('CF-Ray')
        
        if not cf_connecting_ip or not cf_ray:
            logger.warning(f"Missing required Cloudflare headers from {source_ip}")
            return None
        
        # Third check: Is the CF-Connecting-IP valid?
        try:
            ipaddress.ip_address(cf_connecting_ip)
        except ValueError:
            logger.warning(f"Invalid CF-Connecting-IP: {cf_connecting_ip}")
            return None
        
        # Fourth check: CF-Ray format validation (basic)
        if not cf_ray or len(cf_ray) < 16 or '-' not in cf_ray:
            logger.warning(f"Invalid CF-Ray format: {cf_ray}")
            return None
        
        logger.debug(f"Validated Cloudflare request: {source_ip} -> {cf_connecting_ip}")
        return cf_connecting_ip

if __name__ == '__main__':
    try:
        monitor = DDNSMonitor()
        monitor.run()
    except KeyboardInterrupt:
        logger.info("Shutting down DDNS Monitor")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)