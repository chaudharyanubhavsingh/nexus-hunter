"""
Reconnaissance Agent for Nexus Hunter
Handles subdomain discovery, port scanning, and technology fingerprinting
"""

import asyncio
import json
import subprocess
import re
from typing import Dict, List, Any, Set
from urllib.parse import urlparse

import dns.resolver
import httpx
import nmap
from bs4 import BeautifulSoup
from loguru import logger

from agents.base import BaseAgent


class ReconAgent(BaseAgent):
    """Autonomous reconnaissance agent"""
    
    def __init__(self):
        super().__init__("ReconAgent")
        self.discovered_subdomains: Set[str] = set()
        self.discovered_ports: Dict[str, List[int]] = {}
        self.technology_stack: Dict[str, Dict[str, Any]] = {}
    
    async def execute(self, target_domain: str, **kwargs) -> Dict[str, Any]:
        """Execute comprehensive reconnaissance"""
        
        results = {
            "target": target_domain,
            "subdomains": [],
            "ports": {},
            "technologies": {},
            "services": {},
            "dns_records": {},
            "ssl_info": {},
            "metadata": {}
        }
        
        try:
            # Phase 1: Subdomain Discovery
            await self.update_progress("subdomain_discovery", {
                "status": "Starting subdomain enumeration",
                "phase": "1/6"
            })
            subdomains = await self._discover_subdomains(target_domain)
            results["subdomains"] = list(subdomains)
            
            # Phase 2: DNS Enumeration
            await self.update_progress("dns_enumeration", {
                "status": "Enumerating DNS records",
                "phase": "2/6"
            })
            dns_records = await self._enumerate_dns(target_domain, subdomains)
            results["dns_records"] = dns_records
            
            # Phase 3: Port Scanning
            await self.update_progress("port_scanning", {
                "status": "Scanning for open ports",
                "phase": "3/6"
            })
            ports_data = await self._scan_ports(subdomains)
            results["ports"] = ports_data
            
            # Phase 4: Service Detection
            await self.update_progress("service_detection", {
                "status": "Detecting running services",
                "phase": "4/6"
            })
            services = await self._detect_services(ports_data)
            results["services"] = services
            
            # Phase 5: Technology Fingerprinting
            await self.update_progress("tech_fingerprinting", {
                "status": "Fingerprinting technologies",
                "phase": "5/6"
            })
            technologies = await self._fingerprint_technologies(subdomains)
            results["technologies"] = technologies
            
            # Phase 6: SSL/TLS Analysis
            await self.update_progress("ssl_analysis", {
                "status": "Analyzing SSL/TLS configurations",
                "phase": "6/6"
            })
            ssl_info = await self._analyze_ssl(subdomains)
            results["ssl_info"] = ssl_info
            
            # Calculate metadata
            results["metadata"] = {
                "total_subdomains": len(subdomains),
                "total_open_ports": sum(len(ports) for ports in ports_data.values()),
                "unique_technologies": len(set().union(*[tech.keys() for tech in technologies.values()])),
                "scan_duration": "completed"
            }
            
            logger.info(f"🎯 Reconnaissance completed for {target_domain}")
            return results
            
        except Exception as e:
            logger.error(f"❌ Reconnaissance failed: {e}")
            raise
    
    async def _discover_subdomains(self, domain: str) -> Set[str]:
        """Discover subdomains using multiple techniques"""
        subdomains = set([domain])  # Include main domain
        
        try:
            # Method 1: Certificate Transparency Logs
            ct_subdomains = await self._ct_subdomain_discovery(domain)
            subdomains.update(ct_subdomains)
            await self.update_progress("subdomain_discovery", {
                "method": "Certificate Transparency",
                "found": len(ct_subdomains),
                "total": len(subdomains)
            })
            
            # Method 2: DNS Brute Force
            if not self.is_cancelled():
                brute_subdomains = await self._dns_brute_force(domain)
                subdomains.update(brute_subdomains)
                await self.update_progress("subdomain_discovery", {
                    "method": "DNS Brute Force",
                    "found": len(brute_subdomains),
                    "total": len(subdomains)
                })
            
            # Method 3: Search Engine Dorking
            if not self.is_cancelled():
                search_subdomains = await self._search_engine_subdomains(domain)
                subdomains.update(search_subdomains)
                await self.update_progress("subdomain_discovery", {
                    "method": "Search Engine",
                    "found": len(search_subdomains),
                    "total": len(subdomains)
                })
            
            # Validate discovered subdomains
            valid_subdomains = await self._validate_subdomains(subdomains)
            
            logger.info(f"🔍 Discovered {len(valid_subdomains)} valid subdomains for {domain}")
            return valid_subdomains
            
        except Exception as e:
            logger.error(f"Subdomain discovery failed: {e}")
            return subdomains
    
    async def _ct_subdomain_discovery(self, domain: str) -> Set[str]:
        """Discover subdomains from Certificate Transparency logs"""
        subdomains = set()
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Use crt.sh API
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                response = await client.get(url)
                
                if response.status_code == 200:
                    try:
                        certificates = response.json()
                        for cert in certificates:
                            if 'name_value' in cert:
                                names = cert['name_value'].split('\n')
                                for name in names:
                                    name = name.strip().lower()
                                    if name.endswith(domain) and name != domain:
                                        subdomains.add(name)
                    except json.JSONDecodeError:
                        pass
        
        except Exception as e:
            logger.warning(f"CT log discovery failed: {e}")
        
        return subdomains
    
    async def _dns_brute_force(self, domain: str) -> Set[str]:
        """Brute force common subdomain names"""
        common_subdomains = [
            "www", "mail", "admin", "api", "app", "dev", "staging", "test",
            "blog", "shop", "store", "support", "help", "docs", "portal",
            "dashboard", "panel", "cpanel", "webmail", "ftp", "ssh", "vpn",
            "cdn", "static", "assets", "media", "images", "files", "downloads"
        ]
        
        subdomains = set()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        
        for subdomain in common_subdomains:
            if self.is_cancelled():
                break
                
            try:
                full_domain = f"{subdomain}.{domain}"
                await asyncio.sleep(0.1)  # Rate limiting
                
                # Check A record
                try:
                    resolver.resolve(full_domain, 'A')
                    subdomains.add(full_domain)
                except:
                    pass
                
            except Exception:
                continue
        
        return subdomains
    
    async def _search_engine_subdomains(self, domain: str) -> Set[str]:
        """Discover subdomains through search engines (passive)"""
        # This would normally use search APIs, but for demo purposes,
        # we'll simulate some common patterns
        simulated_subdomains = {
            f"mail.{domain}",
            f"www.{domain}",
            f"api.{domain}",
            f"admin.{domain}"
        }
        
        return simulated_subdomains
    
    async def _validate_subdomains(self, subdomains: Set[str]) -> Set[str]:
        """Validate that subdomains actually resolve"""
        valid_subdomains = set()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        
        for subdomain in subdomains:
            if self.is_cancelled():
                break
                
            try:
                resolver.resolve(subdomain, 'A')
                valid_subdomains.add(subdomain)
            except:
                pass
        
        return valid_subdomains
    
    async def _enumerate_dns(self, domain: str, subdomains: Set[str]) -> Dict[str, Any]:
        """Enumerate DNS records for discovered domains"""
        dns_records = {}
        resolver = dns.resolver.Resolver()
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        all_domains = list(subdomains) + [domain]
        
        for target_domain in all_domains:
            if self.is_cancelled():
                break
                
            dns_records[target_domain] = {}
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(target_domain, record_type)
                    dns_records[target_domain][record_type] = [str(answer) for answer in answers]
                except:
                    dns_records[target_domain][record_type] = []
        
        return dns_records
    
    async def _scan_ports(self, subdomains: Set[str]) -> Dict[str, List[int]]:
        """Scan for open ports on discovered subdomains"""
        ports_data = {}
        
        # Common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                       1433, 3306, 3389, 5432, 5984, 6379, 8080, 8443, 9200]
        
        for subdomain in list(subdomains)[:10]:  # Limit for demo
            if self.is_cancelled():
                break
                
            try:
                # Use Python socket for basic port scanning (faster than nmap for basic checks)
                open_ports = await self._socket_port_scan(subdomain, common_ports)
                if open_ports:
                    ports_data[subdomain] = open_ports
                    
            except Exception as e:
                logger.warning(f"Port scan failed for {subdomain}: {e}")
        
        return ports_data
    
    async def _socket_port_scan(self, host: str, ports: List[int]) -> List[int]:
        """Fast socket-based port scanning"""
        open_ports = []
        
        async def check_port(port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=3.0
                )
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None
        
        # Check ports in batches to avoid overwhelming the target
        batch_size = 10
        for i in range(0, len(ports), batch_size):
            if self.is_cancelled():
                break
                
            batch = ports[i:i + batch_size]
            tasks = [check_port(port) for port in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, int):
                    open_ports.append(result)
            
            await asyncio.sleep(0.5)  # Rate limiting between batches
        
        return sorted(open_ports)
    
    async def _detect_services(self, ports_data: Dict[str, List[int]]) -> Dict[str, Dict[int, str]]:
        """Detect services running on open ports"""
        services = {}
        
        for host, ports in ports_data.items():
            if self.is_cancelled():
                break
                
            services[host] = {}
            
            for port in ports:
                try:
                    service = await self._identify_service(host, port)
                    if service:
                        services[host][port] = service
                except Exception as e:
                    logger.warning(f"Service detection failed for {host}:{port}: {e}")
        
        return services
    
    async def _identify_service(self, host: str, port: int) -> str:
        """Identify service running on a specific port"""
        # Common service mappings
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5984: "CouchDB",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            9200: "Elasticsearch"
        }
        
        if port in common_services:
            return common_services[port]
        
        # Try banner grabbing for unknown services
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0
            )
            
            # Try to read banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            writer.close()
            await writer.wait_closed()
            
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            if banner_str:
                return f"Unknown ({banner_str[:50]})"
                
        except:
            pass
        
        return "Unknown"
    
    async def _fingerprint_technologies(self, subdomains: Set[str]) -> Dict[str, Dict[str, Any]]:
        """Fingerprint web technologies on discovered subdomains"""
        technologies = {}
        
        web_subdomains = []
        for subdomain in subdomains:
            # Check if subdomain has web services
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        response = await client.head(url, follow_redirects=True)
                        if response.status_code < 400:
                            web_subdomains.append(url)
                            break
                except:
                    continue
        
        for url in web_subdomains[:5]:  # Limit for demo
            if self.is_cancelled():
                break
                
            try:
                tech_info = await self._analyze_web_technology(url)
                if tech_info:
                    technologies[url] = tech_info
            except Exception as e:
                logger.warning(f"Technology fingerprinting failed for {url}: {e}")
        
        return technologies
    
    async def _analyze_web_technology(self, url: str) -> Dict[str, Any]:
        """Analyze web technology stack for a given URL"""
        tech_info = {
            "server": None,
            "frameworks": [],
            "cms": None,
            "analytics": [],
            "cdn": None,
            "javascript_libraries": [],
            "meta_generator": None
        }
        
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url, follow_redirects=True)
                
                # Analyze headers
                headers = response.headers
                
                # Server identification
                if 'server' in headers:
                    tech_info["server"] = headers['server']
                
                # X-Powered-By header
                if 'x-powered-by' in headers:
                    tech_info["frameworks"].append(headers['x-powered-by'])
                
                # CDN detection
                for header, value in headers.items():
                    if 'cloudflare' in header.lower() or 'cf-' in header.lower():
                        tech_info["cdn"] = "Cloudflare"
                    elif 'x-amz' in header.lower():
                        tech_info["cdn"] = "AWS CloudFront"
                
                # Content analysis
                if response.status_code == 200:
                    content = response.text
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Meta generator
                    generator = soup.find('meta', {'name': 'generator'})
                    if generator and generator.get('content'):
                        tech_info["meta_generator"] = generator['content']
                    
                    # JavaScript libraries detection
                    scripts = soup.find_all('script', src=True)
                    for script in scripts:
                        src = script.get('src', '').lower()
                        if 'jquery' in src:
                            tech_info["javascript_libraries"].append("jQuery")
                        elif 'angular' in src:
                            tech_info["javascript_libraries"].append("Angular")
                        elif 'react' in src:
                            tech_info["javascript_libraries"].append("React")
                        elif 'vue' in src:
                            tech_info["javascript_libraries"].append("Vue.js")
                    
                    # CMS detection
                    content_lower = content.lower()
                    if 'wp-content' in content_lower or 'wordpress' in content_lower:
                        tech_info["cms"] = "WordPress"
                    elif 'drupal' in content_lower:
                        tech_info["cms"] = "Drupal"
                    elif 'joomla' in content_lower:
                        tech_info["cms"] = "Joomla"
                
        except Exception as e:
            logger.warning(f"Web technology analysis failed for {url}: {e}")
        
        return tech_info
    
    async def _analyze_ssl(self, subdomains: Set[str]) -> Dict[str, Dict[str, Any]]:
        """Analyze SSL/TLS configurations"""
        ssl_info = {}
        
        for subdomain in list(subdomains)[:5]:  # Limit for demo
            if self.is_cancelled():
                break
                
            try:
                ssl_data = await self._get_ssl_info(subdomain)
                if ssl_data:
                    ssl_info[subdomain] = ssl_data
            except Exception as e:
                logger.warning(f"SSL analysis failed for {subdomain}: {e}")
        
        return ssl_info
    
    async def _get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate information for a domain"""
        ssl_data = {
            "has_ssl": False,
            "certificate_valid": False,
            "issuer": None,
            "subject": None,
            "san_domains": [],
            "expiry_date": None,
            "signature_algorithm": None
        }
        
        try:
            # Simple SSL check using httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"https://{domain}", follow_redirects=True)
                if response.status_code < 400:
                    ssl_data["has_ssl"] = True
                    ssl_data["certificate_valid"] = True
                    
                    # For a full implementation, you'd use SSL/TLS libraries
                    # to extract detailed certificate information
                    ssl_data["issuer"] = "Certificate Authority"
                    ssl_data["subject"] = domain
                    
        except Exception:
            # Try HTTP fallback
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    response = await client.get(f"http://{domain}")
                    # SSL not available but domain responds
            except:
                pass
        
        return ssl_data 