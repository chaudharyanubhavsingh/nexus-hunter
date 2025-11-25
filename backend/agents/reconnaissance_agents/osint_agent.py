"""
OSINT Agent - Comprehensive Information Gathering
Professional OSINT collection from multiple sources without heavy dependencies
"""

import asyncio
import json
import subprocess
import re
from typing import Dict, List, Any, Optional
from loguru import logger

from agents.base import BaseAgent


class OSINTAgent(BaseAgent):
    """
    Professional Open Source Intelligence Agent
    Specializes in information gathering from public sources
    """
    
    def __init__(self):
        super().__init__("osint_agent")
        
    async def comprehensive_osint(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive OSINT gathering from multiple sources
        
        Args:
            target: Target domain or organization
            options: OSINT options (sources, depth, timeout)
            
        Returns:
            Comprehensive OSINT results
        """
        logger.info(f"🔍 Starting comprehensive OSINT gathering for {target}")
        
        # Clean target
        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Initialize results structure
        results = {
            "target": clean_target,
            "emails": [],
            "subdomains": [],
            "ips": [],
            "social_media": {},
            "dns_records": {},
            "whois_info": {},
            "certificates": [],
            "technologies": [],
            "leaked_credentials": [],
            "company_info": {},
            "employees": []
        }
        
        try:
            # Perform parallel OSINT gathering
            tasks = [
                self._discover_emails(clean_target),
                self._discover_subdomains(clean_target),
                self._gather_dns_info(clean_target),
                self._gather_whois_info(clean_target),
                self._discover_social_media(clean_target),
                self._analyze_certificates(clean_target),
                self._detect_technologies(clean_target)
            ]
            
            # Execute all tasks concurrently
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for i, result in enumerate(task_results):
                if isinstance(result, Exception):
                    logger.debug(f"OSINT task {i} failed: {result}")
                    continue
                    
                if isinstance(result, dict):
                    # Merge results based on task type
                    if i == 0 and "emails" in result:  # Email discovery
                        results["emails"].extend(result["emails"])
                    elif i == 1 and "subdomains" in result:  # Subdomain discovery
                        results["subdomains"].extend(result["subdomains"])
                    elif i == 2 and "dns_records" in result:  # DNS info
                        results["dns_records"].update(result["dns_records"])
                    elif i == 3 and "whois_info" in result:  # WHOIS info
                        results["whois_info"].update(result["whois_info"])
                    elif i == 4 and "social_media" in result:  # Social media
                        results["social_media"].update(result["social_media"])
                    elif i == 5 and "certificates" in result:  # Certificates
                        results["certificates"].extend(result["certificates"])
                    elif i == 6 and "technologies" in result:  # Technologies
                        results["technologies"].extend(result["technologies"])
            
            # Remove duplicates and clean data
            results["emails"] = list(set(results["emails"]))
            results["subdomains"] = list(set(results["subdomains"]))
            results["ips"] = list(set(results["ips"]))
            results["technologies"] = list(set(results["technologies"]))
            
            # Generate analysis
            analysis = self._analyze_osint_results(results, clean_target)
            
            logger.info(f"✅ OSINT gathering completed for {clean_target}")
            
            return {
                "success": True,
                "target": clean_target,
                "osint_data": results,
                "analysis": analysis,
                "method": "comprehensive_osint",
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            logger.error(f"❌ OSINT gathering error: {e}")
            return {
                "success": False,
                "target": clean_target,
                "error": f"OSINT gathering failed: {str(e)}",
                "timestamp": self._get_timestamp()
            }
    
    async def _discover_emails(self, target: str) -> Dict[str, Any]:
        """Discover email addresses related to the target"""
        try:
            import aiohttp
            
            emails = []
            
            # Method 1: Google search simulation (basic patterns)
            email_patterns = [
                rf'\b[A-Za-z0-9._%+-]+@{re.escape(target)}\b',
                rf'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*{re.escape(target.split(".")[0])}[A-Za-z0-9.-]*\b'
            ]
            
            # Method 2: Common email formats
            common_prefixes = ["info", "admin", "support", "contact", "sales", "marketing", 
                             "hr", "careers", "office", "hello", "mail", "noreply"]
            
            for prefix in common_prefixes:
                emails.append(f"{prefix}@{target}")
            
            # Method 3: Try to get emails from domain's main page
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"https://{target}", timeout=10) as response:
                        if response.status == 200:
                            content = await response.text()
                            for pattern in email_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                emails.extend(matches)
            except:
                pass
            
            return {"emails": list(set(emails))}
            
        except Exception as e:
            logger.debug(f"Email discovery failed: {e}")
            return {"emails": []}
    
    async def _discover_subdomains(self, target: str) -> Dict[str, Any]:
        """Basic subdomain discovery using DNS techniques"""
        try:
            import dns.resolver
            
            subdomains = []
            
            # Common subdomain prefixes
            common_subs = [
                "www", "mail", "email", "webmail", "smtp", "pop", "imap", "ftp", "sftp",
                "admin", "administrator", "api", "app", "blog", "cdn", "dev", "development",
                "stage", "staging", "test", "testing", "demo", "portal", "shop", "store",
                "forum", "forums", "support", "help", "docs", "wiki", "m", "mobile",
                "secure", "ssl", "vpn", "remote", "server", "mail1", "mail2", "ns1", "ns2"
            ]
            
            # Test common subdomains
            for sub in common_subs:
                full_domain = f"{sub}.{target}"
                try:
                    result = dns.resolver.resolve(full_domain, 'A')
                    if result:
                        subdomains.append(full_domain)
                except:
                    continue
            
            return {"subdomains": subdomains}
            
        except Exception as e:
            logger.debug(f"Subdomain discovery failed: {e}")
            return {"subdomains": []}
    
    async def _gather_dns_info(self, target: str) -> Dict[str, Any]:
        """Gather comprehensive DNS information"""
        try:
            import dns.resolver
            
            dns_info = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(target, record_type)
                    dns_info[record_type] = [str(rdata) for rdata in answers]
                except:
                    dns_info[record_type] = []
            
            return {"dns_records": dns_info}
            
        except Exception as e:
            logger.debug(f"DNS gathering failed: {e}")
            return {"dns_records": {}}
    
    async def _gather_whois_info(self, target: str) -> Dict[str, Any]:
        """Basic WHOIS information gathering"""
        try:
            # Use whois command if available
            process = await asyncio.create_subprocess_exec(
                'whois', target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                whois_text = stdout.decode()
                
                # Extract key information using regex
                whois_info = {}
                patterns = {
                    'registrar': r'Registrar:\s*(.+)',
                    'creation_date': r'Creation Date:\s*(.+)',
                    'expiry_date': r'Registry Expiry Date:\s*(.+)',
                    'name_servers': r'Name Server:\s*(.+)'
                }
                
                for key, pattern in patterns.items():
                    matches = re.findall(pattern, whois_text, re.IGNORECASE | re.MULTILINE)
                    whois_info[key] = matches
                
                return {"whois_info": whois_info}
            
            return {"whois_info": {}}
            
        except Exception as e:
            logger.debug(f"WHOIS gathering failed: {e}")
            return {"whois_info": {}}
    
    async def _discover_social_media(self, target: str) -> Dict[str, Any]:
        """Discover social media presence"""
        try:
            import aiohttp
            
            social_media = {}
            
            # Extract company/brand name from domain
            brand_name = target.split('.')[0]
            
            # Common social media platforms
            platforms = {
                "twitter": f"https://twitter.com/{brand_name}",
                "facebook": f"https://facebook.com/{brand_name}",
                "linkedin": f"https://linkedin.com/company/{brand_name}",
                "instagram": f"https://instagram.com/{brand_name}",
                "youtube": f"https://youtube.com/c/{brand_name}",
                "github": f"https://github.com/{brand_name}"
            }
            
            # Check if social media profiles exist (basic check)
            async with aiohttp.ClientSession() as session:
                for platform, url in platforms.items():
                    try:
                        async with session.head(url, timeout=5) as response:
                            if response.status == 200:
                                social_media[platform] = url
                    except:
                        continue
            
            return {"social_media": social_media}
            
        except Exception as e:
            logger.debug(f"Social media discovery failed: {e}")
            return {"social_media": {}}
    
    async def _analyze_certificates(self, target: str) -> Dict[str, Any]:
        """Analyze SSL/TLS certificates"""
        try:
            import ssl
            import socket
            
            certificates = []
            
            # Get certificate information
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.create_connection((target, 443), timeout=10)
            ssock = context.wrap_socket(sock, server_hostname=target)
            cert = ssock.getpeercert()
            ssock.close()
            
            if cert:
                cert_info = {
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "version": cert.get('version'),
                    "serial_number": cert.get('serialNumber'),
                    "not_before": cert.get('notBefore'),
                    "not_after": cert.get('notAfter'),
                    "subject_alt_names": [name[1] for name in cert.get('subjectAltName', [])]
                }
                certificates.append(cert_info)
            
            return {"certificates": certificates}
            
        except Exception as e:
            logger.debug(f"Certificate analysis failed: {e}")
            return {"certificates": []}
    
    async def _detect_technologies(self, target: str) -> Dict[str, Any]:
        """Basic technology detection"""
        try:
            import aiohttp
            
            technologies = []
            
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{target}", timeout=10) as response:
                    if response.status == 200:
                        headers = dict(response.headers)
                        content = await response.text()
                        
                        # Detect technologies from headers
                        tech_headers = {
                            "server": headers.get("server", ""),
                            "x-powered-by": headers.get("x-powered-by", ""),
                            "x-generator": headers.get("x-generator", ""),
                            "x-drupal-cache": "Drupal" if "x-drupal-cache" in headers else "",
                            "x-content-type-options": headers.get("x-content-type-options", "")
                        }
                        
                        for header, value in tech_headers.items():
                            if value:
                                technologies.append(f"{header}: {value}")
                        
                        # Detect technologies from content
                        content_lower = content.lower()
                        tech_patterns = {
                            "WordPress": ["wp-content", "wp-includes", "/wp-"],
                            "Drupal": ["drupal", "sites/all/modules"],
                            "Joomla": ["joomla", "option=com_"],
                            "React": ["react", "_reactinternalinstance"],
                            "Angular": ["ng-", "angular"],
                            "Vue.js": ["vue", "v-if", "v-for"],
                            "jQuery": ["jquery", "$("],
                            "Bootstrap": ["bootstrap", "btn-"],
                            "Cloudflare": ["__cf_bm", "cloudflare"]
                        }
                        
                        for tech, patterns in tech_patterns.items():
                            if any(pattern in content_lower for pattern in patterns):
                                technologies.append(tech)
            
            return {"technologies": technologies}
            
        except Exception as e:
            logger.debug(f"Technology detection failed: {e}")
            return {"technologies": []}
    
    def _analyze_osint_results(self, results: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Analyze OSINT results for security insights"""
        analysis = {
            "summary": {
                "total_emails": len(results["emails"]),
                "total_subdomains": len(results["subdomains"]),
                "total_ips": len(results["ips"]),
                "social_media_presence": len(results["social_media"]),
                "technologies_detected": len(results["technologies"]),
                "certificates_found": len(results["certificates"])
            },
            "security_insights": {
                "email_exposure": [],
                "subdomain_exposure": [],
                "technology_risks": [],
                "certificate_issues": [],
                "information_leakage": []
            },
            "recommendations": []
        }
        
        # Analyze emails for security insights
        for email in results["emails"]:
            if any(term in email.lower() for term in ["admin", "root", "test", "dev"]):
                analysis["security_insights"]["email_exposure"].append(f"Potentially sensitive email: {email}")
        
        # Analyze subdomains for security insights  
        for subdomain in results["subdomains"]:
            if any(term in subdomain.lower() for term in ["admin", "test", "dev", "staging", "internal"]):
                analysis["security_insights"]["subdomain_exposure"].append(f"Potentially sensitive subdomain: {subdomain}")
        
        # Analyze technologies for known vulnerabilities
        for tech in results["technologies"]:
            if "server:" in tech.lower():
                analysis["security_insights"]["technology_risks"].append(f"Server information disclosed: {tech}")
        
        # Generate recommendations
        if analysis["summary"]["total_emails"] > 10:
            analysis["recommendations"].append("Consider email address enumeration protection")
        
        if analysis["summary"]["total_subdomains"] > 20:
            analysis["recommendations"].append("Review subdomain exposure and implement subdomain takeover protection")
        
        if len(analysis["security_insights"]["technology_risks"]) > 0:
            analysis["recommendations"].append("Consider hiding server and technology information")
        
        return analysis
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        return await self.comprehensive_osint(target, config)
    
    def get_scan_info(self) -> Dict[str, Any]:
        """Get information about this scanning agent"""
        return {
            "name": "OSINT Information Gathering Agent",
            "description": "Professional OSINT collection from multiple public sources",
            "capabilities": [
                "Email Address Discovery",
                "Subdomain Enumeration",
                "DNS Record Analysis", 
                "WHOIS Information Gathering",
                "Social Media Discovery",
                "SSL Certificate Analysis",
                "Technology Detection",
                "Security Risk Assessment"
            ],
            "supported_sources": ["dns", "whois", "certificates", "web_content", "social_media"],
            "output_formats": ["structured", "security_focused"],
            "tool_version": "custom_osint",
            "agent_version": "1.0.0"
        }


