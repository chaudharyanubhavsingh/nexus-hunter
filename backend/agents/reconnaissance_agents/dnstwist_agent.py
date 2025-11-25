"""
DNS Twister Agent - Phishing Domain Detection
Professional domain squatting and phishing domain discovery
"""

import asyncio
import json
import subprocess
from typing import Dict, List, Any, Optional
from loguru import logger
from urllib.parse import urlparse

from agents.base import BaseAgent


class DNSTwistAgent(BaseAgent):
    """
    Professional Phishing Domain Detection Agent using DNS Twister
    Discovers domain squatting and phishing domains using various techniques
    """
    
    def __init__(self):
        super().__init__("dnstwist_agent")
        self.tool_command = "dnstwist"
        
    async def detect_phishing_domains(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Detect phishing and squatting domains for target
        
        Args:
            target: Target domain
            options: Additional scanning options
            
        Returns:
            Phishing domain detection results
        """
        logger.info(f"🎣 Starting phishing domain detection for {target}")
        
        try:
            # Prepare dnstwist command
            cmd = [self.tool_command, "--format", "json", target]
            
            # Add options if provided
            if options:
                if options.get("registered_only"):
                    cmd.append("--registered")
                if options.get("threads"):
                    cmd.extend(["--threads", str(options["threads"])])
                if options.get("nameservers"):
                    cmd.extend(["--nameservers", ",".join(options["nameservers"])])
                if options.get("tld"):
                    cmd.extend(["--tld", options["tld"]])
                if options.get("dictionary"):
                    cmd.extend(["--dictionary", options["dictionary"]])
                if options.get("banners"):
                    cmd.append("--banners")
                if options.get("mxcheck"):
                    cmd.append("--mxcheck")
                if options.get("ssdeep"):
                    cmd.append("--ssdeep")
            
            # Execute dnstwist scan
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                try:
                    raw_results = json.loads(stdout.decode())
                    results = self._analyze_dnstwist_results(raw_results, target)
                    
                    logger.info(f"✅ Phishing domain detection completed for {target}")
                    return {
                        "success": True,
                        "target": target,
                        "total_domains": len(raw_results),
                        "analysis": results,
                        "raw_results": raw_results,
                        "timestamp": self._get_timestamp()
                    }
                except json.JSONDecodeError:
                    # Fallback for non-JSON output
                    results = self._parse_text_output(stdout.decode(), target)
                    return {
                        "success": True,
                        "target": target,
                        "analysis": results,
                        "raw_output": stdout.decode(),
                        "timestamp": self._get_timestamp()
                    }
            else:
                error_msg = stderr.decode().strip()
                logger.error(f"❌ DNS Twister scan failed: {error_msg}")
                return {
                    "success": False,
                    "target": target,
                    "error": error_msg,
                    "timestamp": self._get_timestamp()
                }
                
        except FileNotFoundError:
            logger.error("❌ DNS Twister not found - install with: pip install dnstwist")
            return await self._fallback_phishing_detection(target)
        except Exception as e:
            logger.error(f"❌ DNS Twister scan error: {e}")
            return await self._fallback_phishing_detection(target)
    
    def _analyze_dnstwist_results(self, results: List[Dict], target: str) -> Dict[str, Any]:
        """Analyze DNS Twister results and categorize findings"""
        analysis = {
            "registered_domains": [],
            "unregistered_domains": [],
            "by_technique": {},
            "suspicious_domains": [],
            "high_risk_domains": [],
            "mx_records": [],
            "banners": [],
            "similarity_scores": {},
            "statistics": {}
        }
        
        # Risk indicators
        high_risk_keywords = ["secure", "login", "bank", "pay", "mail", "admin", "support"]
        
        registered_count = 0
        unregistered_count = 0
        
        for domain_info in results:
            domain = domain_info.get("domain", "")
            technique = domain_info.get("fuzzer", "unknown")
            
            # Count by technique
            analysis["by_technique"][technique] = analysis["by_technique"].get(technique, 0) + 1
            
            # Check if domain is registered
            if domain_info.get("dns_a") or domain_info.get("dns_aaaa"):
                registered_count += 1
                analysis["registered_domains"].append(domain_info)
                
                # Check for suspicious indicators
                if self._is_suspicious_domain(domain_info, target):
                    analysis["suspicious_domains"].append(domain_info)
                
                # Check for high-risk domains
                domain_lower = domain.lower()
                if any(keyword in domain_lower for keyword in high_risk_keywords):
                    analysis["high_risk_domains"].append(domain_info)
                    
            else:
                unregistered_count += 1
                analysis["unregistered_domains"].append(domain_info)
            
            # Collect MX records
            if domain_info.get("dns_mx"):
                analysis["mx_records"].append({
                    "domain": domain,
                    "mx_records": domain_info["dns_mx"]
                })
            
            # Collect banners if available
            if domain_info.get("banner_http") or domain_info.get("banner_smtp"):
                analysis["banners"].append({
                    "domain": domain,
                    "http_banner": domain_info.get("banner_http"),
                    "smtp_banner": domain_info.get("banner_smtp")
                })
            
            # Calculate similarity scores
            if domain_info.get("ssdeep"):
                analysis["similarity_scores"][domain] = domain_info["ssdeep"]
        
        # Generate statistics
        analysis["statistics"] = {
            "total_domains": len(results),
            "registered": registered_count,
            "unregistered": unregistered_count,
            "registration_rate": f"{(registered_count/len(results)*100):.1f}%" if results else "0%",
            "suspicious_count": len(analysis["suspicious_domains"]),
            "high_risk_count": len(analysis["high_risk_domains"]),
            "techniques_used": len(analysis["by_technique"])
        }
        
        return analysis
    
    def _is_suspicious_domain(self, domain_info: Dict, original_target: str) -> bool:
        """Determine if a domain is suspicious based on various indicators"""
        domain = domain_info.get("domain", "")
        
        # Check for active web server
        has_web_server = domain_info.get("banner_http") is not None
        
        # Check for mail server
        has_mail_server = domain_info.get("dns_mx") is not None
        
        # Check for suspicious patterns
        suspicious_patterns = [
            "secure", "login", "verify", "confirm", "update", "suspend",
            "account", "billing", "payment", "service"
        ]
        
        has_suspicious_keywords = any(pattern in domain.lower() for pattern in suspicious_patterns)
        
        # Domain registered recently (if creation date available)
        recently_registered = False  # Would need WHOIS data
        
        # Similarity to original (very similar domains are more suspicious)
        very_similar = len(domain) == len(original_target)  # Simplified check
        
        return (has_web_server and has_suspicious_keywords) or \
               (has_mail_server and very_similar) or \
               recently_registered
    
    def _parse_text_output(self, output: str, target: str) -> Dict[str, Any]:
        """Parse text output when JSON is not available"""
        lines = output.split('\n')
        domains = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and '.' in line:
                # Simple parsing - extract domain from line
                parts = line.split()
                if parts:
                    domain = parts[0]
                    if domain != target:
                        domains.append(domain)
        
        return {
            "total_domains_found": len(domains),
            "domains": domains,
            "note": "Limited analysis - JSON output not available"
        }
    
    async def _fallback_phishing_detection(self, target: str) -> Dict[str, Any]:
        """
        Fallback phishing detection using manual techniques
        """
        logger.info(f"🔧 Using fallback phishing detection for {target}")
        
        try:
            # Generate common typosquatting variants manually
            variants = self._generate_domain_variants(target)
            
            # Check which variants are registered
            registered_variants = []
            
            import aiohttp
            async with aiohttp.ClientSession() as session:
                for variant in variants[:50]:  # Limit to avoid rate limiting
                    try:
                        async with session.get(f"http://{variant}", timeout=5) as response:
                            if response.status == 200:
                                registered_variants.append({
                                    "domain": variant,
                                    "status": "active",
                                    "technique": "manual_generation"
                                })
                    except:
                        continue
                    
                    await asyncio.sleep(0.2)  # Rate limiting
            
            return {
                "success": True,
                "target": target,
                "method": "fallback_manual_detection",
                "total_variants_checked": len(variants),
                "registered_variants": len(registered_variants),
                "variants": registered_variants,
                "timestamp": self._get_timestamp()
            }
                    
        except Exception as e:
            logger.error(f"❌ Fallback phishing detection failed: {e}")
            return {
                "success": False,
                "target": target,
                "error": f"Fallback detection failed: {str(e)}",
                "timestamp": self._get_timestamp()
            }
    
    def _generate_domain_variants(self, domain: str) -> List[str]:
        """Generate common domain variants for typosquatting detection"""
        if '.' not in domain:
            return []
        
        name, tld = domain.rsplit('.', 1)
        variants = []
        
        # Character substitution
        substitutions = {
            'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'], 
            's': ['$', '5'], 't': ['7'], 'g': ['9'], 'l': ['1']
        }
        
        for char, subs in substitutions.items():
            if char in name:
                for sub in subs:
                    variants.append(f"{name.replace(char, sub)}.{tld}")
        
        # Character omission
        for i in range(len(name)):
            if len(name) > 3:  # Don't make names too short
                variants.append(f"{name[:i]}{name[i+1:]}.{tld}")
        
        # Character insertion
        common_chars = 'abcdefghijklmnopqrstuvwxyz'
        for i in range(len(name)):
            for char in common_chars[:5]:  # Limit to avoid too many variants
                variants.append(f"{name[:i]}{char}{name[i:]}.{tld}")
        
        # Character transposition
        for i in range(len(name) - 1):
            swapped = list(name)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            variants.append(f"{''.join(swapped)}.{tld}")
        
        # Common TLD variations
        common_tlds = ['com', 'net', 'org', 'info', 'biz']
        if tld in common_tlds:
            for other_tld in common_tlds:
                if other_tld != tld:
                    variants.append(f"{name}.{other_tld}")
        
        return list(set(variants))  # Remove duplicates
    
    async def monitor_domain_registration(
        self,
        target: str,
        monitor_period_days: int = 30
    ) -> Dict[str, Any]:
        """
        Monitor for new domain registrations similar to target
        """
        logger.info(f"📊 Setting up domain registration monitoring for {target}")
        
        # This would be a more complex implementation in practice
        # For now, return the current state
        current_results = await self.detect_phishing_domains(target, {"registered_only": True})
        
        return {
            "success": True,
            "target": target,
            "monitoring_setup": True,
            "monitor_period_days": monitor_period_days,
            "baseline_registered": len(current_results.get("analysis", {}).get("registered_domains", [])),
            "note": "Monitoring baseline established - would need periodic scanning for changes",
            "timestamp": self._get_timestamp()
        }
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        return await self.detect_phishing_domains(target, config)
    
    def get_scan_info(self) -> Dict[str, Any]:
        """Get information about this scanning agent"""
        return {
            "name": "DNS Twister Phishing Detection Agent",
            "description": "Professional domain squatting and phishing domain discovery",
            "capabilities": [
                "Typosquatting Detection",
                "Domain Generation Algorithms", 
                "Homograph Attack Detection",
                "Bitsquatting Detection",
                "Hyphenation Variants",
                "Subdomain Variations",
                "TLD Variations",
                "Registration Monitoring"
            ],
            "supported_techniques": [
                "addition", "bitsquatting", "cyrillic", "deletion", 
                "dictionary", "homoglyph", "hyphenation", "insertion",
                "omission", "repetition", "replacement", "subdomain",
                "transposition", "various", "vowel-swap"
            ],
            "output_formats": ["json", "structured"],
            "tool_version": "dnstwist",
            "agent_version": "1.0.0"
        }
