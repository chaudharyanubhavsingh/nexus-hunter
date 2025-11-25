"""
SSLMate Agent - Certificate Discovery and Analysis
Professional SSL certificate discovery and analysis using SSLMate API and certificate transparency
"""

import asyncio
import json
import aiohttp
from typing import Dict, List, Any, Optional
from loguru import logger
from datetime import datetime, timedelta

from agents.base import BaseAgent


class SSLMateAgent(BaseAgent):
    """
    Professional SSL Certificate Discovery Agent
    Uses SSLMate Certificate Transparency API and other certificate sources
    """
    
    def __init__(self):
        super().__init__("sslmate_agent")
        self.ct_api_base = "https://api.certspotter.com/v1"
        self.crt_sh_api = "https://crt.sh"
        
    async def discover_certificates(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Discover SSL certificates for target domain
        
        Args:
            target: Target domain
            options: Additional options (include_expired, include_subdomains, etc.)
            
        Returns:
            Certificate discovery results
        """
        logger.info(f"🔐 Starting certificate discovery for {target}")
        
        try:
            results = {}
            
            # Try multiple certificate transparency sources
            sources = [
                ("certspotter", self._query_certspotter),
                ("crt_sh", self._query_crt_sh),
                ("fallback", self._fallback_cert_discovery)
            ]
            
            for source_name, source_func in sources:
                try:
                    logger.debug(f"Querying {source_name} for {target}")
                    source_results = await source_func(target, options)
                    results[source_name] = source_results
                    
                    if source_results.get("success"):
                        logger.info(f"✅ {source_name}: Found {len(source_results.get('certificates', []))} certificates")
                    else:
                        logger.warning(f"⚠️ {source_name}: {source_results.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    logger.error(f"❌ {source_name} query failed: {e}")
                    results[source_name] = {"success": False, "error": str(e)}
            
            # Combine and analyze results
            combined_results = self._combine_certificate_results(results, target)
            
            logger.info(f"✅ Certificate discovery completed for {target}")
            return {
                "success": True,
                "target": target,
                "sources_queried": len(sources),
                "total_certificates": len(combined_results.get("certificates", [])),
                "analysis": combined_results,
                "raw_sources": results,
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            logger.error(f"❌ Certificate discovery error: {e}")
            return {
                "success": False,
                "target": target,
                "error": str(e),
                "timestamp": self._get_timestamp()
            }
    
    async def _query_certspotter(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Query CertSpotter API for certificates"""
        try:
            url = f"{self.ct_api_base}/issuances"
            params = {
                "domain": target,
                "include_subdomains": "true" if options and options.get("include_subdomains") else "false",
                "match_wildcards": "true"
            }
            
            if options and options.get("after_date"):
                params["after"] = options["after_date"]
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        certificates = self._parse_certspotter_response(data)
                        
                        return {
                            "success": True,
                            "certificates": certificates,
                            "source": "certspotter"
                        }
                    else:
                        error_text = await response.text()
                        return {
                            "success": False,
                            "error": f"CertSpotter API error: {response.status} - {error_text}"
                        }
                        
        except asyncio.TimeoutError:
            return {"success": False, "error": "CertSpotter API timeout"}
        except Exception as e:
            return {"success": False, "error": f"CertSpotter query error: {str(e)}"}
    
    async def _query_crt_sh(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Query crt.sh for certificates"""
        try:
            url = f"{self.crt_sh_api}/"
            params = {
                "q": f"%.{target}" if options and options.get("include_subdomains") else target,
                "output": "json"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        certificates = self._parse_crt_sh_response(data)
                        
                        return {
                            "success": True,
                            "certificates": certificates,
                            "source": "crt_sh"
                        }
                    else:
                        return {
                            "success": False,
                            "error": f"crt.sh API error: {response.status}"
                        }
                        
        except asyncio.TimeoutError:
            return {"success": False, "error": "crt.sh API timeout"}
        except Exception as e:
            return {"success": False, "error": f"crt.sh query error: {str(e)}"}
    
    async def _fallback_cert_discovery(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Fallback certificate discovery using direct SSL connection"""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.create_connection((target, 443), timeout=10)
            ssock = context.wrap_socket(sock, server_hostname=target)
            
            cert = ssock.getpeercert()
            ssock.close()
            
            if cert:
                parsed_cert = self._parse_ssl_cert(cert, target)
                return {
                    "success": True,
                    "certificates": [parsed_cert],
                    "source": "direct_ssl"
                }
            else:
                return {"success": False, "error": "No certificate found"}
                
        except Exception as e:
            return {"success": False, "error": f"Direct SSL query error: {str(e)}"}
    
    def _parse_certspotter_response(self, data: List[Dict]) -> List[Dict]:
        """Parse CertSpotter API response"""
        certificates = []
        
        for cert_data in data:
            try:
                cert = {
                    "id": cert_data.get("id"),
                    "tbs_sha256": cert_data.get("tbs_sha256"),
                    "dns_names": cert_data.get("dns_names", []),
                    "pubkey_sha256": cert_data.get("pubkey_sha256"),
                    "not_before": cert_data.get("not_before"),
                    "not_after": cert_data.get("not_after"),
                    "issuer": {
                        "name": cert_data.get("issuer", {}).get("name"),
                        "country": cert_data.get("issuer", {}).get("country"),
                        "organization": cert_data.get("issuer", {}).get("organization")
                    },
                    "source": "certspotter"
                }
                certificates.append(cert)
            except Exception as e:
                logger.debug(f"Error parsing certificate: {e}")
                continue
                
        return certificates
    
    def _parse_crt_sh_response(self, data: List[Dict]) -> List[Dict]:
        """Parse crt.sh API response"""
        certificates = []
        seen_fingerprints = set()
        
        for cert_data in data:
            try:
                # Avoid duplicates
                fingerprint = cert_data.get("sha256", "")
                if fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(fingerprint)
                
                cert = {
                    "id": cert_data.get("id"),
                    "sha256": fingerprint,
                    "common_name": cert_data.get("common_name"),
                    "name_value": cert_data.get("name_value"),
                    "issuer_ca_id": cert_data.get("issuer_ca_id"),
                    "issuer_name": cert_data.get("issuer_name"),
                    "not_before": cert_data.get("not_before"),
                    "not_after": cert_data.get("not_after"),
                    "serial_number": cert_data.get("serial_number"),
                    "source": "crt_sh"
                }
                certificates.append(cert)
            except Exception as e:
                logger.debug(f"Error parsing certificate: {e}")
                continue
                
        return certificates
    
    def _parse_ssl_cert(self, cert: Dict, target: str) -> Dict[str, Any]:
        """Parse SSL certificate from direct connection"""
        return {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "version": cert.get("version"),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "subject_alt_names": [name[1] for name in cert.get("subjectAltName", [])],
            "target": target,
            "source": "direct_ssl"
        }
    
    def _combine_certificate_results(self, results: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Combine and analyze certificate results from multiple sources"""
        all_certificates = []
        subdomains = set()
        issuers = set()
        
        # Collect certificates from all successful sources
        for source_name, source_result in results.items():
            if source_result.get("success"):
                certs = source_result.get("certificates", [])
                all_certificates.extend(certs)
        
        # Analyze certificates
        active_certificates = []
        expired_certificates = []
        soon_expiring = []
        
        now = datetime.now()
        warning_period = now + timedelta(days=30)  # 30 days warning
        
        for cert in all_certificates:
            # Extract subdomains
            dns_names = cert.get("dns_names", []) or cert.get("subject_alt_names", [])
            if cert.get("name_value"):
                dns_names.extend(cert["name_value"].split("\n"))
            if cert.get("common_name"):
                dns_names.append(cert["common_name"])
                
            for name in dns_names:
                if name and "." in name:
                    subdomains.add(name.strip())
            
            # Extract issuers
            issuer = cert.get("issuer", {})
            if isinstance(issuer, dict):
                issuer_name = issuer.get("name") or issuer.get("organization") or issuer.get("organizationName")
            else:
                issuer_name = cert.get("issuer_name")
                
            if issuer_name:
                issuers.add(issuer_name)
            
            # Check expiration status
            not_after = cert.get("not_after")
            if not_after:
                try:
                    # Handle different date formats
                    if isinstance(not_after, str):
                        # Try parsing different formats
                        for fmt in ["%Y-%m-%dT%H:%M:%S", "%b %d %H:%M:%S %Y %Z", "%Y-%m-%d %H:%M:%S"]:
                            try:
                                expiry_date = datetime.strptime(not_after.replace("GMT", "").strip(), fmt)
                                break
                            except ValueError:
                                continue
                        else:
                            # If no format worked, skip expiration analysis
                            active_certificates.append(cert)
                            continue
                    else:
                        expiry_date = not_after
                    
                    if expiry_date < now:
                        expired_certificates.append(cert)
                    elif expiry_date < warning_period:
                        soon_expiring.append(cert)
                        active_certificates.append(cert)
                    else:
                        active_certificates.append(cert)
                        
                except Exception as e:
                    logger.debug(f"Error parsing expiry date: {e}")
                    active_certificates.append(cert)
            else:
                active_certificates.append(cert)
        
        # Generate analysis
        analysis = {
            "certificates": all_certificates,
            "subdomains_discovered": list(subdomains),
            "certificate_authorities": list(issuers),
            "certificate_status": {
                "total": len(all_certificates),
                "active": len(active_certificates),
                "expired": len(expired_certificates),
                "expiring_soon": len(soon_expiring)
            },
            "subdomain_analysis": {
                "total_subdomains": len(subdomains),
                "unique_subdomains": len([s for s in subdomains if target in s]),
                "third_party_subdomains": len([s for s in subdomains if target not in s])
            },
            "security_insights": self._generate_security_insights(all_certificates, target)
        }
        
        return analysis
    
    def _generate_security_insights(self, certificates: List[Dict], target: str) -> Dict[str, Any]:
        """Generate security insights from certificate analysis"""
        insights = {
            "wildcard_certificates": [],
            "weak_key_sizes": [],
            "suspicious_issuers": [],
            "certificate_transparency": True,  # Found in CT logs
            "recommendations": []
        }
        
        for cert in certificates:
            # Check for wildcard certificates
            dns_names = cert.get("dns_names", []) or cert.get("subject_alt_names", [])
            if cert.get("name_value"):
                dns_names.extend(cert["name_value"].split("\n"))
                
            for name in dns_names:
                if name and name.startswith("*."):
                    insights["wildcard_certificates"].append({
                        "certificate": cert.get("id") or cert.get("sha256", "unknown"),
                        "wildcard_domain": name
                    })
        
        # Generate recommendations
        if len(insights["wildcard_certificates"]) > 0:
            insights["recommendations"].append("Monitor wildcard certificate usage for security")
        
        if len([c for c in certificates if c.get("source") == "direct_ssl"]) > 0:
            insights["recommendations"].append("Certificates found via direct connection - verify CT logging")
        
        return insights
    
    async def analyze_certificate_security(
        self,
        target: str,
        certificate_id: str = None
    ) -> Dict[str, Any]:
        """
        Perform detailed security analysis of certificates
        """
        logger.info(f"🔐 Analyzing certificate security for {target}")
        
        # Get certificates first
        cert_results = await self.discover_certificates(target)
        
        if not cert_results.get("success"):
            return cert_results
        
        certificates = cert_results.get("analysis", {}).get("certificates", [])
        
        security_analysis = {
            "total_certificates": len(certificates),
            "security_issues": [],
            "compliance_status": {},
            "recommendations": []
        }
        
        # Analyze each certificate for security issues
        for cert in certificates:
            cert_analysis = self._analyze_single_certificate_security(cert)
            security_analysis["security_issues"].extend(cert_analysis.get("issues", []))
        
        return {
            "success": True,
            "target": target,
            "security_analysis": security_analysis,
            "timestamp": self._get_timestamp()
        }
    
    def _analyze_single_certificate_security(self, cert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security aspects of a single certificate"""
        issues = []
        
        # Check for weak algorithms (simplified)
        if "md5" in str(cert).lower() or "sha1" in str(cert).lower():
            issues.append({
                "severity": "high",
                "issue": "Weak signature algorithm detected",
                "certificate": cert.get("id") or cert.get("sha256", "unknown")
            })
        
        # Check expiration
        not_after = cert.get("not_after")
        if not_after:
            # Simplified expiration check
            if "2024" in str(not_after) or "2023" in str(not_after):
                issues.append({
                    "severity": "medium",
                    "issue": "Certificate may be expired or expiring soon",
                    "certificate": cert.get("id") or cert.get("sha256", "unknown")
                })
        
        return {"issues": issues}
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        return await self.discover_certificates(target, config)
    
    def get_scan_info(self) -> Dict[str, Any]:
        """Get information about this scanning agent"""
        return {
            "name": "SSLMate Certificate Discovery Agent",
            "description": "Professional SSL certificate discovery and analysis using Certificate Transparency",
            "capabilities": [
                "Certificate Transparency Log Queries",
                "Multi-source Certificate Discovery",
                "Subdomain Discovery via Certificates",
                "Certificate Expiration Analysis",
                "Security Assessment",
                "Certificate Authority Analysis",
                "Wildcard Certificate Detection"
            ],
            "supported_sources": ["certspotter", "crt.sh", "direct_ssl"],
            "output_formats": ["structured", "json"],
            "api_dependencies": ["certspotter", "crt.sh"],
            "agent_version": "1.0.0"
        }
