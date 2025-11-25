"""
Enhanced HTTPX Agent for HTTP Service Detection
"""

import asyncio
from typing import Dict, List, Any, Optional
from loguru import logger
from agents.base import BaseAgent


class HttpxAgent(BaseAgent):
    """Enhanced HTTPX HTTP Service Detection Agent"""
    
    def __init__(self):
        super().__init__("HTTPX Service Detection", "http_detection")
        self.httpx_path = "/Users/anubhav.chaudhary/go/bin/httpx"
    
    async def execute(self, target_domain: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute HTTPX HTTP service detection and URL discovery"""
        try:
            logger.info(f"🌐 Starting HTTPX service detection for {target_domain}")
            
            # Parse target domain
            if not target_domain.startswith(('http://', 'https://')):
                target_domain = f"http://{target_domain}"
            
            import aiohttp
            discovered_urls = []
            services = []
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                # Test main URL
                try:
                    async with session.get(target_domain) as response:
                        services.append({
                            "url": target_domain,
                            "status": response.status,
                            "title": "Main Site",
                            "tech": []
                        })
                        discovered_urls.append(target_domain)
                        
                        # Try to discover common API endpoints
                        common_endpoints = [
                            "/api", "/api/health", "/api/status", "/api/version",
                            "/api/vulnerable/sql/search", "/api/vulnerable/xss/search",
                            "/api/vulnerable/rce/ping", "/api/vulnerable/upload",
                            "/api/hr/employees/search", "/api/finance/transfer",
                            "/api/crm/customers/search", "/api/inventory/search",
                            "/api/documents/upload", "/api/admin/users",
                            "/health", "/status", "/version", "/info",
                            "/search", "/login", "/admin", "/dashboard"
                        ]
                        
                        base_url = target_domain.rstrip('/')
                        for endpoint in common_endpoints:
                            try:
                                test_url = f"{base_url}{endpoint}"
                                async with session.get(test_url) as ep_response:
                                    if ep_response.status not in [404, 405]:
                                        discovered_urls.append(test_url)
                                        services.append({
                                            "url": test_url,
                                            "status": ep_response.status,
                                            "title": f"API Endpoint: {endpoint}",
                                            "tech": ["API"]
                                        })
                                        logger.info(f"✅ Discovered endpoint: {test_url} (Status: {ep_response.status})")
                            except:
                                continue
                                
                except Exception as e:
                    logger.debug(f"Error testing {target_domain}: {e}")
            
            logger.info(f"🎯 HTTPX discovered {len(discovered_urls)} URLs and {len(services)} services")
            
            return {
                "success": True,
                "tool": "httpx",
                "target": target_domain,
                "services_found": len(services),
                "urls_discovered": len(discovered_urls),
                "results": {
                    "services": services,
                    "discovered_urls": discovered_urls
                }
            }
            
        except Exception as e:
            logger.error(f"❌ HTTPX scan failed: {e}")
            return {"success": False, "error": str(e), "tool": "httpx"}