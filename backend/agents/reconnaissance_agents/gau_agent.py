"""
GAU Agent - Get All URLs (Wayback Machine & More)
Professional URL discovery from multiple sources including Wayback Machine
"""

import asyncio
import json
import subprocess
from typing import Dict, List, Any, Optional
from loguru import logger
from urllib.parse import urlparse

from agents.base import BaseAgent


class GAUAgent(BaseAgent):
    """
    Professional URL Discovery Agent using GAU
    Fetches URLs from Wayback Machine, Common Crawl, AlienVault OTX, and URLScan
    """
    
    def __init__(self):
        super().__init__("gau_agent")
        self.tool_command = "gau"
        self.tool_path = "/Users/anubhav.chaudhary/go/bin/gau"
        
    async def discover_urls(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Discover URLs for target from multiple sources
        
        Args:
            target: Target domain
            options: Additional scanning options
            
        Returns:
            URL discovery results with categorized URLs
        """
        logger.info(f"🔍 Starting URL discovery for {target}")
        
        try:
            # Prepare GAU command
            cmd = [self.tool_path, target]
            
            # Add options if provided
            if options:
                if options.get("providers"):
                    cmd.extend(["--providers", ",".join(options["providers"])])
                if options.get("threads"):
                    cmd.extend(["--threads", str(options["threads"])])
                if options.get("timeout"):
                    cmd.extend(["--timeout", str(options["timeout"])])
                if options.get("verbose"):
                    cmd.append("--verbose")
                if options.get("include_subs"):
                    cmd.append("--subs")
                if options.get("blacklist"):
                    cmd.extend(["--blacklist", ",".join(options["blacklist"])])
                if options.get("from_date"):
                    cmd.extend(["--from", options["from_date"]])
                if options.get("to_date"):
                    cmd.extend(["--to", options["to_date"]])
            
            # Execute GAU scan
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                urls = stdout.decode().strip().split('\n')
                urls = [url.strip() for url in urls if url.strip()]
                
                results = self._analyze_discovered_urls(urls, target)
                logger.info(f"✅ URL discovery completed for {target} - Found {len(urls)} URLs")
                
                return {
                    "success": True,
                    "target": target,
                    "total_urls": len(urls),
                    "urls": urls,
                    "analysis": results,
                    "timestamp": self._get_timestamp()
                }
            else:
                error_msg = stderr.decode().strip()
                logger.error(f"❌ GAU scan failed: {error_msg}")
                return {
                    "success": False,
                    "target": target,
                    "error": error_msg,
                    "timestamp": self._get_timestamp()
                }
                
        except FileNotFoundError:
            logger.error("❌ GAU not found - install with: go install github.com/lc/gau/v2/cmd/gau@latest")
            return await self._fallback_url_discovery(target)
        except Exception as e:
            logger.error(f"❌ GAU scan error: {e}")
            return await self._fallback_url_discovery(target)
    
    def _analyze_discovered_urls(self, urls: List[str], target: str) -> Dict[str, Any]:
        """Analyze and categorize discovered URLs"""
        analysis = {
            "by_extension": {},
            "by_status_code": {},
            "by_path_depth": {},
            "potential_secrets": [],
            "api_endpoints": [],
            "admin_panels": [],
            "interesting_files": [],
            "subdomains": set(),
            "parameters": set()
        }
        
        # File extensions of interest
        interesting_extensions = {
            "config": [".env", ".config", ".ini", ".conf", ".xml", ".yml", ".yaml"],
            "backup": [".bak", ".backup", ".old", ".orig", ".tmp"],
            "source": [".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".go"],
            "data": [".sql", ".db", ".sqlite", ".json", ".csv", ".xlsx"],
            "logs": [".log", ".txt"]
        }
        
        # Keywords indicating potential secrets
        secret_keywords = [
            "api", "key", "token", "secret", "password", "pass", "pwd",
            "auth", "login", "credential", "config", "env", "admin"
        ]
        
        # Admin panel indicators
        admin_indicators = [
            "admin", "administrator", "panel", "dashboard", "control",
            "manage", "login", "auth", "wp-admin", "phpmyadmin"
        ]
        
        for url in urls:
            try:
                parsed = urlparse(url)
                
                # Track subdomains
                if parsed.hostname and target in parsed.hostname:
                    analysis["subdomains"].add(parsed.hostname)
                
                # Extract file extension
                path = parsed.path.lower()
                if '.' in path:
                    ext = '.' + path.split('.')[-1]
                    analysis["by_extension"][ext] = analysis["by_extension"].get(ext, 0) + 1
                    
                    # Check for interesting files
                    for category, extensions in interesting_extensions.items():
                        if ext in extensions:
                            analysis["interesting_files"].append({
                                "url": url,
                                "category": category,
                                "extension": ext
                            })
                
                # Path depth analysis
                depth = len([p for p in parsed.path.split('/') if p])
                analysis["by_path_depth"][depth] = analysis["by_path_depth"].get(depth, 0) + 1
                
                # Check for potential secrets
                url_lower = url.lower()
                for keyword in secret_keywords:
                    if keyword in url_lower:
                        analysis["potential_secrets"].append(url)
                        break
                
                # Check for API endpoints
                if any(indicator in path for indicator in ["/api/", "/v1/", "/v2/", "/rest/", "/graphql"]):
                    analysis["api_endpoints"].append(url)
                
                # Check for admin panels
                if any(indicator in path for indicator in admin_indicators):
                    analysis["admin_panels"].append(url)
                
                # Extract parameters
                if parsed.query:
                    params = parsed.query.split('&')
                    for param in params:
                        if '=' in param:
                            param_name = param.split('=')[0]
                            analysis["parameters"].add(param_name)
                            
            except Exception as e:
                logger.debug(f"Error analyzing URL {url}: {e}")
                continue
        
        # Convert sets to lists for JSON serialization
        analysis["subdomains"] = list(analysis["subdomains"])
        analysis["parameters"] = list(analysis["parameters"])
        
        # Generate summary statistics
        analysis["summary"] = {
            "unique_subdomains": len(analysis["subdomains"]),
            "unique_extensions": len(analysis["by_extension"]),
            "potential_secrets": len(analysis["potential_secrets"]),
            "api_endpoints": len(analysis["api_endpoints"]),
            "admin_panels": len(analysis["admin_panels"]),
            "interesting_files": len(analysis["interesting_files"]),
            "unique_parameters": len(analysis["parameters"])
        }
        
        return analysis
    
    async def _fallback_url_discovery(self, target: str) -> Dict[str, Any]:
        """
        Fallback URL discovery using web scraping and common paths
        """
        logger.info(f"🔧 Using fallback URL discovery for {target}")
        
        try:
            import aiohttp
            
            # Common paths to check
            common_paths = [
                "/", "/index.html", "/robots.txt", "/sitemap.xml",
                "/admin", "/login", "/api", "/swagger", "/docs",
                "/.env", "/config", "/backup", "/old", "/test"
            ]
            
            discovered_urls = []
            
            async with aiohttp.ClientSession() as session:
                for path in common_paths:
                    try:
                        url = f"http://{target}{path}"
                        async with session.get(url, timeout=5) as response:
                            if response.status == 200:
                                discovered_urls.append(url)
                    except:
                        continue
                    
                    await asyncio.sleep(0.1)  # Rate limiting
            
            return {
                "success": True,
                "target": target,
                "total_urls": len(discovered_urls),
                "urls": discovered_urls,
                "method": "fallback_path_enumeration",
                "analysis": self._analyze_discovered_urls(discovered_urls, target),
                "timestamp": self._get_timestamp()
            }
                    
        except Exception as e:
            logger.error(f"❌ Fallback URL discovery failed: {e}")
            return {
                "success": False,
                "target": target,
                "error": f"Fallback discovery failed: {str(e)}",
                "timestamp": self._get_timestamp()
            }
    
    async def search_sensitive_urls(
        self,
        target: str,
        keywords: List[str] = None
    ) -> Dict[str, Any]:
        """
        Search for URLs containing sensitive information
        """
        if not keywords:
            keywords = [
                "api", "key", "token", "secret", "password", "admin",
                "config", "env", "backup", "database", "sql"
            ]
        
        logger.info(f"🔐 Searching for sensitive URLs in {target}")
        
        # First get all URLs
        all_urls_result = await self.discover_urls(target)
        
        if not all_urls_result.get("success"):
            return all_urls_result
        
        urls = all_urls_result.get("urls", [])
        sensitive_urls = []
        
        for url in urls:
            url_lower = url.lower()
            for keyword in keywords:
                if keyword in url_lower:
                    sensitive_urls.append({
                        "url": url,
                        "keyword": keyword,
                        "category": self._categorize_sensitive_url(url, keyword)
                    })
                    break
        
        return {
            "success": True,
            "target": target,
            "total_urls_checked": len(urls),
            "sensitive_urls_found": len(sensitive_urls),
            "sensitive_urls": sensitive_urls,
            "keywords_searched": keywords,
            "timestamp": self._get_timestamp()
        }
    
    def _categorize_sensitive_url(self, url: str, keyword: str) -> str:
        """Categorize sensitive URL based on keyword and context"""
        url_lower = url.lower()
        
        if keyword in ["api", "token", "key"]:
            return "api_credentials"
        elif keyword in ["password", "pass", "pwd"]:
            return "authentication"
        elif keyword in ["admin", "administrator"]:
            return "administrative"
        elif keyword in ["config", "env"]:
            return "configuration"
        elif keyword in ["backup", "old", "bak"]:
            return "backup_files"
        elif keyword in ["database", "sql", "db"]:
            return "database"
        else:
            return "general_sensitive"
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        return await self.discover_urls(target, config)
    
    def get_scan_info(self) -> Dict[str, Any]:
        """Get information about this scanning agent"""
        return {
            "name": "GAU URL Discovery Agent",
            "description": "Professional URL discovery from Wayback Machine, Common Crawl, and other sources",
            "capabilities": [
                "Wayback Machine URL Discovery",
                "Common Crawl URL Fetching", 
                "AlienVault OTX Integration",
                "URLScan Integration",
                "URL Analysis and Categorization",
                "Sensitive URL Detection",
                "API Endpoint Discovery",
                "Admin Panel Detection"
            ],
            "supported_sources": ["wayback", "commoncrawl", "otx", "urlscan"],
            "output_formats": ["structured", "raw"],
            "tool_version": "gau",
            "agent_version": "1.0.0"
        }
