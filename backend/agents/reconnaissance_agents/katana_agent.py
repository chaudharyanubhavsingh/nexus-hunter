"""
Katana Agent - Advanced Web Crawling & JavaScript Discovery
Professional web application crawling and endpoint discovery
"""

import asyncio
import json
import subprocess
import tempfile
import os
from typing import Dict, List, Any, Optional
from loguru import logger

from agents.base import BaseAgent


class KatanaAgent(BaseAgent):
    """
    Professional Web Crawling and JavaScript Discovery Agent
    Specializes in endpoint discovery, JS file analysis, and deep web crawling
    """
    
    def __init__(self):
        super().__init__("katana_agent")
        self.tool_command = "katana"
        self.tool_path = "/Users/anubhav.chaudhary/go/bin/katana"
        
    async def crawl_and_discover(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive web crawling and endpoint discovery
        
        Args:
            target: Target URL or domain
            options: Crawling options (depth, scope, filters)
            
        Returns:
            Crawling results with discovered endpoints, JS files, and forms
        """
        logger.info(f"🕷️ Starting Katana web crawling for {target}")
        
        # Normalize target to URL format
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            # Prepare katana command with comprehensive options
            cmd = [
                self.tool_path,
                "-u", target,
                "-j",  # JSONL output for parsing
                "-d", str(options.get("depth", 3)) if options else "3",
                "-jc",  # Enable JavaScript crawling
                "-silent"  # Reduce noise
            ]
            
            # Add additional options
            if options:
                if options.get("crawl_duration"):
                    cmd.extend(["-ct", f"{options['crawl_duration']}s"])
                if options.get("js_crawling", True):
                    if "-jc" not in cmd:
                        cmd.append("-jc")
                if options.get("include_subdomains"):
                    cmd.append("-scp")
                if options.get("headless_crawling"):
                    cmd.extend(["-headless", "-system-chrome"])
                    
            # Execute katana crawl
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Parse JSON output
                raw_output = stdout.decode().strip()
                if not raw_output:
                    logger.warning(f"No crawling data returned for {target}")
                    return await self._fallback_crawling(target)
                
                # Parse each line as JSON
                crawl_data = []
                for line in raw_output.split('\n'):
                    if line.strip():
                        try:
                            entry = json.loads(line)
                            crawl_data.append(entry)
                        except json.JSONDecodeError:
                            continue
                
                # Analyze crawling results
                analysis = self._analyze_crawl_results(crawl_data, target)
                
                logger.info(f"✅ Katana crawling completed for {target} - Found {len(crawl_data)} endpoints")
                
                return {
                    "success": True,
                    "target": target,
                    "total_endpoints": len(crawl_data),
                    "crawl_data": crawl_data,
                    "analysis": analysis,
                    "method": "katana_crawling",
                    "timestamp": self._get_timestamp()
                }
            else:
                error_msg = stderr.decode().strip()
                logger.error(f"❌ Katana crawling failed: {error_msg}")
                return await self._fallback_crawling(target)
                
        except FileNotFoundError:
            logger.error("❌ Katana not found - install with: go install github.com/projectdiscovery/katana/cmd/katana@latest")
            return await self._fallback_crawling(target)
        except Exception as e:
            logger.error(f"❌ Katana crawling error: {e}")
            return await self._fallback_crawling(target)
    
    def _analyze_crawl_results(self, crawl_data: List[Dict], target: str) -> Dict[str, Any]:
        """Analyze crawling results for security intelligence"""
        analysis = {
            "endpoints": {
                "total": len(crawl_data),
                "by_method": {},
                "by_scope": {},
                "by_file_type": {},
                "parameters_found": []
            },
            "javascript_files": {
                "total_js_files": 0,
                "js_files": [],
                "js_endpoints": [],
                "potential_apis": []
            },
            "forms_and_inputs": {
                "forms_found": 0,
                "input_fields": [],
                "upload_forms": [],
                "login_forms": []
            },
            "security_insights": {
                "admin_endpoints": [],
                "api_endpoints": [],
                "sensitive_files": [],
                "development_endpoints": [],
                "database_files": [],
                "config_files": []
            },
            "technologies": {
                "frameworks_detected": [],
                "cms_detected": [],
                "javascript_frameworks": []
            }
        }
        
        # Security-relevant patterns
        sensitive_patterns = {
            "admin": ["admin", "administrator", "manage", "control", "panel"],
            "api": ["api", "rest", "graphql", "v1", "v2", "v3", "endpoint"],
            "development": ["dev", "test", "staging", "debug", "temp"],
            "config": ["config", "settings", ".env", "configuration"],
            "database": ["db", "database", "sql", "backup", "dump"],
            "sensitive": ["password", "secret", "key", "token", "auth"]
        }
        
        # File extension patterns
        file_extensions = {
            "js": [".js", ".jsx", ".ts", ".tsx"],
            "config": [".json", ".xml", ".yaml", ".yml", ".conf"],
            "backup": [".bak", ".backup", ".old", ".orig"],
            "source": [".php", ".asp", ".aspx", ".py", ".rb"],
            "data": [".sql", ".db", ".sqlite", ".csv"]
        }
        
        for entry in crawl_data:
            url = entry.get("url", "")
            method = entry.get("method", "GET")
            scope = entry.get("scope", "unknown")
            tag = entry.get("tag", "")
            body = entry.get("body", "")
            
            # Count by method
            analysis["endpoints"]["by_method"][method] = \
                analysis["endpoints"]["by_method"].get(method, 0) + 1
            
            # Count by scope
            analysis["endpoints"]["by_scope"][scope] = \
                analysis["endpoints"]["by_scope"].get(scope, 0) + 1
            
            # Analyze file types
            for ext_type, extensions in file_extensions.items():
                for ext in extensions:
                    if ext in url.lower():
                        analysis["endpoints"]["by_file_type"][ext_type] = \
                            analysis["endpoints"]["by_file_type"].get(ext_type, 0) + 1
            
            # JavaScript file analysis
            if any(ext in url.lower() for ext in file_extensions["js"]):
                analysis["javascript_files"]["js_files"].append(url)
                analysis["javascript_files"]["total_js_files"] += 1
                
                # Check for potential API endpoints in JS
                if any(api_term in url.lower() for api_term in ["api", "endpoint", "rest"]):
                    analysis["javascript_files"]["potential_apis"].append(url)
            
            # Form analysis
            if tag in ["form", "input"] or "form" in body.lower():
                analysis["forms_and_inputs"]["forms_found"] += 1
                
                # Check for specific form types
                if any(term in body.lower() for term in ["upload", "file"]):
                    analysis["forms_and_inputs"]["upload_forms"].append(url)
                if any(term in body.lower() for term in ["login", "password", "username"]):
                    analysis["forms_and_inputs"]["login_forms"].append(url)
            
            # Security insights
            url_lower = url.lower()
            for category, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    if pattern in url_lower:
                        insight_key = f"{category}_endpoints"
                        if insight_key in analysis["security_insights"]:
                            analysis["security_insights"][insight_key].append(url)
            
            # Extract parameters
            if "?" in url:
                params = url.split("?")[1].split("&")
                for param in params:
                    if "=" in param:
                        param_name = param.split("=")[0]
                        if param_name not in analysis["endpoints"]["parameters_found"]:
                            analysis["endpoints"]["parameters_found"].append(param_name)
        
        # Technology detection (basic patterns)
        all_urls = " ".join([entry.get("url", "") for entry in crawl_data])
        
        # JavaScript frameworks
        js_frameworks = {
            "React": ["react", "jsx"],
            "Angular": ["angular", "ng-"],
            "Vue.js": ["vue", "vuejs"],
            "jQuery": ["jquery", "jquery.min"],
            "Bootstrap": ["bootstrap"],
            "Next.js": ["_next", "next.js"]
        }
        
        for framework, indicators in js_frameworks.items():
            if any(indicator in all_urls.lower() for indicator in indicators):
                analysis["technologies"]["javascript_frameworks"].append(framework)
        
        # Generate summary statistics
        analysis["summary"] = {
            "total_endpoints": analysis["endpoints"]["total"],
            "unique_parameters": len(analysis["endpoints"]["parameters_found"]),
            "javascript_files": analysis["javascript_files"]["total_js_files"],
            "forms_discovered": analysis["forms_and_inputs"]["forms_found"],
            "security_relevant_endpoints": sum(
                len(v) for v in analysis["security_insights"].values() if isinstance(v, list)
            ),
            "technologies_detected": len(analysis["technologies"]["javascript_frameworks"]),
            "methods_used": list(analysis["endpoints"]["by_method"].keys()),
            "file_types_found": list(analysis["endpoints"]["by_file_type"].keys())
        }
        
        return analysis
    
    async def _fallback_crawling(self, target: str) -> Dict[str, Any]:
        """
        Fallback crawling using basic HTTP requests
        """
        logger.info(f"🔧 Using fallback crawling method for {target}")
        
        try:
            import aiohttp
            import re
            from urllib.parse import urljoin, urlparse
            
            endpoints = []
            js_files = []
            
            # Normalize target
            if not target.startswith(('http://', 'https://')):
                target = f"https://{target}"
            
            async with aiohttp.ClientSession() as session:
                try:
                    # Fetch main page
                    async with session.get(target, timeout=30) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Extract JavaScript files
                            js_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
                            js_matches = re.findall(js_pattern, content, re.IGNORECASE)
                            
                            for js_match in js_matches:
                                js_url = urljoin(target, js_match)
                                js_files.append(js_url)
                                endpoints.append({
                                    "url": js_url,
                                    "method": "GET",
                                    "scope": "javascript",
                                    "tag": "script"
                                })
                            
                            # Extract links
                            link_pattern = r'<a[^>]+href=["\']([^"\']+)["\']'
                            link_matches = re.findall(link_pattern, content, re.IGNORECASE)
                            
                            for link_match in link_matches:
                                link_url = urljoin(target, link_match)
                                # Only include same-domain links
                                if urlparse(link_url).netloc == urlparse(target).netloc:
                                    endpoints.append({
                                        "url": link_url,
                                        "method": "GET",
                                        "scope": "in-scope",
                                        "tag": "link"
                                    })
                            
                            # Extract forms
                            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\']'
                            form_matches = re.findall(form_pattern, content, re.IGNORECASE)
                            
                            for form_match in form_matches:
                                form_url = urljoin(target, form_match)
                                endpoints.append({
                                    "url": form_url,
                                    "method": "POST",
                                    "scope": "in-scope",
                                    "tag": "form"
                                })
                                
                except Exception as e:
                    logger.debug(f"Error fetching {target}: {e}")
            
            # Remove duplicates
            unique_endpoints = []
            seen_urls = set()
            for endpoint in endpoints:
                url = endpoint["url"]
                if url not in seen_urls:
                    seen_urls.add(url)
                    unique_endpoints.append(endpoint)
            
            analysis = self._analyze_crawl_results(unique_endpoints, target)
            
            return {
                "success": True,
                "target": target,
                "total_endpoints": len(unique_endpoints),
                "crawl_data": unique_endpoints,
                "analysis": analysis,
                "method": "fallback_basic_crawling",
                "timestamp": self._get_timestamp()
            }
                    
        except Exception as e:
            logger.error(f"❌ Fallback crawling failed: {e}")
            return {
                "success": False,
                "target": target,
                "error": f"Fallback crawling failed: {str(e)}",
                "timestamp": self._get_timestamp()
            }
    
    async def javascript_analysis(
        self,
        target: str,
        js_files: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Deep analysis of JavaScript files for endpoints and secrets
        """
        logger.info(f"🔍 Analyzing JavaScript files for {target}")
        
        if not js_files:
            # First crawl to find JS files
            crawl_results = await self.crawl_and_discover(target)
            if crawl_results.get("success"):
                js_files = crawl_results["analysis"]["javascript_files"]["js_files"]
            else:
                return crawl_results
        
        try:
            import aiohttp
            import re
            
            analysis = {
                "js_files_analyzed": 0,
                "endpoints_extracted": [],
                "potential_secrets": [],
                "api_patterns": [],
                "interesting_functions": [],
                "external_services": []
            }
            
            # Patterns for extracting information from JS
            patterns = {
                "endpoints": [
                    r'["\']\/[a-zA-Z0-9\/_\-\.]*["\']',  # API endpoints
                    r'["\']https?:\/\/[^"\']+["\']',       # URLs
                ],
                "secrets": [
                    r'["\'][a-zA-Z0-9]{32,}["\']',        # Potential tokens
                    r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',  # API keys
                    r'secret["\']?\s*[:=]\s*["\'][^"\']+["\']',        # Secrets
                ],
                "functions": [
                    r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',      # Function definitions
                    r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*function\s*\(',  # Object methods
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                for js_file in js_files[:10]:  # Limit to first 10 JS files
                    try:
                        async with session.get(js_file, timeout=30) as response:
                            if response.status == 200:
                                js_content = await response.text()
                                analysis["js_files_analyzed"] += 1
                                
                                # Extract endpoints
                                for endpoint_pattern in patterns["endpoints"]:
                                    matches = re.findall(endpoint_pattern, js_content)
                                    for match in matches:
                                        clean_match = match.strip('"\'')
                                        if clean_match not in analysis["endpoints_extracted"]:
                                            analysis["endpoints_extracted"].append(clean_match)
                                
                                # Extract potential secrets
                                for secret_pattern in patterns["secrets"]:
                                    matches = re.findall(secret_pattern, js_content, re.IGNORECASE)
                                    analysis["potential_secrets"].extend(matches)
                                
                                # Extract function names
                                for func_pattern in patterns["functions"]:
                                    matches = re.findall(func_pattern, js_content)
                                    analysis["interesting_functions"].extend(matches)
                                    
                    except Exception as e:
                        logger.debug(f"Error analyzing JS file {js_file}: {e}")
            
            # Remove duplicates and clean up
            analysis["endpoints_extracted"] = list(set(analysis["endpoints_extracted"]))
            analysis["potential_secrets"] = list(set(analysis["potential_secrets"]))
            analysis["interesting_functions"] = list(set(analysis["interesting_functions"]))
            
            return {
                "success": True,
                "target": target,
                "analysis": analysis,
                "timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            logger.error(f"❌ JavaScript analysis failed: {e}")
            return {
                "success": False,
                "target": target,
                "error": f"JavaScript analysis failed: {str(e)}",
                "timestamp": self._get_timestamp()
            }
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        return await self.crawl_and_discover(target, config)
    
    def get_scan_info(self) -> Dict[str, Any]:
        """Get information about this scanning agent"""
        return {
            "name": "Katana Web Crawling Agent",
            "description": "Professional web application crawling and endpoint discovery",
            "capabilities": [
                "Deep Web Crawling",
                "JavaScript File Discovery",
                "Endpoint Extraction",
                "Form Discovery",
                "Parameter Enumeration",
                "Technology Detection",
                "Security Endpoint Identification",
                "API Discovery"
            ],
            "supported_methods": ["GET", "POST", "PUT", "DELETE"],
            "output_formats": ["structured", "json"],
            "tool_version": "katana",
            "agent_version": "1.0.0"
        }
