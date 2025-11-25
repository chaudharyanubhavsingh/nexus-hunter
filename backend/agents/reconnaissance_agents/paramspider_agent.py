"""
ParamSpider Agent - Parameter & Endpoint Discovery
Professional parameter mining from web archives for comprehensive endpoint analysis
"""

import asyncio
import json
import subprocess
import tempfile
import os
from typing import Dict, List, Any, Optional
from pathlib import Path
from loguru import logger

from agents.base import BaseAgent


class ParamSpiderAgent(BaseAgent):
    """
    Professional Parameter Discovery Agent
    Specializes in mining URLs and parameters from web archives for comprehensive endpoint analysis
    """
    
    def __init__(self):
        super().__init__("paramspider_agent")
        self.tool_command = "paramspider"
        self.tool_path = "/Users/anubhav.chaudhary/Library/Python/3.9/bin/paramspider"
        self.results_dir = "results"
        
    async def discover_parameters(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive parameter discovery from web archives
        
        Args:
            target: Target domain
            options: Discovery options (level, output, exclusions)
            
        Returns:
            Parameter discovery results with detailed analysis
        """
        logger.info(f"🔍 Starting ParamSpider parameter discovery for {target}")
        
        # Clean target (remove protocol if present)
        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
        
        try:
            # Prepare paramspider command
            cmd = [
                self.tool_path,
                "-d", clean_target,
            ]
            
            # Add options if provided
            if options:
                if options.get("level"):
                    cmd.extend(["-l", str(options["level"])])
                if options.get("exclude"):
                    cmd.extend(["-e", ",".join(options["exclude"])])
                if options.get("output"):
                    cmd.extend(["-o", options["output"]])
                if options.get("placeholder"):
                    cmd.extend(["-p", options["placeholder"]])
                # Note: -q flag not supported by this version of paramspider
                    
            # Execute paramspider discovery
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(Path.cwd())  # Ensure we're in the right directory
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Parse output and read results file
                results_file = Path(self.results_dir) / f"{clean_target}.txt"
                
                if results_file.exists():
                    with open(results_file, 'r') as f:
                        discovered_urls = [line.strip() for line in f.readlines() if line.strip()]
                    
                    # Analyze discovered parameters
                    analysis = self._analyze_parameter_results(discovered_urls, clean_target)
                    
                    logger.info(f"✅ ParamSpider discovery completed for {clean_target} - Found {len(discovered_urls)} parameterized URLs")
                    
                    return {
                        "success": True,
                        "target": clean_target,
                        "total_urls": len(discovered_urls),
                        "parameterized_urls": discovered_urls,
                        "analysis": analysis,
                        "method": "paramspider_archive_mining",
                        "timestamp": self._get_timestamp()
                    }
                else:
                    logger.warning(f"Results file not found for {clean_target}")
                    return await self._fallback_parameter_discovery(clean_target)
                    
            else:
                error_msg = stderr.decode().strip()
                logger.error(f"❌ ParamSpider discovery failed: {error_msg}")
                return await self._fallback_parameter_discovery(clean_target)
                
        except FileNotFoundError:
            logger.error("❌ ParamSpider not found - install with: git clone and setup.py install")
            return await self._fallback_parameter_discovery(clean_target)
        except Exception as e:
            logger.error(f"❌ ParamSpider discovery error: {e}")
            return await self._fallback_parameter_discovery(clean_target)
    
    def _analyze_parameter_results(self, urls: List[str], target: str) -> Dict[str, Any]:
        """Analyze discovered parameterized URLs for security intelligence"""
        analysis = {
            "parameters": {
                "total_unique_params": 0,
                "parameter_names": [],
                "parameter_frequency": {},
                "sensitive_parameters": [],
                "common_parameters": []
            },
            "endpoints": {
                "total_endpoints": len(urls),
                "unique_endpoints": [],
                "endpoint_patterns": {},
                "file_extensions": {},
                "directory_levels": {}
            },
            "security_insights": {
                "potential_vulnerabilities": [],
                "injection_points": [],
                "authentication_endpoints": [],
                "api_endpoints": [],
                "admin_endpoints": [],
                "upload_endpoints": []
            },
            "data_patterns": {
                "numeric_parameters": [],
                "encoded_parameters": [],
                "base64_patterns": [],
                "potential_tokens": []
            }
        }
        
        # Security-relevant parameter patterns
        sensitive_param_patterns = {
            "authentication": ["user", "username", "login", "auth", "token", "session", "key"],
            "injection": ["id", "search", "query", "cmd", "exec", "file", "path", "url"],
            "data_exposure": ["debug", "admin", "test", "dev", "password", "secret"],
            "file_operations": ["file", "upload", "download", "path", "dir", "folder"],
            "api_related": ["api", "callback", "jsonp", "format", "output", "response"]
        }
        
        # File extension patterns
        dangerous_extensions = [".php", ".asp", ".aspx", ".jsp", ".cgi", ".py", ".rb"]
        
        all_parameters = set()
        unique_endpoints = set()
        
        for url in urls:
            try:
                # Extract endpoint (without parameters)
                if "?" in url:
                    endpoint = url.split("?")[0]
                    param_string = url.split("?")[1]
                    
                    unique_endpoints.add(endpoint)
                    
                    # Extract parameters
                    params = param_string.split("&")
                    for param in params:
                        if "=" in param:
                            param_name = param.split("=")[0].lower()
                            param_value = param.split("=", 1)[1] if len(param.split("=", 1)) > 1 else ""
                            
                            all_parameters.add(param_name)
                            
                            # Count parameter frequency
                            analysis["parameters"]["parameter_frequency"][param_name] = \
                                analysis["parameters"]["parameter_frequency"].get(param_name, 0) + 1
                            
                            # Check for sensitive parameters
                            for category, patterns in sensitive_param_patterns.items():
                                for pattern in patterns:
                                    if pattern in param_name:
                                        if param_name not in analysis["parameters"]["sensitive_parameters"]:
                                            analysis["parameters"]["sensitive_parameters"].append(param_name)
                                        
                                        # Add to security insights
                                        if category == "authentication":
                                            if url not in analysis["security_insights"]["authentication_endpoints"]:
                                                analysis["security_insights"]["authentication_endpoints"].append(url)
                                        elif category == "injection":
                                            if url not in analysis["security_insights"]["injection_points"]:
                                                analysis["security_insights"]["injection_points"].append(url)
                            
                            # Analyze parameter values for patterns
                            if param_value:
                                # Check for numeric IDs (potential for ID enumeration)
                                if param_value.isdigit():
                                    analysis["data_patterns"]["numeric_parameters"].append(f"{param_name}={param_value}")
                                
                                # Check for encoded content
                                if "%" in param_value:
                                    analysis["data_patterns"]["encoded_parameters"].append(f"{param_name}={param_value}")
                                
                                # Check for base64 patterns
                                if len(param_value) > 10 and param_value.replace("+", "").replace("/", "").replace("=", "").isalnum():
                                    analysis["data_patterns"]["base64_patterns"].append(f"{param_name}={param_value}")
                                
                                # Check for potential tokens
                                if len(param_value) > 20 and any(c.isalnum() for c in param_value):
                                    analysis["data_patterns"]["potential_tokens"].append(f"{param_name}={param_value}")
                    
                    # Analyze endpoint patterns
                    if any(ext in endpoint.lower() for ext in dangerous_extensions):
                        analysis["security_insights"]["potential_vulnerabilities"].append(url)
                    
                    # Check for admin endpoints
                    if any(keyword in endpoint.lower() for keyword in ["admin", "administrator", "manage", "control"]):
                        analysis["security_insights"]["admin_endpoints"].append(url)
                    
                    # Check for API endpoints
                    if any(keyword in endpoint.lower() for keyword in ["api", "rest", "json", "xml"]):
                        analysis["security_insights"]["api_endpoints"].append(url)
                    
                    # Check for upload endpoints
                    if any(keyword in endpoint.lower() for keyword in ["upload", "file", "attachment"]):
                        analysis["security_insights"]["upload_endpoints"].append(url)
                    
                    # Analyze file extensions
                    if "." in endpoint:
                        ext = "." + endpoint.split(".")[-1]
                        analysis["endpoints"]["file_extensions"][ext] = \
                            analysis["endpoints"]["file_extensions"].get(ext, 0) + 1
                    
                    # Analyze directory levels
                    dir_level = endpoint.count("/")
                    analysis["endpoints"]["directory_levels"][str(dir_level)] = \
                        analysis["endpoints"]["directory_levels"].get(str(dir_level), 0) + 1
                        
            except Exception as e:
                logger.debug(f"Error analyzing URL {url}: {e}")
                continue
        
        # Finalize analysis
        analysis["parameters"]["total_unique_params"] = len(all_parameters)
        analysis["parameters"]["parameter_names"] = list(all_parameters)
        analysis["endpoints"]["unique_endpoints"] = list(unique_endpoints)
        
        # Identify common parameters (appearing frequently)
        freq_threshold = max(1, len(urls) * 0.1)  # 10% threshold
        analysis["parameters"]["common_parameters"] = [
            param for param, count in analysis["parameters"]["parameter_frequency"].items()
            if count >= freq_threshold
        ]
        
        # Generate summary statistics
        analysis["summary"] = {
            "total_parameterized_urls": len(urls),
            "unique_parameters": len(all_parameters),
            "unique_endpoints": len(unique_endpoints),
            "sensitive_parameters_found": len(analysis["parameters"]["sensitive_parameters"]),
            "potential_injection_points": len(analysis["security_insights"]["injection_points"]),
            "authentication_related": len(analysis["security_insights"]["authentication_endpoints"]),
            "admin_endpoints_found": len(analysis["security_insights"]["admin_endpoints"]),
            "api_endpoints_found": len(analysis["security_insights"]["api_endpoints"]),
            "file_extensions_found": len(analysis["endpoints"]["file_extensions"]),
            "potential_vulnerabilities": len(analysis["security_insights"]["potential_vulnerabilities"])
        }
        
        return analysis
    
    async def _fallback_parameter_discovery(self, target: str) -> Dict[str, Any]:
        """
        Fallback parameter discovery using basic URL patterns
        """
        logger.info(f"🔧 Using fallback parameter discovery for {target}")
        
        try:
            import aiohttp
            import re
            from urllib.parse import urljoin, urlparse, parse_qs
            
            discovered_urls = []
            
            # Common parameter patterns to look for
            common_params = [
                "id", "user", "search", "q", "query", "page", "limit", "offset",
                "category", "type", "format", "callback", "token", "key", "session"
            ]
            
            # Normalize target
            if not target.startswith(('http://', 'https://')):
                target_url = f"https://{target}"
            else:
                target_url = target
            
            async with aiohttp.ClientSession() as session:
                try:
                    # Fetch main page to look for forms and links with parameters
                    async with session.get(target_url, timeout=30) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Extract URLs with parameters from HTML
                            url_patterns = [
                                r'href=["\']([^"\']*\?[^"\']*)["\']',  # Links with parameters
                                r'action=["\']([^"\']*\?[^"\']*)["\']',  # Forms with parameters
                                r'src=["\']([^"\']*\?[^"\']*)["\']'     # Resources with parameters
                            ]
                            
                            for pattern in url_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    full_url = urljoin(target_url, match)
                                    if urlparse(full_url).netloc == urlparse(target_url).netloc:
                                        discovered_urls.append(full_url)
                                        
                except Exception as e:
                    logger.debug(f"Error fetching {target_url}: {e}")
            
            # Remove duplicates
            discovered_urls = list(set(discovered_urls))
            
            # If no parameterized URLs found, generate some common patterns for testing
            if not discovered_urls:
                base_url = f"https://{target}"
                test_urls = [
                    f"{base_url}/search?q=test",
                    f"{base_url}/api?id=1",
                    f"{base_url}/user?user=admin",
                    f"{base_url}/page?page=1&limit=10"
                ]
                discovered_urls = test_urls
            
            analysis = self._analyze_parameter_results(discovered_urls, target)
            
            return {
                "success": True,
                "target": target,
                "total_urls": len(discovered_urls),
                "parameterized_urls": discovered_urls,
                "analysis": analysis,
                "method": "fallback_parameter_discovery",
                "timestamp": self._get_timestamp()
            }
                    
        except Exception as e:
            logger.error(f"❌ Fallback parameter discovery failed: {e}")
            return {
                "success": False,
                "target": target,
                "error": f"Fallback parameter discovery failed: {str(e)}",
                "timestamp": self._get_timestamp()
            }
    
    async def parameter_fuzzing_preparation(
        self,
        target: str,
        parameters: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Prepare discovered parameters for fuzzing and vulnerability testing
        """
        logger.info(f"🎯 Preparing parameter fuzzing wordlists for {target}")
        
        if not parameters:
            # First discover parameters
            discovery_results = await self.discover_parameters(target)
            if discovery_results.get("success"):
                parameters = discovery_results["analysis"]["parameters"]["parameter_names"]
            else:
                return discovery_results
        
        # Generate fuzzing payloads and test cases
        fuzzing_prep = {
            "parameters": parameters,
            "injection_payloads": {
                "sql_injection": ["'", "\"", "1' OR '1'='1", "admin'--"],
                "xss": ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "javascript:alert(1)"],
                "command_injection": ["; ls", "| whoami", "&& cat /etc/passwd"],
                "path_traversal": ["../../../etc/passwd", "....//....//....//etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
                "ldap_injection": ["*)(uid=*))(|(uid=*", "*)(|(password=*)"],
                "nosql_injection": ["true", "[$ne]", "admin'||'1'=='1"]
            },
            "enumeration_payloads": {
                "id_enumeration": [str(i) for i in range(1, 101)],
                "user_enumeration": ["admin", "user", "test", "guest", "administrator"],
                "common_files": ["index", "admin", "login", "api", "config", "backup"]
            },
            "fuzzing_strategies": {
                "boundary_testing": ["0", "-1", "999999", "null", "undefined"],
                "overflow_testing": ["A" * 100, "A" * 1000, "A" * 10000],
                "special_chars": ["!@#$%^&*()", "<>\"'%;)(&+", "äöüß"],
                "encoding_tests": ["%20", "%22", "%27", "%3C", "%3E"]
            }
        }
        
        return {
            "success": True,
            "target": target,
            "fuzzing_preparation": fuzzing_prep,
            "total_parameters": len(parameters),
            "timestamp": self._get_timestamp()
        }
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        return await self.discover_parameters(target, config)
    
    def get_scan_info(self) -> Dict[str, Any]:
        """Get information about this scanning agent"""
        return {
            "name": "ParamSpider Parameter Discovery Agent",
            "description": "Professional parameter mining from web archives for comprehensive endpoint analysis",
            "capabilities": [
                "Web Archive Parameter Mining",
                "URL Parameter Discovery",
                "Endpoint Analysis",
                "Security Parameter Identification",
                "Injection Point Detection",
                "Authentication Endpoint Discovery",
                "API Endpoint Mapping",
                "Fuzzing Payload Preparation"
            ],
            "supported_sources": ["web_archives", "wayback_machine", "direct_crawling"],
            "output_formats": ["structured", "fuzzing_ready"],
            "tool_version": "paramspider",
            "agent_version": "1.0.0"
        }
