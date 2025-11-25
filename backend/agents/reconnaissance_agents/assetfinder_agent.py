"""
AssetFinder Agent - Certificate Transparency Focused Discovery
Professional subdomain discovery using certificate transparency logs and historical data
"""

import asyncio
import os
import subprocess
from typing import Dict, List, Any, Optional
from loguru import logger

from agents.base import BaseAgent


class AssetFinderAgent(BaseAgent):
    """
    Professional Certificate Transparency Subdomain Discovery Agent
    Specialized in historical subdomain discovery through CT logs
    """
    
    def __init__(self):
        super().__init__("assetfinder_agent")
        self.tool_path = os.path.expanduser("~/go/bin/assetfinder")
        
    async def discover_subdomains(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Discover subdomains using certificate transparency logs
        
        Args:
            target: Target domain
            options: Discovery options
            
        Returns:
            Subdomain discovery results with historical analysis
        """
        logger.info(f"🔍 Starting AssetFinder CT discovery for {target}")
        
        try:
            # Prepare assetfinder command
            cmd = [self.tool_path]
            
            # Add options
            if options:
                if options.get("subs_only"):
                    cmd.append("--subs-only")
            
            # Add target domain
            cmd.append(target)
            
            # Execute assetfinder
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split('\n')
                subdomains = [sub.strip() for sub in subdomains if sub.strip() and sub.strip() != target]
                
                analysis = self._analyze_subdomains(subdomains, target)
                
                logger.info(f"✅ AssetFinder completed for {target} - Found {len(subdomains)} subdomains")
                
                return {
                    "success": True,
                    "target": target,
                    "subdomains": subdomains,
                    "total_subdomains": len(subdomains),
                    "analysis": analysis,
                    "source": "certificate_transparency",
                    "timestamp": self._get_timestamp()
                }
            else:
                error_msg = stderr.decode().strip()
                logger.error(f"❌ AssetFinder scan failed: {error_msg}")
                return {
                    "success": False,
                    "target": target,
                    "error": error_msg,
                    "timestamp": self._get_timestamp()
                }
                
        except FileNotFoundError:
            logger.error("❌ AssetFinder not found - install with: go install github.com/tomnomnom/assetfinder@latest")
            return await self._fallback_ct_discovery(target)
        except Exception as e:
            logger.error(f"❌ AssetFinder scan error: {e}")
            return await self._fallback_ct_discovery(target)
    
    def _analyze_subdomains(self, subdomains: List[str], target: str) -> Dict[str, Any]:
        """Analyze discovered subdomains for patterns and insights"""
        analysis = {
            "by_level": {},
            "by_pattern": {},
            "interesting_subdomains": [],
            "potential_targets": [],
            "technology_indicators": [],
            "development_indicators": []
        }
        
        # Interesting subdomain patterns
        interesting_patterns = {
            "admin": ["admin", "administrator", "manage", "control"],
            "development": ["dev", "test", "staging", "beta", "alpha", "demo"],
            "api": ["api", "rest", "graphql", "webhook"],
            "database": ["db", "database", "mysql", "postgres", "mongo"],
            "mail": ["mail", "smtp", "imap", "webmail", "exchange"],
            "monitoring": ["monitor", "stats", "metrics", "grafana", "kibana"],
            "security": ["vpn", "sso", "auth", "login", "secure"],
            "backup": ["backup", "bak", "archive", "old"],
            "cdn": ["cdn", "static", "assets", "media", "img"]
        }
        
        for subdomain in subdomains:
            # Calculate subdomain level
            level = subdomain.count('.') - target.count('.')
            analysis["by_level"][level] = analysis["by_level"].get(level, 0) + 1
            
            # Check for interesting patterns
            subdomain_lower = subdomain.lower()
            for category, patterns in interesting_patterns.items():
                for pattern in patterns:
                    if pattern in subdomain_lower:
                        analysis["by_pattern"][category] = analysis["by_pattern"].get(category, 0) + 1
                        analysis["interesting_subdomains"].append({
                            "subdomain": subdomain,
                            "category": category,
                            "pattern": pattern
                        })
                        
                        # Mark as potential target
                        if category in ["admin", "api", "database", "development"]:
                            analysis["potential_targets"].append(subdomain)
                        break
        
        # Generate statistics
        analysis["statistics"] = {
            "total_subdomains": len(subdomains),
            "unique_levels": len(analysis["by_level"]),
            "interesting_count": len(analysis["interesting_subdomains"]),
            "potential_targets": len(analysis["potential_targets"]),
            "pattern_categories": len(analysis["by_pattern"])
        }
        
        return analysis
    
    async def _fallback_ct_discovery(self, target: str) -> Dict[str, Any]:
        """
        Fallback certificate transparency discovery using crt.sh API
        """
        logger.info(f"🔧 Using fallback CT discovery for {target}")
        
        try:
            import aiohttp
            
            url = "https://crt.sh/"
            params = {
                "q": f"%.{target}",
                "output": "json"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        subdomains = set()
                        for cert in data:
                            name_value = cert.get("name_value", "")
                            if name_value:
                                for name in name_value.split("\n"):
                                    name = name.strip()
                                    if name and target in name and name != target:
                                        subdomains.add(name)
                        
                        subdomain_list = list(subdomains)
                        analysis = self._analyze_subdomains(subdomain_list, target)
                        
                        return {
                            "success": True,
                            "target": target,
                            "subdomains": subdomain_list,
                            "total_subdomains": len(subdomain_list),
                            "analysis": analysis,
                            "source": "fallback_crt_sh_api",
                            "timestamp": self._get_timestamp()
                        }
                    else:
                        return {
                            "success": False,
                            "target": target,
                            "error": f"crt.sh API error: {response.status}",
                            "timestamp": self._get_timestamp()
                        }
                        
        except Exception as e:
            logger.error(f"❌ Fallback CT discovery failed: {e}")
            return {
                "success": False,
                "target": target,
                "error": f"Fallback discovery failed: {str(e)}",
                "timestamp": self._get_timestamp()
            }
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        return await self.discover_subdomains(target, config)
    
    async def historical_analysis(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform historical analysis of certificate transparency data
        """
        logger.info(f"📈 Starting historical CT analysis for {target}")
        
        # Get current subdomains
        current_result = await self.discover_subdomains(target, options)
        
        if not current_result.get("success"):
            return current_result
        
        # Enhance with historical context
        current_subdomains = current_result.get("subdomains", [])
        
        # This would be enhanced with time-series analysis in a full implementation
        historical_analysis = {
            "current_subdomains": len(current_subdomains),
            "growth_analysis": "Historical growth analysis would require time-series data",
            "certificate_authorities": "Would extract CA information from full CT logs",
            "expiration_tracking": "Would track certificate expiration patterns"
        }
        
        current_result["historical_analysis"] = historical_analysis
        return current_result
    
    def get_scan_info(self) -> Dict[str, Any]:
        """Get information about this scanning agent"""
        return {
            "name": "AssetFinder Certificate Transparency Agent",
            "description": "Professional subdomain discovery using certificate transparency logs and historical data",
            "capabilities": [
                "Certificate Transparency Log Parsing",
                "Historical Subdomain Discovery",
                "Expired Certificate Analysis",
                "Subdomain Pattern Analysis",
                "Development Environment Detection",
                "API Endpoint Discovery",
                "Administrative Interface Detection"
            ],
            "data_sources": ["Certificate Transparency Logs", "crt.sh", "Historical certificates"],
            "output_formats": ["structured", "json"],
            "tool_version": "assetfinder",
            "agent_version": "1.0.0"
        }