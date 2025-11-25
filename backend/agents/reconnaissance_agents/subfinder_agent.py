"""
Subfinder Agent - Professional Subdomain Discovery
Integrates with Subfinder tool for comprehensive subdomain enumeration
"""

import asyncio
import json
import os
import subprocess
import tempfile
from typing import Dict, List, Any, Set
from pathlib import Path

from loguru import logger
from agents.base import BaseAgent


class SubfinderAgent(BaseAgent):
    """
    Professional subdomain discovery using Subfinder
    Enhanced with cybersecurity expert guidance and prompt engineering
    """
    
    def __init__(self):
        super().__init__("SubfinderAgent", "reconnaissance")
        self.discovered_subdomains: Set[str] = set()
        self.sources_used: List[str] = []
        
        # Subfinder configuration
        self.subfinder_path = self._get_subfinder_path()
        self.config_file = None
        self.max_subdomains = 10000  # Safety limit
        
        # Initialize configuration
        self._setup_subfinder_config()
    
    def _get_subfinder_path(self) -> str:
        """Get Subfinder binary path"""
        # Try common installation paths
        possible_paths = [
            "/usr/local/bin/subfinder",
            "/usr/bin/subfinder", 
            "/opt/homebrew/bin/subfinder",
            "subfinder"  # If in PATH
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, "-version"], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    logger.info(f"✅ Found Subfinder at: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        # If not found, provide installation instructions
        logger.warning("⚠️ Subfinder not found. Installing...")
        return self._install_subfinder()
    
    def _install_subfinder(self) -> str:
        """Install Subfinder if not present"""
        try:
            # Install via Go
            install_cmd = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            result = subprocess.run(install_cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                go_bin = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True).stdout.strip()
                subfinder_path = f"{go_bin}/bin/subfinder"
                logger.info(f"✅ Subfinder installed at: {subfinder_path}")
                return subfinder_path
            else:
                # Fallback: use Docker
                logger.warning("Go installation failed, using Docker fallback")
                return "docker run --rm projectdiscovery/subfinder:latest"
                
        except Exception as e:
            logger.warning(f"Subfinder installation failed: {e}")
            # Return built-in implementation as fallback
            return "builtin"
    
    def _setup_subfinder_config(self):
        """Setup Subfinder configuration with API keys"""
        config_dir = Path.home() / ".config" / "subfinder"
        config_dir.mkdir(parents=True, exist_ok=True)
        
        config_file = config_dir / "config.yaml"
        
        if not config_file.exists():
            # Create basic configuration
            config_content = """
# Subfinder Configuration for Nexus Hunter
version: 2

# API Keys for enhanced subdomain discovery
# Add your API keys here for better results

sources:
  - virustotal
  - censys
  - shodan
  - securitytrails
  - chaos
  - waybackarchive
  - anubisdb
  - alienvault
  - binaryedge
  - bufferover
  - c99
  - certdb
  - certspotter
  - crtsh
  - dnsdumpster
  - dnsrepo
  - hackertarget
  - intelx
  - passivetotal
  - rapiddns
  - riddler
  - robtex
  - spyse
  - sublist3r
  - threatbook
  - urlscan
  - zoomeye

# Rate limiting
rate-limit: 10

# Maximum timeout
timeout: 30

# Exclude wildcard subdomains
exclude-sources:
  - archiveis

# Output format
output-format: json
"""
            with open(config_file, 'w') as f:
                f.write(config_content)
        
        self.config_file = str(config_file)
    
    async def execute(self, scan_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Execute comprehensive subdomain discovery with cybersecurity expertise"""
        target_domain = scan_data.get("target") or scan_data.get("domain")
        
        if not target_domain:
            raise ValueError("No target domain specified for subdomain discovery")
        
        # Clean domain input
        target_domain = target_domain.replace("http://", "").replace("https://", "").split("/")[0]
        
        # Set expert context for intelligent decision making
        self.set_expert_context({
            "target": target_domain,
            "target_type": "domain",
            "scan_type": scan_data.get("scan_type", "comprehensive"),
            "business_context": scan_data.get("business_context", "security_assessment")
        })
        
        logger.info(f"🔍 Starting expert-guided subdomain discovery for {target_domain}")
        
        # Phase 1: Get expert planning guidance
        await self.expert_update_progress("planning", {
            "status": "Getting expert reconnaissance guidance",
            "target": target_domain
        }, guidance_needed=True)
        
        results = {
            "target_domain": target_domain,
            "subdomains": [],
            "sources_used": [],
            "total_found": 0,
            "discovery_methods": [],
            "expert_guided": True,
            "methodology": "cybersecurity_professional",
            "metadata": {}
        }
        
        try:
            # Phase 2: Expert-guided Subfinder Discovery
            await self.expert_update_progress("execution", {
                "status": "🧠 Executing expert-guided Subfinder reconnaissance",
                "phase": "2/5",
                "methodology": "multi-source_professional"
            }, guidance_needed=True)
            
            subfinder_results = await self._run_subfinder(target_domain)
            results["subdomains"].extend(subfinder_results.get("subdomains", []))
            results["sources_used"].extend(subfinder_results.get("sources", []))
            results["discovery_methods"].append("Expert-Guided Subfinder")
            
            # Phase 3: Certificate Transparency with Expert Analysis
            if not self.is_cancelled():
                await self.expert_update_progress("certificate_analysis", {
                    "status": "🔍 Professional Certificate Transparency analysis",
                    "phase": "3/5",
                    "intelligence_type": "passive_reconnaissance"
                })
                
                ct_results = await self._query_certificate_transparency(target_domain)
                results["subdomains"].extend(ct_results)
                results["discovery_methods"].append("Certificate Transparency Intelligence")
            
            # Phase 4: Expert-guided DNS Operations
            if not self.is_cancelled():
                await self.expert_update_progress("dns_operations", {
                    "status": "🎯 Strategic DNS brute force with expert wordlists",
                    "phase": "4/5",
                    "technique": "intelligent_enumeration"
                })
                
                brute_results = await self._dns_brute_force(target_domain)
                results["subdomains"].extend(brute_results)
                results["discovery_methods"].append("Expert DNS Enumeration")
            
            # Phase 5: Professional Validation and Analysis
            await self.expert_update_progress("analysis", {
                "status": "🧬 Professional validation and intelligence analysis",
                "phase": "5/5",
                "analysis_type": "comprehensive_validation"
            }, guidance_needed=True)
            
            validated_subdomains = await self._validate_subdomains(list(set(results["subdomains"])))
            results["subdomains"] = validated_subdomains
            results["total_found"] = len(validated_subdomains)
            
            # Professional Metadata with Expert Analysis
            results["metadata"] = {
                "discovery_sources": len(results["sources_used"]),
                "methods_used": len(results["discovery_methods"]),
                "validation_rate": f"{len(validated_subdomains)}/{len(set(results['subdomains']))}",
                "top_level_domain": target_domain,
                "expert_analysis": {
                    "methodology": "cybersecurity_professional_reconnaissance", 
                    "confidence_level": "high",
                    "attack_surface_expansion": len(validated_subdomains),
                    "intelligence_quality": "professional_grade",
                    "operational_security": "maintained"
                },
                "professional_assessment": {
                    "discovery_completeness": "comprehensive" if len(validated_subdomains) > 5 else "limited",
                    "target_complexity": "high" if len(validated_subdomains) > 20 else "moderate",
                    "reconnaissance_depth": "multi-layered",
                    "next_phase_readiness": "prepared"
                }
            }
            
            # Final expert guidance on results
            final_guidance = await self.get_expert_guidance("analysis", {
                "subdomains_found": len(validated_subdomains),
                "sources_used": len(results["sources_used"]),
                "target_complexity": results["metadata"]["professional_assessment"]["target_complexity"]
            })
            
            results["expert_recommendations"] = {
                "analysis": final_guidance.get("guidance", "Professional reconnaissance completed"),
                "confidence": final_guidance.get("confidence", 85),
                "next_steps": [
                    "Proceed with port scanning on discovered assets",
                    "Prioritize high-value subdomains for deeper analysis",
                    "Consider service enumeration on active hosts"
                ]
            }
            
            logger.info(f"✅ Expert-guided subdomain discovery completed: {len(validated_subdomains)} validated subdomains")
            return results
            
        except Exception as e:
            logger.error(f"❌ Subfinder agent failed: {e}")
            raise
    
    async def _run_subfinder(self, domain: str) -> Dict[str, Any]:
        """Run Subfinder tool with optimal configuration"""
        results = {"subdomains": [], "sources": []}
        
        if self.subfinder_path == "builtin":
            # Use built-in implementation
            return await self._builtin_subdomain_discovery(domain)
        
        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                temp_output = temp_file.name
            
            # Build Subfinder command
            cmd = [
                self.subfinder_path,
                "-d", domain,
                "-o", temp_output,
                "-oJ",  # JSON output
                "-config", self.config_file,
                "-all",  # Use all sources
                "-recursive",  # Recursive discovery
                "-timeout", "30",
                "-rate-limit", "10",
                "-silent"
            ]
            
            # Execute Subfinder
            logger.info(f"🚀 Executing: {' '.join(cmd)}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse results
            if os.path.exists(temp_output):
                try:
                    with open(temp_output, 'r') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    subdomain_data = json.loads(line)
                                    subdomain = subdomain_data.get("host", "").strip()
                                    source = subdomain_data.get("source", "")
                                    
                                    if subdomain and subdomain.endswith(domain):
                                        results["subdomains"].append(subdomain)
                                        if source and source not in results["sources"]:
                                            results["sources"].append(source)
                                except json.JSONDecodeError:
                                    # Handle plain text output
                                    subdomain = line.strip()
                                    if subdomain.endswith(domain):
                                        results["subdomains"].append(subdomain)
                
                except Exception as e:
                    logger.warning(f"Failed to parse Subfinder output: {e}")
                
                # Cleanup
                os.unlink(temp_output)
            
            logger.info(f"📊 Subfinder found {len(results['subdomains'])} subdomains from {len(results['sources'])} sources")
            return results
            
        except Exception as e:
            logger.error(f"Subfinder execution failed: {e}")
            # Fallback to built-in
            return await self._builtin_subdomain_discovery(domain)
    
    async def _builtin_subdomain_discovery(self, domain: str) -> Dict[str, Any]:
        """Built-in subdomain discovery as fallback"""
        logger.info("🔧 Using built-in subdomain discovery")
        
        common_subdomains = [
            "www", "mail", "admin", "api", "app", "dev", "staging", "test",
            "blog", "shop", "store", "support", "help", "docs", "portal",
            "dashboard", "panel", "cpanel", "webmail", "ftp", "ssh", "vpn",
            "cdn", "static", "assets", "media", "images", "files", "downloads",
            "mobile", "m", "beta", "alpha", "demo", "preview", "sandbox"
        ]
        
        discovered = []
        
        for subdomain in common_subdomains:
            if self.is_cancelled():
                break
            
            full_domain = f"{subdomain}.{domain}"
            if await self._check_subdomain_exists(full_domain):
                discovered.append(full_domain)
        
        return {
            "subdomains": discovered,
            "sources": ["builtin_wordlist"]
        }
    
    async def _query_certificate_transparency(self, domain: str) -> List[str]:
        """Query Certificate Transparency logs for subdomains"""
        import httpx
        
        subdomains = []
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Query crt.sh
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
                                    if name.endswith(domain) and '*' not in name:
                                        subdomains.append(name)
                    except json.JSONDecodeError:
                        pass
        
        except Exception as e:
            logger.warning(f"Certificate Transparency query failed: {e}")
        
        return list(set(subdomains))
    
    async def _dns_brute_force(self, domain: str) -> List[str]:
        """Intelligent DNS brute force with common subdomains"""
        import dns.resolver
        
        wordlists = {
            "common": [
                "www", "mail", "admin", "api", "app", "dev", "staging", "test",
                "blog", "shop", "store", "support", "help", "docs", "portal"
            ],
            "extended": [
                "dashboard", "panel", "cpanel", "webmail", "ftp", "ssh", "vpn",
                "cdn", "static", "assets", "media", "images", "files", "downloads",
                "mobile", "m", "beta", "alpha", "demo", "preview", "sandbox",
                "jenkins", "gitlab", "github", "jira", "confluence", "wiki"
            ]
        }
        
        discovered = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        
        # Use all wordlists
        all_subdomains = wordlists["common"] + wordlists["extended"]
        
        # Batch processing for better performance
        batch_size = 20
        for i in range(0, len(all_subdomains), batch_size):
            if self.is_cancelled():
                break
            
            batch = all_subdomains[i:i + batch_size]
            tasks = []
            
            for subdomain in batch:
                full_domain = f"{subdomain}.{domain}"
                tasks.append(self._check_subdomain_exists(full_domain))
            
            # Execute batch
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for j, exists in enumerate(results):
                if exists is True:
                    discovered.append(f"{batch[j]}.{domain}")
            
            # Rate limiting
            await asyncio.sleep(0.5)
        
        return discovered
    
    async def _check_subdomain_exists(self, subdomain: str) -> bool:
        """Check if subdomain exists via DNS resolution"""
        import dns.resolver
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 3
            
            # Try A record
            try:
                resolver.resolve(subdomain, 'A')
                return True
            except:
                pass
            
            # Try CNAME record
            try:
                resolver.resolve(subdomain, 'CNAME')
                return True
            except:
                pass
                
        except Exception:
            pass
        
        return False
    
    async def _validate_subdomains(self, subdomains: List[str]) -> List[str]:
        """Validate discovered subdomains"""
        valid_subdomains = []
        
        # Batch validation
        batch_size = 50
        for i in range(0, len(subdomains), batch_size):
            if self.is_cancelled():
                break
            
            batch = subdomains[i:i + batch_size]
            tasks = [self._check_subdomain_exists(subdomain) for subdomain in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for j, is_valid in enumerate(results):
                if is_valid is True:
                    valid_subdomains.append(batch[j])
        
        # Remove duplicates and sort
        valid_subdomains = sorted(list(set(valid_subdomains)))
        
        # Apply safety limit
        if len(valid_subdomains) > self.max_subdomains:
            logger.warning(f"⚠️ Found {len(valid_subdomains)} subdomains, limiting to {self.max_subdomains}")
            valid_subdomains = valid_subdomains[:self.max_subdomains]
        
        return valid_subdomains
