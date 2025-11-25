"""
Enhanced Professional Scan Orchestrator
Coordinates three main security agents for comprehensive bug bounty and penetration testing
"""

import asyncio
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from loguru import logger

from agents.agentic_ai.controller import AgenticController
# Main Orchestrator Agents
from agents.recon_agent import ReconAgent
from agents.exploit_agent import ExploitAgent
from agents.report_agent import ReportAgent


class EnhancedScanOrchestrator:
    """
    Professional Security Scan Orchestrator
    Coordinates three main security agents for comprehensive security assessments
    """
    
    def __init__(self):
        self.controller = AgenticController()
        # Initialize three main orchestrator agents
        self.agents = {
            # =================== MAIN ORCHESTRATOR AGENTS ===================
            "ReconAgent": ReconAgent(),
            "ExploitAgent": ExploitAgent(), 
            "ReportAgent": ReportAgent()
        }
        
        # Define professional scan workflows
        self.scan_workflows = {
            # Main agent workflows
            "reconnaissance": self._reconnaissance_workflow,
            "vulnerability": self._vulnerability_only_workflow,
            "vulnerability_exploitation": self._vulnerability_exploitation_workflow,
            "reporting": self._reporting_workflow,
            
            # Combined workflows
            "full": self._full_security_audit_workflow,
            "fast": self._fast_scan_workflow,
            "deep": self._deep_scan_workflow
        }
        
        logger.info(f"🎯 EnhancedScanOrchestrator initialized with {len(self.agents)} main agents")
    
    async def orchestrate_scan(
        self, 
        scan_type: str, 
        target_domain: str, 
        config: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Orchestrate a professional security scan
        
        Args:
            scan_type: Type of scan to perform
            target_domain: Target domain to scan
            config: Scan configuration options
            progress_callback: Progress update callback
        """
        
        if scan_type not in self.scan_workflows:
            raise ValueError(f"Unknown scan type: {scan_type}. Available: {list(self.scan_workflows.keys())}")
        
        start_time = datetime.now()
        logger.info(f"🎯 Starting {scan_type} scan for {target_domain}")
        
        context = {
            "target": target_domain,
            "config": config or {},
            "progress_callback": progress_callback,
            "metadata": {
                "scan_id": f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "start_time": start_time.isoformat(),
                "orchestrator_version": "3.0",
                "scan_type": scan_type,
                "target": target_domain
            }
        }
        
        try:
            # Execute the selected workflow
            workflow_func = self.scan_workflows[scan_type]
            results = await workflow_func(context)
            
            # Calculate scan duration
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            results["metadata"].update({
                "end_time": end_time.isoformat(),
                "duration_seconds": duration,
                "status": "completed"
            })
            
            logger.info(f"✅ {scan_type} scan completed for {target_domain} in {duration:.2f}s")
            return results
            
        except Exception as e:
            logger.error(f"❌ {scan_type} scan failed for {target_domain}: {e}")
            
            return {
                "success": False,
                "error": str(e),
                "scan_type": scan_type,
                "target": target_domain,
                "metadata": context["metadata"]
            }
    
    # =================== WORKFLOW IMPLEMENTATIONS ===================
    
    async def _reconnaissance_workflow(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute reconnaissance workflow using ReconAgent"""
        target = context["target"]
        config = context.get("config", {})
        progress_callback = context.get("progress_callback")
        
        if progress_callback:
            await progress_callback(10, "🔍 Starting reconnaissance...")
        
        try:
            # Execute ReconAgent
            recon_agent = self.agents["ReconAgent"]
            scan_data = {"target": target, "config": config}
            
            if progress_callback:
                await progress_callback(50, "🔍 Running reconnaissance agents...")
            
            # Add timeout to prevent infinite hangs (CRITICAL FIX for 50% bug)
            try:
                recon_results = await asyncio.wait_for(
                    recon_agent.execute(scan_data),
                    timeout=180  # 3 minutes max for recon phase
                )
            except asyncio.TimeoutError:
                logger.error("❌ Reconnaissance timed out after 3 minutes")
                recon_results = {
                    "agent": "ReconAgent",
                    "target": target,
                    "error": "Reconnaissance phase timed out",
                    "subdomains": [],
                    "ports": {},
                    "urls": [f"http://{target}", f"https://{target}"],  # Fallback URLs
                    "technologies": {},
                    "services": {},
                    "timeout": True
                }
            
            if progress_callback:
                await progress_callback(100, "✅ Reconnaissance completed")
            
            return {
                "success": True,
                "scan_type": "reconnaissance",
                "target": target,
                "ReconAgent": recon_results,
                "metadata": context["metadata"]
            }
            
        except Exception as e:
            logger.error(f"❌ Reconnaissance workflow failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "scan_type": "reconnaissance",
                "target": target,
                "metadata": context["metadata"]
            }
    
    async def _vulnerability_only_workflow(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute vulnerability scanning only (no recon, direct to ExploitAgent)"""
        target = context["target"]
        config = context.get("config", {})
        progress_callback = context.get("progress_callback")
        
        if progress_callback:
            await progress_callback(10, "🔍 Starting vulnerability-only scan...")
        
        try:
            # Execute ExploitAgent directly without recon data
            exploit_agent = self.agents["ExploitAgent"]
            target_data = {
                "target": target,
                "recon_data": {},  # Empty recon data
                "discovered_urls": [],  # Will use fallback endpoints
                "discovered_services": {},
                "discovered_technologies": {},
                "discovered_ports": {}
            }
            
            # Set scan_type in config for ExploitAgent (CRITICAL FIX)
            enhanced_config = {
                **config,
                "scan_type": "vulnerability_only"  # Tell ExploitAgent to run vulnerability assessment
            }
            
            if progress_callback:
                await progress_callback(50, "🔍 Running vulnerability detection agents...")
            
            # Add timeout to prevent hangs
            try:
                exploit_results = await asyncio.wait_for(
                    exploit_agent.execute(target_data, config=enhanced_config),  # Use enhanced_config
                    timeout=900  # 15 minutes max for vulnerability detection (26 agents * 60s each needs more time)
                )
            except asyncio.TimeoutError:
                logger.error("❌ Vulnerability detection timed out after 15 minutes")
                exploit_results = {
                    "agent": "ExploitAgent",
                    "target": target,
                    "error": "Vulnerability detection phase timed out",
                    "vulnerabilities": [],
                    "timeout": True
                }
            
            if progress_callback:
                await progress_callback(100, "✅ Vulnerability scan completed")
            
            return {
                "success": True,
                "scan_type": "vulnerability",
                "target": target,
                "ExploitAgent": exploit_results,
                "metadata": context["metadata"]
            }
            
        except Exception as e:
            logger.error(f"❌ Vulnerability-only workflow failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "scan_type": "vulnerability",
                "target": target,
                "metadata": context["metadata"]
            }
    
    async def _vulnerability_exploitation_workflow(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute vulnerability and exploitation workflow using ExploitAgent"""
        target = context["target"]
        config = context.get("config", {})
        progress_callback = context.get("progress_callback")
        recon_data = context.get("recon_data", {})  # Get recon data!
        
        if progress_callback:
            await progress_callback(10, "💥 Starting vulnerability and exploitation testing...")
        
        try:
            # Execute ExploitAgent WITH RECON DATA
            exploit_agent = self.agents["ExploitAgent"]
            target_data = {
                "target": target,
                "recon_data": recon_data,  # Pass discovered endpoints and services
                "discovered_urls": recon_data.get("urls", []),
                "discovered_services": recon_data.get("services", {}),
                "discovered_technologies": recon_data.get("technologies", {}),
                "discovered_ports": recon_data.get("ports", {})
            }
            
            # Set scan_type in config for ExploitAgent (CRITICAL FIX)
            enhanced_config = {
                **config,
                "scan_type": "comprehensive"  # Tell ExploitAgent to run both vulnerability and exploitation
            }
            
            if progress_callback:
                await progress_callback(50, "💥 Running exploitation and vulnerability agents...")
            
            # Add timeout to prevent hangs
            try:
                exploit_results = await asyncio.wait_for(
                    exploit_agent.execute(target_data, config=enhanced_config),  # Use enhanced_config
                    timeout=1200  # 20 minutes max for exploitation in standalone workflow (15 agents * 90s each)
                )
            except asyncio.TimeoutError:
                logger.error("❌ Exploitation timed out")
                exploit_results = {
                    "agent": "ExploitAgent",
                    "target": target,
                    "error": "Exploitation phase timed out",
                    "vulnerabilities": [],
                    "timeout": True
                }
            
            if progress_callback:
                await progress_callback(100, "✅ Vulnerability and exploitation testing completed")
            
            return {
                "success": True,
                "scan_type": "vulnerability_exploitation",
                "target": target,
                "ExploitAgent": exploit_results,
                "metadata": context["metadata"]
            }
            
        except Exception as e:
            logger.error(f"❌ Vulnerability exploitation workflow failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "scan_type": "vulnerability_exploitation",
                "target": target,
                "metadata": context["metadata"]
            }
    
    async def _reporting_workflow(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute reporting workflow using ReportAgent"""
        target = context["target"]
        config = context.get("config", {})
        progress_callback = context.get("progress_callback")
        scan_data = context.get("scan_data", {})
        
        if progress_callback:
            await progress_callback(10, "📊 Starting report generation...")
        
        try:
            # Execute ReportAgent
            report_agent = self.agents["ReportAgent"]
            
            if progress_callback:
                await progress_callback(50, "📊 Generating comprehensive reports...")
            
            # Add timeout to prevent hangs
            try:
                report_results = await asyncio.wait_for(
                    report_agent.execute(scan_data, config=config),
                    timeout=90  # 1.5 minutes max for reporting in standalone workflow
                )
            except asyncio.TimeoutError:
                logger.error("❌ Report generation timed out")
                report_results = {
                    "agent": "ReportAgent",
                    "error": "Report generation timed out",
                    "timeout": True
                }
            
            if progress_callback:
                await progress_callback(100, "✅ Report generation completed")
            
            return {
                "success": True,
                "scan_type": "reporting",
                "target": target,
                "ReportAgent": report_results,
                "metadata": context["metadata"]
            }
            
        except Exception as e:
            logger.error(f"❌ Reporting workflow failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "scan_type": "reporting",
                "target": target,
                "metadata": context["metadata"]
            }
    
    async def _full_security_audit_workflow(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute complete security audit: Recon -> Exploit -> Report"""
        target = context["target"]
        config = context.get("config", {})
        progress_callback = context.get("progress_callback")
        
        if progress_callback:
            await progress_callback(5, "🎯 Starting full security audit...")
        
        try:
            # Phase 1: Reconnaissance
            if progress_callback:
                await progress_callback(20, "🔍 Phase 1: Reconnaissance...")
            
            # CRITICAL FIX: Remove progress_callback from sub-workflows to prevent backwards progress
            recon_context = {**context, "config": {**config, "scan_type": "comprehensive"}}
            recon_context.pop("progress_callback", None)  # Remove to prevent sub-workflow from resetting progress
            
            # Add timeout for recon phase in full scan
            try:
                recon_results = await asyncio.wait_for(
                    self._reconnaissance_workflow(recon_context),
                    timeout=200  # 3.3 minutes max for recon in full scan
                )
            except asyncio.TimeoutError:
                logger.error("❌ Reconnaissance phase timed out in full scan")
                recon_results = {
                    "success": True,
                    "scan_type": "reconnaissance",
                    "target": target,
                    "ReconAgent": {
                        "agent": "ReconAgent",
                        "target": target,
                        "error": "Timeout",
                        "urls": [f"http://{target}", f"https://{target}"],
                        "subdomains": [],
                        "ports": {},
                        "timeout": True
                    },
                    "metadata": context["metadata"]
                }
            
            # Phase 2: Vulnerability & Exploitation (WITH RECON DATA)
            if progress_callback:
                await progress_callback(60, "💥 Phase 2: Vulnerability & Exploitation...")
            
            # PASS RECON RESULTS TO EXPLOITATION PHASE
            exploit_context = {
                **context, 
                "config": {**config, "scan_type": "comprehensive"},
                "recon_data": recon_results.get("ReconAgent", {})  # Pass discovered endpoints!
            }
            exploit_context.pop("progress_callback", None)  # CRITICAL FIX: Remove to prevent sub-workflow from resetting progress
            
            # Add timeout for exploitation phase
            try:
                exploit_results = await asyncio.wait_for(
                    self._vulnerability_exploitation_workflow(exploit_context),
                    timeout=1500  # 25 minutes max for exploitation (more than the inner 20min timeout)
                )
            except asyncio.TimeoutError:
                logger.error("❌ Exploitation phase timed out in full scan")
                exploit_results = {
                    "success": True,
                    "scan_type": "vulnerability_exploitation",
                    "target": target,
                    "ExploitAgent": {
                        "agent": "ExploitAgent",
                        "target": target,
                        "error": "Timeout",
                        "vulnerabilities": [],
                        "timeout": True
                    },
                    "metadata": context["metadata"]
                }
            
            # Prepare combined scan data for reporting
            combined_scan_data = {
                "ReconAgent": recon_results.get("ReconAgent", {}),
                "ExploitAgent": exploit_results.get("ExploitAgent", {})
            }
            
            # Phase 3: Reporting
            if progress_callback:
                await progress_callback(90, "📊 Phase 3: Report generation...")
            
            report_context = {
                **context, 
                "config": {**config, "report_types": ["vulnerability_report", "executive_report"]},
                "scan_data": combined_scan_data
            }
            report_context.pop("progress_callback", None)  # CRITICAL FIX: Remove to prevent sub-workflow from resetting progress
            
            # Add timeout for reporting phase
            try:
                report_results = await asyncio.wait_for(
                    self._reporting_workflow(report_context),
                    timeout=60  # 1 minute max for reporting
                )
            except asyncio.TimeoutError:
                logger.error("❌ Reporting phase timed out in full scan")
                report_results = {
                    "success": True,
                    "scan_type": "reporting",
                    "target": target,
                    "ReportAgent": {
                        "error": "Timeout",
                        "timeout": True
                    },
                    "metadata": context["metadata"]
                }
            
            if progress_callback:
                await progress_callback(100, "✅ Full security audit completed")
            
            return {
                "success": True,
                "scan_type": "full",
                "target": target,
                "ReconAgent": recon_results.get("ReconAgent", {}),
                "ExploitAgent": exploit_results.get("ExploitAgent", {}),
                "ReportAgent": report_results.get("ReportAgent", {}),
                "metadata": context["metadata"]
            }
            
        except Exception as e:
            logger.error(f"❌ Full security audit failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "scan_type": "full",
                "target": target,
                "metadata": context["metadata"]
            }
    
    async def _fast_scan_workflow(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute fast scan: Basic recon + vulnerability assessment"""
        target = context["target"]
        config = context.get("config", {})
        progress_callback = context.get("progress_callback")
        
        # Configure for fast scanning
        fast_config = {
            **config,
            "scan_type": "fast",
            "subdomain_agents": ["subfinder"],  # Limit to fastest
            "vulnerability_agents": ["nuclei", "wafw00f"],  # Essential vulns
            "exploitation_agents": ["sql_injection", "xss", "ssrf"]  # Common exploits
        }
        
        if progress_callback:
            await progress_callback(10, "⚡ Starting fast security scan...")
        
        try:
            # Fast reconnaissance
            recon_context = {**context, "config": fast_config}
            recon_results = await self._reconnaissance_workflow(recon_context)
            
            if progress_callback:
                await progress_callback(70, "⚡ Fast vulnerability testing...")
            
            # Fast exploitation
            exploit_context = {**context, "config": fast_config}
            exploit_results = await self._vulnerability_exploitation_workflow(exploit_context)
            
            if progress_callback:
                await progress_callback(100, "✅ Fast scan completed")
            
            return {
                "success": True,
                "scan_type": "fast",
                "target": target,
                "ReconAgent": recon_results.get("ReconAgent", {}),
                "ExploitAgent": exploit_results.get("ExploitAgent", {}),
                "metadata": context["metadata"]
            }
            
        except Exception as e:
            logger.error(f"❌ Fast scan failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "scan_type": "fast",
                "target": target,
                "metadata": context["metadata"]
            }
    
    async def _deep_scan_workflow(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute deep scan: All agents with comprehensive testing"""
        target = context["target"]
        config = context.get("config", {})
        progress_callback = context.get("progress_callback")
        
        # Configure for deep scanning
        deep_config = {
            **config,
            "scan_type": "deep",
            # Use all available agents for maximum coverage
        }
        
        if progress_callback:
            await progress_callback(5, "🔬 Starting deep security scan...")
        
        try:
            # Deep reconnaissance
            if progress_callback:
                await progress_callback(25, "🔬 Deep reconnaissance phase...")
            
            recon_context = {**context, "config": deep_config}
            recon_results = await self._reconnaissance_workflow(recon_context)
            
            # Deep exploitation
            if progress_callback:
                await progress_callback(70, "🔬 Deep exploitation phase...")
            
            exploit_context = {**context, "config": deep_config}
            exploit_results = await self._vulnerability_exploitation_workflow(exploit_context)
            
            # Comprehensive reporting
            if progress_callback:
                await progress_callback(90, "🔬 Comprehensive reporting...")
            
            combined_scan_data = {
                "ReconAgent": recon_results.get("ReconAgent", {}),
                "ExploitAgent": exploit_results.get("ExploitAgent", {})
            }
            
            report_context = {
                **context,
                "config": {**deep_config, "report_types": ["vulnerability_report", "executive_report"]},
                "scan_data": combined_scan_data
            }
            report_results = await self._reporting_workflow(report_context)
            
            if progress_callback:
                await progress_callback(100, "✅ Deep scan completed")
            
            return {
                "success": True,
                "scan_type": "deep",
                "target": target,
                "ReconAgent": recon_results.get("ReconAgent", {}),
                "ExploitAgent": exploit_results.get("ExploitAgent", {}),
                "ReportAgent": report_results.get("ReportAgent", {}),
                "metadata": context["metadata"]
            }
            
        except Exception as e:
            logger.error(f"❌ Deep scan failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "scan_type": "deep",
                "target": target,
                "metadata": context["metadata"]
            }
    
    # =================== UTILITY METHODS ===================
    
    def get_available_scans(self) -> Dict[str, Dict[str, Any]]:
        """Get information about available scan types"""
        return {
            "reconnaissance": {
                "description": "Comprehensive reconnaissance and information gathering",
                "duration": "20-40 minutes",
                "agents": "ReconAgent with all reconnaissance sub-agents",
                "focus": "Subdomain discovery, port scanning, service detection, OSINT"
            },
            "vulnerability_exploitation": {
                "description": "Vulnerability assessment and exploitation testing",
                "duration": "1-3 hours",
                "agents": "ExploitAgent with all vulnerability and exploitation sub-agents",
                "focus": "Vulnerability detection, security testing, exploitation attempts"
            },
            "reporting": {
                "description": "Professional security report generation",
                "duration": "5-10 minutes",
                "agents": "ReportAgent with all reporting sub-agents",
                "focus": "Vulnerability reports, executive summaries, technical documentation"
            },
            "full": {
                "description": "Complete security audit (Recon + Exploit + Report)",
                "duration": "2-4 hours",
                "agents": "All agents in sequence",
                "focus": "Comprehensive security assessment with professional reporting"
            },
            "fast": {
                "description": "Quick security assessment with essential checks",
                "duration": "30-60 minutes",
                "agents": "Selected high-impact agents",
                "focus": "Essential vulnerabilities and quick reconnaissance"
            },
            "deep": {
                "description": "Thorough security assessment with all available agents",
                "duration": "3-6 hours",
                "agents": "All agents with comprehensive configuration",
                "focus": "Maximum coverage and detailed analysis"
            }
        }
    
    def get_agent_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about available agents"""
        agent_info = {}
        
        for agent_name, agent in self.agents.items():
            if hasattr(agent, 'get_available_agents'):
                agent_info[agent_name] = {
                    "type": "orchestrator",
                    "sub_agents": agent.get_available_agents(),
                    "description": f"Orchestrates all {agent_name.replace('Agent', '').lower()} agents"
                }
            else:
                agent_info[agent_name] = {
                    "type": "agent",
                    "description": f"{agent_name} - Security agent"
                }
        
        return agent_info
