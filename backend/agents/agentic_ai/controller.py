"""
Agentic AI Controller - The brain of the Nexus Hunter AI system
Orchestrates all agents with intelligent decision making
Enhanced with AI Brain integration for expert-level decisions
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from enum import Enum
from dataclasses import dataclass, asdict
import uuid

from loguru import logger
from agents.base import BaseAgent

# Import the AI Brain
from agents.agentic_ai.ai_brain import ai_brain, DecisionType, get_ai_decision


class AgentStatus(str, Enum):
    """Agent execution status"""
    IDLE = "idle"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    WAITING = "waiting"


class TaskPriority(str, Enum):
    """Task priority levels"""
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"


class AgentType(str, Enum):
    """Available agent types"""
    # Core security agents
    RECONNAISSANCE = "recon"
    VULNERABILITY = "vulnerability"
    EXPLOIT = "exploit"
    
    # New enhanced agents
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    PORT_SCANNING = "port_scanning"
    WEB_TECHNOLOGY = "web_technology"
    SECRET_SCANNING = "secret_scanning"
    NUCLEI_SCANNING = "nuclei_scanning"
    
    # Specialized agents
    GITHUB_INTELLIGENCE = "github_intelligence"
    DNS_INTELLIGENCE = "dns_intelligence"
    SSL_INTELLIGENCE = "ssl_intelligence"
    WAF_DETECTION = "waf_detection"
    
    # Workflow agents
    WORKFLOW_ORCHESTRATOR = "workflow_orchestrator"
    REPORT_GENERATOR = "report_generator"
    NOTIFICATION_HANDLER = "notification_handler"


@dataclass
class AgentTask:
    """Represents a task assigned to an agent"""
    id: str
    agent_type: AgentType
    priority: TaskPriority
    target_data: Dict[str, Any]
    dependencies: List[str]  # Task IDs this task depends on
    config: Dict[str, Any]
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: AgentStatus = AgentStatus.WAITING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    progress: int = 0


@dataclass
class AgentCapability:
    """Defines what an agent can do"""
    agent_type: AgentType
    name: str
    description: str
    input_requirements: List[str]
    output_types: List[str]
    dependencies: List[AgentType]
    estimated_duration: int  # seconds
    resource_intensity: str  # "low", "medium", "high"


class AIIntelligence:
    """
    AI Intelligence Engine - Acts as local LLM for decision making
    This simulates advanced AI reasoning for agent orchestration
    """
    
    def __init__(self):
        self.decision_history: List[Dict[str, Any]] = []
        self.agent_performance_metrics: Dict[AgentType, Dict[str, float]] = {}
        self.learning_data: Dict[str, Any] = {}
    
    async def analyze_target(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        AI-powered target analysis to determine optimal scanning strategy
        """
        logger.info(f"🧠 AI analyzing target: {target}")
        
        analysis = {
            "target_type": self._classify_target(target),
            "risk_assessment": self._assess_risk_level(target, context),
            "recommended_agents": self._recommend_agent_sequence(target, context),
            "resource_allocation": self._optimize_resource_allocation(target),
            "expected_duration": self._estimate_scan_duration(target),
            "confidence_score": 0.85
        }
        
        return analysis
    
    def _classify_target(self, target: str) -> str:
        """Classify the target type for intelligent agent selection"""
        if target.startswith(("http://", "https://")):
            return "web_application"
        elif "." in target and not target.replace(".", "").replace("-", "").isdigit():
            return "domain"
        elif target.replace(".", "").isdigit():
            return "ip_address"
        elif "/" in target:
            return "network_range"
        else:
            return "hostname"
    
    def _assess_risk_level(self, target: str, context: Dict[str, Any]) -> str:
        """Assess risk level to determine scanning intensity"""
        risk_factors = 0
        
        # Domain age and reputation factors
        if "suspicious_patterns" in context:
            risk_factors += 2
        
        # Technology stack complexity
        if context.get("technology_complexity", "low") == "high":
            risk_factors += 1
        
        # Previous findings
        if context.get("previous_vulnerabilities", 0) > 0:
            risk_factors += 1
        
        if risk_factors >= 3:
            return "high"
        elif risk_factors >= 1:
            return "medium"
        else:
            return "low"
    
    def _recommend_agent_sequence(self, target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """AI-powered agent sequence recommendation"""
        target_type = self._classify_target(target)
        risk_level = self._assess_risk_level(target, context)
        
        # Base sequence for all targets
        sequence = [
            {
                "agent": AgentType.SUBDOMAIN_DISCOVERY,
                "priority": TaskPriority.HIGH,
                "rationale": "Foundation for all subsequent scans"
            },
            {
                "agent": AgentType.DNS_INTELLIGENCE,
                "priority": TaskPriority.HIGH,
                "rationale": "Critical infrastructure analysis"
            }
        ]
        
        # Add port scanning for active targets
        if target_type in ["web_application", "domain", "ip_address"]:
            sequence.append({
                "agent": AgentType.PORT_SCANNING,
                "priority": TaskPriority.HIGH,
                "rationale": "Service discovery and attack surface mapping"
            })
        
        # Technology fingerprinting for web apps
        if target_type == "web_application":
            sequence.append({
                "agent": AgentType.WEB_TECHNOLOGY,
                "priority": TaskPriority.MEDIUM,
                "rationale": "Technology stack identification"
            })
            
            sequence.append({
                "agent": AgentType.WAF_DETECTION,
                "priority": TaskPriority.MEDIUM,
                "rationale": "Defense mechanism identification"
            })
        
        # Vulnerability scanning based on risk
        if risk_level in ["medium", "high"]:
            sequence.extend([
                {
                    "agent": AgentType.NUCLEI_SCANNING,
                    "priority": TaskPriority.HIGH,
                    "rationale": "Comprehensive vulnerability assessment"
                },
                {
                    "agent": AgentType.VULNERABILITY,
                    "priority": TaskPriority.HIGH,
                    "rationale": "Custom vulnerability testing"
                }
            ])
        
        # Secret scanning for high-value targets
        if risk_level == "high" or context.get("has_repositories", False):
            sequence.extend([
                {
                    "agent": AgentType.SECRET_SCANNING,
                    "priority": TaskPriority.MEDIUM,
                    "rationale": "Credential and secret discovery"
                },
                {
                    "agent": AgentType.GITHUB_INTELLIGENCE,
                    "priority": TaskPriority.MEDIUM,
                    "rationale": "Code repository analysis"
                }
            ])
        
        return sequence
    
    def _optimize_resource_allocation(self, target: str) -> Dict[str, Any]:
        """Optimize resource allocation based on target complexity"""
        return {
            "max_concurrent_agents": 3,
            "thread_pool_size": 10,
            "memory_limit_mb": 1024,
            "timeout_seconds": 3600,
            "rate_limit_requests_per_second": 10
        }
    
    def _estimate_scan_duration(self, target: str) -> int:
        """Estimate total scan duration in seconds"""
        base_duration = 300  # 5 minutes base
        
        if "." in target:  # Domain
            base_duration += 600  # Additional 10 minutes
        
        return base_duration
    
    async def decide_next_action(self, current_state: Dict[str, Any], available_agents: List[AgentType]) -> Optional[Dict[str, Any]]:
        """
        Core AI decision making - determines what to do next based on current state
        """
        completed_tasks = current_state.get("completed_tasks", [])
        running_tasks = current_state.get("running_tasks", [])
        pending_tasks = current_state.get("pending_tasks", [])
        
        # AI reasoning for next action
        if not completed_tasks and not running_tasks:
            # Start with reconnaissance
            return {
                "action": "start_task",
                "agent_type": AgentType.SUBDOMAIN_DISCOVERY,
                "rationale": "Beginning comprehensive scan with subdomain discovery"
            }
        
        # If recon is complete, move to port scanning
        recon_complete = any(task.get("agent_type") == AgentType.SUBDOMAIN_DISCOVERY 
                           for task in completed_tasks)
        
        if recon_complete and AgentType.PORT_SCANNING not in [t.get("agent_type") for t in running_tasks]:
            return {
                "action": "start_task", 
                "agent_type": AgentType.PORT_SCANNING,
                "rationale": "Reconnaissance complete, proceeding with port scanning"
            }
        
        # Continue with intelligent sequencing...
        return None


class AgenticController(BaseAgent):
    """
    Main Agentic AI Controller with Professional Cybersecurity Expertise
    Orchestrates all security agents with AI-powered decision making and prompt engineering
    """
    
    def __init__(self):
        super().__init__("AgenticController", "agentic_orchestration")
        self.ai_brain = AIIntelligence()
        self.active_agents: Dict[str, BaseAgent] = {}
        self.task_queue: List[AgentTask] = []
        self.completed_tasks: List[AgentTask] = []
        self.agent_capabilities: Dict[AgentType, AgentCapability] = {}
        self.execution_graph: Dict[str, Set[str]] = {}  # Task dependencies
        self.max_concurrent_agents = 5
        self.resource_monitor = ResourceMonitor()
        
        # Professional cybersecurity expertise
        self.professional_standards = True
        self.expert_methodology = "senior_cybersecurity_orchestration"
        
        # Initialize agent capabilities
        self._initialize_agent_capabilities()
    
    def _initialize_agent_capabilities(self):
        """Initialize the capabilities of all available agents"""
        self.agent_capabilities = {
            AgentType.SUBDOMAIN_DISCOVERY: AgentCapability(
                agent_type=AgentType.SUBDOMAIN_DISCOVERY,
                name="Subdomain Discovery Agent",
                description="Discovers subdomains using multiple techniques",
                input_requirements=["target_domain"],
                output_types=["subdomains", "dns_records"],
                dependencies=[],
                estimated_duration=300,
                resource_intensity="medium"
            ),
            
            AgentType.PORT_SCANNING: AgentCapability(
                agent_type=AgentType.PORT_SCANNING,
                name="Port Scanning Agent", 
                description="Scans for open ports and services",
                input_requirements=["target_hosts"],
                output_types=["open_ports", "services"],
                dependencies=[AgentType.SUBDOMAIN_DISCOVERY],
                estimated_duration=600,
                resource_intensity="high"
            ),
            
            AgentType.WEB_TECHNOLOGY: AgentCapability(
                agent_type=AgentType.WEB_TECHNOLOGY,
                name="Web Technology Agent",
                description="Fingerprints web technologies and frameworks",
                input_requirements=["web_hosts"],
                output_types=["technologies", "frameworks", "cms"],
                dependencies=[AgentType.PORT_SCANNING],
                estimated_duration=200,
                resource_intensity="low"
            ),
            
            AgentType.NUCLEI_SCANNING: AgentCapability(
                agent_type=AgentType.NUCLEI_SCANNING,
                name="Nuclei Vulnerability Scanner",
                description="Comprehensive vulnerability scanning with Nuclei",
                input_requirements=["web_hosts", "services"],
                output_types=["vulnerabilities", "security_issues"],
                dependencies=[AgentType.WEB_TECHNOLOGY],
                estimated_duration=900,
                resource_intensity="high"
            ),
            
            AgentType.SECRET_SCANNING: AgentCapability(
                agent_type=AgentType.SECRET_SCANNING,
                name="Secret Scanning Agent",
                description="Scans for exposed credentials and secrets",
                input_requirements=["web_hosts", "repositories"],
                output_types=["secrets", "credentials", "api_keys"],
                dependencies=[AgentType.WEB_TECHNOLOGY],
                estimated_duration=400,
                resource_intensity="medium"
            ),
            
            AgentType.GITHUB_INTELLIGENCE: AgentCapability(
                agent_type=AgentType.GITHUB_INTELLIGENCE,
                name="GitHub Intelligence Agent",
                description="Analyzes GitHub repositories for security issues",
                input_requirements=["domain", "organization"],
                output_types=["repositories", "commits", "secrets"],
                dependencies=[],
                estimated_duration=500,
                resource_intensity="medium"
            )
        }
    
    async def execute(self, scan_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Enhanced execution with AI Brain integration for expert-level decision making
        """
        logger.info("🧠 Starting AI-Brain enhanced professional cybersecurity orchestration")
        
        target = scan_data.get("target", "unknown")
        scan_id = scan_data.get("scan_id", str(uuid.uuid4()))
        
        # Set expert context for professional orchestration
        self.set_expert_context({
            "target": target,
            "scan_id": scan_id,
            "business_context": scan_data.get("business_context", "security_assessment"),
            "compliance_requirements": scan_data.get("compliance", []),
            "risk_tolerance": scan_data.get("risk_tolerance", "medium")
        })
        
        try:
            # Phase 1: AI Brain Strategic Planning
            await self.expert_update_progress("ai_strategic_planning", {
                "status": "🧠 AI Brain analyzing target and planning expert strategy",
                "phase": "1/7",
                "methodology": "ai_enhanced_expert_orchestration"
            }, guidance_needed=True)
            
            # Get AI Brain strategic decision
            strategic_context = {
                "target": target,
                "scan_data": scan_data,
                "phase": "strategic_planning",
                "available_agents": list(self.agent_capabilities.keys())
            }
            
            ai_strategy = await get_ai_decision(DecisionType.SCAN_STRATEGY, strategic_context)
            logger.info(f"🧠 AI Strategy: {ai_strategy.get('decision')} (Confidence: {ai_strategy.get('confidence', 0)*100:.1f}%)")
            
            # Phase 2: AI-Enhanced Target Analysis
            await self.expert_update_progress("ai_target_analysis", {
                "status": "🔍 AI Brain performing expert target analysis",
                "phase": "2/7",
                "ai_confidence": ai_strategy.get('confidence', 0.8),
                "recommended_approach": ai_strategy.get('decision', 'standard')
            })
            
            # Use AI Brain's analysis instead of basic analysis
            ai_analysis = await ai_brain.analyze_scan_results({
                "target": target,
                "initial_data": scan_data,
                "strategy": ai_strategy
            })
            
            logger.info(f"🧠 AI Analysis completed with expert insights")
            
            # Phase 3: AI-Guided Agent Selection and Orchestration
            await self.expert_update_progress("ai_agent_orchestration", {
                "status": "🤖 AI Brain selecting optimal agents with expert knowledge",
                "phase": "3/7",
                "agent_selection_strategy": "ai_optimized"
            }, guidance_needed=True)
            
            # Get AI Brain agent selection
            agent_context = {
                "target": target,
                "analysis": ai_analysis,
                "available_agents": list(self.agent_capabilities.keys()),
                "phase": "agent_selection",
                "strategy": ai_strategy
            }
            
            agent_decision = await get_ai_decision(DecisionType.AGENT_SELECTION, agent_context)
            recommended_agents = agent_decision.get('recommended_agents', ['ReconAgent', 'ExploitAgent'])
            
            # Create AI-optimized execution plan
            execution_plan = await self._create_ai_execution_plan(target, ai_analysis, agent_decision)
            
            # Phase 4: AI-Supervised Agent Execution
            await self.expert_update_progress("ai_supervised_execution", {
                "status": "⚡ AI Brain supervising expert agent execution",
                "phase": "4/7",
                "agents_selected": len(recommended_agents),
                "execution_strategy": "ai_supervised"
            }, guidance_needed=True)
            
            results = await self._ai_orchestrate_agents(execution_plan, scan_data, ai_strategy)
            
            # Phase 5: AI-Enhanced Intelligence Analysis
            await self.expert_update_progress("ai_intelligence_analysis", {
                "status": "🔬 AI Brain performing expert intelligence correlation",
                "phase": "5/7",
                "analysis_depth": "ai_enhanced_expert"
            })
            
            # Let AI Brain analyze results
            analysis_context = {
                "results": results,
                "target": target,
                "execution_plan": execution_plan,
                "phase": "results_analysis"
            }
            
            ai_results_analysis = await get_ai_decision(DecisionType.VULNERABILITY_ASSESSMENT, analysis_context)
            final_results = await self._ai_aggregate_and_analyze_results(results, ai_analysis, ai_results_analysis)
            
            # Phase 6: AI-Guided Threat Assessment
            await self.expert_update_progress("ai_threat_assessment", {
                "status": "🎯 AI Brain conducting expert threat assessment",
                "phase": "6/7",
                "assessment_type": "ai_enhanced_professional"
            }, guidance_needed=True)
            
            # AI Brain threat assessment
            threat_context = {
                "results": final_results,
                "vulnerabilities": final_results.get("vulnerabilities", []),
                "target": target,
                "phase": "threat_assessment"
            }
            
            threat_assessment = await get_ai_decision(DecisionType.RISK_PRIORITIZATION, threat_context)
            
            # Phase 7: AI-Optimized Professional Reporting
            await self.expert_update_progress("ai_reporting_strategy", {
                "status": "📋 AI Brain generating professional reporting strategy",
                "phase": "7/7",
                "report_standards": "ai_optimized_professional"
            })
            
            # AI Brain reporting strategy
            reporting_context = {
                "scan_data": final_results,
                "vulnerabilities": final_results.get("vulnerabilities", []),
                "target": target,
                "audience": "mixed",
                "phase": "reporting"
            }
            
            reporting_strategy = await get_ai_decision(DecisionType.REPORTING_STRATEGY, reporting_context)
            report = await self._generate_ai_intelligent_report(final_results, ai_analysis, reporting_strategy)
            
            # Get final AI assessment
            final_assessment_context = {
                "target": target,
                "findings": len(final_results.get("vulnerabilities", [])),
                "coverage": len(execution_plan),
                "risk_score": self._calculate_risk_score(final_results),
                "ai_decisions": {
                    "strategy": ai_strategy,
                    "agent_selection": agent_decision,
                    "threat_assessment": threat_assessment,
                    "reporting_strategy": reporting_strategy
                }
            }
            
            final_ai_assessment = await get_ai_decision(DecisionType.WORKFLOW_OPTIMIZATION, final_assessment_context)
            
            logger.info(f"✅ AI-Brain enhanced professional assessment completed for {target}")
            
            return {
                "scan_id": scan_id,
                "target": target,
                "ai_brain_enhanced": True,
                "professional_assessment": True,
                "expert_guided": True,
                "methodology": "ai_brain_cybersecurity_expert_orchestration",
                "ai_decisions": {
                    "strategy": ai_strategy,
                    "analysis": ai_analysis,
                    "agent_selection": agent_decision,
                    "threat_assessment": threat_assessment,
                    "reporting_strategy": reporting_strategy,
                    "final_assessment": final_ai_assessment
                },
                "execution_plan": execution_plan,
                "results": final_results,
                "report": report,
                "ai_expert_assessment": {
                    "professional_opinion": final_ai_assessment.get("decision", "AI-enhanced professional assessment completed"),
                    "confidence": final_ai_assessment.get("confidence", 95),
                    "methodology_effectiveness": "ai_optimized_high",
                    "coverage_completeness": "ai_enhanced_comprehensive",
                    "expert_recommendations": final_ai_assessment.get("next_steps", [])
                },
                "metadata": {
                    "total_agents_used": len(execution_plan),
                    "total_vulnerabilities": len(final_results.get("vulnerabilities", [])),
                    "risk_score": self._calculate_risk_score(final_results),
                    "scan_efficiency": self._calculate_efficiency_score(),
                    "ai_brain_decisions": len([ai_strategy, agent_decision, threat_assessment, reporting_strategy]),
                    "professional_standards": True,
                    "expert_methodology": "ai_brain_enhanced_cybersecurity_expert",
                    "ai_confidence_average": sum([
                        ai_strategy.get('confidence', 0.8),
                        agent_decision.get('confidence', 0.8),
                        threat_assessment.get('confidence', 0.8),
                        reporting_strategy.get('confidence', 0.8)
                    ]) / 4
                }
            }
            
        except Exception as e:
            logger.error(f"❌ AI-Brain enhanced professional assessment failed: {e}")
            raise
    
    async def _create_ai_execution_plan(self, target: str, ai_analysis: Dict[str, Any], agent_decision: Dict[str, Any]) -> List[AgentTask]:
        """Create AI-optimized execution plan based on AI Brain decisions"""
        tasks = []
        recommended_agents = agent_decision.get("recommended_agents", [])
        
        for i, agent_name in enumerate(recommended_agents):
            # Map agent names to types
            agent_type_mapping = {
                "ReconAgent": AgentType.RECONNAISSANCE,
                "SubfinderAgent": AgentType.SUBDOMAIN_DISCOVERY,
                "NaabuAgent": AgentType.PORT_SCANNING,
                "HttpxAgent": AgentType.WEB_TECHNOLOGY,
                "NucleiAgent": AgentType.NUCLEI_SCANNING,
                "ExploitAgent": AgentType.EXPLOIT,
                "SQLInjectionAgent": AgentType.VULNERABILITY,
                "XSSAgent": AgentType.VULNERABILITY,
                "ReportAgent": AgentType.REPORT_GENERATOR
            }
            
            agent_type = agent_type_mapping.get(agent_name, AgentType.RECONNAISSANCE)
            
            # Create task dependencies based on AI recommendations
            dependencies = []
            if i > 0:
                dependencies = [tasks[-1].id]  # Depend on previous task
            
            # Set priority based on AI decision
            priority_mapping = {
                "critical": TaskPriority.CRITICAL,
                "high": TaskPriority.HIGH,
                "medium": TaskPriority.MEDIUM,
                "low": TaskPriority.LOW
            }
            
            priority = priority_mapping.get(agent_decision.get("priority_level", "medium"), TaskPriority.MEDIUM)
            
            task = AgentTask(
                id=str(uuid.uuid4()),
                agent_type=agent_type,
                priority=priority,
                target_data={"target": target, "ai_context": ai_analysis, "ai_decision": agent_decision},
                dependencies=dependencies,
                config={
                    **ai_analysis.get("resource_allocation", {}),
                    "ai_guided": True,
                    "expert_mode": True
                },
                created_at=datetime.utcnow()
            )
            
            tasks.append(task)
            logger.info(f"📋 AI-Created task: {agent_name} - Priority: {priority.value}")
        
        return tasks
    
    async def _ai_orchestrate_agents(self, tasks: List[AgentTask], scan_data: Dict[str, Any], ai_strategy: Dict[str, Any]) -> Dict[str, Any]:
        """AI-supervised agent orchestration with real-time decision making"""
        results = {}
        
        # Execute tasks based on AI strategy and dependencies
        remaining_tasks = tasks.copy()
        
        while remaining_tasks and not self.is_cancelled():
            # Find tasks that can be executed (no unmet dependencies)
            ready_tasks = [
                task for task in remaining_tasks
                if all(dep_id in [completed.id for completed in self.completed_tasks] 
                      for dep_id in task.dependencies)
            ]
            
            if not ready_tasks:
                logger.warning("⚠️ No ready tasks found, breaking execution loop")
                break
            
            # Execute ready tasks (up to max concurrent)
            concurrent_tasks = ready_tasks[:self.max_concurrent_agents]
            
            for task in concurrent_tasks:
                logger.info(f"🚀 AI-Supervised starting agent: {task.agent_type.value}")
                
                # Get AI guidance for this specific agent execution
                execution_context = {
                    "task": asdict(task),
                    "current_results": results,
                    "phase": "agent_execution",
                    "target": scan_data.get("target", "unknown")
                }
                
                # AI Brain can provide real-time guidance
                try:
                    ai_guidance = await get_ai_decision(DecisionType.AGENT_SELECTION, execution_context)
                    logger.info(f"🧠 AI Guidance for {task.agent_type.value}: {ai_guidance.get('decision', 'proceed')}")
                except Exception as e:
                    logger.warning(f"⚠️ AI guidance failed for {task.agent_type.value}: {e}")
                    ai_guidance = {"decision": "proceed"}
                
                result = await self._execute_agent_task(task, scan_data)
                results[task.agent_type.value] = result
                
                task.status = AgentStatus.COMPLETED
                task.completed_at = datetime.utcnow()
                task.result = result
                
                self.completed_tasks.append(task)
                remaining_tasks.remove(task)
        
        return results
    
    async def _ai_aggregate_and_analyze_results(self, results: Dict[str, Any], ai_analysis: Dict[str, Any], ai_results_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """AI-powered result aggregation with expert analysis"""
        aggregated = {
            "subdomains": [],
            "open_ports": {},
            "technologies": {},
            "vulnerabilities": [],
            "secrets": [],
            "security_score": 0,
            "recommendations": [],
            "ai_insights": ai_results_analysis
        }
        
        # Aggregate results from all agents
        for agent_type, result in results.items():
            if isinstance(result, dict) and "error" not in result:
                if "subdomains" in result:
                    aggregated["subdomains"].extend(result["subdomains"])
                if "ports" in result:
                    aggregated["open_ports"].update(result["ports"])
                if "technologies" in result:
                    aggregated["technologies"].update(result["technologies"])
                if "vulnerabilities" in result:
                    aggregated["vulnerabilities"].extend(result["vulnerabilities"])
                if "secrets" in result:
                    aggregated["secrets"].extend(result["secrets"])
        
        # AI-powered analysis and scoring
        aggregated["security_score"] = self._calculate_risk_score(aggregated)
        
        # Get AI recommendations based on results
        recommendation_context = {
            "aggregated_results": aggregated,
            "vulnerabilities": aggregated["vulnerabilities"],
            "phase": "recommendation_generation"
        }
        
        try:
            ai_recommendations = await get_ai_decision(DecisionType.VULNERABILITY_ASSESSMENT, recommendation_context)
            aggregated["recommendations"] = ai_recommendations.get("next_steps", [])
            aggregated["ai_risk_assessment"] = ai_recommendations.get("risk_assessment", "Standard risk level")
        except Exception as e:
            logger.warning(f"⚠️ AI recommendation generation failed: {e}")
            aggregated["recommendations"] = await self._generate_ai_recommendations(aggregated, ai_analysis)
        
        return aggregated
    
    async def _generate_ai_intelligent_report(self, results: Dict[str, Any], ai_analysis: Dict[str, Any], reporting_strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI-optimized intelligent report"""
        return {
            "executive_summary": {
                "risk_level": self._get_risk_level(results["security_score"]),
                "total_findings": len(results.get("vulnerabilities", [])) + len(results.get("secrets", [])),
                "key_recommendations": reporting_strategy.get("next_steps", results.get("recommendations", []))[:3],
                "ai_confidence": reporting_strategy.get("confidence", 0.85),
                "methodology": "ai_brain_enhanced_expert_assessment"
            },
            "detailed_findings": {
                "vulnerabilities": results.get("vulnerabilities", []),
                "secrets": results.get("secrets", []),
                "infrastructure": {
                    "subdomains": results.get("subdomains", []),
                    "open_ports": results.get("open_ports", {}),
                    "technologies": results.get("technologies", {})
                }
            },
            "ai_insights": {
                "target_classification": ai_analysis.get("decision", "Unknown"),
                "risk_assessment": reporting_strategy.get("risk_assessment", "AI-assessed risk"),
                "confidence_score": reporting_strategy.get("confidence", 0.85),
                "expert_recommendations": reporting_strategy.get("next_steps", []),
                "methodology_effectiveness": "ai_optimized"
            },
            "reporting_strategy": reporting_strategy
        }
    
    async def _create_execution_plan(self, target: str, ai_analysis: Dict[str, Any]) -> List[AgentTask]:
        """Create an optimized execution plan based on AI analysis (legacy method)"""
        # This method is kept for backward compatibility
        return await self._create_ai_execution_plan(target, ai_analysis, {"recommended_agents": ["ReconAgent", "ExploitAgent"]})
    
    async def _orchestrate_agents(self, tasks: List[AgentTask], scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate the execution of all agents (legacy method)"""
        # This method is kept for backward compatibility
        return await self._ai_orchestrate_agents(tasks, scan_data, {"decision": "standard_orchestration"})
    
    async def _execute_agent_task(self, task: AgentTask, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific agent task"""
        agent_type = task.agent_type
        
        try:
            # Import and instantiate the appropriate agent
            agent = await self._get_agent_instance(agent_type)
            
            # Prepare agent-specific data
            agent_data = {**scan_data, **task.target_data, "config": task.config}
            
            # Execute the agent
            task.status = AgentStatus.RUNNING
            task.started_at = datetime.utcnow()
            
            result = await agent.execute(agent_data)
            
            logger.info(f"✅ Agent {agent_type.value} completed successfully")
            return result
            
        except Exception as e:
            logger.error(f"❌ Agent {agent_type.value} failed: {e}")
            task.status = AgentStatus.FAILED
            task.error = str(e)
            return {"error": str(e)}
    
    async def _get_agent_instance(self, agent_type: AgentType) -> BaseAgent:
        """Get an instance of the specified agent type"""
        # Dynamic agent imports based on type
        if agent_type == AgentType.SUBDOMAIN_DISCOVERY:
            from agents.reconnaissance_agents.subfinder_agent import SubfinderAgent
            return SubfinderAgent()
        elif agent_type == AgentType.PORT_SCANNING:
            from agents.reconnaissance_agents.naabu_agent import NaabuAgent
            return NaabuAgent()
        elif agent_type == AgentType.WEB_TECHNOLOGY:
            from agents.reconnaissance_agents.httpx_agent import HttpxAgent
            return HttpxAgent()
        elif agent_type == AgentType.NUCLEI_SCANNING:
            from agents.vulnerability_agents.nuclei_agent import NucleiAgent
            return NucleiAgent()
        elif agent_type == AgentType.SECRET_SCANNING:
            from agents.vulnerability_agents.secret_agent import SecretAgent
            return SecretAgent()
        elif agent_type == AgentType.GITHUB_INTELLIGENCE:
            from agents.reconnaissance_agents.github_agent import GitHubAgent
            return GitHubAgent()
        else:
            # Fallback to existing agents
            from agents.recon_agent import ReconAgent
            return ReconAgent()
    
    async def _aggregate_and_analyze_results(self, results: Dict[str, Any], ai_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """AI-powered result aggregation and correlation analysis"""
        aggregated = {
            "subdomains": [],
            "open_ports": {},
            "technologies": {},
            "vulnerabilities": [],
            "secrets": [],
            "security_score": 0,
            "recommendations": []
        }
        
        # Aggregate results from all agents
        for agent_type, result in results.items():
            if isinstance(result, dict) and "error" not in result:
                if "subdomains" in result:
                    aggregated["subdomains"].extend(result["subdomains"])
                if "ports" in result:
                    aggregated["open_ports"].update(result["ports"])
                if "technologies" in result:
                    aggregated["technologies"].update(result["technologies"])
                if "vulnerabilities" in result:
                    aggregated["vulnerabilities"].extend(result["vulnerabilities"])
                if "secrets" in result:
                    aggregated["secrets"].extend(result["secrets"])
        
        # AI-powered correlation analysis
        aggregated["security_score"] = self._calculate_risk_score(aggregated)
        aggregated["recommendations"] = await self._generate_ai_recommendations(aggregated, ai_analysis)
        
        return aggregated
    
    def _calculate_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall security risk score (0-100)"""
        score = 0
        
        # Vulnerability scoring
        vulns = results.get("vulnerabilities", [])
        for vuln in vulns:
            severity = vuln.get("severity", "low").lower()
            if severity == "critical":
                score += 25
            elif severity == "high":
                score += 15
            elif severity == "medium":
                score += 8
            elif severity == "low":
                score += 3
        
        # Secret exposure scoring
        secrets = results.get("secrets", [])
        score += len(secrets) * 10
        
        # Open service scoring
        ports = results.get("open_ports", {})
        total_open_ports = sum(len(port_list) for port_list in ports.values())
        score += min(total_open_ports * 2, 20)
        
        return min(score, 100)
    
    async def _generate_ai_recommendations(self, results: Dict[str, Any], ai_analysis: Dict[str, Any]) -> List[str]:
        """Generate AI-powered security recommendations"""
        recommendations = []
        
        # Vulnerability-based recommendations
        vulns = results.get("vulnerabilities", [])
        critical_vulns = [v for v in vulns if v.get("severity") == "critical"]
        if critical_vulns:
            recommendations.append(
                f"🚨 CRITICAL: {len(critical_vulns)} critical vulnerabilities found - immediate remediation required"
            )
        
        # Port security recommendations
        open_ports = results.get("open_ports", {})
        risky_ports = []
        for host, ports in open_ports.items():
            risky_ports.extend([p for p in ports if p in [21, 23, 135, 139, 445, 3389]])
        
        if risky_ports:
            recommendations.append(
                f"⚠️ High-risk services detected on ports {risky_ports} - consider restricting access"
            )
        
        # Secret exposure recommendations
        secrets = results.get("secrets", [])
        if secrets:
            recommendations.append(
                f"🔐 {len(secrets)} potential secrets found - review and rotate credentials immediately"
            )
        
        return recommendations
    
    async def _generate_intelligent_report(self, results: Dict[str, Any], ai_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive AI-powered security report"""
        return {
            "executive_summary": {
                "risk_level": self._get_risk_level(results["security_score"]),
                "total_findings": len(results.get("vulnerabilities", [])) + len(results.get("secrets", [])),
                "key_recommendations": results.get("recommendations", [])[:3]
            },
            "detailed_findings": {
                "vulnerabilities": results.get("vulnerabilities", []),
                "secrets": results.get("secrets", []),
                "infrastructure": {
                    "subdomains": results.get("subdomains", []),
                    "open_ports": results.get("open_ports", {}),
                    "technologies": results.get("technologies", {})
                }
            },
            "ai_insights": {
                "target_classification": ai_analysis.get("target_type"),
                "risk_assessment": ai_analysis.get("risk_assessment"),
                "confidence_score": ai_analysis.get("confidence_score", 0.8)
            }
        }
    
    def _get_risk_level(self, score: float) -> str:
        """Convert numeric risk score to risk level"""
        if score >= 70:
            return "Critical"
        elif score >= 40:
            return "High"
        elif score >= 20:
            return "Medium"
        else:
            return "Low"
    
    def _calculate_efficiency_score(self) -> float:
        """Calculate scan efficiency score"""
        if not self.completed_tasks:
            return 0.0
        
        successful_tasks = [t for t in self.completed_tasks if t.status == AgentStatus.COMPLETED]
        return (len(successful_tasks) / len(self.completed_tasks)) * 100


class ResourceMonitor:
    """Monitor and manage system resources during agent execution"""
    
    def __init__(self):
        self.cpu_usage = 0.0
        self.memory_usage = 0.0
        self.active_agents = 0
    
    async def check_resources(self) -> Dict[str, float]:
        """Check current system resource usage"""
        # Placeholder for resource monitoring
        return {
            "cpu_percent": self.cpu_usage,
            "memory_percent": self.memory_usage,
            "active_agents": self.active_agents
        }
    
    def can_start_agent(self) -> bool:
        """Determine if system can handle starting another agent"""
        return self.active_agents < 5 and self.cpu_usage < 80 and self.memory_usage < 90
