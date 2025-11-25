"""
AI Brain - The Central Intelligence System for Nexus Hunter
Acts as the master controller with 5+ years bug bounty expertise
Uses Gemini API or Cursor background agent for real-time decision making
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, asdict
import uuid
import os

from loguru import logger

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    logger.warning("Google Gemini AI not available - using fallback intelligence")


class IntelligenceLevel(str, Enum):
    """AI Intelligence levels"""
    EXPERT = "expert"           # 5+ years bug bounty expert
    ADVANCED = "advanced"       # 3-5 years experience
    INTERMEDIATE = "intermediate" # 1-3 years experience
    BASIC = "basic"            # Beginner level


class DecisionType(str, Enum):
    """Types of decisions the AI brain makes"""
    SCAN_STRATEGY = "scan_strategy"
    AGENT_SELECTION = "agent_selection"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    EXPLOITATION_APPROACH = "exploitation_approach"
    REPORTING_STRATEGY = "reporting_strategy"
    RISK_PRIORITIZATION = "risk_prioritization"
    WORKFLOW_OPTIMIZATION = "workflow_optimization"


@dataclass
class SystemArchitecture:
    """Standardized system architecture tree for prompts"""
    brain: Dict[str, Any]
    agents: Dict[str, Dict[str, Any]]
    workflows: Dict[str, Any]
    tools: Dict[str, Any]
    capabilities: Dict[str, Any]
    
    def to_prompt_context(self) -> str:
        """Convert architecture to prompt context"""
        return f"""
NEXUS HUNTER SYSTEM ARCHITECTURE:

🧠 AI BRAIN (Central Controller):
- Role: Master decision maker with 5+ years bug bounty expertise
- Capabilities: {', '.join(self.brain.get('capabilities', []))}
- Intelligence Level: {self.brain.get('level', 'expert')}

🤖 AGENT HIERARCHY:
{self._format_agents()}

⚙️ WORKFLOW ENGINE:
{self._format_workflows()}

🛠️ AVAILABLE TOOLS:
{self._format_tools()}

🎯 SYSTEM CAPABILITIES:
{self._format_capabilities()}
"""
    
    def _format_agents(self) -> str:
        """Format agents for prompt"""
        result = ""
        for category, agents in self.agents.items():
            result += f"\n  📂 {category.upper()}:\n"
            for agent_name, agent_info in agents.items():
                result += f"    • {agent_name}: {agent_info.get('description', 'N/A')}\n"
        return result
    
    def _format_workflows(self) -> str:
        """Format workflows for prompt"""
        result = ""
        for workflow_name, workflow_info in self.workflows.items():
            result += f"  • {workflow_name}: {workflow_info.get('description', 'N/A')}\n"
        return result
    
    def _format_tools(self) -> str:
        """Format tools for prompt"""
        result = ""
        for tool_category, tools in self.tools.items():
            result += f"  📦 {tool_category}: {', '.join(tools)}\n"
        return result
    
    def _format_capabilities(self) -> str:
        """Format capabilities for prompt"""
        result = ""
        for capability, details in self.capabilities.items():
            result += f"  ✅ {capability}: {details.get('description', 'N/A')}\n"
        return result


class AIBrain:
    """
    Central AI Brain - Master Controller with Security Expert Intelligence
    
    This system acts as the brain of Nexus Hunter with the expertise of a 
    5+ year bug bounty hunter, making intelligent decisions about:
    - Scan strategies and agent selection
    - Vulnerability assessment approaches  
    - Exploitation techniques and safety
    - Report generation strategies
    - Real-time workflow optimization
    """
    
    def __init__(self):
        self.intelligence_level = IntelligenceLevel.EXPERT
        self.decision_history: List[Dict[str, Any]] = []
        self.system_architecture = self._initialize_architecture()
        self.gemini_model = None
        self.active_context: Dict[str, Any] = {}
        
        # Initialize Gemini AI if available
        self._initialize_gemini()
        
        # Security expert persona
        self.expert_persona = {
            "years_experience": 5,
            "specializations": [
                "Web Application Security", "API Security", "Network Penetration Testing",
                "Business Logic Vulnerabilities", "Advanced Exploitation Techniques",
                "Responsible Disclosure", "Bug Bounty Hunting", "OWASP Top 10",
                "Zero-day Discovery", "Social Engineering", "Mobile Security"
            ],
            "mindset": "methodical, thorough, ethical, results-driven",
            "approach": "comprehensive reconnaissance → targeted exploitation → responsible disclosure"
        }
        
        logger.info(f"🧠 AI Brain initialized with {self.intelligence_level} level intelligence")
    
    def _initialize_gemini(self):
        """Initialize Gemini AI if available"""
        if GEMINI_AVAILABLE:
            try:
                api_key = os.getenv('GEMINI_API_KEY')
                if api_key:
                    genai.configure(api_key=api_key)
                    self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
                    logger.info("🤖 Gemini AI initialized successfully")
                else:
                    logger.warning("🔑 GEMINI_API_KEY not found - using fallback intelligence")
            except Exception as e:
                logger.error(f"❌ Failed to initialize Gemini AI: {e}")
    
    def _initialize_architecture(self) -> SystemArchitecture:
        """Initialize the standardized system architecture"""
        return SystemArchitecture(
            brain={
                "level": "expert",
                "capabilities": [
                    "strategic_planning", "agent_orchestration", "vulnerability_analysis",
                    "exploitation_guidance", "report_generation", "risk_assessment"
                ],
                "decision_types": [dt.value for dt in DecisionType]
            },
            agents={
                "reconnaissance": {
                    "ReconAgent": {"description": "Orchestrates all reconnaissance agents"},
                    "SubfinderAgent": {"description": "Subdomain discovery"},
                    "AmassAgent": {"description": "Advanced subdomain enumeration"},
                    "NaabuAgent": {"description": "Port scanning"},
                    "HttpxAgent": {"description": "HTTP service detection"},
                    "OSINTAgent": {"description": "Open source intelligence"},
                    "GitHubAgent": {"description": "Code repository analysis"}
                },
                "exploitation": {
                    "ExploitAgent": {"description": "Orchestrates all exploitation agents"},
                    "SQLInjectionAgent": {"description": "SQL injection testing"},
                    "XSSAgent": {"description": "Cross-site scripting testing"},
                    "SSRFAgent": {"description": "Server-side request forgery"},
                    "RCEAgent": {"description": "Remote code execution"},
                    "BusinessLogicAgent": {"description": "Business logic vulnerabilities"}
                },
                "vulnerability_assessment": {
                    "NucleiAgent": {"description": "Comprehensive vulnerability scanning"},
                    "FfufAgent": {"description": "Web fuzzing"},
                    "Wafw00fAgent": {"description": "WAF detection"},
                    "SecretAgent": {"description": "Secret and credential scanning"}
                },
                "reporting": {
                    "ReportAgent": {"description": "Orchestrates all reporting agents"},
                    "ExecutiveReportAgent": {"description": "Business-focused reports"},
                    "TechnicalReportAgent": {"description": "Technical vulnerability reports"},
                    "DisclosureReportAgent": {"description": "Responsible disclosure"}
                }
            },
            workflows={
                "reconnaissance": {"description": "Comprehensive information gathering"},
                "vulnerability_exploitation": {"description": "Safe vulnerability testing"},
                "reporting": {"description": "Professional report generation"},
                "full_assessment": {"description": "Complete security assessment"}
            },
            tools={
                "reconnaissance": ["subfinder", "amass", "naabu", "httpx", "gau", "katana"],
                "vulnerability_scanning": ["nuclei", "ffuf", "wafw00f", "sqlmap"],
                "exploitation": ["custom_payloads", "safe_exploitation", "poc_generation"],
                "reporting": ["jinja2_templates", "pdf_generation", "html_reports"]
            },
            capabilities={
                "autonomous_scanning": {"description": "Fully autonomous security assessments"},
                "intelligent_agent_selection": {"description": "AI-driven agent orchestration"},
                "real_time_decisions": {"description": "Dynamic workflow optimization"},
                "expert_analysis": {"description": "5+ years bug bounty expertise"},
                "safe_exploitation": {"description": "Ethical vulnerability testing"},
                "professional_reporting": {"description": "Industry-standard reports"}
            }
        )
    
    async def make_decision(self, decision_type: DecisionType, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make an intelligent decision based on context and expert knowledge
        
        Args:
            decision_type: Type of decision to make
            context: Current context and data
            
        Returns:
            Decision with reasoning and recommendations
        """
        logger.info(f"🧠 Making {decision_type} decision with expert analysis")
        
        # Update active context
        self.active_context.update(context)
        
        # Create expert prompt
        prompt = self._create_expert_prompt(decision_type, context)
        
        # Get AI decision
        if self.gemini_model:
            decision = await self._get_gemini_decision(prompt)
        else:
            decision = await self._get_fallback_decision(decision_type, context)
        
        # Log decision
        decision_record = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "type": decision_type.value,
            "context": context,
            "decision": decision,
            "confidence": decision.get("confidence", 0.8)
        }
        
        self.decision_history.append(decision_record)
        
        logger.info(f"✅ Decision made with {decision.get('confidence', 0.8)*100:.1f}% confidence")
        return decision
    
    def _create_expert_prompt(self, decision_type: DecisionType, context: Dict[str, Any]) -> str:
        """Create expert-level prompt for AI decision making"""
        
        base_prompt = f"""
You are a SENIOR CYBERSECURITY EXPERT with 5+ years of professional bug bounty hunting experience.

EXPERTISE PROFILE:
- 5+ years in bug bounty hunting and penetration testing
- Specializations: {', '.join(self.expert_persona['specializations'])}
- Mindset: {self.expert_persona['mindset']}
- Approach: {self.expert_persona['approach']}

{self.system_architecture.to_prompt_context()}

CURRENT SITUATION:
Decision Type: {decision_type.value}
Target: {context.get('target', 'Unknown')}
Current Phase: {context.get('phase', 'Unknown')}
Available Data: {json.dumps(context, indent=2, default=str)}

EXPERT REQUIREMENTS:
1. Think like a seasoned bug bounty hunter
2. Prioritize high-impact vulnerabilities
3. Consider business context and risk
4. Recommend optimal agent combinations
5. Ensure ethical and safe testing approaches
6. Focus on actionable intelligence

RESPONSE FORMAT (JSON):
{{
    "decision": "specific_recommendation",
    "reasoning": "expert_analysis_with_technical_details",
    "recommended_agents": ["agent1", "agent2"],
    "priority_level": "critical|high|medium|low",
    "confidence": 0.0-1.0,
    "next_steps": ["step1", "step2"],
    "risk_assessment": "risk_analysis",
    "expected_outcomes": ["outcome1", "outcome2"],
    "expert_notes": "additional_professional_insights"
}}

"""
        
        # Add decision-specific context
        if decision_type == DecisionType.SCAN_STRATEGY:
            base_prompt += self._get_scan_strategy_context(context)
        elif decision_type == DecisionType.AGENT_SELECTION:
            base_prompt += self._get_agent_selection_context(context)
        elif decision_type == DecisionType.VULNERABILITY_ASSESSMENT:
            base_prompt += self._get_vulnerability_context(context)
        elif decision_type == DecisionType.EXPLOITATION_APPROACH:
            base_prompt += self._get_exploitation_context(context)
        elif decision_type == DecisionType.REPORTING_STRATEGY:
            base_prompt += self._get_reporting_context(context)
        
        return base_prompt
    
    def _get_scan_strategy_context(self, context: Dict[str, Any]) -> str:
        """Add scan strategy specific context"""
        return """
SCAN STRATEGY DECISION:
Consider:
- Target type and complexity
- Available time and resources
- Compliance requirements
- Previous scan results
- Business criticality

Recommend optimal scanning approach, agent sequence, and resource allocation.
"""
    
    def _get_agent_selection_context(self, context: Dict[str, Any]) -> str:
        """Add agent selection specific context"""
        return """
AGENT SELECTION DECISION:
Consider:
- Current scan phase
- Available agents and tools
- Target characteristics
- Previous results
- Resource constraints

Select the most effective agents for current objectives.
"""
    
    def _get_vulnerability_context(self, context: Dict[str, Any]) -> str:
        """Add vulnerability assessment context"""
        return """
VULNERABILITY ASSESSMENT DECISION:
Consider:
- Discovered vulnerabilities
- Severity and exploitability
- Business impact
- Remediation complexity
- Disclosure timeline

Prioritize vulnerabilities and recommend next actions.
"""
    
    def _get_exploitation_context(self, context: Dict[str, Any]) -> str:
        """Add exploitation approach context"""
        return """
EXPLOITATION APPROACH DECISION:
Consider:
- Vulnerability type and severity
- Safe exploitation methods
- Proof-of-concept requirements
- Legal and ethical boundaries
- Impact demonstration

Recommend safe and effective exploitation approach.
"""
    
    def _get_reporting_context(self, context: Dict[str, Any]) -> str:
        """Add reporting strategy context"""
        return """
REPORTING STRATEGY DECISION:
Consider:
- Audience (technical vs executive)
- Vulnerability severity
- Business impact
- Disclosure requirements
- Remediation guidance

Recommend optimal reporting approach and content.
"""
    
    async def _get_gemini_decision(self, prompt: str) -> Dict[str, Any]:
        """Get decision from Gemini AI"""
        try:
            response = await asyncio.to_thread(
                self.gemini_model.generate_content, prompt
            )
            
            # Parse JSON response
            response_text = response.text.strip()
            if response_text.startswith('```json'):
                response_text = response_text[7:-3].strip()
            elif response_text.startswith('```'):
                response_text = response_text[3:-3].strip()
            
            decision = json.loads(response_text)
            decision["source"] = "gemini_ai"
            
            return decision
            
        except Exception as e:
            logger.error(f"❌ Gemini AI decision failed: {e}")
            return await self._get_fallback_decision(DecisionType.SCAN_STRATEGY, {})
    
    async def _get_fallback_decision(self, decision_type: DecisionType, context: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback decision making using built-in expert logic"""
        
        target = context.get('target', 'unknown')
        phase = context.get('phase', 'initial')
        
        # Expert decision based on built-in knowledge
        if decision_type == DecisionType.SCAN_STRATEGY:
            return {
                "decision": "comprehensive_scan_with_reconnaissance_first",
                "reasoning": "As a bug bounty expert, always start with thorough reconnaissance to map the attack surface before exploitation",
                "recommended_agents": ["ReconAgent", "ExploitAgent", "ReportAgent"],
                "priority_level": "high",
                "confidence": 0.85,
                "next_steps": [
                    "Execute subdomain discovery",
                    "Perform port scanning",
                    "Identify web technologies",
                    "Begin vulnerability assessment"
                ],
                "risk_assessment": "Standard reconnaissance poses minimal risk while providing maximum intelligence",
                "expected_outcomes": [
                    "Complete attack surface mapping",
                    "Technology stack identification",
                    "Initial vulnerability discovery"
                ],
                "expert_notes": "This approach follows industry best practices for bug bounty hunting",
                "source": "fallback_expert_logic"
            }
        
        elif decision_type == DecisionType.AGENT_SELECTION:
            if phase == "reconnaissance":
                return {
                    "decision": "multi_agent_reconnaissance_approach",
                    "reasoning": "Use multiple reconnaissance agents for comprehensive coverage and cross-validation",
                    "recommended_agents": ["SubfinderAgent", "AmassAgent", "NaabuAgent", "HttpxAgent"],
                    "priority_level": "high",
                    "confidence": 0.9,
                    "next_steps": ["Execute parallel reconnaissance", "Correlate results", "Identify high-value targets"],
                    "risk_assessment": "Low risk - passive reconnaissance techniques",
                    "expected_outcomes": ["Comprehensive subdomain list", "Open port inventory", "Service fingerprints"],
                    "expert_notes": "Parallel execution improves speed while maintaining thoroughness",
                    "source": "fallback_expert_logic"
                }
        
        # Default fallback
        return {
            "decision": "proceed_with_standard_approach",
            "reasoning": "Using standard security assessment methodology",
            "recommended_agents": ["ReconAgent"],
            "priority_level": "medium",
            "confidence": 0.7,
            "next_steps": ["Continue with current approach"],
            "risk_assessment": "Standard risk level",
            "expected_outcomes": ["Standard results"],
            "expert_notes": "Fallback decision - consider manual review",
            "source": "fallback_expert_logic"
        }
    
    async def analyze_scan_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan results with expert intelligence"""
        
        analysis_context = {
            "results": results,
            "phase": "analysis",
            "target": results.get("target", "unknown")
        }
        
        return await self.make_decision(DecisionType.VULNERABILITY_ASSESSMENT, analysis_context)
    
    async def optimize_workflow(self, current_workflow: Dict[str, Any], performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize workflow based on performance data"""
        
        optimization_context = {
            "current_workflow": current_workflow,
            "performance_data": performance_data,
            "phase": "optimization"
        }
        
        return await self.make_decision(DecisionType.WORKFLOW_OPTIMIZATION, optimization_context)
    
    async def plan_exploitation(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Plan safe exploitation approach"""
        
        exploitation_context = {
            "vulnerabilities": vulnerabilities,
            "phase": "exploitation_planning",
            "safety_requirements": "ethical_testing_only"
        }
        
        return await self.make_decision(DecisionType.EXPLOITATION_APPROACH, exploitation_context)
    
    async def generate_report_strategy(self, scan_data: Dict[str, Any], audience: str = "mixed") -> Dict[str, Any]:
        """Generate intelligent reporting strategy"""
        
        reporting_context = {
            "scan_data": scan_data,
            "audience": audience,
            "phase": "reporting",
            "vulnerabilities": scan_data.get("vulnerabilities", [])
        }
        
        return await self.make_decision(DecisionType.REPORTING_STRATEGY, reporting_context)
    
    def get_decision_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent decision history"""
        return self.decision_history[-limit:]
    
    def get_system_architecture(self) -> SystemArchitecture:
        """Get the system architecture for prompts"""
        return self.system_architecture
    
    async def continuous_monitoring(self):
        """Continuous background monitoring and decision making"""
        logger.info("🧠 Starting continuous AI monitoring")
        
        while True:
            try:
                # Monitor system health
                # Make proactive decisions
                # Optimize ongoing operations
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"❌ Continuous monitoring error: {e}")
                await asyncio.sleep(60)  # Back off on error


# Global AI Brain instance
ai_brain = AIBrain()


async def get_ai_decision(decision_type: DecisionType, context: Dict[str, Any]) -> Dict[str, Any]:
    """Global function to get AI decisions"""
    return await ai_brain.make_decision(decision_type, context)


async def start_ai_brain():
    """Start the AI brain background monitoring"""
    await ai_brain.continuous_monitoring()





