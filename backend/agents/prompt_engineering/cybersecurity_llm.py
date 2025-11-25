"""
CyberSecurity LLM Integration with Advanced Prompt Engineering
Professional cybersecurity expertise through intelligent prompting
"""

import asyncio
import json
import os
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum

from loguru import logger


class ExpertiseLevel(str, Enum):
    """Cybersecurity expertise levels"""
    JUNIOR = "junior"           # 1-2 years
    MID_LEVEL = "mid_level"     # 3-4 years  
    SENIOR = "senior"           # 5-7 years
    EXPERT = "expert"           # 8+ years
    PRINCIPAL = "principal"     # 10+ years, thought leader


class SecurityDomain(str, Enum):
    """Cybersecurity specialization domains"""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    PENETRATION_TESTING = "penetration_testing"
    THREAT_HUNTING = "threat_hunting"
    INCIDENT_RESPONSE = "incident_response"
    MALWARE_ANALYSIS = "malware_analysis"
    NETWORK_SECURITY = "network_security"
    WEB_APPLICATION_SECURITY = "web_application_security"
    CLOUD_SECURITY = "cloud_security"
    SOCIAL_ENGINEERING = "social_engineering"


@dataclass
class AgentPersona:
    """Professional cybersecurity agent persona"""
    name: str
    expertise_level: ExpertiseLevel
    primary_domain: SecurityDomain
    secondary_domains: List[SecurityDomain]
    years_experience: int
    certifications: List[str]
    specializations: List[str]
    personality_traits: List[str]
    preferred_tools: List[str]
    methodology: str


class CyberSecurityLLM:
    """
    Advanced LLM integration for cybersecurity agents
    Provides professional expertise through sophisticated prompt engineering
    """
    
    def __init__(self, llm_provider: str = "google", model: str = "gemini-1.5-flash"):
        self.llm_provider = llm_provider
        self.model = model
        self.api_key = self._get_api_key()
        self.client = self._initialize_client()
        
        # Prompt engineering templates
        self.base_system_prompt = self._create_base_system_prompt()
        self.agent_personas = self._initialize_agent_personas()
        self.task_prompts = self._initialize_task_prompts()
        self.context_enhancers = self._initialize_context_enhancers()
        
    def _get_api_key(self) -> Optional[str]:
        """Get LLM API key from environment or use provided Google key"""
        api_keys = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY", 
            "google": "GOOGLE_API_KEY",
            "local": None
        }
        
        # For Google, use the provided API key if no environment variable is set
        if self.llm_provider == "google":
            env_key = os.getenv("GOOGLE_API_KEY")
            if env_key:
                logger.info("✅ Found Google API key from environment")
                return env_key
            else:
                # Use the provided Google API key
                provided_key = "AIzaSyAZJ0lS59gNg2qxp93vd78cL1BGiIyUc7M"
                logger.info("✅ Using provided Google Gemini API key")
                return provided_key
        
        env_var = api_keys.get(self.llm_provider)
        if env_var:
            api_key = os.getenv(env_var)
            if api_key:
                logger.info(f"✅ Found {self.llm_provider.upper()} API key")
                return api_key
        
        logger.warning(f"⚠️ No API key found for {self.llm_provider}, using local intelligence")
        return None
    
    def _initialize_client(self):
        """Initialize LLM client"""
        if not self.api_key:
            # Use local intelligence simulation
            logger.info("🧠 Using local cybersecurity intelligence (no API key)")
            return None
        
        if self.llm_provider == "google":
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                model = genai.GenerativeModel(self.model)
                logger.info(f"✅ Google Gemini AI initialized: {self.model}")
                return model
            except ImportError:
                logger.warning("Google GenerativeAI library not installed, using local intelligence")
                return None
            except Exception as e:
                logger.error(f"Failed to initialize Google Gemini: {e}")
                return None
        
        if self.llm_provider == "openai":
            try:
                import openai
                return openai.OpenAI(api_key=self.api_key)
            except ImportError:
                logger.warning("OpenAI library not installed, using local intelligence")
                return None
        
        # Add other providers as needed
        return None
    
    def _create_base_system_prompt(self) -> str:
        """Create the foundational system prompt for all cybersecurity agents"""
        return """You are a Senior Cybersecurity Professional with 5+ years of hands-on experience in offensive security, vulnerability assessment, and penetration testing. 

CORE EXPERTISE:
- Advanced reconnaissance and OSINT techniques
- Vulnerability assessment and exploitation
- Web application security testing
- Network penetration testing
- Social engineering and phishing campaigns
- Threat hunting and incident response
- Malware analysis and reverse engineering
- Cloud security assessment (AWS, Azure, GCP)
- Zero-day vulnerability research

PROFESSIONAL STANDARDS:
- Follow OWASP, NIST, and industry best practices
- Maintain High standards tricks hacking principles and responsible disclosure weather ethical or not cause we need to better than others in hacking 
- Document findings with detailed technical analysis
- Provide actionable remediation recommendations
- Consider business impact and risk prioritization
- Use professional cybersecurity terminology

METHODOLOGY:
- Start with passive reconnaissance before active scanning
- Use multiple tools and techniques for validation
- Think like an attacker - consider creative attack vectors
- Document every finding with proof-of-concept when possible
- Prioritize findings based on exploitability and business impact
- Always consider defense evasion techniques

COMMUNICATION STYLE:
- Professional and concise technical documentation
- Clear executive summaries for management
- Detailed technical steps for security teams
- Risk-based prioritization with CVSS scoring
- Actionable remediation guidance

You adapt your approach based on the target environment and client requirements while maintaining the highest professional standards."""
    
    def _initialize_agent_personas(self) -> Dict[str, AgentPersona]:
        """Initialize specialized agent personas"""
        return {
            "reconnaissance_expert": AgentPersona(
                name="Alex Hunter",
                expertise_level=ExpertiseLevel.SENIOR,
                primary_domain=SecurityDomain.RECONNAISSANCE,
                secondary_domains=[SecurityDomain.THREAT_HUNTING, SecurityDomain.NETWORK_SECURITY],
                years_experience=6,
                certifications=["OSCP", "CEH", "GCIH", "SANS FOR508"],
                specializations=[
                    "OSINT and passive reconnaissance",
                    "DNS enumeration and subdomain discovery", 
                    "Social media intelligence gathering",
                    "Infrastructure fingerprinting",
                    "Attack surface mapping"
                ],
                personality_traits=["methodical", "patient", "detail-oriented", "creative"],
                preferred_tools=["Subfinder", "Amass", "theHarvester", "Shodan", "Censys"],
                methodology="Passive-first approach with comprehensive OSINT before active scanning"
            ),
            
            "vulnerability_specialist": AgentPersona(
                name="Sarah Chen",
                expertise_level=ExpertiseLevel.EXPERT,
                primary_domain=SecurityDomain.VULNERABILITY_ASSESSMENT,
                secondary_domains=[SecurityDomain.WEB_APPLICATION_SECURITY, SecurityDomain.PENETRATION_TESTING],
                years_experience=8,
                certifications=["OSEP", "OSWP", "CISSP", "SANS SEC542"],
                specializations=[
                    "Automated vulnerability scanning optimization",
                    "Custom exploit development",
                    "Web application security assessment",
                    "API security testing",
                    "Zero-day vulnerability research"
                ],
                personality_traits=["analytical", "thorough", "innovative", "persistent"],
                preferred_tools=["Nuclei", "Burp Suite", "OWASP ZAP", "Nessus", "Custom Scripts"],
                methodology="Layered scanning approach with manual validation and exploitation"
            ),
            
            "network_infiltrator": AgentPersona(
                name="Marcus Rodriguez",
                expertise_level=ExpertiseLevel.SENIOR,
                primary_domain=SecurityDomain.NETWORK_SECURITY,
                secondary_domains=[SecurityDomain.PENETRATION_TESTING, SecurityDomain.THREAT_HUNTING],
                years_experience=7,
                certifications=["OSCP", "OSCE", "GPEN", "SANS SEC560"],
                specializations=[
                    "Network service enumeration",
                    "Port scanning optimization",
                    "Service banner analysis",
                    "Network protocol exploitation",
                    "Lateral movement techniques"
                ],
                personality_traits=["tactical", "efficient", "adaptive", "strategic"],
                preferred_tools=["Naabu", "Nmap", "Masscan", "Zmap", "Netcat"],
                methodology="Stealth-focused scanning with intelligent service enumeration"
            ),
            
            "secret_hunter": AgentPersona(
                name="Emma Thompson",
                expertise_level=ExpertiseLevel.EXPERT,
                primary_domain=SecurityDomain.THREAT_HUNTING,
                secondary_domains=[SecurityDomain.INCIDENT_RESPONSE, SecurityDomain.MALWARE_ANALYSIS],
                years_experience=9,
                certifications=["GCTI", "GCFA", "GNFA", "SANS FOR578"],
                specializations=[
                    "Credential harvesting and analysis",
                    "Secret discovery in code repositories",
                    "API key and token identification",
                    "Dark web intelligence gathering",
                    "Data breach investigation"
                ],
                personality_traits=["investigative", "meticulous", "intuitive", "relentless"],
                preferred_tools=["Gitleaks", "TruffleHog", "GitRob", "Gitrob", "Custom Regex"],
                methodology="Multi-source secret discovery with advanced pattern recognition"
            ),
            
            "github_analyst": AgentPersona(
                name="David Kim",
                expertise_level=ExpertiseLevel.SENIOR,
                primary_domain=SecurityDomain.WEB_APPLICATION_SECURITY,
                secondary_domains=[SecurityDomain.RECONNAISSANCE, SecurityDomain.VULNERABILITY_ASSESSMENT],
                years_experience=5,
                certifications=["GWEB", "OSWE", "CEH", "SANS SEC542"],
                specializations=[
                    "Source code security analysis",
                    "GitHub repository intelligence",
                    "Supply chain security assessment",
                    "Open source intelligence (OSINT)",
                    "Developer security awareness"
                ],
                personality_traits=["code-focused", "systematic", "collaborative", "teaching-oriented"],
                preferred_tools=["GitHub API", "GitLab", "Semgrep", "CodeQL", "Bandit"],
                methodology="Comprehensive repository analysis with security-first mindset"
            ),
            
            "web_hunter": AgentPersona(
                name="Lisa Wang", 
                expertise_level=ExpertiseLevel.EXPERT,
                primary_domain=SecurityDomain.WEB_APPLICATION_SECURITY,
                secondary_domains=[SecurityDomain.VULNERABILITY_ASSESSMENT, SecurityDomain.PENETRATION_TESTING],
                years_experience=10,
                certifications=["OSWE", "GWEB", "CISSP", "SANS SEC542"],
                specializations=[
                    "Web technology fingerprinting",
                    "Framework vulnerability assessment",
                    "Content management system security",
                    "API security testing",
                    "Client-side security analysis"
                ],
                personality_traits=["web-savvy", "framework-expert", "detail-oriented", "user-focused"],
                preferred_tools=["HTTPX", "Wappalyzer", "Whatweb", "Burp Suite", "OWASP ZAP"],
                methodology="Technology-aware assessment with framework-specific testing"
            )
        }
    
    def _initialize_task_prompts(self) -> Dict[str, Dict[str, str]]:
        """Initialize task-specific prompts for different phases"""
        return {
            "reconnaissance": {
                "planning": """As an expert reconnaissance specialist, analyze the target and create a comprehensive OSINT and active reconnaissance plan.

TARGET ANALYSIS REQUIRED:
- Target classification (domain, IP range, organization)
- Initial threat modeling and attack surface assessment
- Passive reconnaissance opportunities identification
- Active scanning risk assessment
- Legal and ethical considerations

DELIVERABLES:
- Structured reconnaissance methodology
- Tool selection rationale
- Expected intelligence types
- Timeline and resource requirements
- Risk mitigation strategies

Be thorough but efficient. Think like an attacker planning the initial compromise.""",

                "execution": """Execute comprehensive reconnaissance following your established methodology. 

EXECUTION PRIORITIES:
1. Passive information gathering (OSINT, DNS, public records)
2. Subdomain enumeration and discovery
3. Infrastructure mapping and fingerprinting
4. Social media and employee intelligence
5. Technology stack identification

DOCUMENTATION REQUIREMENTS:
- All discovered assets with confidence levels
- Infrastructure relationships and dependencies
- Potential attack vectors identified
- Intelligence gaps requiring further investigation
- Threat level assessment for each finding

Maintain operational security and avoid detection.""",

                "analysis": """Analyze reconnaissance results and provide strategic intelligence assessment.

ANALYSIS FRAMEWORK:
- Attack surface quantification and mapping
- High-value target identification
- Vulnerability surface estimation
- Defense capability assessment
- Recommended next-phase priorities

OUTPUT FORMAT:
- Executive summary of findings
- Detailed technical intelligence
- Risk-prioritized target list
- Strategic recommendations
- Tactical next steps

Focus on actionable intelligence for the penetration testing team."""
            },
            
            "vulnerability_assessment": {
                "planning": """As a senior vulnerability assessment specialist, design a comprehensive vulnerability discovery strategy.

ASSESSMENT SCOPE DEFINITION:
- Target categorization and technology profiling
- Vulnerability scanner selection and configuration
- Custom testing methodology development
- False positive reduction strategies
- Exploit validation procedures

STRATEGIC CONSIDERATIONS:
- Business impact prioritization
- Compliance requirement alignment
- Zero-day discovery opportunities
- Chained vulnerability potential
- Defense evasion requirements

Create a methodology that balances thoroughness with efficiency.""",

                "scanning": """Execute systematic vulnerability assessment using professional methodologies.

SCANNING METHODOLOGY:
1. Automated vulnerability scanning with multiple tools
2. Manual verification of critical findings
3. Custom exploit development for unique vulnerabilities
4. Business logic flaw identification
5. Configuration weakness assessment

VALIDATION REQUIREMENTS:
- Proof-of-concept development for critical findings
- False positive elimination through manual testing
- Exploit chain development where applicable
- Business impact quantification
- CVSS scoring with environmental factors

Document everything with forensic-level detail.""",

                "reporting": """Generate professional vulnerability assessment report with executive and technical sections.

REPORT STRUCTURE:
- Executive Summary (business risk focus)
- Technical Findings (detailed vulnerability analysis)
- Proof-of-Concept Documentation
- Risk Prioritization Matrix
- Detailed Remediation Guidance

QUALITY STANDARDS:
- Clear vulnerability descriptions with impact analysis
- Step-by-step reproduction procedures
- CVSS 3.1 scoring with rationale
- Remediation timelines based on risk
- Strategic security improvement recommendations

Ensure the report serves both management and technical audiences."""
            },
            
            # Add more task prompts for other agents...
            "network_scanning": {
                "planning": """As a network security specialist, develop an intelligent port scanning and service enumeration strategy.

NETWORK RECONNAISSANCE STRATEGY:
- Target network profiling and categorization
- Scanning technique selection (stealth vs speed)
- Service enumeration methodology
- Banner grabbing and fingerprinting approach
- Network topology mapping procedures

OPERATIONAL CONSIDERATIONS:
- IDS/IPS evasion techniques
- Rate limiting and timing strategies
- Scanning pattern randomization
- Network segmentation discovery
- Critical service prioritization

Design an approach that maximizes intelligence while minimizing detection risk.""",
                
                "execution": """Execute comprehensive network scanning following operational security best practices.

SCANNING PHASES:
1. Host discovery and network mapping
2. Port scanning with intelligent timing
3. Service enumeration and banner grabbing
4. Version detection and fingerprinting
5. Network service vulnerability assessment

INTELLIGENCE GATHERING:
- Service configurations and versions
- Network architecture insights
- Security control identification
- Potential pivot points
- Vulnerable service discovery

Maintain detailed logs of all scanning activities and findings."""
            },
            
            "secret_discovery": {
                "planning": """As a credential harvesting expert, develop a comprehensive secret discovery methodology.

SECRET HUNTING STRATEGY:
- Multi-source secret discovery approach
- Repository and code analysis techniques
- Web application secret exposure assessment
- Configuration file analysis methodology  
- Third-party service integration review

TARGET PRIORITIZATION:
- High-value credential types identification
- Administrative access discovery focus
- API key and token prioritization
- Database connection string hunting
- Cloud service credential discovery

Create a systematic approach to maximize credential discovery.""",
                
                "execution": """Execute thorough secret discovery across all identified sources.

DISCOVERY PHASES:
1. Public repository analysis (GitHub, GitLab)
2. Web application secret exposure scanning
3. Configuration file and backup analysis
4. JavaScript and client-side secret discovery
5. Third-party service integration review

VALIDATION PROCEDURES:
- Credential validity testing
- Permission and access level assessment
- Related account discovery
- Credential correlation analysis
- Impact quantification

Document all findings with proper chain of custody."""
            }
        }
    
    def _initialize_context_enhancers(self) -> Dict[str, str]:
        """Initialize context enhancement prompts"""
        return {
            "target_context": """CURRENT TARGET CONTEXT:
Target: {target}
Target Type: {target_type}
Industry: {industry}
Risk Level: {risk_level}
Previous Findings: {previous_findings}
Business Context: {business_context}

Adapt your methodology to this specific context.""",
            
            "tool_context": """AVAILABLE TOOLS AND CAPABILITIES:
Primary Tools: {primary_tools}
Backup Methods: {backup_methods}
Environment Constraints: {constraints}
Time Limitations: {time_limits}
Stealth Requirements: {stealth_level}

Optimize your approach for available resources.""",
            
            "campaign_context": """PENETRATION TESTING CAMPAIGN:
Campaign Phase: {phase}
Previous Agent Results: {previous_results}
Current Objectives: {objectives}
Success Criteria: {success_criteria}
Next Phase Requirements: {next_phase}

Ensure your work integrates seamlessly with the overall campaign."""
        }
    
    async def get_agent_guidance(
        self, 
        agent_type: str, 
        task_phase: str, 
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Get intelligent guidance for specific agent and task"""
        
        # Get agent persona
        persona = self.agent_personas.get(f"{agent_type}_expert")
        if not persona:
            persona = self.agent_personas.get("vulnerability_specialist")  # Default fallback
        
        # Build comprehensive prompt
        system_prompt = self._build_system_prompt(persona, task_phase, context)
        
        # Get task-specific prompt
        task_prompt = self.task_prompts.get(agent_type, {}).get(task_phase, "")
        
        # Enhance with context
        enhanced_prompt = self._enhance_with_context(task_prompt, context)
        
        if self.client and self.api_key:
            # Use actual LLM
            return await self._query_llm(system_prompt, enhanced_prompt, context)
        else:
            # Use local intelligence simulation
            return await self._local_intelligence(agent_type, task_phase, context, persona)
    
    def _build_system_prompt(self, persona: AgentPersona, task_phase: str, context: Dict[str, Any]) -> str:
        """Build comprehensive system prompt"""
        persona_prompt = f"""
CYBERSECURITY EXPERT PERSONA:
Name: {persona.name}
Expertise: {persona.expertise_level.value.replace('_', ' ').title()} ({persona.years_experience} years)
Primary Domain: {persona.primary_domain.value.replace('_', ' ').title()}
Certifications: {', '.join(persona.certifications)}
Specializations: {', '.join(persona.specializations)}
Preferred Tools: {', '.join(persona.preferred_tools)}
Methodology: {persona.methodology}

PERSONALITY TRAITS: {', '.join(persona.personality_traits)}
"""
        
        return f"{self.base_system_prompt}\n\n{persona_prompt}"
    
    def _enhance_with_context(self, base_prompt: str, context: Dict[str, Any]) -> str:
        """Enhance prompt with contextual information"""
        enhanced = base_prompt
        
        # Add target context
        if context.get("target"):
            target_context = self.context_enhancers["target_context"].format(
                target=context.get("target", "Unknown"),
                target_type=context.get("target_type", "Unknown"),
                industry=context.get("industry", "Unknown"),
                risk_level=context.get("risk_level", "Medium"),
                previous_findings=context.get("previous_findings", "None"),
                business_context=context.get("business_context", "Standard assessment")
            )
            enhanced += f"\n\n{target_context}"
        
        return enhanced
    
    async def _query_llm(self, system_prompt: str, user_prompt: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Query actual LLM with professional prompts"""
        try:
            if self.llm_provider == "google":
                # Combine system and user prompts for Gemini
                combined_prompt = f"{system_prompt}\n\n{user_prompt}"
                
                # Call Gemini API
                response = self.client.generate_content(
                    combined_prompt,
                    generation_config={
                        "temperature": 0.7,
                        "top_p": 0.8,
                        "max_output_tokens": 2000,
                    }
                )
                
                return {
                    "guidance": response.text,
                    "confidence": 95,
                    "source": "google_gemini",
                    "model": self.model
                }
            
            elif self.llm_provider == "openai":
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0.7,
                    max_tokens=2000
                )
                
                return {
                    "guidance": response.choices[0].message.content,
                    "confidence": 95,
                    "source": "openai",
                    "model": self.model
                }
        
        except Exception as e:
            logger.warning(f"LLM query failed: {e}, falling back to local intelligence")
            return await self._local_intelligence("generic", "execution", context, None)
    
    async def _local_intelligence(
        self, 
        agent_type: str, 
        task_phase: str, 
        context: Dict[str, Any], 
        persona: Optional[AgentPersona]
    ) -> Dict[str, Any]:
        """
        Advanced Local Cybersecurity Intelligence System
        Professional-grade decision making with context analysis
        """
        
        intelligence_responses = {
            "reconnaissance": {
                "planning": {
                    "guidance": """🎯 RECONNAISSANCE STRATEGY:

1. PASSIVE INTELLIGENCE GATHERING:
   - Comprehensive DNS enumeration (subdomains, DNS records)
   - Certificate transparency log analysis
   - Search engine dorking for exposed information
   - Social media and public record research

2. ACTIVE RECONNAISSANCE:
   - Subdomain brute forcing with intelligent wordlists
   - Port scanning with stealth timing
   - Service banner grabbing and fingerprinting
   - Web technology identification

3. OPERATIONAL SECURITY:
   - Use distributed scanning sources
   - Implement random timing delays
   - Rotate user agents and source IPs
   - Monitor for defensive responses

EXPECTED OUTCOMES:
- Complete attack surface mapping
- Technology stack identification
- Potential entry points discovery
- Defensive capability assessment""",
                    "confidence": 85,
                    "methodology": "Passive-first with progressive active techniques"
                },
                
                "execution": {
                    "guidance": """🔍 EXECUTING RECONNAISSANCE:

CURRENT PHASE: Active intelligence gathering
APPROACH: Systematic and methodical discovery

1. SUBDOMAIN ENUMERATION:
   - Using multiple sources (DNS, certificates, search engines)
   - Validating discovered subdomains
   - Categorizing by service type and importance

2. INFRASTRUCTURE MAPPING:
   - Identifying hosting providers and technologies
   - Mapping network relationships
   - Discovering administrative interfaces

3. INTELLIGENCE CORRELATION:
   - Cross-referencing findings across sources
   - Identifying patterns and relationships
   - Building comprehensive target profile

OPERATIONAL NOTES:
- Maintaining stealth profile
- Documenting all findings with confidence levels
- Preparing intelligence for next-phase teams""",
                    "confidence": 90,
                    "phase_status": "executing comprehensive discovery"
                }
            },
            
            "vulnerability_assessment": {
                "planning": {
                    "guidance": """🛡️ VULNERABILITY ASSESSMENT STRATEGY:

1. SCANNER CONFIGURATION:
   - Multi-tool approach (Nuclei + custom scripts)
   - Template selection based on discovered technologies
   - Rate limiting to avoid detection
   - Comprehensive coverage with minimal noise

2. MANUAL VALIDATION:
   - Critical finding verification
   - Business logic flaw identification
   - Custom exploit development
   - False positive elimination

3. RISK PRIORITIZATION:
   - CVSS scoring with environmental factors
   - Business impact consideration
   - Exploitability assessment
   - Chaining potential evaluation

EXPECTED DELIVERABLES:
- Comprehensive vulnerability inventory
- Proof-of-concept exploits
- Risk-prioritized findings list
- Detailed remediation guidance""",
                    "confidence": 92,
                    "methodology": "Layered scanning with expert validation"
                },
                
                "scanning": {
                    "guidance": """⚡ VULNERABILITY SCANNING IN PROGRESS:

CURRENT PHASE: Automated discovery with manual validation
SCANNER STATUS: Multi-template execution active

1. NUCLEI TEMPLATE EXECUTION:
   - Critical vulnerability templates
   - CVE-specific detection rules  
   - Technology-specific assessments
   - Configuration weakness checks

2. CUSTOM VALIDATION:
   - Manual verification of critical findings
   - Business logic testing
   - Authentication bypass attempts
   - Input validation assessments

3. EXPLOIT DEVELOPMENT:
   - Proof-of-concept creation for critical issues
   - Exploit chain identification
   - Impact demonstration preparation

FINDINGS CORRELATION:
- Cross-referencing with reconnaissance data
- Validating vulnerability context
- Assessing real-world exploitability""",
                    "confidence": 88,
                    "current_activity": "systematic vulnerability discovery"
                }
            },
            
            "network_scanning": {
                "execution": {
                    "guidance": """🌐 NETWORK SCANNING EXECUTION:

CURRENT PHASE: Intelligent port discovery and service enumeration
SCANNING APPROACH: Stealth-optimized with comprehensive coverage

1. PORT DISCOVERY:
   - SYN scanning for speed and stealth
   - Service detection and version enumeration
   - Banner grabbing for additional intelligence
   - Custom service probing

2. NETWORK INTELLIGENCE:
   - Infrastructure topology mapping
   - Security control identification
   - Service relationship analysis
   - Potential pivot point discovery

3. VULNERABILITY CORRELATION:
   - Service-specific vulnerability checks
   - Configuration weakness identification
   - Default credential testing
   - Protocol-specific assessments

OPERATIONAL STATUS:
- Maintaining low detection profile
- Correlating findings with reconnaissance data
- Building comprehensive service inventory""",
                    "confidence": 89,
                    "scanning_intensity": "optimized for stealth and coverage"
                }
            }
        }
        
        # Get response for agent and phase
        agent_responses = intelligence_responses.get(agent_type, {})
        response = agent_responses.get(task_phase, {
            "guidance": f"""🤖 CYBERSECURITY EXPERT GUIDANCE:

As a senior cybersecurity professional with 5+ years of experience, I'm analyzing your {agent_type} {task_phase} requirements.

PROFESSIONAL APPROACH:
- Following industry best practices and methodologies
- Prioritizing findings based on business risk
- Maintaining operational security throughout
- Documenting everything for comprehensive reporting

CURRENT CONTEXT:
- Target: {context.get('target', 'Various targets')}
- Phase: {task_phase.title()} execution
- Methodology: Professional cybersecurity standards

RECOMMENDATION:
Proceeding with systematic approach using proven methodologies, maintaining stealth profile, and focusing on actionable intelligence gathering.""",
            "confidence": 80,
            "source": "local_cybersecurity_intelligence"
        })
        
        # Enhance with persona if available
        if persona:
            response["expert"] = persona.name
            response["specialization"] = persona.primary_domain.value
            response["methodology"] = persona.methodology
        
        response["source"] = "local_intelligence"
        return response


# Global instance for easy access
cyber_llm = CyberSecurityLLM()


async def get_expert_guidance(agent_type: str, phase: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to get expert cybersecurity guidance"""
    return await cyber_llm.get_agent_guidance(agent_type, phase, context)
