"""
Technical Report Agent
======================

Generates comprehensive technical security assessment reports with detailed
vulnerability analysis, technical remediation steps, and in-depth security findings
for security teams and technical stakeholders.
"""

import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Any, Optional

from loguru import logger
from agents.base import BaseAgent


@dataclass
class TechnicalMetadata:
    """Technical report metadata"""
    target_domain: str
    assessment_date: str
    scan_duration: str
    tools_used: List[str]
    assessment_scope: str
    tester_name: str
    report_version: str
    total_endpoints: int
    technologies_identified: List[str]


@dataclass
class VulnerabilityDetail:
    """Detailed vulnerability information for technical reports"""
    id: str
    title: str
    severity: str
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    owasp_category: str
    description: str
    technical_impact: str
    affected_endpoints: List[str]
    proof_of_concept: str
    remediation_steps: List[str]
    references: List[str]
    discovery_method: str
    verification_status: str


@dataclass
class TechnicalRecommendation:
    """Technical remediation recommendation"""
    priority: str
    category: str
    title: str
    description: str
    implementation_steps: List[str]
    estimated_effort: str
    risk_reduction: str
    dependencies: List[str]


@dataclass
class TechnicalReport:
    """Complete technical security assessment report"""
    metadata: TechnicalMetadata
    executive_summary: str
    methodology: str
    vulnerabilities: List[VulnerabilityDetail]
    technical_findings: Dict[str, Any]
    infrastructure_analysis: Dict[str, Any]
    recommendations: List[TechnicalRecommendation]
    appendices: Dict[str, Any]
    report_generated: str = ""
    
    def __post_init__(self):
        if not self.report_generated:
            self.report_generated = datetime.now().isoformat()


class TechnicalReportAgent(BaseAgent):
    """Technical security report generation agent"""
    
    def __init__(self):
        super().__init__("TechnicalReportAgent")
        self.report_templates = self._initialize_templates()
        
    def _initialize_templates(self) -> Dict[str, str]:
        """Initialize technical report templates"""
        return {
            "technical_summary": """
# Technical Security Assessment Report

## Assessment Overview
This technical security assessment was conducted on {target} from {start_date} to {end_date}.
The assessment utilized automated scanning tools and manual testing techniques to identify
security vulnerabilities and configuration weaknesses.

## Methodology
- **Reconnaissance**: {recon_methods}
- **Vulnerability Scanning**: {vuln_scan_methods}  
- **Manual Testing**: {manual_methods}
- **Exploitation Testing**: {exploit_methods}

## Technical Summary
- **Total Vulnerabilities**: {total_vulns}
- **Critical**: {critical_count} vulnerabilities requiring immediate attention
- **High**: {high_count} vulnerabilities requiring prompt remediation
- **Medium**: {medium_count} vulnerabilities requiring scheduled remediation
- **Low**: {low_count} vulnerabilities for future consideration
- **Informational**: {info_count} findings for awareness

## Infrastructure Analysis
{infrastructure_summary}

## Key Technical Findings
{key_findings}

## Remediation Priority Matrix
{remediation_matrix}
            """,
            
            "vulnerability_technical": """
## {vuln_id}: {vuln_title}

**Severity**: {severity} (CVSS: {cvss_score})  
**CVSS Vector**: {cvss_vector}  
**CWE**: {cwe_id}  
**OWASP Category**: {owasp_category}  
**Discovery Method**: {discovery_method}  
**Verification Status**: {verification_status}

### Technical Description
{description}

### Technical Impact
{technical_impact}

### Affected Endpoints
{affected_endpoints}

### Proof of Concept
```
{proof_of_concept}
```

### Technical Remediation Steps
{remediation_steps}

### Verification Steps
{verification_steps}

### References
{references}

---
            """,
            
            "technical_recommendation": """
### {priority}: {title}

**Category**: {category}  
**Estimated Effort**: {estimated_effort}  
**Risk Reduction**: {risk_reduction}

**Description**: {description}

**Implementation Steps**:
{implementation_steps}

**Dependencies**: {dependencies}

---
            """
        }
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        scan_results = config.get("scan_results", {}) if config else {}
        report = await self.generate_technical_report(scan_results, config)
        return asdict(report)
        
    async def generate_technical_report(
        self,
        scan_results: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None
    ) -> TechnicalReport:
        """Generate comprehensive technical security report"""
        try:
            logger.info("🔧 Generating technical security report")
            
            config = config or {}
            
            # Extract and process scan data
            metadata = self._extract_technical_metadata(scan_results, config)
            vulnerabilities = await self._process_technical_vulnerabilities(scan_results)
            technical_findings = await self._analyze_technical_findings(scan_results)
            infrastructure_analysis = await self._analyze_infrastructure(scan_results)
            recommendations = self._generate_technical_recommendations(vulnerabilities, technical_findings)
            appendices = self._generate_technical_appendices(scan_results, vulnerabilities)
            
            # Generate executive summary for technical audience
            executive_summary = self._generate_technical_executive_summary(
                metadata, vulnerabilities, technical_findings
            )
            
            # Generate methodology section
            methodology = self._generate_methodology_section(scan_results, config)
            
            report = TechnicalReport(
                metadata=metadata,
                executive_summary=executive_summary,
                methodology=methodology,
                vulnerabilities=vulnerabilities,
                technical_findings=technical_findings,
                infrastructure_analysis=infrastructure_analysis,
                recommendations=recommendations,
                appendices=appendices
            )
            
            logger.info(f"✅ Technical report generated with {len(vulnerabilities)} vulnerabilities")
            return report
            
        except Exception as e:
            logger.error(f"❌ Technical report generation failed: {e}")
            raise
    
    def _extract_technical_metadata(
        self,
        scan_results: Dict[str, Any],
        config: Dict[str, Any]
    ) -> TechnicalMetadata:
        """Extract technical metadata from scan results"""
        
        # Extract target information
        target_domain = scan_results.get("target_domain", config.get("target", "Unknown"))
        
        # Extract timing information
        start_time = scan_results.get("start_time", datetime.now().isoformat())
        end_time = scan_results.get("end_time", datetime.now().isoformat())
        
        # Calculate duration
        try:
            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            duration = str(end_dt - start_dt)
        except:
            duration = "Unknown"
        
        # Extract tools used
        tools_used = []
        for agent_name, agent_results in scan_results.items():
            if isinstance(agent_results, dict) and agent_results.get("agent"):
                tools_used.append(agent_results["agent"])
        
        # Extract technologies
        technologies = []
        if "ReconAgent" in scan_results:
            recon_data = scan_results["ReconAgent"]
            if isinstance(recon_data, dict):
                technologies.extend(recon_data.get("technologies", {}).keys())
        
        return TechnicalMetadata(
            target_domain=target_domain,
            assessment_date=datetime.now().strftime("%Y-%m-%d"),
            scan_duration=duration,
            tools_used=tools_used,
            assessment_scope="Comprehensive technical security assessment",
            tester_name=config.get("tester_name", "Nexus Hunter Security Platform"),
            report_version="1.0",
            total_endpoints=len(scan_results.get("endpoints", [])),
            technologies_identified=technologies
        )
    
    async def _process_technical_vulnerabilities(
        self,
        scan_results: Dict[str, Any]
    ) -> List[VulnerabilityDetail]:
        """Process vulnerabilities with technical details"""
        
        vulnerabilities = []
        vuln_id_counter = 1
        
        # Extract vulnerabilities from different agents
        for agent_name, agent_results in scan_results.items():
            if not isinstance(agent_results, dict):
                continue
                
            agent_vulns = agent_results.get("vulnerabilities", [])
            if not isinstance(agent_vulns, list):
                continue
            
            for vuln in agent_vulns:
                if not isinstance(vuln, dict):
                    continue
                
                # Generate technical vulnerability detail
                tech_vuln = VulnerabilityDetail(
                    id=f"NEXUS-TECH-{vuln_id_counter:03d}",
                    title=vuln.get("title", vuln.get("name", "Unknown Vulnerability")),
                    severity=vuln.get("severity", "medium").lower(),
                    cvss_score=float(vuln.get("cvss_score", 5.0)),
                    cvss_vector=vuln.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"),
                    cwe_id=vuln.get("cwe_id", "CWE-200"),
                    owasp_category=vuln.get("owasp_category", "A01:2021 – Broken Access Control"),
                    description=vuln.get("description", "No technical description available"),
                    technical_impact=vuln.get("impact", "Potential security compromise"),
                    affected_endpoints=vuln.get("affected_urls", [vuln.get("url", "Unknown")]),
                    proof_of_concept=vuln.get("evidence", vuln.get("payload", "Manual verification required")),
                    remediation_steps=self._generate_remediation_steps(vuln),
                    references=vuln.get("references", []),
                    discovery_method=f"Automated scan via {agent_name}",
                    verification_status="Automated Detection"
                )
                
                vulnerabilities.append(tech_vuln)
                vuln_id_counter += 1
        
        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulnerabilities.sort(key=lambda x: severity_order.get(x.severity, 4))
        
        return vulnerabilities
    
    def _generate_remediation_steps(self, vuln: Dict[str, Any]) -> List[str]:
        """Generate technical remediation steps"""
        
        vuln_type = vuln.get("title", "").lower()
        
        if "sql injection" in vuln_type:
            return [
                "Implement parameterized queries/prepared statements",
                "Validate and sanitize all user inputs",
                "Apply principle of least privilege to database accounts",
                "Enable SQL query logging and monitoring",
                "Conduct code review of affected endpoints"
            ]
        elif "xss" in vuln_type or "cross-site scripting" in vuln_type:
            return [
                "Implement proper output encoding/escaping",
                "Use Content Security Policy (CSP) headers",
                "Validate and sanitize user inputs",
                "Apply context-aware output encoding",
                "Review and update input validation routines"
            ]
        elif "csrf" in vuln_type:
            return [
                "Implement anti-CSRF tokens",
                "Verify HTTP Referer header",
                "Use SameSite cookie attribute",
                "Implement proper session management",
                "Add CSRF protection to all state-changing operations"
            ]
        else:
            return [
                "Review and validate the identified vulnerability",
                "Implement appropriate input validation",
                "Apply security best practices for the affected component",
                "Conduct security testing after remediation",
                "Update security documentation and procedures"
            ]
    
    async def _analyze_technical_findings(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze technical findings from scan results"""
        
        findings = {
            "network_analysis": {},
            "web_application_findings": {},
            "infrastructure_weaknesses": {},
            "configuration_issues": {},
            "security_controls": {}
        }
        
        # Analyze reconnaissance data
        if "ReconAgent" in scan_results:
            recon_data = scan_results.get("ReconAgent", {})
            findings["network_analysis"] = {
                "subdomains_discovered": len(recon_data.get("subdomains", [])),
                "open_ports": recon_data.get("ports", {}),
                "technologies_identified": recon_data.get("technologies", {}),
                "dns_records": recon_data.get("dns_info", {})
            }
        
        # Analyze web application findings
        if "ExploitAgent" in scan_results:
            exploit_data = scan_results.get("ExploitAgent", {})
            findings["web_application_findings"] = {
                "total_vulnerabilities": len(exploit_data.get("vulnerabilities", [])),
                "attack_vectors": self._extract_attack_vectors(exploit_data),
                "security_headers": exploit_data.get("security_headers", {}),
                "authentication_issues": exploit_data.get("auth_issues", [])
            }
        
        return findings
    
    def _extract_attack_vectors(self, exploit_data: Dict[str, Any]) -> List[str]:
        """Extract attack vectors from exploit data"""
        vectors = []
        vulnerabilities = exploit_data.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                vuln_type = vuln.get("title", "").lower()
                if "sql injection" in vuln_type:
                    vectors.append("SQL Injection")
                elif "xss" in vuln_type:
                    vectors.append("Cross-Site Scripting")
                elif "csrf" in vuln_type:
                    vectors.append("Cross-Site Request Forgery")
                elif "lfi" in vuln_type:
                    vectors.append("Local File Inclusion")
                elif "rce" in vuln_type:
                    vectors.append("Remote Code Execution")
        
        return list(set(vectors))  # Remove duplicates
    
    async def _analyze_infrastructure(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze infrastructure components"""
        
        infrastructure = {
            "network_topology": {},
            "service_analysis": {},
            "security_posture": {},
            "compliance_status": {}
        }
        
        # Analyze network topology
        if "ReconAgent" in scan_results:
            recon_data = scan_results.get("ReconAgent", {})
            infrastructure["network_topology"] = {
                "external_facing_services": len(recon_data.get("ports", {})),
                "subdomains": len(recon_data.get("subdomains", [])),
                "ip_ranges": recon_data.get("ip_ranges", [])
            }
        
        # Analyze services
        infrastructure["service_analysis"] = {
            "web_servers": [],
            "databases": [],
            "application_frameworks": [],
            "third_party_services": []
        }
        
        return infrastructure
    
    def _generate_technical_recommendations(
        self,
        vulnerabilities: List[VulnerabilityDetail],
        technical_findings: Dict[str, Any]
    ) -> List[TechnicalRecommendation]:
        """Generate technical remediation recommendations"""
        
        recommendations = []
        
        # Critical vulnerability recommendations
        critical_vulns = [v for v in vulnerabilities if v.severity == "critical"]
        if critical_vulns:
            recommendations.append(TechnicalRecommendation(
                priority="Critical",
                category="Vulnerability Remediation",
                title="Address Critical Security Vulnerabilities",
                description=f"Immediately remediate {len(critical_vulns)} critical vulnerabilities that pose severe security risks.",
                implementation_steps=[
                    "Prioritize critical vulnerabilities by exploitability",
                    "Implement emergency patches or workarounds",
                    "Conduct thorough testing in staging environment",
                    "Deploy fixes during maintenance window",
                    "Verify remediation through re-testing"
                ],
                estimated_effort="1-2 weeks",
                risk_reduction="High",
                dependencies=["Development team", "Operations team", "Security team"]
            ))
        
        # High vulnerability recommendations
        high_vulns = [v for v in vulnerabilities if v.severity == "high"]
        if high_vulns:
            recommendations.append(TechnicalRecommendation(
                priority="High",
                category="Security Hardening",
                title="Remediate High-Priority Security Issues",
                description=f"Address {len(high_vulns)} high-priority vulnerabilities to strengthen security posture.",
                implementation_steps=[
                    "Review and prioritize high-severity findings",
                    "Develop remediation plan with timelines",
                    "Implement security controls and patches",
                    "Update security policies and procedures",
                    "Conduct security validation testing"
                ],
                estimated_effort="2-4 weeks",
                risk_reduction="Medium-High",
                dependencies=["Development team", "Security team"]
            ))
        
        # Infrastructure recommendations
        recommendations.append(TechnicalRecommendation(
            priority="Medium",
            category="Infrastructure Security",
            title="Implement Security Monitoring and Logging",
            description="Establish comprehensive security monitoring and incident response capabilities.",
            implementation_steps=[
                "Deploy security information and event management (SIEM)",
                "Configure centralized logging for all systems",
                "Implement intrusion detection/prevention systems",
                "Establish security incident response procedures",
                "Configure automated alerting for security events"
            ],
            estimated_effort="4-6 weeks",
            risk_reduction="Medium",
            dependencies=["Infrastructure team", "Security team", "Operations team"]
        ))
        
        # Application security recommendations
        recommendations.append(TechnicalRecommendation(
            priority="Medium",
            category="Application Security",
            title="Implement Secure Development Practices",
            description="Establish secure coding practices and security testing in the development lifecycle.",
            implementation_steps=[
                "Implement secure coding guidelines and training",
                "Integrate static application security testing (SAST)",
                "Deploy dynamic application security testing (DAST)",
                "Establish security code review processes",
                "Implement dependency vulnerability scanning"
            ],
            estimated_effort="6-8 weeks",
            risk_reduction="Medium",
            dependencies=["Development team", "Security team", "DevOps team"]
        ))
        
        return recommendations
    
    def _generate_technical_appendices(
        self,
        scan_results: Dict[str, Any],
        vulnerabilities: List[VulnerabilityDetail]
    ) -> Dict[str, Any]:
        """Generate technical appendices"""
        
        return {
            "scan_configuration": {
                "tools_used": list(scan_results.keys()),
                "scan_parameters": "Comprehensive automated security assessment",
                "coverage": "External attack surface and web application security"
            },
            "vulnerability_statistics": {
                "total_vulnerabilities": len(vulnerabilities),
                "by_severity": {
                    "critical": len([v for v in vulnerabilities if v.severity == "critical"]),
                    "high": len([v for v in vulnerabilities if v.severity == "high"]),
                    "medium": len([v for v in vulnerabilities if v.severity == "medium"]),
                    "low": len([v for v in vulnerabilities if v.severity == "low"])
                }
            },
            "technical_details": {
                "scan_timestamp": datetime.now().isoformat(),
                "report_version": "1.0",
                "assessment_methodology": "OWASP Testing Guide v4.0 + Custom Nexus Hunter Framework"
            }
        }
    
    def _generate_technical_executive_summary(
        self,
        metadata: TechnicalMetadata,
        vulnerabilities: List[VulnerabilityDetail],
        technical_findings: Dict[str, Any]
    ) -> str:
        """Generate executive summary for technical audience"""
        
        critical_count = len([v for v in vulnerabilities if v.severity == "critical"])
        high_count = len([v for v in vulnerabilities if v.severity == "high"])
        medium_count = len([v for v in vulnerabilities if v.severity == "medium"])
        low_count = len([v for v in vulnerabilities if v.severity == "low"])
        
        summary = f"""
## Technical Executive Summary

This comprehensive technical security assessment of {metadata.target_domain} identified {len(vulnerabilities)} security vulnerabilities and configuration weaknesses. The assessment utilized automated scanning tools and manual testing techniques to evaluate the security posture of the target infrastructure.

### Key Technical Findings

- **Critical Vulnerabilities**: {critical_count} issues requiring immediate remediation
- **High-Priority Issues**: {high_count} vulnerabilities requiring prompt attention  
- **Medium-Priority Issues**: {medium_count} vulnerabilities for scheduled remediation
- **Low-Priority Issues**: {low_count} vulnerabilities for future consideration

### Infrastructure Analysis

The target infrastructure consists of {len(metadata.technologies_identified)} identified technologies and {metadata.total_endpoints} assessed endpoints. The assessment covered external attack surface enumeration, web application security testing, and infrastructure configuration analysis.

### Remediation Priority

1. **Immediate Action Required**: Address all critical vulnerabilities within 48-72 hours
2. **Short-term Remediation**: Resolve high-priority issues within 2-4 weeks
3. **Medium-term Planning**: Schedule medium-priority fixes within 1-3 months
4. **Long-term Improvements**: Address low-priority issues during regular maintenance cycles

### Technical Recommendations

The primary technical recommendations focus on implementing secure coding practices, establishing comprehensive security monitoring, and addressing identified vulnerabilities through a risk-based approach. Detailed remediation steps are provided for each identified vulnerability.
        """
        
        return summary.strip()
    
    def _generate_methodology_section(
        self,
        scan_results: Dict[str, Any],
        config: Dict[str, Any]
    ) -> str:
        """Generate methodology section"""
        
        return """
## Assessment Methodology

This technical security assessment followed a comprehensive methodology based on industry best practices and security frameworks:

### 1. Reconnaissance Phase
- **Passive Information Gathering**: DNS enumeration, subdomain discovery, technology identification
- **Active Reconnaissance**: Port scanning, service enumeration, web application discovery
- **OSINT Collection**: Public information gathering, certificate transparency logs

### 2. Vulnerability Assessment Phase  
- **Automated Scanning**: Comprehensive vulnerability scanning using multiple tools
- **Web Application Testing**: OWASP Top 10 assessment, business logic testing
- **Configuration Analysis**: Security configuration review, hardening assessment

### 3. Exploitation Testing Phase
- **Proof of Concept Development**: Safe exploitation of identified vulnerabilities
- **Impact Assessment**: Evaluation of potential security impact and business risk
- **Evidence Collection**: Documentation of findings with technical evidence

### 4. Analysis and Reporting Phase
- **Risk Assessment**: CVSS scoring and business impact analysis  
- **Remediation Planning**: Technical remediation steps and implementation guidance
- **Report Generation**: Comprehensive technical documentation and executive summary

### Tools and Techniques Used
- **Network Scanning**: Nmap, Masscan, Naabu
- **Web Application Testing**: Nuclei, FFUF, Custom scripts
- **Vulnerability Assessment**: Multiple specialized security tools
- **Manual Testing**: Expert security analysis and validation

### Assessment Scope
The assessment covered the external attack surface of the target domain, including all discovered subdomains, web applications, and publicly accessible services. The testing was conducted in a safe and controlled manner to minimize any potential impact on production systems.
        """

