"""
Disclosure Report Agent
=======================

Generates responsible security disclosure documents following industry best practices
for coordinated vulnerability disclosure. Focuses on critical and high-severity
vulnerabilities that require immediate attention and responsible disclosure.
"""

import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from loguru import logger
from agents.base import BaseAgent


@dataclass
class DisclosureMetadata:
    """Disclosure report metadata"""
    target_domain: str
    disclosure_date: str
    discovery_date: str
    researcher_name: str
    contact_email: str
    disclosure_timeline: str
    severity_threshold: str
    total_critical_high: int
    report_id: str


@dataclass
class DisclosureVulnerability:
    """Vulnerability information for disclosure"""
    id: str
    title: str
    severity: str
    cvss_score: float
    description: str
    impact_summary: str
    affected_components: List[str]
    discovery_method: str
    proof_of_concept: Optional[str]
    remediation_summary: str
    timeline_criticality: str


@dataclass
class DisclosureTimeline:
    """Coordinated disclosure timeline"""
    initial_contact: str
    acknowledgment_deadline: str
    remediation_deadline: str
    public_disclosure_date: str
    extension_policy: str
    emergency_contact: str


@dataclass
class DisclosureReport:
    """Complete responsible disclosure document"""
    metadata: DisclosureMetadata
    executive_summary: str
    disclosure_policy: str
    vulnerabilities: List[DisclosureVulnerability]
    timeline: DisclosureTimeline
    contact_information: Dict[str, str]
    legal_considerations: str
    next_steps: List[str]
    report_generated: str = ""
    
    def __post_init__(self):
        if not self.report_generated:
            self.report_generated = datetime.now().isoformat()


class DisclosureReportAgent(BaseAgent):
    """Responsible security disclosure report generation agent"""
    
    def __init__(self):
        super().__init__("DisclosureReportAgent")
        self.disclosure_templates = self._initialize_templates()
        
    def _initialize_templates(self) -> Dict[str, str]:
        """Initialize disclosure report templates"""
        return {
            "disclosure_summary": """
# Security Disclosure Report

## Executive Summary

This document outlines {total_critical_high} critical and high-severity security vulnerabilities 
discovered in {target_domain} during a security assessment conducted on {discovery_date}.

These vulnerabilities pose significant security risks and require immediate attention. 
This disclosure follows responsible disclosure practices to ensure coordinated remediation 
while protecting the security of users and systems.

## Disclosure Overview

- **Target**: {target_domain}
- **Discovery Date**: {discovery_date}
- **Disclosure Date**: {disclosure_date}
- **Researcher**: {researcher_name}
- **Severity Threshold**: {severity_threshold}
- **Total Critical/High Issues**: {total_critical_high}

## Coordinated Disclosure Timeline

This disclosure follows a {timeline} coordinated disclosure timeline:

1. **Initial Contact**: {initial_contact}
2. **Acknowledgment Expected**: {acknowledgment_deadline}
3. **Remediation Deadline**: {remediation_deadline}
4. **Public Disclosure**: {public_disclosure_date}

## Contact Information

For questions or concerns regarding this disclosure, please contact:
- **Primary Contact**: {contact_email}
- **Emergency Contact**: {emergency_contact}
            """,
            
            "vulnerability_disclosure": """
## {vuln_id}: {title}

**Severity**: {severity} (CVSS: {cvss_score})  
**Timeline Criticality**: {timeline_criticality}

### Summary
{description}

### Security Impact
{impact_summary}

### Affected Components
{affected_components}

### Discovery Method
{discovery_method}

### Proof of Concept
{proof_of_concept}

### Recommended Remediation
{remediation_summary}

---
            """,
            
            "disclosure_policy": """
## Responsible Disclosure Policy

This security disclosure follows industry best practices for coordinated vulnerability disclosure:

### Our Commitment
- **Good Faith**: All testing was conducted in good faith to improve security
- **No Harm**: No data was accessed, modified, or deleted during testing
- **Confidentiality**: Vulnerability details will remain confidential until remediation
- **Cooperation**: We are committed to working with your security team

### Disclosure Timeline
- **Standard Timeline**: 90 days from initial contact to public disclosure
- **Critical Issues**: 30 days for critical vulnerabilities with active exploitation risk
- **Extensions**: Available upon request with valid justification
- **Emergency Contact**: Immediate response for critical security incidents

### Expectations
- **Acknowledgment**: Initial response within 5 business days
- **Communication**: Regular updates on remediation progress
- **Credit**: Appropriate recognition in security advisories (if desired)
- **Coordination**: Collaborative approach to remediation and disclosure

### Legal Considerations
This disclosure is made in good faith under responsible disclosure principles. 
The researcher has not violated any laws or terms of service during the security assessment. 
This disclosure is intended to improve security and protect users.
            """
        }
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        scan_results = config.get("scan_results", {}) if config else {}
        report = await self.generate_disclosure_report(scan_results, config)
        return asdict(report)
        
    async def generate_disclosure_report(
        self,
        scan_results: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None
    ) -> DisclosureReport:
        """Generate responsible disclosure report"""
        try:
            logger.info("📧 Generating responsible disclosure report")
            
            config = config or {}
            
            # Extract and process scan data for disclosure
            metadata = self._extract_disclosure_metadata(scan_results, config)
            vulnerabilities = await self._process_disclosure_vulnerabilities(scan_results)
            timeline = self._generate_disclosure_timeline(metadata)
            
            # Generate disclosure content
            executive_summary = self._generate_disclosure_summary(metadata, vulnerabilities)
            disclosure_policy = self._generate_disclosure_policy()
            contact_information = self._generate_contact_information(config)
            legal_considerations = self._generate_legal_considerations()
            next_steps = self._generate_next_steps(vulnerabilities, timeline)
            
            report = DisclosureReport(
                metadata=metadata,
                executive_summary=executive_summary,
                disclosure_policy=disclosure_policy,
                vulnerabilities=vulnerabilities,
                timeline=timeline,
                contact_information=contact_information,
                legal_considerations=legal_considerations,
                next_steps=next_steps
            )
            
            logger.info(f"✅ Disclosure report generated for {len(vulnerabilities)} critical/high vulnerabilities")
            return report
            
        except Exception as e:
            logger.error(f"❌ Disclosure report generation failed: {e}")
            raise
    
    def _extract_disclosure_metadata(
        self,
        scan_results: Dict[str, Any],
        config: Dict[str, Any]
    ) -> DisclosureMetadata:
        """Extract metadata for disclosure report"""
        
        # Extract target information
        target_domain = scan_results.get("target_domain", config.get("target", "Unknown"))
        
        # Count critical and high vulnerabilities
        total_critical_high = 0
        for agent_name, agent_results in scan_results.items():
            if isinstance(agent_results, dict):
                vulnerabilities = agent_results.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    if isinstance(vuln, dict):
                        severity = vuln.get("severity", "").lower()
                        if severity in ["critical", "high"]:
                            total_critical_high += 1
        
        # Generate report ID
        report_id = f"NEXUS-DISCLOSURE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        return DisclosureMetadata(
            target_domain=target_domain,
            disclosure_date=datetime.now().strftime("%Y-%m-%d"),
            discovery_date=config.get("discovery_date", datetime.now().strftime("%Y-%m-%d")),
            researcher_name=config.get("researcher_name", "Nexus Hunter Security Research Team"),
            contact_email=config.get("contact_email", "security@nexushunter.com"),
            disclosure_timeline="90-day coordinated disclosure",
            severity_threshold="Critical and High severity vulnerabilities",
            total_critical_high=total_critical_high,
            report_id=report_id
        )
    
    async def _process_disclosure_vulnerabilities(
        self,
        scan_results: Dict[str, Any]
    ) -> List[DisclosureVulnerability]:
        """Process vulnerabilities for disclosure (Critical and High only)"""
        
        disclosure_vulnerabilities = []
        vuln_id_counter = 1
        
        # Extract only critical and high vulnerabilities
        for agent_name, agent_results in scan_results.items():
            if not isinstance(agent_results, dict):
                continue
                
            agent_vulns = agent_results.get("vulnerabilities", [])
            if not isinstance(agent_vulns, list):
                continue
            
            for vuln in agent_vulns:
                if not isinstance(vuln, dict):
                    continue
                
                severity = vuln.get("severity", "").lower()
                if severity not in ["critical", "high"]:
                    continue  # Only include critical and high for disclosure
                
                # Generate disclosure vulnerability
                disclosure_vuln = DisclosureVulnerability(
                    id=f"DISC-{vuln_id_counter:03d}",
                    title=vuln.get("title", vuln.get("name", "Security Vulnerability")),
                    severity=severity.title(),
                    cvss_score=float(vuln.get("cvss_score", 7.5 if severity == "high" else 9.0)),
                    description=self._sanitize_description_for_disclosure(vuln.get("description", "")),
                    impact_summary=self._generate_impact_summary(vuln, severity),
                    affected_components=vuln.get("affected_urls", [vuln.get("url", "Multiple components")]),
                    discovery_method="Automated security assessment",
                    proof_of_concept=self._sanitize_poc_for_disclosure(vuln.get("evidence", "")),
                    remediation_summary=self._generate_remediation_summary(vuln),
                    timeline_criticality="Immediate" if severity == "critical" else "High Priority"
                )
                
                disclosure_vulnerabilities.append(disclosure_vuln)
                vuln_id_counter += 1
        
        # Sort by severity (critical first)
        disclosure_vulnerabilities.sort(key=lambda x: 0 if x.severity == "Critical" else 1)
        
        return disclosure_vulnerabilities
    
    def _sanitize_description_for_disclosure(self, description: str) -> str:
        """Sanitize vulnerability description for responsible disclosure"""
        if not description:
            return "A security vulnerability was identified that could potentially compromise system security."
        
        # Remove any sensitive information or overly technical exploitation details
        sanitized = description.replace("exploit", "security issue")
        sanitized = sanitized.replace("payload", "test input")
        sanitized = sanitized.replace("shell", "system access")
        
        # Ensure description is professional and appropriate for disclosure
        if len(sanitized) > 500:
            sanitized = sanitized[:497] + "..."
        
        return sanitized
    
    def _sanitize_poc_for_disclosure(self, evidence: str) -> Optional[str]:
        """Sanitize proof of concept for responsible disclosure"""
        if not evidence:
            return "Proof of concept available upon request for remediation purposes."
        
        # For disclosure, we provide limited PoC information
        if len(evidence) > 200:
            return "Detailed proof of concept available to security team for remediation verification."
        
        # Remove any actual exploit code or sensitive details
        sanitized = evidence.replace("<?php", "[PHP_CODE]")
        sanitized = sanitized.replace("<script>", "[SCRIPT_TAG]")
        sanitized = sanitized.replace("' OR 1=1", "[SQL_INJECTION_PAYLOAD]")
        
        return f"Limited proof of concept: {sanitized}"
    
    def _generate_impact_summary(self, vuln: Dict[str, Any], severity: str) -> str:
        """Generate business impact summary for disclosure"""
        
        vuln_type = vuln.get("title", "").lower()
        
        if "sql injection" in vuln_type:
            return "Potential unauthorized database access, data theft, or data manipulation."
        elif "rce" in vuln_type or "remote code execution" in vuln_type:
            return "Potential complete system compromise and unauthorized server access."
        elif "xss" in vuln_type:
            return "Potential user session hijacking, credential theft, or malicious content injection."
        elif "csrf" in vuln_type:
            return "Potential unauthorized actions performed on behalf of authenticated users."
        elif "lfi" in vuln_type:
            return "Potential access to sensitive files and system information disclosure."
        else:
            if severity == "critical":
                return "Critical security vulnerability with potential for significant system compromise."
            else:
                return "High-priority security vulnerability requiring prompt remediation."
    
    def _generate_remediation_summary(self, vuln: Dict[str, Any]) -> str:
        """Generate high-level remediation summary for disclosure"""
        
        vuln_type = vuln.get("title", "").lower()
        
        if "sql injection" in vuln_type:
            return "Implement parameterized queries and input validation to prevent SQL injection attacks."
        elif "xss" in vuln_type:
            return "Implement proper output encoding and Content Security Policy to prevent XSS attacks."
        elif "csrf" in vuln_type:
            return "Implement anti-CSRF tokens and proper request validation."
        elif "rce" in vuln_type:
            return "Review and secure code execution paths, implement input validation and sandboxing."
        elif "lfi" in vuln_type:
            return "Implement proper file path validation and access controls."
        else:
            return "Review and implement appropriate security controls for the identified vulnerability."
    
    def _generate_disclosure_timeline(self, metadata: DisclosureMetadata) -> DisclosureTimeline:
        """Generate coordinated disclosure timeline"""
        
        disclosure_date = datetime.strptime(metadata.disclosure_date, "%Y-%m-%d")
        
        # Standard 90-day timeline, but 30 days for critical issues
        has_critical = metadata.total_critical_high > 0  # Simplified check
        timeline_days = 30 if has_critical else 90
        
        return DisclosureTimeline(
            initial_contact=disclosure_date.strftime("%Y-%m-%d"),
            acknowledgment_deadline=(disclosure_date + timedelta(days=5)).strftime("%Y-%m-%d"),
            remediation_deadline=(disclosure_date + timedelta(days=timeline_days)).strftime("%Y-%m-%d"),
            public_disclosure_date=(disclosure_date + timedelta(days=timeline_days + 14)).strftime("%Y-%m-%d"),
            extension_policy="Extensions available upon request with valid justification",
            emergency_contact="security-emergency@nexushunter.com"
        )
    
    def _generate_disclosure_summary(
        self,
        metadata: DisclosureMetadata,
        vulnerabilities: List[DisclosureVulnerability]
    ) -> str:
        """Generate executive summary for disclosure"""
        
        critical_count = len([v for v in vulnerabilities if v.severity == "Critical"])
        high_count = len([v for v in vulnerabilities if v.severity == "High"])
        
        return f"""
## Security Disclosure Summary

This responsible disclosure document outlines {len(vulnerabilities)} security vulnerabilities discovered in {metadata.target_domain} that require immediate attention.

### Vulnerability Overview
- **Critical Vulnerabilities**: {critical_count} (require immediate remediation)
- **High-Priority Vulnerabilities**: {high_count} (require prompt remediation)
- **Total Issues Disclosed**: {len(vulnerabilities)}

### Discovery Information
- **Assessment Date**: {metadata.discovery_date}
- **Disclosure Date**: {metadata.disclosure_date}
- **Research Team**: {metadata.researcher_name}

### Coordinated Disclosure Process
This disclosure follows industry-standard responsible disclosure practices with a coordinated timeline for remediation. We are committed to working collaboratively with your security team to ensure these vulnerabilities are addressed promptly and effectively.

### Immediate Actions Required
1. Acknowledge receipt of this disclosure within 5 business days
2. Assign security team members to assess and remediate the identified issues
3. Establish communication channel for progress updates
4. Begin remediation of critical vulnerabilities immediately

### Our Commitment
- Confidentiality of vulnerability details until remediation is complete
- Collaborative approach to remediation and verification
- Professional and constructive communication throughout the process
- Recognition of your security team's efforts in addressing these issues

We appreciate your attention to these security matters and look forward to working together to improve the security posture of your systems.
        """
    
    def _generate_disclosure_policy(self) -> str:
        """Generate disclosure policy section"""
        return self.disclosure_templates["disclosure_policy"]
    
    def _generate_contact_information(self, config: Dict[str, Any]) -> Dict[str, str]:
        """Generate contact information"""
        return {
            "primary_contact": config.get("contact_email", "security@nexushunter.com"),
            "researcher_name": config.get("researcher_name", "Nexus Hunter Security Research Team"),
            "emergency_contact": "security-emergency@nexushunter.com",
            "pgp_key": "Available upon request for encrypted communication",
            "response_time": "5 business days for initial acknowledgment"
        }
    
    def _generate_legal_considerations(self) -> str:
        """Generate legal considerations section"""
        return """
## Legal Considerations

This security disclosure is made in good faith under responsible disclosure principles and industry best practices:

### Research Methodology
- All security testing was conducted using automated tools and safe testing methods
- No unauthorized access to data, systems, or user accounts was attempted or achieved
- No data was accessed, modified, deleted, or exfiltrated during the assessment
- Testing was limited to identifying security vulnerabilities without causing harm

### Legal Compliance
- This research was conducted in accordance with applicable laws and regulations
- No terms of service or acceptable use policies were intentionally violated
- The research was conducted for legitimate security research purposes
- This disclosure is made to improve security and protect users

### Responsible Disclosure
- Vulnerability details will remain confidential until remediation is complete
- No public disclosure will occur without coordination with your security team
- We are committed to working collaboratively to address these security issues
- This disclosure follows industry-standard coordinated vulnerability disclosure practices

### Disclaimer
This disclosure is provided "as is" for security improvement purposes. The research team makes no warranties regarding the completeness or accuracy of the findings and is not responsible for any actions taken based on this disclosure.
        """
    
    def _generate_next_steps(
        self,
        vulnerabilities: List[DisclosureVulnerability],
        timeline: DisclosureTimeline
    ) -> List[str]:
        """Generate next steps for disclosure process"""
        
        steps = [
            f"Acknowledge receipt of this disclosure by {timeline.acknowledgment_deadline}",
            "Assign dedicated security team members to assess the reported vulnerabilities",
            "Establish secure communication channel for progress updates and questions",
            "Begin immediate assessment and remediation of critical vulnerabilities",
            f"Provide remediation timeline and progress updates by {timeline.remediation_deadline}",
            "Coordinate testing and verification of implemented fixes",
            f"Plan coordinated public disclosure for {timeline.public_disclosure_date} (if applicable)",
            "Consider security advisory publication with appropriate researcher credit"
        ]
        
        if any(v.severity == "Critical" for v in vulnerabilities):
            steps.insert(3, "Prioritize critical vulnerabilities for emergency remediation within 48-72 hours")
        
        return steps

