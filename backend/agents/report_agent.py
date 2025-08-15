"""
Report Agent for Nexus Hunter
Generates professional bug bounty reports and responsible disclosure emails
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import jinja2
import markdown

from loguru import logger

from agents.base import BaseAgent


class ReportAgent(BaseAgent):
    """Autonomous report generation agent"""
    
    def __init__(self):
        super().__init__("ReportAgent")
        self.template_env = self._setup_templates()
        self.severity_colors = {
            "critical": "#FF0000",
            "high": "#FF6600", 
            "medium": "#FFAA00",
            "low": "#00AA00",
            "info": "#0066AA"
        }
    
    def _setup_templates(self) -> jinja2.Environment:
        """Setup Jinja2 template environment"""
        template_loader = jinja2.DictLoader({
            "vulnerability_report.md": self._get_vulnerability_template(),
            "executive_summary.md": self._get_executive_template(),
            "disclosure_email.txt": self._get_disclosure_template(),
            "technical_details.md": self._get_technical_template()
        })
        
        return jinja2.Environment(
            loader=template_loader,
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
    
    async def execute(self, scan_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        
        results = {
            "report_id": f"NEXUS-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "reports": {},
            "metadata": {},
            "delivery_methods": []
        }
        
        try:
            # Phase 1: Analyze scan data
            await self.update_progress("data_analysis", {
                "status": "Analyzing scan results and vulnerabilities",
                "phase": "1/4"
            })
            
            analysis = await self._analyze_scan_data(scan_data)
            results["metadata"] = analysis
            
            # Phase 2: Generate executive summary
            await self.update_progress("executive_summary", {
                "status": "Generating executive summary report",
                "phase": "2/4"
            })
            
            executive_report = await self._generate_executive_summary(analysis)
            results["reports"]["executive_summary"] = executive_report
            
            # Phase 3: Generate technical report
            await self.update_progress("technical_report", {
                "status": "Creating detailed technical vulnerability report",
                "phase": "3/4"
            })
            
            technical_report = await self._generate_technical_report(analysis)
            results["reports"]["technical_report"] = technical_report
            
            # Phase 4: Generate disclosure emails
            await self.update_progress("disclosure_generation", {
                "status": "Generating responsible disclosure communications",
                "phase": "4/4"
            })
            
            disclosure_emails = await self._generate_disclosure_emails(analysis)
            results["reports"]["disclosure_emails"] = disclosure_emails
            
            # Generate additional formats
            if not self.is_cancelled():
                html_report = await self._generate_html_report(analysis)
                results["reports"]["html_report"] = html_report
                
                json_report = await self._generate_json_report(analysis)
                results["reports"]["json_report"] = json_report
            
            results["delivery_methods"] = ["markdown", "html", "json", "email"]
            
            logger.info(f"📊 Report generation completed: {results['report_id']}")
            return results
            
        except Exception as e:
            logger.error(f"❌ Report generation failed: {e}")
            raise
    
    async def _analyze_scan_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze and categorize scan data"""
        
        analysis = {
            "scan_summary": {},
            "vulnerabilities": [],
            "risk_assessment": {},
            "recommendations": [],
            "target_info": {},
            "timeline": datetime.now().isoformat()
        }
        
        # Extract target information
        recon_data = scan_data.get("ReconAgent", {})
        exploit_data = scan_data.get("ExploitAgent", {})
        
        analysis["target_info"] = {
            "domain": recon_data.get("target", "Unknown"),
            "subdomains_discovered": len(recon_data.get("subdomains", [])),
            "technologies_identified": len(recon_data.get("technologies", {})),
            "ports_discovered": sum(len(ports) for ports in recon_data.get("ports", {}).values()),
            "scan_scope": "Full reconnaissance and vulnerability assessment"
        }
        
        # Analyze vulnerabilities
        vulnerabilities = exploit_data.get("vulnerabilities", [])
        analysis["vulnerabilities"] = await self._categorize_vulnerabilities(vulnerabilities)
        
        # Risk assessment
        analysis["risk_assessment"] = await self._calculate_risk_assessment(vulnerabilities)
        
        # Generate recommendations
        analysis["recommendations"] = await self._generate_security_recommendations(analysis)
        
        # Scan summary
        analysis["scan_summary"] = {
            "total_vulnerabilities": len(vulnerabilities),
            "critical_count": len([v for v in vulnerabilities if v.get("severity") == "critical"]),
            "high_count": len([v for v in vulnerabilities if v.get("severity") == "high"]),
            "medium_count": len([v for v in vulnerabilities if v.get("severity") == "medium"]),
            "low_count": len([v for v in vulnerabilities if v.get("severity") == "low"]),
            "scan_duration": "Completed",
            "coverage": "Full application assessment"
        }
        
        return analysis
    
    async def _categorize_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict[str, Any]]:
        """Categorize and enrich vulnerability data"""
        categorized = []
        
        for vuln in vulnerabilities:
            enriched_vuln = {
                **vuln,
                "id": f"NEXUS-{len(categorized) + 1:03d}",
                "cvss_vector": await self._generate_cvss_vector(vuln),
                "remediation": await self._get_remediation_advice(vuln),
                "references": await self._get_vulnerability_references(vuln),
                "business_impact": await self._assess_business_impact(vuln)
            }
            categorized.append(enriched_vuln)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        categorized.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 4))
        
        return categorized
    
    async def _generate_cvss_vector(self, vulnerability: Dict) -> str:
        """Generate CVSS vector for vulnerability"""
        severity = vulnerability.get("severity", "medium").lower()
        category = vulnerability.get("category", "").lower()
        
        # Simplified CVSS mapping
        cvss_mappings = {
            "sql injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cross-site scripting": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "server-side request forgery": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
            "command injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "path traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        }
        
        return cvss_mappings.get(category, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L")
    
    async def _get_remediation_advice(self, vulnerability: Dict) -> str:
        """Get specific remediation advice for vulnerability"""
        category = vulnerability.get("category", "").lower()
        
        remediation_map = {
            "sql injection": "Implement parameterized queries and input validation. Use prepared statements or stored procedures. Apply principle of least privilege to database accounts.",
            "cross-site scripting": "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers. Sanitize user input and encode output.",
            "server-side request forgery": "Implement allowlist-based input validation. Use network segmentation. Validate and sanitize URLs before making requests.",
            "command injection": "Use parameterized APIs instead of shell commands. Implement strict input validation. Use allowlists for acceptable input values.",
            "path traversal": "Validate and sanitize file paths. Use allowlists for acceptable file names. Implement proper access controls."
        }
        
        return remediation_map.get(category, "Implement proper input validation and follow secure coding practices.")
    
    async def _get_vulnerability_references(self, vulnerability: Dict) -> List[str]:
        """Get relevant references for vulnerability type"""
        category = vulnerability.get("category", "").lower()
        
        reference_map = {
            "sql injection": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            "cross-site scripting": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ],
            "server-side request forgery": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
            ]
        }
        
        return reference_map.get(category, ["https://owasp.org/www-project-top-ten/"])
    
    async def _assess_business_impact(self, vulnerability: Dict) -> str:
        """Assess business impact of vulnerability"""
        severity = vulnerability.get("severity", "medium").lower()
        category = vulnerability.get("category", "").lower()
        
        impact_map = {
            "critical": "High business risk - immediate attention required. Could lead to complete system compromise.",
            "high": "Significant business risk - prompt remediation needed. Could result in data breaches or service disruption.",
            "medium": "Moderate business risk - should be addressed in next development cycle.",
            "low": "Low business risk - can be addressed during routine maintenance."
        }
        
        base_impact = impact_map.get(severity, "Unknown business impact")
        
        # Add category-specific context
        if "injection" in category:
            base_impact += " Data integrity and confidentiality may be compromised."
        elif "xss" in category:
            base_impact += " User session hijacking and data theft possible."
        
        return base_impact
    
    async def _calculate_risk_assessment(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Calculate overall risk assessment"""
        if not vulnerabilities:
            return {
                "overall_risk": "Low",
                "risk_score": 0,
                "key_concerns": ["No significant vulnerabilities identified"],
                "immediate_actions": ["Continue monitoring and regular security assessments"]
            }
        
        # Calculate risk score
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        total_score = sum(severity_weights.get(v.get("severity", "low"), 1) for v in vulnerabilities)
        
        # Determine overall risk level
        if total_score >= 20:
            overall_risk = "Critical"
        elif total_score >= 10:
            overall_risk = "High"
        elif total_score >= 5:
            overall_risk = "Medium"
        else:
            overall_risk = "Low"
        
        # Key concerns
        categories = list(set(v.get("category", "Unknown") for v in vulnerabilities))
        key_concerns = [f"{cat} vulnerabilities detected" for cat in categories[:3]]
        
        # Immediate actions
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]
        high_vulns = [v for v in vulnerabilities if v.get("severity") == "high"]
        
        immediate_actions = []
        if critical_vulns:
            immediate_actions.append("Address critical vulnerabilities immediately")
        if high_vulns:
            immediate_actions.append("Plan remediation for high-severity issues")
        immediate_actions.append("Implement security monitoring")
        
        return {
            "overall_risk": overall_risk,
            "risk_score": total_score,
            "key_concerns": key_concerns,
            "immediate_actions": immediate_actions
        }
    
    async def _generate_security_recommendations(self, analysis: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate security recommendations based on findings"""
        recommendations = [
            {
                "category": "Immediate Actions",
                "recommendation": "Address all critical and high-severity vulnerabilities identified in this assessment",
                "priority": "High"
            },
            {
                "category": "Security Testing",
                "recommendation": "Implement regular automated security testing in the development pipeline",
                "priority": "Medium"
            },
            {
                "category": "Security Monitoring",
                "recommendation": "Deploy Web Application Firewall (WAF) and intrusion detection systems",
                "priority": "Medium"
            },
            {
                "category": "Developer Training",
                "recommendation": "Provide secure coding training focused on identified vulnerability categories",
                "priority": "Medium"
            },
            {
                "category": "Security Policies",
                "recommendation": "Establish and enforce secure development lifecycle (SDLC) practices",
                "priority": "Low"
            }
        ]
        
        return recommendations
    
    async def _generate_executive_summary(self, analysis: Dict[str, Any]) -> str:
        """Generate executive summary report"""
        template = self.template_env.get_template("executive_summary.md")
        
        return template.render(
            analysis=analysis,
            generated_date=datetime.now().strftime("%B %d, %Y"),
            report_id=f"NEXUS-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        )
    
    async def _generate_technical_report(self, analysis: Dict[str, Any]) -> str:
        """Generate detailed technical report"""
        template = self.template_env.get_template("technical_details.md")
        
        return template.render(
            analysis=analysis,
            generated_date=datetime.now().strftime("%B %d, %Y"),
            report_id=f"NEXUS-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        )
    
    async def _generate_disclosure_emails(self, analysis: Dict[str, Any]) -> Dict[str, str]:
        """Generate responsible disclosure emails"""
        template = self.template_env.get_template("disclosure_email.txt")
        
        emails = {}
        
        # Generate different email templates based on severity
        critical_vulns = [v for v in analysis["vulnerabilities"] if v.get("severity") == "critical"]
        high_vulns = [v for v in analysis["vulnerabilities"] if v.get("severity") == "high"]
        
        if critical_vulns:
            emails["critical_disclosure"] = template.render(
                severity="critical",
                vulnerabilities=critical_vulns,
                target_domain=analysis["target_info"]["domain"],
                urgency="immediate attention",
                timeline="within 24 hours"
            )
        
        if high_vulns:
            emails["high_disclosure"] = template.render(
                severity="high",
                vulnerabilities=high_vulns,
                target_domain=analysis["target_info"]["domain"],
                urgency="prompt attention",
                timeline="within 7 days"
            )
        
        # General disclosure email
        emails["general_disclosure"] = template.render(
            severity="general",
            vulnerabilities=analysis["vulnerabilities"],
            target_domain=analysis["target_info"]["domain"],
            urgency="attention",
            timeline="within 30 days"
        )
        
        return emails
    
    async def _generate_html_report(self, analysis: Dict[str, Any]) -> str:
        """Generate HTML version of the report"""
        # Convert markdown to HTML
        md_report = await self._generate_technical_report(analysis)
        html_content = markdown.markdown(md_report, extensions=['tables', 'toc'])
        
        # Wrap in HTML template
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Assessment Report - {analysis['target_info']['domain']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #1a1a1a; color: white; padding: 20px; }}
                .vulnerability {{ border-left: 4px solid #ff6600; padding: 10px; margin: 10px 0; }}
                .critical {{ border-left-color: #ff0000; }}
                .high {{ border-left-color: #ff6600; }}
                .medium {{ border-left-color: #ffaa00; }}
                .low {{ border-left-color: #00aa00; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔐 Nexus Hunter Security Assessment</h1>
                <p>Generated on {datetime.now().strftime('%B %d, %Y')}</p>
            </div>
            {html_content}
        </body>
        </html>
        """
        
        return html_template
    
    async def _generate_json_report(self, analysis: Dict[str, Any]) -> str:
        """Generate JSON version of the report"""
        return json.dumps(analysis, indent=2, default=str)
    
    def _get_executive_template(self) -> str:
        """Executive summary template"""
        return """
# 🔐 NEXUS HUNTER SECURITY ASSESSMENT
## Executive Summary Report

**Report ID:** {{ report_id }}  
**Generated:** {{ generated_date }}  
**Target:** {{ analysis.target_info.domain }}

---

## 🎯 Assessment Overview

This security assessment was conducted using Nexus Hunter's autonomous penetration testing platform. The assessment included comprehensive reconnaissance, vulnerability scanning, and exploitation testing.

**Scope:**
- Target Domain: {{ analysis.target_info.domain }}
- Subdomains Discovered: {{ analysis.target_info.subdomains_discovered }}
- Technologies Analyzed: {{ analysis.target_info.technologies_identified }}
- Ports Scanned: {{ analysis.target_info.ports_discovered }}

## 🚨 Key Findings

**Overall Risk Level:** {{ analysis.risk_assessment.overall_risk }}
**Risk Score:** {{ analysis.risk_assessment.risk_score }}/100

### Vulnerability Summary
- **Critical:** {{ analysis.scan_summary.critical_count }}
- **High:** {{ analysis.scan_summary.high_count }}
- **Medium:** {{ analysis.scan_summary.medium_count }}
- **Low:** {{ analysis.scan_summary.low_count }}

## ⚡ Key Concerns
{% for concern in analysis.risk_assessment.key_concerns %}
- {{ concern }}
{% endfor %}

## 🔧 Immediate Actions Required
{% for action in analysis.risk_assessment.immediate_actions %}
- {{ action }}
{% endfor %}

## 📋 Recommendations
{% for rec in analysis.recommendations %}
**{{ rec.category }}** (Priority: {{ rec.priority }})
{{ rec.recommendation }}

{% endfor %}

---
*This report was generated by Nexus Hunter Autonomous Security Platform*
"""
    
    def _get_technical_template(self) -> str:
        """Technical details template"""
        return """
# 🔐 NEXUS HUNTER TECHNICAL SECURITY REPORT

**Report ID:** {{ report_id }}  
**Generated:** {{ generated_date }}  
**Target:** {{ analysis.target_info.domain }}

---

## 📊 Scan Summary

| Metric | Value |
|--------|-------|
| Total Vulnerabilities | {{ analysis.scan_summary.total_vulnerabilities }} |
| Critical Severity | {{ analysis.scan_summary.critical_count }} |
| High Severity | {{ analysis.scan_summary.high_count }} |
| Medium Severity | {{ analysis.scan_summary.medium_count }} |
| Low Severity | {{ analysis.scan_summary.low_count }} |

## 🔍 Detailed Vulnerability Findings

{% for vuln in analysis.vulnerabilities %}
### {{ vuln.id }}: {{ vuln.title }}

**Severity:** {{ vuln.severity|upper }}  
**Category:** {{ vuln.category }}  
**CVSS Vector:** {{ vuln.cvss_vector }}

**Description:**
{{ vuln.description }}

**Location:**
- **URL:** {{ vuln.url }}
- **Parameter:** {{ vuln.parameter }}
- **Method:** {{ vuln.method }}

**Proof of Concept:**
```
{{ vuln.poc }}
```

**Business Impact:**
{{ vuln.business_impact }}

**Remediation:**
{{ vuln.remediation }}

**References:**
{% for ref in vuln.references %}
- {{ ref }}
{% endfor %}

---
{% endfor %}

## 🛡️ Security Recommendations

{% for rec in analysis.recommendations %}
### {{ rec.category }} ({{ rec.priority }} Priority)
{{ rec.recommendation }}

{% endfor %}

---
*Generated by Nexus Hunter - Autonomous Bug Bounty Intelligence Platform*
"""
    
    def _get_disclosure_template(self) -> str:
        """Responsible disclosure email template"""
        return """
Subject: Security Vulnerability Disclosure - {{ target_domain }}

Dear Security Team,

I hope this email finds you well. I am reaching out to responsibly disclose security vulnerabilities I discovered during a security assessment of {{ target_domain }}.

## Summary
I have identified {{ vulnerabilities|length }} security {{ 'vulnerability' if vulnerabilities|length == 1 else 'vulnerabilities' }} affecting your application, with {{ severity }} severity level requiring {{ urgency }}.

## Vulnerability Details
{% for vuln in vulnerabilities %}
**{{ loop.index }}. {{ vuln.title }}**
- Severity: {{ vuln.severity|upper }}
- Location: {{ vuln.url }}
- Category: {{ vuln.category }}

{% endfor %}

## Proposed Timeline
I recommend addressing these findings {{ timeline }}. I am happy to provide additional technical details and assist with remediation if needed.

## Responsible Disclosure
I am committed to responsible disclosure practices and will:
- Keep these findings confidential until they are resolved
- Provide reasonable time for remediation
- Work collaboratively on any clarifications needed

Please confirm receipt of this report and let me know your preferred method for sharing detailed technical information securely.

Best regards,
Nexus Hunter Security Research Team

---
This disclosure was generated by Nexus Hunter Autonomous Security Platform
"""
    
    def _get_vulnerability_template(self) -> str:
        """Individual vulnerability report template"""
        return """
# {{ title }}

**Severity:** {{ severity|upper }}
**Category:** {{ category }}
**Discovered:** {{ timestamp }}

## Description
{{ description }}

## Technical Details
- **URL:** {{ url }}
- **Parameter:** {{ parameter }}
- **Method:** {{ method }}
- **Payload:** `{{ payload }}`

## Evidence
{{ evidence }}

## Remediation
{{ remediation }}

## References
{% for ref in references %}
- {{ ref }}
{% endfor %}
""" 