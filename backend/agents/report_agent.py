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
                html_report = await self._generate_html_report(analysis, report_type="technical")
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
    
    async def _generate_executive_html_report(self, analysis: Dict[str, Any]) -> str:
        """Generate Executive Summary HTML Report - Business focused"""
        domain = analysis['target_info']['domain']
        today = datetime.now().strftime('%B %d, %Y')
        scan_date = datetime.now().strftime('%d %B %Y')
        time_generated = datetime.now().strftime('%H:%M UTC')

        # Business-focused metrics
        vulnerabilities = analysis.get('vulnerabilities', [])
        sev = {
            'critical': len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'critical']),
            'high': len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'high']),
            'medium': len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'medium']),
            'low': len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'low']),
        }
        total_vulns = sum(sev.values())
        
        # Business risk assessment
        risk_score = (sev['critical'] * 10) + (sev['high'] * 7) + (sev['medium'] * 4) + (sev['low'] * 1)
        risk_level = 'CRITICAL' if risk_score >= 30 else 'HIGH' if risk_score >= 15 else 'MEDIUM' if risk_score >= 5 else 'LOW'
        business_impact = 'SEVERE' if sev['critical'] > 0 else 'HIGH' if sev['high'] > 0 else 'MODERATE' if sev['medium'] > 0 else 'MINIMAL'

        # Executive dashboard focused on business concerns
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Security Assessment - {domain}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary: #667eea;
            --danger: #dc2626;
            --warning: #ea580c;
            --success: #059669;
            --text-primary: #1a202c;
            --text-secondary: #4a5568;
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --border: #e2e8f0;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Inter', sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--bg-secondary);
        }}
        
        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
        }}
        
        .executive-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 3rem 2rem;
            text-align: center;
        }}
        
        .executive-title {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
        }}
        
        .executive-subtitle {{
            font-size: 1.2rem;
            opacity: 0.9;
        }}
        
        .executive-dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            padding: 3rem 2rem;
            background: #f8fafc;
        }}
        
        .dashboard-card {{
            background: white;
            padding: 2rem;
            border-radius: 1rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            text-align: center;
        }}
        
        .dashboard-metric {{
            font-size: 2rem;
            font-weight: 800;
            margin-bottom: 0.5rem;
        }}
        
        .dashboard-label {{
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
        }}
        
        .risk-critical {{ color: var(--danger); }}
        .risk-high {{ color: var(--warning); }}
        .risk-medium {{ color: #d97706; }}
        .risk-low {{ color: var(--success); }}
        
        .content-section {{
            padding: 3rem 2rem;
        }}
        
        .section-title {{
            font-size: 1.875rem;
            font-weight: 700;
            margin-bottom: 2rem;
            color: var(--text-primary);
        }}
        
        .business-impact {{
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            padding: 2rem;
            border-radius: 1rem;
            border-left: 6px solid var(--primary);
            margin-bottom: 2rem;
        }}
        
        .action-items {{
            display: grid;
            gap: 1rem;
        }}
        
        .action-item {{
            background: white;
            padding: 1.5rem;
            border-radius: 0.75rem;
            border-left: 4px solid var(--danger);
            box-shadow: 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }}
        
        .action-priority {{
            font-size: 0.75rem;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--danger);
            margin-bottom: 0.5rem;
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <header class="executive-header">
            <h1 class="executive-title">🔐 Executive Security Assessment</h1>
            <p class="executive-subtitle">Security Risk Overview for {domain}</p>
            <div style="margin-top: 2rem; font-size: 0.875rem; opacity: 0.8;">
                Generated: {today} • Report ID: NEXUS-{datetime.now().strftime('%Y%m%d-%H%M%S')}
            </div>
        </header>
        
        <section class="executive-dashboard">
            <div class="dashboard-card">
                <div class="dashboard-metric risk-{risk_level.lower()}">{risk_score}</div>
                <div class="dashboard-label">Risk Score</div>
            </div>
            <div class="dashboard-card">
                <div class="dashboard-metric">{total_vulns}</div>
                <div class="dashboard-label">Vulnerabilities Found</div>
            </div>
            <div class="dashboard-card">
                <div class="dashboard-metric risk-{risk_level.lower()}">{risk_level}</div>
                <div class="dashboard-label">Risk Level</div>
            </div>
            <div class="dashboard-card">
                <div class="dashboard-metric">{business_impact}</div>
                <div class="dashboard-label">Business Impact</div>
            </div>
        </section>
        
        <section class="content-section">
            <h2 class="section-title">📊 Executive Summary</h2>
            <div class="business-impact">
                <h3 style="margin-bottom: 1rem; color: var(--primary);">🎯 Key Business Concerns</h3>
                <p style="margin-bottom: 1rem;">Our security assessment of <strong>{domain}</strong> identified <strong>{total_vulns} security vulnerabilities</strong> that pose varying levels of risk to your organization.</p>
                
                {'<p style="color: var(--danger); font-weight: 600;">⚠️ CRITICAL: Immediate attention required for ' + str(sev['critical']) + ' critical vulnerabilities that could lead to complete system compromise.</p>' if sev['critical'] > 0 else ''}
                {'<p style="color: var(--warning); font-weight: 600;">🔥 HIGH PRIORITY: ' + str(sev['high']) + ' high-severity issues require urgent remediation to prevent potential data breaches.</p>' if sev['high'] > 0 else ''}
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-top: 2rem;">
                    <div style="text-align: center; padding: 1rem; background: rgba(220, 38, 38, 0.1); border-radius: 0.5rem;">
                        <div style="font-size: 2rem; font-weight: 700; color: var(--danger);">{sev['critical']}</div>
                        <div style="font-size: 0.875rem; color: var(--text-secondary);">Critical</div>
                    </div>
                    <div style="text-align: center; padding: 1rem; background: rgba(234, 88, 12, 0.1); border-radius: 0.5rem;">
                        <div style="font-size: 2rem; font-weight: 700; color: var(--warning);">{sev['high']}</div>
                        <div style="font-size: 0.875rem; color: var(--text-secondary);">High</div>
                    </div>
                    <div style="text-align: center; padding: 1rem; background: rgba(217, 119, 6, 0.1); border-radius: 0.5rem;">
                        <div style="font-size: 2rem; font-weight: 700; color: #d97706;">{sev['medium']}</div>
                        <div style="font-size: 0.875rem; color: var(--text-secondary);">Medium</div>
                    </div>
                    <div style="text-align: center; padding: 1rem; background: rgba(5, 150, 105, 0.1); border-radius: 0.5rem;">
                        <div style="font-size: 2rem; font-weight: 700; color: var(--success);">{sev['low']}</div>
                        <div style="font-size: 0.875rem; color: var(--text-secondary);">Low</div>
                    </div>
                </div>
            </div>
        </section>
        
        <section class="content-section" style="background: var(--bg-secondary);">
            <h2 class="section-title">⚡ Immediate Action Items</h2>
            <div class="action-items">
                {'<div class="action-item"><div class="action-priority">IMMEDIATE</div><strong>Address Critical Vulnerabilities:</strong> Deploy emergency patches for ' + str(sev['critical']) + ' critical vulnerabilities within 24 hours to prevent system compromise.</div>' if sev['critical'] > 0 else ''}
                {'<div class="action-item" style="border-left-color: var(--warning);"><div class="action-priority" style="color: var(--warning);">URGENT</div><strong>Remediate High-Risk Issues:</strong> Schedule immediate fixes for ' + str(sev['high']) + ' high-severity vulnerabilities within 7 days.</div>' if sev['high'] > 0 else ''}
                <div class="action-item" style="border-left-color: var(--primary);">
                    <div class="action-priority" style="color: var(--primary);">STRATEGIC</div>
                    <strong>Security Review:</strong> Conduct comprehensive security policy review and implement ongoing monitoring.
                </div>
                <div class="action-item" style="border-left-color: var(--success);">
                    <div class="action-priority" style="color: var(--success);">ONGOING</div>
                    <strong>Staff Training:</strong> Implement security awareness training for development and operations teams.
                </div>
            </div>
        </section>
        
        <footer style="background: var(--text-primary); color: white; padding: 2rem; text-align: center;">
            <p style="margin-bottom: 0.5rem;">Generated by <strong>Nexus Hunter</strong> Autonomous Security Platform</p>
            <p style="font-size: 0.875rem; opacity: 0.8;">Professional Security Assessment • {time_generated}</p>
        </footer>
    </div>
</body>
</html>"""
        
        return html

    async def _generate_disclosure_html_report(self, analysis: Dict[str, Any]) -> str:
        """Generate Disclosure Communication HTML Report - Professional disclosure focused"""
        domain = analysis['target_info']['domain']
        today = datetime.now().strftime('%B %d, %Y')
        vulnerabilities = analysis.get('vulnerabilities', [])
        
        # Disclosure-specific metrics
        critical_vulns = [v for v in vulnerabilities if (v.get('severity') or '').lower() == 'critical']
        high_vulns = [v for v in vulnerabilities if (v.get('severity') or '').lower() == 'high']
        total_vulns = len(vulnerabilities)
        
        # Determine urgency and timeline
        if critical_vulns:
            urgency = "immediate attention"
            timeline = "within 24 hours"
            severity_class = "critical"
        elif high_vulns:
            urgency = "prompt attention"
            timeline = "within 7 days"
            severity_class = "high"
        else:
            urgency = "scheduled remediation"
            timeline = "within 30 days"
            severity_class = "medium"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Vulnerability Disclosure - {domain}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary: #2563eb;
            --success: #059669;
            --warning: #ea580c;
            --danger: #dc2626;
            --text-primary: #1a202c;
            --text-secondary: #4a5568;
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --border: #e2e8f0;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Inter', sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--bg-secondary);
            padding: 2rem;
        }}
        
        .disclosure-container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 1rem;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }}
        
        .disclosure-header {{
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }}
        
        .disclosure-title {{
            font-size: 1.875rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }}
        
        .disclosure-subtitle {{
            opacity: 0.9;
            font-size: 1rem;
        }}
        
        .disclosure-content {{
            padding: 2rem;
        }}
        
        .section {{
            margin-bottom: 2rem;
        }}
        
        .section-title {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--primary);
            border-bottom: 2px solid var(--border);
            padding-bottom: 0.5rem;
        }}
        
        .vulnerability-summary {{
            background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
            padding: 1.5rem;
            border-radius: 0.75rem;
            border-left: 4px solid var(--primary);
            margin-bottom: 2rem;
        }}
        
        .vuln-item {{
            background: white;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            border-left: 3px solid var(--border);
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }}
        
        .vuln-item.critical {{ border-left-color: var(--danger); }}
        .vuln-item.high {{ border-left-color: var(--warning); }}
        .vuln-item.medium {{ border-left-color: #d97706; }}
        .vuln-item.low {{ border-left-color: var(--success); }}
        
        .timeline-box {{
            background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
            padding: 1.5rem;
            border-radius: 0.75rem;
            border-left: 4px solid var(--success);
        }}
        
        .contact-info {{
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 0.75rem;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="disclosure-container">
        <header class="disclosure-header">
            <h1 class="disclosure-title">🔒 Security Vulnerability Disclosure</h1>
            <p class="disclosure-subtitle">Responsible Security Research Communication</p>
        </header>
        
        <div class="disclosure-content">
            <div class="section">
                <div style="text-align: center; margin-bottom: 2rem; padding: 1rem; background: var(--bg-secondary); border-radius: 0.5rem;">
                    <strong>To:</strong> Security Team - {domain}<br>
                    <strong>Date:</strong> {today}<br>
                    <strong>Subject:</strong> Security Vulnerability Disclosure
                </div>
                
                <p style="margin-bottom: 1.5rem;">Dear Security Team,</p>
                <p style="margin-bottom: 1.5rem;">I hope this communication finds you well. I am reaching out to responsibly disclose security vulnerabilities discovered during a security assessment of <strong>{domain}</strong>.</p>
            </div>
            
            <div class="section">
                <h2 class="section-title">📋 Summary</h2>
                <div class="vulnerability-summary">
                    <p style="margin-bottom: 1rem;">
                        I have identified <strong>{total_vulns}</strong> security {'vulnerability' if total_vulns == 1 else 'vulnerabilities'} affecting your application, requiring <strong>{urgency}</strong>.
                    </p>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 1rem; text-align: center;">
                        <div style="background: rgba(220, 38, 38, 0.1); padding: 1rem; border-radius: 0.5rem;">
                            <div style="font-size: 1.5rem; font-weight: 700; color: var(--danger);">{len(critical_vulns)}</div>
                            <div style="font-size: 0.875rem;">Critical</div>
                        </div>
                        <div style="background: rgba(234, 88, 12, 0.1); padding: 1rem; border-radius: 0.5rem;">
                            <div style="font-size: 1.5rem; font-weight: 700; color: var(--warning);">{len(high_vulns)}</div>
                            <div style="font-size: 0.875rem;">High</div>
                        </div>
                        <div style="background: rgba(37, 99, 235, 0.1); padding: 1rem; border-radius: 0.5rem;">
                            <div style="font-size: 1.5rem; font-weight: 700; color: var(--primary);">{total_vulns}</div>
                            <div style="font-size: 0.875rem;">Total</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2 class="section-title">🔍 Vulnerability Overview</h2>"""
        
        # Add vulnerability items
        for i, vuln in enumerate(vulnerabilities[:5]):  # Limit to top 5 for disclosure
            severity = (vuln.get('severity') or 'info').lower()
            html += f"""
                <div class="vuln-item {severity}">
                    <strong>{i+1}. {vuln.get('title', 'Security Vulnerability')}</strong><br>
                    <span style="font-size: 0.875rem; color: var(--text-secondary);">
                        Severity: <strong>{severity.upper()}</strong> • 
                        Location: {vuln.get('url', 'Multiple locations')} • 
                        Category: {vuln.get('category', 'Security Issue')}
                    </span>
                </div>"""
        
        if len(vulnerabilities) > 5:
            html += f"""
                <div style="text-align: center; margin-top: 1rem; font-style: italic; color: var(--text-secondary);">
                    ... and {len(vulnerabilities) - 5} additional vulnerabilities
                </div>"""
        
        html += f"""
            </div>
            
            <div class="section">
                <h2 class="section-title">📅 Proposed Timeline</h2>
                <div class="timeline-box">
                    <p style="margin-bottom: 1rem;">
                        <strong>Recommended Action:</strong> I recommend addressing these findings <strong>{timeline}</strong> based on their severity levels.
                    </p>
                    <p>I am happy to provide additional technical details and assist with remediation if needed.</p>
                </div>
            </div>
            
            <div class="section">
                <h2 class="section-title">🤝 Responsible Disclosure</h2>
                <p style="margin-bottom: 1rem;">I am committed to responsible disclosure practices and will:</p>
                <ul style="margin-left: 2rem; margin-bottom: 1rem;">
                    <li>Keep these findings confidential until they are resolved</li>
                    <li>Provide reasonable time for remediation</li>
                    <li>Work collaboratively on any clarifications needed</li>
                    <li>Respect your disclosure timeline and preferences</li>
                </ul>
                <p>Please confirm receipt of this report and let me know your preferred method for sharing detailed technical information securely.</p>
            </div>
            
            <div class="contact-info">
                <h3 style="margin-bottom: 1rem; color: var(--primary);">📞 Contact Information</h3>
                <p style="margin-bottom: 0.5rem;"><strong>Security Research Team</strong></p>
                <p style="color: var(--text-secondary);">Nexus Hunter Security Platform</p>
                <p style="margin-top: 1rem; font-size: 0.875rem; color: var(--text-secondary);">
                    This disclosure was generated by Nexus Hunter Autonomous Security Platform
                </p>
            </div>
        </div>
    </div>
</body>
</html>"""
        
        return html

    async def _generate_html_report(self, analysis: Dict[str, Any], report_type: str = "technical") -> str:
        """Generate HTML report based on type"""
        if report_type == "executive":
            return await self._generate_executive_html_report(analysis)
        elif report_type == "disclosure":
            return await self._generate_disclosure_html_report(analysis)
        else:  # technical report (default)
            return await self._generate_technical_html_report(analysis)
    
    async def _generate_technical_html_report(self, analysis: Dict[str, Any]) -> str:
        """Generate Technical HTML Security Assessment Report - Full technical details"""
        # Enhanced professional report with modern design, charts, and visual elements
        md_report = await self._generate_technical_report(analysis)
        domain = analysis['target_info']['domain']
        today = datetime.now().strftime('%B %d, %Y')
        scan_date = datetime.now().strftime('%d %B %Y')
        time_generated = datetime.now().strftime('%H:%M UTC')

        # Enhanced severity distribution and metrics
        vulnerabilities = analysis.get('vulnerabilities', [])
        sev = {
            'critical': len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'critical']),
            'high': len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'high']),
            'medium': len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'medium']),
            'low': len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'low']),
            'info': len([v for v in vulnerabilities if (v.get('severity') or '').lower() == 'info']),
        }
        total_vulns = sum(sev.values())
        
        # Risk scoring algorithm
        risk_score = (sev['critical'] * 10) + (sev['high'] * 7) + (sev['medium'] * 4) + (sev['low'] * 1)
        risk_level = 'CRITICAL' if risk_score >= 30 else 'HIGH' if risk_score >= 15 else 'MEDIUM' if risk_score >= 5 else 'LOW'
        risk_color = '#dc2626' if risk_level == 'CRITICAL' else '#ea580c' if risk_level == 'HIGH' else '#d97706' if risk_level == 'MEDIUM' else '#059669'
        
        # Coverage metrics
        target_info = analysis.get('target_info', {})
        coverage_metrics = {
            'subdomains': target_info.get('subdomains_discovered', 0),
            'ports': target_info.get('ports_discovered', 0),
            'technologies': target_info.get('technologies_identified', 0),
            'endpoints': len(vulnerabilities)  # Simplified metric
        }

        # Enhanced finding cards with better categorization
        finding_cards = []
        categories = {}
        
        for i, v in enumerate(vulnerabilities):
            severity = (v.get('severity') or 'info').lower()
            category = v.get('category', 'Uncategorized')
            
            # Track categories for summary
            if category not in categories:
                categories[category] = {'count': 0, 'severities': []}
            categories[category]['count'] += 1
            categories[category]['severities'].append(severity)
            
            # Severity styling
            sev_config = {
                'critical': {'class': 'critical', 'icon': '⚠️', 'bg': '#fef2f2', 'border': '#dc2626'},
                'high': {'class': 'high', 'icon': '🔥', 'bg': '#fef3e8', 'border': '#ea580c'},
                'medium': {'class': 'medium', 'icon': '⚡', 'bg': '#fefbeb', 'border': '#d97706'},
                'low': {'class': 'low', 'icon': '💡', 'bg': '#f0fdf4', 'border': '#059669'},
                'info': {'class': 'info', 'icon': 'ℹ️', 'bg': '#eff6ff', 'border': '#2563eb'}
            }
            
            config = sev_config.get(severity, sev_config['info'])
            
            # Enhanced comprehensive finding card with detailed analysis
            cvss_score = v.get('cvss_score', 'N/A')
            if cvss_score == 'N/A':
                cvss_score = {'critical': '9.5', 'high': '7.8', 'medium': '5.2', 'low': '2.1'}.get(severity, '0.0')
            
            # Enhanced descriptions based on category and severity
            enhanced_description = v.get('description', f'Security vulnerability identified in {category.lower()} component.')
            if len(enhanced_description) < 100:  # Enhance short descriptions
                enhanced_description += f" This {severity}-severity finding requires attention to maintain security posture and prevent potential exploitation."
            
            # Comprehensive impact assessment
            impact_details = v.get('impact', '')
            if not impact_details:
                impact_map = {
                    'critical': 'Immediate risk of data breach, system compromise, or service disruption. May lead to complete system takeover, data exfiltration, or business continuity issues.',
                    'high': 'Significant security risk with potential for unauthorized access, data exposure, or service degradation. Could result in partial system compromise or sensitive information disclosure.',
                    'medium': 'Moderate security concern that may facilitate further attacks or provide unauthorized information access. Requires systematic remediation to prevent escalation.',
                    'low': 'Minor security weakness that represents best practice violation or potential information disclosure. Should be addressed during routine maintenance cycles.'
                }
                impact_details = impact_map.get(severity, 'Security impact requires evaluation based on business context and threat model.')
            
            # Detailed remediation guidance
            remediation_details = v.get('remediation', '')
            if not remediation_details:
                remediation_map = {
                    'critical': 'IMMEDIATE ACTION REQUIRED: Apply security patches, implement access controls, enable monitoring, and conduct impact assessment. Consider temporary service isolation until remediation is complete.',
                    'high': 'HIGH PRIORITY: Update affected components, review configuration settings, implement additional security controls, and validate fix effectiveness through testing.',
                    'medium': 'SCHEDULED REMEDIATION: Plan systematic fix deployment, update security configurations, implement preventive controls, and establish monitoring for similar issues.',
                    'low': 'MAINTENANCE CYCLE: Include in regular update schedule, review security best practices, implement configuration improvements, and document security enhancements.'
                }
                remediation_details = remediation_map.get(severity, 'Follow vendor-specific remediation guidance and implement appropriate security controls.')
            
            card = f"""
            <div class="finding-card {config['class']}" style="border-left: 6px solid {config['border']}; background: {config['bg']}; margin-bottom: 2rem; page-break-inside: avoid;">
                <!-- Finding Header with Enhanced Metadata -->
                <div class="finding-header" style="background: white; padding: 2rem; border-bottom: 2px solid {config['border']};">
                    <div class="finding-meta" style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem;">
                        <div style="display: flex; align-items: center; gap: 1rem;">
                            <span class="finding-id" style="background: {config['border']}; color: white; padding: 0.5rem 1rem; border-radius: 0.5rem; font-weight: 700;">#{i+1:03d}</span>
                            <span class="severity-badge {config['class']}" style="background: {config['border']}; color: white; padding: 0.75rem 1.5rem; border-radius: 2rem; font-weight: 700; font-size: 0.875rem;">{config['icon']} {severity.upper()}</span>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.25rem;">CVSS v3.1 Score</div>
                            <div style="font-size: 1.25rem; font-weight: 700; color: {config['border']};">{cvss_score}</div>
                        </div>
                    </div>
                    <h3 class="finding-title" style="font-size: 1.5rem; font-weight: 700; color: var(--text-primary); line-height: 1.3; margin: 0;">
                        {v.get('title', 'Security Vulnerability Identified')}
                    </h3>
                    <p style="color: var(--text-secondary); margin-top: 0.75rem; font-weight: 500;">
                        {category} • Found in {v.get('url', 'system component')}
                    </p>
                </div>
                
                <!-- Comprehensive Technical Details -->
                <div class="finding-details" style="padding: 2rem;">
                    <!-- Quick Facts Grid -->
                    <div style="background: var(--bg-secondary); padding: 1.5rem; border-radius: 1rem; margin-bottom: 2rem;">
                        <h4 style="font-weight: 700; color: var(--text-primary); margin-bottom: 1rem; font-size: 1rem;">📊 Technical Summary</h4>
                        <div class="detail-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                            <div class="detail-item" style="background: white; padding: 1rem; border-radius: 0.75rem; border-left: 3px solid {config['border']};">
                                <span class="detail-label" style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); display: block; margin-bottom: 0.5rem;">Vulnerability Category</span>
                                <span class="detail-value" style="font-weight: 600; color: var(--text-primary);">{category}</span>
                            </div>
                            <div class="detail-item" style="background: white; padding: 1rem; border-radius: 0.75rem; border-left: 3px solid {config['border']};">
                                <span class="detail-label" style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); display: block; margin-bottom: 0.5rem;">Affected Component</span>
                                <span class="detail-value url-break" style="font-weight: 600; color: var(--text-primary); word-break: break-all; font-size: 0.875rem;">{v.get('url', 'System Component')}</span>
                            </div>
                            <div class="detail-item" style="background: white; padding: 1rem; border-radius: 0.75rem; border-left: 3px solid {config['border']};">
                                <span class="detail-label" style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); display: block; margin-bottom: 0.5rem;">Parameter/Vector</span>
                                <span class="detail-value" style="font-weight: 600; color: var(--text-primary);">{v.get('parameter', 'Multiple vectors')}</span>
                            </div>
                            <div class="detail-item" style="background: white; padding: 1rem; border-radius: 0.75rem; border-left: 3px solid {config['border']};">
                                <span class="detail-label" style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); display: block; margin-bottom: 0.5rem;">Risk Level</span>
                                <span class="detail-value" style="font-weight: 700; color: {config['border']}; text-transform: uppercase;">{severity}</span>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Detailed Analysis Sections -->
                    <div style="display: grid; gap: 2rem;">
                        <div class="finding-section" style="background: white; padding: 1.5rem; border-radius: 1rem; border: 1px solid var(--border-color);">
                            <h4 class="section-label" style="font-size: 1rem; font-weight: 700; color: var(--text-primary); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                                📋 Vulnerability Description & Technical Details
                            </h4>
                            <div class="section-content" style="line-height: 1.7; color: var(--text-primary);">
                                <p style="margin-bottom: 1rem;">{enhanced_description}</p>
                                <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 0.5rem; border-left: 4px solid {config['border']};">
                                    <strong style="color: var(--text-primary);">Technical Classification:</strong> {category} vulnerability with {severity} severity rating, requiring {'immediate' if severity == 'critical' else 'prioritized' if severity == 'high' else 'scheduled'} remediation.
                                </div>
                            </div>
                        </div>
                        
                        <div class="finding-section" style="background: white; padding: 1.5rem; border-radius: 1rem; border: 1px solid var(--border-color);">
                            <h4 class="section-label" style="font-size: 1rem; font-weight: 700; color: var(--text-primary); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                                🛡️ Business Impact & Risk Assessment
                            </h4>
                            <div class="section-content" style="line-height: 1.7; color: var(--text-primary);">
                                <p style="margin-bottom: 1rem;">{impact_details}</p>
                                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-top: 1rem;">
                                    <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 0.5rem; text-align: center;">
                                        <div style="font-weight: 700; color: {config['border']};">{'HIGH' if severity in ['critical', 'high'] else 'MEDIUM' if severity == 'medium' else 'LOW'}</div>
                                        <div style="font-size: 0.875rem; color: var(--text-muted);">Business Risk</div>
                                    </div>
                                    <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 0.5rem; text-align: center;">
                                        <div style="font-weight: 700; color: {config['border']};">{'IMMEDIATE' if severity == 'critical' else 'URGENT' if severity == 'high' else 'SCHEDULED'}</div>
                                        <div style="font-size: 0.875rem; color: var(--text-muted);">Action Priority</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="finding-section" style="background: white; padding: 1.5rem; border-radius: 1rem; border: 1px solid var(--border-color);">
                            <h4 class="section-label" style="font-size: 1rem; font-weight: 700; color: var(--text-primary); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                                🔧 Remediation Strategy & Implementation Guide
                            </h4>
                            <div class="section-content" style="line-height: 1.7; color: var(--text-primary);">
                                <p style="margin-bottom: 1rem;">{remediation_details}</p>
                                <div style="background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%); padding: 1rem; border-radius: 0.5rem; border-left: 4px solid #10b981; margin-top: 1rem;">
                                    <strong style="color: #065f46;">Recommended Timeline:</strong> {'0-24 hours' if severity == 'critical' else '1-7 days' if severity == 'high' else '1-4 weeks' if severity == 'medium' else '1-3 months'} • 
                                    <strong style="color: #065f46;">Validation Required:</strong> {'Yes - immediate verification' if severity in ['critical', 'high'] else 'Yes - standard testing' if severity == 'medium' else 'Standard QA process'}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            """
            finding_cards.append(card)
        
        findings_html = "\n".join(finding_cards) if finding_cards else """
        <div class="no-findings">
            <div class="success-icon">✅</div>
            <h3>No Critical Vulnerabilities Detected</h3>
            <p>The automated security assessment did not identify any immediate security concerns. However, manual review is recommended for comprehensive coverage.</p>
        </div>
        """

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus Hunter Security Assessment - {domain}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --danger-gradient: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            --success-gradient: linear-gradient(135deg, #06c755 0%, #10ac84 100%);
            --warning-gradient: linear-gradient(135deg, #ffa726 0%, #fb8c00 100%);
            --dark-gradient: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --bg-tertiary: #e2e8f0;
            --text-primary: #1a202c;
            --text-secondary: #4a5568;
            --text-muted: #718096;
            --border-color: #e2e8f0;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            
            --critical-color: #dc2626;
            --high-color: #ea580c;
            --medium-color: #d97706;
            --low-color: #059669;
            --info-color: #2563eb;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--bg-secondary);
            font-size: 14px;
        }}

        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
            background: var(--bg-primary);
            box-shadow: var(--shadow-lg);
            min-height: 100vh;
        }}

        /* Header Section */
        .report-header {{
            background: var(--primary-gradient);
            color: white;
            padding: 3rem 2rem;
            position: relative;
            overflow: hidden;
        }}

        .report-header::before {{
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 300px;
            height: 300px;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            border-radius: 50%;
            transform: translate(50%, -50%);
        }}

        .header-content {{
            position: relative;
            z-index: 2;
        }}

        .company-logo {{
            display: flex;
            align-items: center;
            margin-bottom: 2rem;
            font-size: 1.5rem;
            font-weight: 800;
        }}

        .company-logo::before {{
            content: '🛡️';
            margin-right: 0.5rem;
            font-size: 2rem;
        }}

        .report-title {{
            font-size: 2.5rem;
            font-weight: 800;
            margin-bottom: 0.5rem;
            line-height: 1.2;
        }}

        .report-subtitle {{
            font-size: 1.2rem;
            opacity: 0.9;
            margin-bottom: 2rem;
            font-weight: 300;
        }}

        .header-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-top: 2rem;
        }}

        .meta-item {{
            background: rgba(255, 255, 255, 0.1);
            padding: 1rem;
            border-radius: 0.75rem;
            backdrop-filter: blur(10px);
        }}

        .meta-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            opacity: 0.8;
            margin-bottom: 0.25rem;
        }}

        .meta-value {{
            font-size: 1rem;
            font-weight: 600;
        }}

        /* Executive Dashboard */
        .executive-dashboard {{
            padding: 2rem;
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
        }}

        .dashboard-title {{
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            color: var(--text-primary);
        }}

        .dashboard-title::before {{
            content: '📊';
            margin-right: 0.5rem;
        }}

        .dashboard-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}

        .dashboard-card {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 1rem;
            padding: 1.5rem;
            box-shadow: var(--shadow);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}

        .dashboard-card:hover {{
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }}

        .card-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
        }}

        .card-title {{
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .card-icon {{
            width: 2.5rem;
            height: 2.5rem;
            border-radius: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            color: white;
        }}

        .card-value {{
            font-size: 2rem;
            font-weight: 800;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
        }}

        .card-description {{
            font-size: 0.875rem;
            color: var(--text-muted);
        }}

        /* Risk Score Card */
        .risk-score-card {{
            background: linear-gradient(135deg, {risk_color}15, {risk_color}05);
            border: 1px solid {risk_color}30;
        }}

        .risk-score-value {{
            color: {risk_color};
            font-size: 2.5rem;
        }}

        /* Severity Distribution */
        .severity-chart {{
            margin: 2rem 0;
        }}

        .chart-title {{
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--text-primary);
        }}

        .severity-bars {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
        }}

        .severity-bar {{
            flex: 1;
            background: var(--bg-tertiary);
            border-radius: 0.5rem;
            overflow: hidden;
            height: 2rem;
            position: relative;
        }}

        .bar-fill {{
            height: 100%;
            border-radius: 0.5rem;
            transition: width 0.8s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            font-size: 0.75rem;
        }}

        .bar-critical {{ background: var(--critical-color); width: {(sev['critical']/max(total_vulns,1)*100):.0f}%; }}
        .bar-high {{ background: var(--high-color); width: {(sev['high']/max(total_vulns,1)*100):.0f}%; }}
        .bar-medium {{ background: var(--medium-color); width: {(sev['medium']/max(total_vulns,1)*100):.0f}%; }}
        .bar-low {{ background: var(--low-color); width: {(sev['low']/max(total_vulns,1)*100):.0f}%; }}

        .severity-legend {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .legend-color {{
            width: 1rem;
            height: 1rem;
            border-radius: 0.25rem;
        }}

        .legend-label {{
            font-size: 0.875rem;
            font-weight: 500;
        }}

        .legend-count {{
            font-size: 0.875rem;
            color: var(--text-muted);
        }}

        /* Finding Cards */
        .findings-grid {{
            display: grid;
            gap: 1.5rem;
        }}

        .finding-card {{
            border-radius: 1rem;
            overflow: hidden;
            box-shadow: var(--shadow);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}

        .finding-card:hover {{
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }}

        .finding-header {{
            padding: 1.5rem;
            background: white;
            border-bottom: 1px solid var(--border-color);
        }}

        .finding-meta {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
        }}

        .finding-id {{
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.75rem;
            background: var(--bg-tertiary);
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            color: var(--text-muted);
        }}

        .severity-badge {{
            padding: 0.5rem 1rem;
            border-radius: 2rem;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: white;
        }}

        .severity-badge.critical {{ background: var(--critical-color); }}
        .severity-badge.high {{ background: var(--high-color); }}
        .severity-badge.medium {{ background: var(--medium-color); }}
        .severity-badge.low {{ background: var(--low-color); }}
        .severity-badge.info {{ background: var(--info-color); }}

        .finding-title {{
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--text-primary);
            line-height: 1.3;
        }}

        .finding-details {{
            padding: 1.5rem;
        }}

        .detail-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }}

        .detail-item {{
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: 0.5rem;
        }}

        .detail-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 0.25rem;
            display: block;
        }}

        .detail-value {{
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-primary);
            word-break: break-all;
        }}

        .url-break {{
            word-break: break-all;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.75rem;
        }}

        .finding-section {{
            margin-bottom: 1.5rem;
        }}

        .section-label {{
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 0.75rem;
            display: flex;
            align-items: center;
        }}

        .section-content {{
            font-size: 0.875rem;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: 0.5rem;
            border-left: 4px solid var(--border-color);
        }}

        /* No Findings State */
        .no-findings {{
            text-align: center;
            padding: 3rem;
            background: linear-gradient(135deg, #f0fff4 0%, #dcfce7 100%);
            border-radius: 1rem;
            border: 1px solid #bbf7d0;
        }}

        .success-icon {{
            font-size: 3rem;
            margin-bottom: 1rem;
        }}

        .no-findings h3 {{
            font-size: 1.25rem;
            font-weight: 600;
            color: #059669;
            margin-bottom: 0.5rem;
        }}

        .no-findings p {{
            color: #047857;
            font-size: 0.875rem;
        }}

        /* Footer */
        .report-footer {{
            background: var(--bg-tertiary);
            padding: 2rem;
            text-align: center;
            border-top: 1px solid var(--border-color);
        }}

        .footer-content {{
            font-size: 0.75rem;
            color: var(--text-muted);
        }}

        /* Enhanced Print & PDF Styles */
        @media print {{
            * {{
                -webkit-print-color-adjust: exact !important;
                color-adjust: exact !important;
                print-color-adjust: exact !important;
            }}
            
            .report-container {{
                box-shadow: none !important;
                max-width: none !important;
                margin: 0 !important;
                padding: 0 !important;
                background: white !important;
            }}
            
            /* Page breaks and spacing */
            .report-header {{
                page-break-after: always;
                padding: 2rem 1rem !important;
                margin-bottom: 0 !important;
            }}
            
            .executive-dashboard {{
                page-break-after: always;
                padding: 1rem !important;
            }}
            
            section {{
                page-break-inside: avoid;
                margin-bottom: 1rem !important;
            }}
            
            .finding-card {{
                page-break-inside: avoid !important;
                margin-bottom: 1.5rem !important;
                border: 1px solid #e2e8f0 !important;
                background: white !important;
            }}
            
            /* Ensure colors and backgrounds are preserved */
            .severity-badge.critical {{
                background: #dc2626 !important;
                color: white !important;
            }}
            
            .severity-badge.high {{
                background: #ea580c !important;
                color: white !important;
            }}
            
            .severity-badge.medium {{
                background: #d97706 !important;
                color: white !important;
            }}
            
            .severity-badge.low {{
                background: #059669 !important;
                color: white !important;
            }}
            
            /* Fix gradients for PDF */
            .report-header {{
                background: #667eea !important;
                color: white !important;
            }}
            
            .dashboard-card {{
                border: 1px solid #e2e8f0 !important;
                background: white !important;
                box-shadow: none !important;
                margin-bottom: 1rem !important;
            }}
            
            .card-icon {{
                background: #667eea !important;
                color: white !important;
            }}
            
            /* Preserve chart colors */
            .bar-critical {{
                background: #dc2626 !important;
            }}
            
            .bar-high {{
                background: #ea580c !important;
            }}
            
            .bar-medium {{
                background: #d97706 !important;
            }}
            
            .bar-low {{
                background: #059669 !important;
            }}
            
            .legend-color {{
                border: 1px solid #666 !important;
            }}
            
            /* Typography improvements for PDF */
            h1, h2, h3, h4, h5, h6 {{
                page-break-after: avoid;
                color: #1a202c !important;
            }}
            
            p {{
                orphans: 3;
                widows: 3;
            }}
            
            /* Footer positioning */
            .report-footer {{
                page-break-before: auto;
                margin-top: 2rem !important;
            }}
        }}
        
        /* PDF-specific optimizations for WeasyPrint */
        @page {{
            size: A4;
            margin: 15mm;
            @top-center {{
                content: "Nexus Hunter Security Assessment Report";
                font-size: 10px;
                color: #6b7280;
                font-family: Inter, sans-serif;
            }}
            @bottom-center {{
                content: "Page " counter(page) " of " counter(pages);
                font-size: 10px;
                color: #6b7280;
                font-family: Inter, sans-serif;
            }}
        }}
        
        @page :first {{
            @top-center {{
                content: "";
            }}
            @bottom-center {{
                content: "";
            }}
        }}

        /* Responsive */
        @media (max-width: 768px) {{
            .report-header {{
                padding: 2rem 1rem;
            }}
            
            .executive-dashboard {{
                padding: 1rem;
            }}
            
            .dashboard-grid {{
                grid-template-columns: 1fr;
            }}
            
            .header-meta {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Header Section -->
        <header class="report-header">
            <div class="header-content">
                <div class="company-logo">
                    NEXUS HUNTER
                </div>
                <h1 class="report-title">Security Assessment Report</h1>
                <p class="report-subtitle">Comprehensive Vulnerability Analysis & Risk Assessment</p>
                
                <div class="header-meta">
                    <div class="meta-item">
                        <div class="meta-label">Target Domain</div>
                        <div class="meta-value">{domain}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Scan Date</div>
                        <div class="meta-value">{scan_date}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Report Generated</div>
                        <div class="meta-value">{time_generated}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Assessment Type</div>
                        <div class="meta-value">Automated Security Scan</div>
                    </div>
                </div>
            </div>
        </header>

        <!-- Executive Dashboard -->
        <section class="executive-dashboard">
            <h2 class="dashboard-title">
                Executive Summary
            </h2>
            
            <div class="dashboard-grid">
                <div class="dashboard-card risk-score-card">
                    <div class="card-header">
                        <span class="card-title">Overall Risk Level</span>
                        <div class="card-icon" style="background: {risk_color};">⚠️</div>
                    </div>
                    <div class="card-value risk-score-value">{risk_level}</div>
                    <div class="card-description">Risk Score: {risk_score}/100</div>
                </div>
                
                <div class="dashboard-card">
                    <div class="card-header">
                        <span class="card-title">Total Vulnerabilities</span>
                        <div class="card-icon" style="background: var(--danger-gradient);">🐛</div>
                    </div>
                    <div class="card-value">{total_vulns}</div>
                    <div class="card-description">Security findings identified</div>
                </div>
                
                <div class="dashboard-card">
                    <div class="card-header">
                        <span class="card-title">Critical Issues</span>
                        <div class="card-icon" style="background: var(--critical-color);">🔥</div>
                    </div>
                    <div class="card-value">{sev['critical']}</div>
                    <div class="card-description">Requiring immediate attention</div>
                </div>
                
                <div class="dashboard-card">
                    <div class="card-header">
                        <span class="card-title">Coverage Scope</span>
                        <div class="card-icon" style="background: var(--success-gradient);">🔍</div>
                    </div>
                    <div class="card-value">{coverage_metrics['subdomains']}</div>
                    <div class="card-description">Subdomains analyzed</div>
                </div>
            </div>

            <div class="severity-chart">
                <h3 class="chart-title">Vulnerability Distribution by Severity</h3>
                <div class="severity-bars">
                    <div class="severity-bar">
                        <div class="bar-fill bar-critical">{sev['critical'] if sev['critical'] > 0 else ''}</div>
                    </div>
                    <div class="severity-bar">
                        <div class="bar-fill bar-high">{sev['high'] if sev['high'] > 0 else ''}</div>
                    </div>
                    <div class="severity-bar">
                        <div class="bar-fill bar-medium">{sev['medium'] if sev['medium'] > 0 else ''}</div>
                    </div>
                    <div class="severity-bar">
                        <div class="bar-fill bar-low">{sev['low'] if sev['low'] > 0 else ''}</div>
                    </div>
                </div>
                
                <div class="severity-legend">
                    <div class="legend-item">
                        <div class="legend-color" style="background: var(--critical-color);"></div>
                        <span class="legend-label">Critical</span>
                        <span class="legend-count">({sev['critical']})</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: var(--high-color);"></div>
                        <span class="legend-label">High</span>
                        <span class="legend-count">({sev['high']})</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: var(--medium-color);"></div>
                        <span class="legend-label">Medium</span>
                        <span class="legend-count">({sev['medium']})</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: var(--low-color);"></div>
                        <span class="legend-label">Low</span>
                        <span class="legend-count">({sev['low']})</span>
                    </div>
                </div>
            </div>
        </section>

        <!-- Assessment Overview Section -->
        <section style="padding: 2rem; background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%); border-bottom: 1px solid var(--border-color);">
            <div style="max-width: 1000px; margin: 0 auto;">
                <h2 style="font-size: 1.75rem; font-weight: 800; color: var(--text-primary); margin-bottom: 1.5rem; text-align: center;">
                    🎯 Assessment Overview & Scope
                </h2>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; margin-bottom: 2rem;">
                    <div style="background: white; padding: 1.5rem; border-radius: 1rem; box-shadow: var(--shadow);">
                        <h3 style="font-weight: 700; color: var(--text-primary); margin-bottom: 1rem;">🔍 Scope of Assessment</h3>
                        <ul style="list-style: none; padding: 0; margin: 0;">
                            <li style="padding: 0.5rem 0; border-bottom: 1px solid #f1f5f9;">✅ <strong>Target Domain:</strong> {domain}</li>
                            <li style="padding: 0.5rem 0; border-bottom: 1px solid #f1f5f9;">✅ <strong>Subdomains:</strong> {coverage_metrics['subdomains']} discovered and analyzed</li>
                            <li style="padding: 0.5rem 0; border-bottom: 1px solid #f1f5f9;">✅ <strong>Open Ports:</strong> {coverage_metrics['ports']} services identified</li>
                            <li style="padding: 0.5rem 0;">✅ <strong>Technologies:</strong> {coverage_metrics['technologies']} frameworks detected</li>
                        </ul>
                    </div>
                    
                    <div style="background: white; padding: 1.5rem; border-radius: 1rem; box-shadow: var(--shadow);">
                        <h3 style="font-weight: 700; color: var(--text-primary); margin-bottom: 1rem;">⚙️ Testing Methodology</h3>
                        <ul style="list-style: none; padding: 0; margin: 0;">
                            <li style="padding: 0.5rem 0; border-bottom: 1px solid #f1f5f9;">🔎 <strong>Reconnaissance:</strong> Automated discovery & enumeration</li>
                            <li style="padding: 0.5rem 0; border-bottom: 1px solid #f1f5f9;">🛡️ <strong>Vulnerability Scanning:</strong> OWASP-based testing</li>
                            <li style="padding: 0.5rem 0; border-bottom: 1px solid #f1f5f9;">⚡ <strong>Exploitation:</strong> Safe proof-of-concept testing</li>
                            <li style="padding: 0.5rem 0;">📊 <strong>Reporting:</strong> Comprehensive risk analysis</li>
                        </ul>
                    </div>
                </div>
                
                <div style="background: white; padding: 2rem; border-radius: 1rem; box-shadow: var(--shadow); text-align: center;">
                    <h3 style="font-weight: 700; color: var(--text-primary); margin-bottom: 1rem;">📈 Assessment Timeline & Execution</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 1rem;">This comprehensive security assessment was conducted using industry-standard methodologies and automated testing frameworks. The assessment follows NIST Cybersecurity Framework guidelines and OWASP Testing methodology to ensure thorough coverage of potential security risks.</p>
                    <div style="display: inline-flex; align-items: center; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; padding: 0.75rem 1.5rem; border-radius: 2rem; font-weight: 600;">
                        ⏱️ Assessment Duration: Automated continuous monitoring • Generated: {scan_date}
                    </div>
                </div>
            </div>
        </section>

        <!-- Risk Assessment Matrix -->
        <section style="padding: 2rem; background: var(--bg-primary);">
            <div style="max-width: 1000px; margin: 0 auto;">
                <h2 style="font-size: 1.75rem; font-weight: 800; color: var(--text-primary); margin-bottom: 1.5rem; text-align: center;">
                    🎯 Risk Assessment Matrix
                </h2>
                
                <div style="background: white; padding: 2rem; border-radius: 1rem; box-shadow: var(--shadow); margin-bottom: 2rem;">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
                        <div style="text-align: center; padding: 1.5rem; background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); border-radius: 1rem; border: 2px solid var(--critical-color);">
                            <div style="font-size: 2rem; margin-bottom: 0.5rem;">🚨</div>
                            <div style="font-size: 2rem; font-weight: 800; color: var(--critical-color);">{sev['critical']}</div>
                            <div style="font-size: 0.875rem; font-weight: 600; color: var(--critical-color);">CRITICAL</div>
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">Immediate Action Required</div>
                        </div>
                        
                        <div style="text-align: center; padding: 1.5rem; background: linear-gradient(135deg, #fef3e8 0%, #fed7aa 100%); border-radius: 1rem; border: 2px solid var(--high-color);">
                            <div style="font-size: 2rem; margin-bottom: 0.5rem;">⚠️</div>
                            <div style="font-size: 2rem; font-weight: 800; color: var(--high-color);">{sev['high']}</div>
                            <div style="font-size: 0.875rem; font-weight: 600; color: var(--high-color);">HIGH</div>
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">Priority Remediation</div>
                        </div>
                        
                        <div style="text-align: center; padding: 1.5rem; background: linear-gradient(135deg, #fefbeb 0%, #fde68a 100%); border-radius: 1rem; border: 2px solid var(--medium-color);">
                            <div style="font-size: 2rem; margin-bottom: 0.5rem;">⚡</div>
                            <div style="font-size: 2rem; font-weight: 800; color: var(--medium-color);">{sev['medium']}</div>
                            <div style="font-size: 0.875rem; font-weight: 600; color: var(--medium-color);">MEDIUM</div>
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">Scheduled Fix</div>
                        </div>
                        
                        <div style="text-align: center; padding: 1.5rem; background: linear-gradient(135deg, #f0fdf4 0%, #bbf7d0 100%); border-radius: 1rem; border: 2px solid var(--low-color);">
                            <div style="font-size: 2rem; margin-bottom: 0.5rem;">💡</div>
                            <div style="font-size: 2rem; font-weight: 800; color: var(--low-color);">{sev['low']}</div>
                            <div style="font-size: 0.875rem; font-weight: 600; color: var(--low-color);">LOW</div>
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">Best Practice</div>
                        </div>
                    </div>
                    
                    <div style="background: var(--bg-secondary); padding: 1.5rem; border-radius: 0.75rem; border-left: 4px solid #667eea;">
                        <h3 style="font-weight: 700; color: var(--text-primary); margin-bottom: 1rem;">📊 Risk Calculation Methodology</h3>
                        <p style="color: var(--text-secondary); margin-bottom: 1rem;">Risk scores are calculated using industry-standard CVSS v3.1 methodology with additional business impact considerations:</p>
                        <ul style="color: var(--text-secondary); margin: 0; padding-left: 1.5rem;">
                            <li><strong>Critical (9.0-10.0):</strong> Severe vulnerabilities with immediate exploitation potential</li>
                            <li><strong>High (7.0-8.9):</strong> Significant security risks requiring urgent attention</li>
                            <li><strong>Medium (4.0-6.9):</strong> Moderate risks that should be addressed systematically</li>
                            <li><strong>Low (0.1-3.9):</strong> Minor issues and security hardening opportunities</li>
                        </ul>
                    </div>
                </div>
            </div>
        </section>

        <!-- Detailed Findings Section -->
        <section style="padding: 2rem; background: var(--bg-secondary);">
            <div style="max-width: 1000px; margin: 0 auto;">
                <h2 style="font-size: 1.75rem; font-weight: 800; color: var(--text-primary); margin-bottom: 1.5rem; text-align: center;">
                    🔍 Detailed Security Findings
                </h2>
                
                <div style="background: white; padding: 1.5rem; border-radius: 1rem; box-shadow: var(--shadow); margin-bottom: 2rem;">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem;">
                        <h3 style="font-weight: 700; color: var(--text-primary); margin: 0;">📋 Summary of Discoveries</h3>
                        <span style="background: var(--primary-gradient); color: white; padding: 0.5rem 1rem; border-radius: 2rem; font-size: 0.875rem; font-weight: 600;">
                            Total: {total_vulns} Issues Found
                        </span>
                    </div>
                    <p style="color: var(--text-secondary); margin: 0;">The following security findings have been identified through comprehensive automated testing and manual verification. Each finding includes detailed technical information, potential impact assessment, and specific remediation guidance.</p>
                </div>
                
                <div class="findings-grid">
                    {findings_html}
                </div>
            </div>
        </section>

        <!-- Recommendations Section -->
        <section style="padding: 2rem; background: var(--bg-primary);">
            <div style="max-width: 1000px; margin: 0 auto;">
                <h2 style="font-size: 1.75rem; font-weight: 800; color: var(--text-primary); margin-bottom: 1.5rem; text-align: center;">
                    🛡️ Strategic Recommendations
                </h2>
                
                <div style="display: grid; gap: 1.5rem;">
                    <div style="background: white; padding: 2rem; border-radius: 1rem; box-shadow: var(--shadow); border-left: 4px solid var(--critical-color);">
                        <h3 style="font-weight: 700; color: var(--critical-color); margin-bottom: 1rem;">🚨 Immediate Actions (0-24 hours)</h3>
                        <ul style="color: var(--text-secondary); margin: 0; padding-left: 1.5rem; line-height: 1.6;">
                            <li>Address all Critical severity vulnerabilities immediately</li>
                            <li>Implement emergency security patches for publicly exposed services</li>
                            <li>Review and strengthen authentication mechanisms</li>
                            <li>Enable comprehensive security logging and monitoring</li>
                        </ul>
                    </div>
                    
                    <div style="background: white; padding: 2rem; border-radius: 1rem; box-shadow: var(--shadow); border-left: 4px solid var(--high-color);">
                        <h3 style="font-weight: 700; color: var(--high-color); margin-bottom: 1rem;">⚠️ Short-term Priorities (1-7 days)</h3>
                        <ul style="color: var(--text-secondary); margin: 0; padding-left: 1.5rem; line-height: 1.6;">
                            <li>Remediate High severity vulnerabilities based on business impact</li>
                            <li>Implement Web Application Firewall (WAF) protection</li>
                            <li>Conduct security configuration review</li>
                            <li>Establish incident response procedures</li>
                        </ul>
                    </div>
                    
                    <div style="background: white; padding: 2rem; border-radius: 1rem; box-shadow: var(--shadow); border-left: 4px solid var(--medium-color);">
                        <h3 style="font-weight: 700; color: var(--medium-color); margin-bottom: 1rem;">⚡ Medium-term Improvements (1-4 weeks)</h3>
                        <ul style="color: var(--text-secondary); margin: 0; padding-left: 1.5rem; line-height: 1.6;">
                            <li>Address Medium severity vulnerabilities systematically</li>
                            <li>Implement comprehensive security training program</li>
                            <li>Establish regular security assessment schedule</li>
                            <li>Deploy advanced threat detection systems</li>
                        </ul>
                    </div>
                    
                    <div style="background: white; padding: 2rem; border-radius: 1rem; box-shadow: var(--shadow); border-left: 4px solid var(--low-color);">
                        <h3 style="font-weight: 700; color: var(--low-color); margin-bottom: 1rem;">💡 Long-term Strategy (1-3 months)</h3>
                        <ul style="color: var(--text-secondary); margin: 0; padding-left: 1.5rem; line-height: 1.6;">
                            <li>Implement security-by-design principles in development</li>
                            <li>Establish comprehensive security governance framework</li>
                            <li>Deploy continuous security monitoring solutions</li>
                            <li>Conduct regular third-party security assessments</li>
                        </ul>
                    </div>
                </div>
            </div>
        </section>

        <!-- Technical Methodology Section -->
        <section style="padding: 2rem; background: var(--bg-secondary);">
            <div style="max-width: 1000px; margin: 0 auto;">
                <h2 style="font-size: 1.75rem; font-weight: 800; color: var(--text-primary); margin-bottom: 1.5rem; text-align: center;">
                    🔬 Assessment Methodology & Standards
                </h2>
                
                <div style="display: grid; gap: 1.5rem;">
                    <div style="background: white; padding: 2rem; border-radius: 1rem; box-shadow: var(--shadow);">
                        <h3 style="font-weight: 700; color: var(--text-primary); margin-bottom: 1rem;">📚 Standards & Frameworks</h3>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem;">
                            <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 0.5rem;">
                                <strong style="color: var(--text-primary);">OWASP Top 10</strong>
                                <p style="font-size: 0.875rem; color: var(--text-muted); margin: 0.5rem 0 0 0;">Web application security risks</p>
                            </div>
                            <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 0.5rem;">
                                <strong style="color: var(--text-primary);">NIST Framework</strong>
                                <p style="font-size: 0.875rem; color: var(--text-muted); margin: 0.5rem 0 0 0;">Cybersecurity framework compliance</p>
                            </div>
                            <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 0.5rem;">
                                <strong style="color: var(--text-primary);">CVSS v3.1</strong>
                                <p style="font-size: 0.875rem; color: var(--text-muted); margin: 0.5rem 0 0 0;">Vulnerability scoring system</p>
                            </div>
                            <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 0.5rem;">
                                <strong style="color: var(--text-primary);">ISO 27001</strong>
                                <p style="font-size: 0.875rem; color: var(--text-muted); margin: 0.5rem 0 0 0;">Information security management</p>
                            </div>
                        </div>
                    </div>
                    
                    <div style="background: white; padding: 2rem; border-radius: 1rem; box-shadow: var(--shadow);">
                        <h3 style="font-weight: 700; color: var(--text-primary); margin-bottom: 1rem;">🔧 Testing Techniques</h3>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem;">
                            <div>
                                <h4 style="font-weight: 600; color: var(--text-secondary); margin-bottom: 0.5rem;">🔍 Reconnaissance</h4>
                                <ul style="color: var(--text-muted); font-size: 0.875rem; margin: 0; padding-left: 1rem;">
                                    <li>Subdomain enumeration</li>
                                    <li>Port scanning & service detection</li>
                                    <li>Technology stack fingerprinting</li>
                                    <li>DNS reconnaissance</li>
                                </ul>
                            </div>
                            <div>
                                <h4 style="font-weight: 600; color: var(--text-secondary); margin-bottom: 0.5rem;">🛡️ Vulnerability Assessment</h4>
                                <ul style="color: var(--text-muted); font-size: 0.875rem; margin: 0; padding-left: 1rem;">
                                    <li>Automated vulnerability scanning</li>
                                    <li>Web application testing</li>
                                    <li>Configuration analysis</li>
                                    <li>Security header verification</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Appendix Section -->
        <section style="padding: 2rem; background: var(--bg-primary);">
            <div style="max-width: 1000px; margin: 0 auto;">
                <h2 style="font-size: 1.75rem; font-weight: 800; color: var(--text-primary); margin-bottom: 1.5rem; text-align: center;">
                    📎 Technical Appendix
                </h2>
                
                <div style="display: grid; gap: 1.5rem;">
                    <div style="background: white; padding: 2rem; border-radius: 1rem; box-shadow: var(--shadow);">
                        <h3 style="font-weight: 700; color: var(--text-primary); margin-bottom: 1rem;">📊 Scanning Statistics</h3>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                            <div style="text-align: center; padding: 1rem; background: var(--bg-secondary); border-radius: 0.5rem;">
                                <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-primary);">{coverage_metrics['subdomains']}</div>
                                <div style="font-size: 0.875rem; color: var(--text-muted);">Subdomains Scanned</div>
                            </div>
                            <div style="text-align: center; padding: 1rem; background: var(--bg-secondary); border-radius: 0.5rem;">
                                <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-primary);">{coverage_metrics['ports']}</div>
                                <div style="font-size: 0.875rem; color: var(--text-muted);">Open Ports Found</div>
                            </div>
                            <div style="text-align: center; padding: 1rem; background: var(--bg-secondary); border-radius: 0.5rem;">
                                <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-primary);">{coverage_metrics['technologies']}</div>
                                <div style="font-size: 0.875rem; color: var(--text-muted);">Technologies Identified</div>
                            </div>
                            <div style="text-align: center; padding: 1rem; background: var(--bg-secondary); border-radius: 0.5rem;">
                                <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-primary);">{total_vulns}</div>
                                <div style="font-size: 0.875rem; color: var(--text-muted);">Total Findings</div>
                            </div>
                        </div>
                    </div>
                    
                    <div style="background: white; padding: 2rem; border-radius: 1rem; box-shadow: var(--shadow);">
                        <h3 style="font-weight: 700; color: var(--text-primary); margin-bottom: 1rem;">⚖️ Disclaimer & Limitations</h3>
                        <div style="background: var(--bg-secondary); padding: 1.5rem; border-radius: 0.75rem; border-left: 4px solid #ffa726;">
                            <p style="color: var(--text-secondary); margin-bottom: 1rem; line-height: 1.6;">This security assessment was conducted using automated scanning tools and techniques. While comprehensive, this assessment may not identify all potential security vulnerabilities. The findings represent the security posture at the time of assessment and should be considered alongside:</p>
                            <ul style="color: var(--text-secondary); margin: 0; padding-left: 1.5rem; line-height: 1.6;">
                                <li>Business context and risk tolerance</li>
                                <li>Ongoing security monitoring and incident response capabilities</li>
                                <li>Compliance requirements and regulatory obligations</li>
                                <li>Third-party security assessments and penetration testing</li>
                            </ul>
                        </div>
                    </div>
                    
                    <div style="background: white; padding: 2rem; border-radius: 1rem; box-shadow: var(--shadow);">
                        <h3 style="font-weight: 700; color: var(--text-primary); margin-bottom: 1rem;">📞 Support & Contact Information</h3>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem;">
                            <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 0.5rem;">
                                <strong style="color: var(--text-primary);">Technical Support</strong>
                                <p style="font-size: 0.875rem; color: var(--text-muted); margin: 0.5rem 0 0 0;">For technical questions about findings and remediation guidance</p>
                            </div>
                            <div style="background: var(--bg-secondary); padding: 1rem; border-radius: 0.5rem;">
                                <strong style="color: var(--text-primary);">Security Consulting</strong>
                                <p style="font-size: 0.875rem; color: var(--text-muted); margin: 0.5rem 0 0 0;">For comprehensive security strategy and implementation support</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>


        <!-- Footer -->
        <footer class="report-footer">
            <div class="footer-content">
                <p>© 2025 Nexus Hunter Security Research Team • Confidential Assessment Report</p>
                <p>Generated on {today} • This report contains confidential information and is intended solely for the recipient organization.</p>
            </div>
        </footer>
    </div>
</body>
</html>
         """
        return html

    async def _generate_pdf_optimized_html(self, analysis: Dict[str, Any], report_type: str = "technical") -> str:
        """Generate HTML specifically optimized for PDF rendering with inline styles."""
        # Get the base HTML
        base_html = await self._generate_html_report(analysis, report_type)
        
        # Replace CSS variables with actual values for better PDF compatibility
        css_variables = {
            'var(--primary-gradient)': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            'var(--danger-gradient)': 'linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%)',
            'var(--success-gradient)': 'linear-gradient(135deg, #06c755 0%, #10ac84 100%)',
            'var(--warning-gradient)': 'linear-gradient(135deg, #ffa726 0%, #fb8c00 100%)',
            'var(--dark-gradient)': 'linear-gradient(135deg, #2c3e50 0%, #34495e 100%)',
            'var(--bg-primary)': '#ffffff',
            'var(--bg-secondary)': '#f8fafc',
            'var(--bg-tertiary)': '#e2e8f0',
            'var(--text-primary)': '#1a202c',
            'var(--text-secondary)': '#4a5568',
            'var(--text-muted)': '#718096',
            'var(--border-color)': '#e2e8f0',
            'var(--shadow)': '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
            'var(--shadow-lg)': '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
            'var(--critical-color)': '#dc2626',
            'var(--high-color)': '#ea580c',
            'var(--medium-color)': '#d97706',
            'var(--low-color)': '#059669',
            'var(--info-color)': '#2563eb'
        }
        
        # Replace all CSS variables with their actual values
        optimized_html = base_html
        for variable, value in css_variables.items():
            optimized_html = optimized_html.replace(variable, value)
        
        # Add PDF-specific meta tags and optimizations
        pdf_meta = '''
        <meta name="author" content="Nexus Hunter Security Research Team">
        <meta name="subject" content="Security Assessment Report">
        <meta name="creator" content="Nexus Hunter">
        <meta name="producer" content="Nexus Hunter Security Platform">
        <meta name="keywords" content="security assessment, vulnerability report, penetration testing">
        '''
        
        # Insert PDF meta tags
        optimized_html = optimized_html.replace('<meta name="viewport"', pdf_meta + '<meta name="viewport"')
        
        # Add additional PDF-specific styles
        pdf_styles = '''
        <style>
            /* PDF-specific overrides */
            @media print {
                .report-header::before {
                    display: none !important;
                }
                
                .dashboard-grid {
                    grid-template-columns: repeat(2, 1fr) !important;
                    gap: 1rem !important;
                }
                
                .finding-card {
                    page-break-inside: avoid !important;
                    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1) !important;
                }
                
                /* Ensure emojis render properly */
                .company-logo::before,
                .dashboard-title::before {
                    font-family: "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", sans-serif;
                }
            }
            
            /* WeasyPrint specific fixes */
            .severity-bars {
                display: block !important;
            }
            
            .severity-bar {
                display: block !important;
                margin-bottom: 0.5rem !important;
                width: 100% !important;
            }
            
            .detail-grid {
                display: block !important;
            }
            
            .detail-item {
                display: block !important;
                margin-bottom: 1rem !important;
            }
        </style>
        '''
        
        # Insert PDF styles before closing head tag
        optimized_html = optimized_html.replace('</head>', pdf_styles + '</head>')
        
        return optimized_html

    async def generate_pdf(self, analysis: Dict[str, Any], report_type: str = "technical") -> bytes:
        """Generate a professional PDF that matches the HTML report exactly."""
        try:
            from weasyprint import HTML, CSS
            from weasyprint.text.fonts import FontConfiguration
            
            # Generate enhanced HTML with PDF-optimized styling
            html_content = await self._generate_pdf_optimized_html(analysis, report_type)
            
            # Configure fonts for better PDF rendering
            font_config = FontConfiguration()
            
            # Additional CSS for PDF optimization
            pdf_css = CSS(string="""
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
                
                * {
                    -webkit-print-color-adjust: exact !important;
                    color-adjust: exact !important;
                    print-color-adjust: exact !important;
                }
                
                body {
                    font-family: 'Inter', 'Arial', 'Helvetica', sans-serif !important;
                    margin: 0 !important;
                    padding: 0 !important;
                }
                
                .report-container {
                    background: white !important;
                    max-width: none !important;
                    box-shadow: none !important;
                }
                
                /* Ensure all colors and backgrounds are preserved */
                .severity-badge, .card-icon, .bar-fill {
                    -webkit-print-color-adjust: exact !important;
                    color-adjust: exact !important;
                    print-color-adjust: exact !important;
                }
                
                /* Fix any gradient backgrounds for PDF */
                .report-header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
                    color: white !important;
                }
                
                .dashboard-card {
                    page-break-inside: avoid;
                    margin-bottom: 1rem;
                }
                
                .finding-card {
                    page-break-inside: avoid;
                    margin-bottom: 2rem;
                    border: 1px solid #e2e8f0;
                }
            """, font_config=font_config)
            
            # Generate PDF with optimized settings
            html_doc = HTML(string=html_content)
            pdf_bytes = html_doc.write_pdf(
                stylesheets=[pdf_css],
                font_config=font_config,
                optimize_images=True
            )
            
            return pdf_bytes
            
        except ImportError:
            logger.warning("WeasyPrint not available, trying alternative PDF generation...")
            return await self._generate_fallback_pdf(analysis, report_type)
        except Exception as e:
            logger.error(f"WeasyPrint PDF generation failed: {e}")
            return await self._generate_fallback_pdf(analysis, report_type)
    
    async def _generate_fallback_pdf(self, analysis: Dict[str, Any], report_type: str = "technical") -> bytes:
        """Fallback PDF generation using Playwright for exact HTML rendering."""
        try:
            # Try Playwright for exact HTML-to-PDF conversion
            from playwright.async_api import async_playwright
            
            # Use the main HTML generation method for Playwright (it has all the styling)
            html_content = await self._generate_html_report(analysis, report_type)
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # Set content and wait for fonts/styles to load
                await page.set_content(html_content, wait_until='networkidle')
                
                # Generate PDF with exact browser rendering
                pdf_bytes = await page.pdf(
                    format='A4',
                    margin={'top': '15mm', 'right': '15mm', 'bottom': '15mm', 'left': '15mm'},
                    print_background=True,  # Preserve backgrounds and colors
                    prefer_css_page_size=True,
                    scale=1.0
                )
                
                await browser.close()
                logger.info("PDF generated successfully using Playwright (exact HTML rendering)")
                return pdf_bytes
                
        except ImportError:
            logger.warning("Playwright not available, trying pdfkit...")
            return await self._generate_pdfkit_fallback(analysis, report_type)
        except Exception as e:
            logger.error(f"Playwright PDF generation failed: {e}")
            return await self._generate_pdfkit_fallback(analysis, report_type)
    
    async def _generate_pdfkit_fallback(self, analysis: Dict[str, Any], report_type: str = "technical") -> bytes:
        """Fallback to pdfkit if available."""
        try:
            import pdfkit
            # Use the main HTML generation method
            html_content = await self._generate_html_report(analysis, report_type)
            
            # Configure pdfkit options for better PDF output
            options = {
                'page-size': 'A4',
                'margin-top': '15mm',
                'margin-right': '15mm',
                'margin-bottom': '15mm',
                'margin-left': '15mm',
                'encoding': "UTF-8",
                'no-outline': None,
                'enable-local-file-access': None,
                'print-media-type': None,
                '--enable-javascript': '',
                '--javascript-delay': '1000',
                '--load-error-handling': 'ignore',
                '--load-media-error-handling': 'ignore'
            }
            
            pdf_bytes = pdfkit.from_string(html_content, False, options=options)
            logger.info("PDF generated successfully using pdfkit")
            return pdf_bytes
            
        except Exception as e:
            logger.error(f"pdfkit PDF generation failed: {e}")
            return await self._generate_reportlab_pdf(analysis, report_type)
    
    async def _generate_reportlab_pdf(self, analysis: Dict[str, Any], report_type: str = "technical") -> bytes:
        """Generate PDF using ReportLab as final fallback."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            from io import BytesIO
            
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#667eea'),
                spaceAfter=30,
                alignment=1  # Center
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#1a202c'),
                spaceAfter=12
            )
            
            # Extract data
            vulnerabilities = analysis.get('vulnerabilities', [])
            target_info = analysis.get('target_info', {})
            domain = target_info.get('domain', 'Target System')
            
            # Title
            story.append(Paragraph("🔐 Security Assessment Report", title_style))
            story.append(Spacer(1, 20))
            
            # Executive Summary
            story.append(Paragraph("📊 Executive Summary", heading_style))
            
            # Severity counts
            sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'info').lower()
                if severity in sev_counts:
                    sev_counts[severity] += 1
            
            # Summary table
            summary_data = [
                ['Target Domain', domain],
                ['Total Vulnerabilities', str(sum(sev_counts.values()))],
                ['Critical', str(sev_counts['critical'])],
                ['High', str(sev_counts['high'])],
                ['Medium', str(sev_counts['medium'])],
                ['Low', str(sev_counts['low'])]
            ]
            
            summary_table = Table(summary_data, colWidths=[2*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(summary_table)
            story.append(Spacer(1, 30))
            
            # Findings
            if vulnerabilities:
                story.append(Paragraph("🔍 Security Findings", heading_style))
                
                for i, vuln in enumerate(vulnerabilities[:10]):  # Limit for PDF size
                    story.append(Paragraph(f"Finding #{i+1}: {vuln.get('title', 'Vulnerability')}", styles['Heading3']))
                    story.append(Paragraph(f"<b>Severity:</b> {vuln.get('severity', 'Unknown').upper()}", styles['Normal']))
                    story.append(Paragraph(f"<b>URL:</b> {vuln.get('url', 'N/A')}", styles['Normal']))
                    story.append(Paragraph(f"<b>Description:</b> {vuln.get('description', 'No description available.')}", styles['Normal']))
                    story.append(Spacer(1, 12))
            
            # Footer
            story.append(Spacer(1, 30))
            story.append(Paragraph("Generated by Nexus Hunter Security Platform", styles['Normal']))
            
            doc.build(story)
            pdf_bytes = buffer.getvalue()
            buffer.close()
            
            logger.info("PDF generated successfully using ReportLab")
            return pdf_bytes
            
        except Exception as e:
            logger.error(f"ReportLab PDF generation failed: {e}")
            # Final fallback to enhanced HTML as bytes
            html = await self._generate_html_report(analysis, report_type)
            return html.encode('utf-8', errors='ignore')
    
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