"""
Executive Report Agent
======================

Generates executive-level security assessment reports focused on business impact,
risk management, and strategic recommendations for leadership teams.
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

from loguru import logger
from agents.base import BaseAgent


@dataclass
class BusinessImpactAssessment:
    """Business impact assessment"""
    financial_impact: str
    operational_impact: str
    reputational_impact: str
    compliance_impact: str
    overall_risk_level: str
    business_continuity_risk: str


@dataclass
class ExecutiveSummary:
    """Executive summary of security assessment"""
    key_findings: List[str]
    critical_risks: List[str]
    business_impact: BusinessImpactAssessment
    investment_recommendations: List[str]
    timeline_priorities: Dict[str, List[str]]
    success_metrics: List[str]


@dataclass
class ExecutiveReport:
    """Complete executive report"""
    report_metadata: Dict[str, Any]
    executive_summary: ExecutiveSummary
    risk_dashboard: Dict[str, Any]
    investment_analysis: Dict[str, Any]
    compliance_status: Dict[str, Any]
    strategic_recommendations: List[str]
    next_steps: List[str]


class ExecutiveReportAgent(BaseAgent):
    """Executive-level security report generation agent"""
    
    def __init__(self):
        super().__init__("ExecutiveReportAgent")
        self.business_impact_calculator = BusinessImpactCalculator()
        
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        # For executive reporting, we expect vulnerability report in config
        vulnerability_report = config.get("vulnerability_report", {}) if config else {}
        business_context = config.get("business_context", {}) if config else {}
        report = await self.generate_executive_report(vulnerability_report, business_context)
        return asdict(report)
        
    async def generate_executive_report(
        self,
        vulnerability_report: Dict[str, Any],
        business_context: Optional[Dict[str, Any]] = None
    ) -> ExecutiveReport:
        """Generate executive-level security report"""
        try:
            logger.info("📊 Generating executive security report")
            
            business_context = business_context or {}
            
            # Extract key metrics
            report_metadata = self._extract_report_metadata(vulnerability_report)
            
            # Generate business impact assessment
            business_impact = await self._assess_business_impact(
                vulnerability_report, business_context
            )
            
            # Create executive summary
            executive_summary = self._create_executive_summary(
                vulnerability_report, business_impact, business_context
            )
            
            # Generate risk dashboard
            risk_dashboard = self._create_risk_dashboard(vulnerability_report)
            
            # Investment analysis
            investment_analysis = self._analyze_security_investment(
                vulnerability_report, business_context
            )
            
            # Compliance status
            compliance_status = self._assess_compliance_status(
                vulnerability_report, business_context
            )
            
            # Strategic recommendations
            strategic_recommendations = self._generate_strategic_recommendations(
                vulnerability_report, business_impact, business_context
            )
            
            # Next steps
            next_steps = self._define_next_steps(
                vulnerability_report, business_impact
            )
            
            report = ExecutiveReport(
                report_metadata=report_metadata,
                executive_summary=executive_summary,
                risk_dashboard=risk_dashboard,
                investment_analysis=investment_analysis,
                compliance_status=compliance_status,
                strategic_recommendations=strategic_recommendations,
                next_steps=next_steps
            )
            
            logger.info("✅ Executive report generated successfully")
            return report
            
        except Exception as e:
            logger.error(f"❌ Executive report generation failed: {e}")
            raise
    
    def _extract_report_metadata(self, vulnerability_report: Dict[str, Any]) -> Dict[str, Any]:
        """Extract report metadata"""
        metadata = vulnerability_report.get("metadata", {})
        statistics = vulnerability_report.get("statistics", {})
        
        return {
            "assessment_date": datetime.now().strftime("%B %d, %Y"),
            "target_organization": metadata.get("organization", "Organization"),
            "assessment_scope": metadata.get("target", "Unknown"),
            "assessment_duration": f"{metadata.get('duration_seconds', 0) // 3600}h {(metadata.get('duration_seconds', 0) % 3600) // 60}m",
            "total_vulnerabilities": statistics.get("total_vulnerabilities", 0),
            "critical_vulnerabilities": statistics.get("severity_distribution", {}).get("critical", 0),
            "high_vulnerabilities": statistics.get("severity_distribution", {}).get("high", 0),
            "systems_assessed": statistics.get("unique_affected_systems", 0)
        }
    
    async def _assess_business_impact(
        self,
        vulnerability_report: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> BusinessImpactAssessment:
        """Assess business impact of security vulnerabilities"""
        statistics = vulnerability_report.get("statistics", {})
        severity_dist = statistics.get("severity_distribution", {})
        
        # Calculate impact levels
        financial_impact = self._assess_financial_impact(severity_dist, business_context)
        operational_impact = self._assess_operational_impact(severity_dist, business_context)
        reputational_impact = self._assess_reputational_impact(severity_dist, business_context)
        compliance_impact = self._assess_compliance_impact(vulnerability_report, business_context)
        overall_risk_level = self._calculate_overall_risk_level(severity_dist)
        business_continuity_risk = self._assess_business_continuity_risk(severity_dist, business_context)
        
        return BusinessImpactAssessment(
            financial_impact=financial_impact,
            operational_impact=operational_impact,
            reputational_impact=reputational_impact,
            compliance_impact=compliance_impact,
            overall_risk_level=overall_risk_level,
            business_continuity_risk=business_continuity_risk
        )
    
    def _assess_financial_impact(
        self,
        severity_dist: Dict[str, int],
        business_context: Dict[str, Any]
    ) -> str:
        """Assess potential financial impact"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        # Industry-specific impact multipliers
        industry = business_context.get("industry", "general")
        revenue = business_context.get("annual_revenue", 0)
        
        if critical_count > 0:
            if industry in ["financial", "healthcare", "government"]:
                return f"CRITICAL - Potential losses of ${revenue * 0.05:.0f}M+ from data breaches, regulatory fines, and business disruption"
            else:
                return f"HIGH - Potential losses of ${revenue * 0.02:.0f}M+ from security incidents and recovery costs"
        elif high_count > 2:
            return f"MODERATE - Potential losses of ${revenue * 0.01:.0f}M+ from security incidents and remediation costs"
        elif high_count > 0:
            return "LOW-MODERATE - Limited financial impact expected, primarily remediation costs"
        else:
            return "MINIMAL - Low financial impact, routine security maintenance costs"
    
    def _assess_operational_impact(
        self,
        severity_dist: Dict[str, int],
        business_context: Dict[str, Any]
    ) -> str:
        """Assess operational impact"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        if critical_count > 0:
            return "SEVERE - Potential for complete system compromise, data loss, and extended service outages"
        elif high_count > 3:
            return "HIGH - Significant risk of service disruption, data compromise, and operational delays"
        elif high_count > 0:
            return "MODERATE - Limited operational impact, potential for isolated service disruptions"
        else:
            return "LOW - Minimal operational impact expected"
    
    def _assess_reputational_impact(
        self,
        severity_dist: Dict[str, int],
        business_context: Dict[str, Any]
    ) -> str:
        """Assess reputational impact"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        public_facing = business_context.get("public_facing", True)
        customer_data = business_context.get("handles_customer_data", True)
        
        if critical_count > 0 and (public_facing or customer_data):
            return "SEVERE - High risk of negative media coverage, customer loss, and long-term brand damage"
        elif high_count > 2 and customer_data:
            return "HIGH - Significant reputational risk from potential data breaches or security incidents"
        elif high_count > 0:
            return "MODERATE - Limited reputational impact, manageable with proper communication"
        else:
            return "LOW - Minimal reputational risk"
    
    def _assess_compliance_impact(
        self,
        vulnerability_report: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> str:
        """Assess compliance impact"""
        regulations = business_context.get("applicable_regulations", [])
        severity_dist = vulnerability_report.get("statistics", {}).get("severity_distribution", {})
        
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        if not regulations:
            return "LOW - No specific regulatory requirements identified"
        
        high_risk_regulations = ["GDPR", "HIPAA", "PCI-DSS", "SOX", "FISMA"]
        has_high_risk_regs = any(reg in regulations for reg in high_risk_regulations)
        
        if critical_count > 0 and has_high_risk_regs:
            return f"CRITICAL - High risk of regulatory violations under {', '.join(regulations)}, potential fines in millions"
        elif high_count > 0 and has_high_risk_regs:
            return f"HIGH - Moderate risk of compliance violations under {', '.join(regulations)}"
        elif has_high_risk_regs:
            return f"MODERATE - Some compliance concerns under {', '.join(regulations)}"
        else:
            return "LOW - Limited compliance impact"
    
    def _calculate_overall_risk_level(self, severity_dist: Dict[str, int]) -> str:
        """Calculate overall organizational risk level"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        medium_count = severity_dist.get("medium", 0)
        
        # Risk scoring algorithm
        risk_score = (critical_count * 10) + (high_count * 5) + (medium_count * 2)
        
        if risk_score >= 30:
            return "CRITICAL"
        elif risk_score >= 15:
            return "HIGH"
        elif risk_score >= 5:
            return "MODERATE"
        else:
            return "LOW"
    
    def _assess_business_continuity_risk(
        self,
        severity_dist: Dict[str, int],
        business_context: Dict[str, Any]
    ) -> str:
        """Assess business continuity risk"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        business_critical_systems = business_context.get("business_critical_systems", True)
        
        if critical_count > 0 and business_critical_systems:
            return "HIGH - Critical vulnerabilities in business-essential systems pose immediate continuity risk"
        elif high_count > 2 and business_critical_systems:
            return "MODERATE - Multiple high-severity vulnerabilities may impact business operations"
        elif high_count > 0:
            return "LOW-MODERATE - Limited business continuity impact expected"
        else:
            return "LOW - Minimal business continuity risk"
    
    def _create_executive_summary(
        self,
        vulnerability_report: Dict[str, Any],
        business_impact: BusinessImpactAssessment,
        business_context: Dict[str, Any]
    ) -> ExecutiveSummary:
        """Create executive summary"""
        statistics = vulnerability_report.get("statistics", {})
        severity_dist = statistics.get("severity_distribution", {})
        
        # Key findings
        key_findings = self._generate_key_findings(severity_dist, business_impact)
        
        # Critical risks
        critical_risks = self._identify_critical_risks(vulnerability_report, business_impact)
        
        # Investment recommendations
        investment_recommendations = self._generate_investment_recommendations(
            severity_dist, business_context
        )
        
        # Timeline priorities
        timeline_priorities = self._create_timeline_priorities(severity_dist)
        
        # Success metrics
        success_metrics = self._define_success_metrics(severity_dist, business_context)
        
        return ExecutiveSummary(
            key_findings=key_findings,
            critical_risks=critical_risks,
            business_impact=business_impact,
            investment_recommendations=investment_recommendations,
            timeline_priorities=timeline_priorities,
            success_metrics=success_metrics
        )
    
    def _generate_key_findings(
        self,
        severity_dist: Dict[str, int],
        business_impact: BusinessImpactAssessment
    ) -> List[str]:
        """Generate key executive findings"""
        findings = []
        
        total_vulns = sum(severity_dist.values())
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        # Overall assessment
        findings.append(f"Security assessment identified {total_vulns} vulnerabilities across the assessed infrastructure")
        
        # Critical findings
        if critical_count > 0:
            findings.append(f"{critical_count} critical vulnerabilities require immediate executive attention and resource allocation")
        
        # High-severity findings
        if high_count > 0:
            findings.append(f"{high_count} high-severity vulnerabilities pose significant business risk")
        
        # Business impact
        if business_impact.overall_risk_level in ["CRITICAL", "HIGH"]:
            findings.append(f"Overall organizational risk level assessed as {business_impact.overall_risk_level}")
        
        # Positive findings
        if critical_count == 0 and high_count <= 2:
            findings.append("Security posture demonstrates good foundational controls with manageable risk levels")
        
        return findings
    
    def _identify_critical_risks(
        self,
        vulnerability_report: Dict[str, Any],
        business_impact: BusinessImpactAssessment
    ) -> List[str]:
        """Identify critical business risks"""
        risks = []
        
        # Extract vulnerability categories
        category_dist = vulnerability_report.get("statistics", {}).get("category_distribution", {})
        
        # High-impact vulnerability types
        if category_dist.get("Injection", 0) > 0:
            risks.append("Data breach risk from injection vulnerabilities enabling unauthorized database access")
        
        if category_dist.get("Broken Authentication", 0) > 0:
            risks.append("Account takeover risk from authentication weaknesses")
        
        if category_dist.get("Sensitive Data Exposure", 0) > 0:
            risks.append("Regulatory compliance violations from exposed sensitive data")
        
        if category_dist.get("Cross-Site Scripting", 0) > 0:
            risks.append("User account compromise and malware distribution through XSS attacks")
        
        # Business impact risks
        if business_impact.financial_impact.startswith("CRITICAL"):
            risks.append("Significant financial losses from potential security incidents")
        
        if business_impact.compliance_impact.startswith("CRITICAL"):
            risks.append("Regulatory fines and legal liability from compliance violations")
        
        if business_impact.reputational_impact.startswith("SEVERE"):
            risks.append("Brand damage and customer loss from security incidents")
        
        return risks[:5]  # Top 5 critical risks
    
    def _generate_investment_recommendations(
        self,
        severity_dist: Dict[str, int],
        business_context: Dict[str, Any]
    ) -> List[str]:
        """Generate security investment recommendations"""
        recommendations = []
        
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        total_vulns = sum(severity_dist.values())
        
        # Immediate investments
        if critical_count > 0:
            recommendations.append("Immediate: Allocate emergency budget for critical vulnerability remediation ($50K-$200K)")
        
        # Security team investments
        if total_vulns > 20:
            recommendations.append("Expand security team capacity or engage external security consultants")
        
        # Technology investments
        if high_count > 5:
            recommendations.append("Invest in Web Application Firewall (WAF) and security monitoring tools ($100K-$500K annually)")
        
        # Process investments
        recommendations.append("Implement DevSecOps practices and security testing automation ($200K-$1M investment)")
        
        # Training investments
        recommendations.append("Security awareness training for all employees ($50K-$100K annually)")
        
        # Compliance investments
        if business_context.get("applicable_regulations"):
            recommendations.append("Compliance management platform and audit preparation ($100K-$300K)")
        
        return recommendations
    
    def _create_timeline_priorities(self, severity_dist: Dict[str, int]) -> Dict[str, List[str]]:
        """Create timeline-based priority recommendations"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        medium_count = severity_dist.get("medium", 0)
        
        timeline = {
            "immediate_24_48_hours": [],
            "short_term_1_4_weeks": [],
            "medium_term_1_3_months": [],
            "long_term_3_12_months": []
        }
        
        # Immediate actions
        if critical_count > 0:
            timeline["immediate_24_48_hours"].extend([
                f"Address all {critical_count} critical vulnerabilities",
                "Activate incident response team",
                "Implement temporary protective measures"
            ])
        
        # Short-term actions
        if high_count > 0:
            timeline["short_term_1_4_weeks"].extend([
                f"Remediate {high_count} high-severity vulnerabilities",
                "Deploy Web Application Firewall (WAF)",
                "Enhance monitoring and alerting"
            ])
        
        # Medium-term actions
        if medium_count > 0:
            timeline["medium_term_1_3_months"].extend([
                f"Address {medium_count} medium-severity vulnerabilities",
                "Implement security testing in CI/CD pipeline",
                "Conduct security awareness training"
            ])
        
        # Long-term actions
        timeline["long_term_3_12_months"].extend([
            "Establish comprehensive security program",
            "Implement zero-trust architecture",
            "Regular penetration testing schedule",
            "Security metrics and KPI dashboard"
        ])
        
        return timeline
    
    def _define_success_metrics(
        self,
        severity_dist: Dict[str, int],
        business_context: Dict[str, Any]
    ) -> List[str]:
        """Define success metrics for security improvements"""
        metrics = [
            "Zero critical vulnerabilities within 30 days",
            "Reduce high-severity vulnerabilities by 80% within 90 days",
            "Achieve 95% vulnerability remediation SLA compliance",
            "Implement automated security testing with 100% CI/CD coverage",
            "Conduct quarterly penetration testing with trend analysis"
        ]
        
        # Add compliance metrics if applicable
        if business_context.get("applicable_regulations"):
            metrics.append("Achieve 100% compliance audit readiness")
        
        # Add business metrics
        metrics.extend([
            "Zero security-related business disruptions",
            "Maintain customer trust scores above 90%",
            "Reduce security incident response time to <4 hours"
        ])
        
        return metrics
    
    def _create_risk_dashboard(self, vulnerability_report: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive risk dashboard"""
        statistics = vulnerability_report.get("statistics", {})
        severity_dist = statistics.get("severity_distribution", {})
        
        total_vulns = sum(severity_dist.values())
        
        return {
            "risk_score": self._calculate_risk_score(severity_dist),
            "vulnerability_trend": "Baseline Assessment",  # Would track over time
            "top_risk_categories": self._get_top_risk_categories(
                statistics.get("category_distribution", {})
            ),
            "systems_at_risk": statistics.get("unique_affected_systems", 0),
            "remediation_progress": {
                "critical": {"completed": 0, "total": severity_dist.get("critical", 0)},
                "high": {"completed": 0, "total": severity_dist.get("high", 0)},
                "medium": {"completed": 0, "total": severity_dist.get("medium", 0)}
            },
            "security_posture_grade": self._calculate_security_grade(severity_dist),
            "industry_comparison": "Assessment needed",  # Would require industry data
            "compliance_status": "Under Review"
        }
    
    def _calculate_risk_score(self, severity_dist: Dict[str, int]) -> int:
        """Calculate overall risk score (0-100)"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        medium_count = severity_dist.get("medium", 0)
        low_count = severity_dist.get("low", 0)
        
        # Weighted risk calculation
        risk_score = (critical_count * 25) + (high_count * 15) + (medium_count * 5) + (low_count * 1)
        
        # Normalize to 0-100 scale
        return min(100, risk_score)
    
    def _get_top_risk_categories(self, category_dist: Dict[str, int]) -> List[Dict[str, Any]]:
        """Get top risk categories"""
        sorted_categories = sorted(
            category_dist.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [
            {"category": cat, "count": count, "risk_level": self._assess_category_risk(cat, count)}
            for cat, count in sorted_categories[:5]
        ]
    
    def _assess_category_risk(self, category: str, count: int) -> str:
        """Assess risk level for vulnerability category"""
        high_risk_categories = ["Injection", "Broken Authentication", "Sensitive Data Exposure"]
        
        if category in high_risk_categories and count > 0:
            return "High"
        elif count > 3:
            return "Medium"
        elif count > 0:
            return "Low"
        else:
            return "None"
    
    def _calculate_security_grade(self, severity_dist: Dict[str, int]) -> str:
        """Calculate overall security grade"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        medium_count = severity_dist.get("medium", 0)
        
        if critical_count > 0:
            return "F"
        elif high_count > 5:
            return "D"
        elif high_count > 2:
            return "C"
        elif high_count > 0 or medium_count > 10:
            return "B"
        else:
            return "A"
    
    def _analyze_security_investment(
        self,
        vulnerability_report: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze security investment requirements"""
        severity_dist = vulnerability_report.get("statistics", {}).get("severity_distribution", {})
        
        # Calculate investment requirements
        immediate_cost = self._calculate_immediate_remediation_cost(severity_dist)
        annual_security_budget = self._estimate_annual_security_budget(severity_dist, business_context)
        roi_analysis = self._calculate_security_roi(severity_dist, business_context)
        
        return {
            "immediate_remediation_cost": immediate_cost,
            "recommended_annual_security_budget": annual_security_budget,
            "roi_analysis": roi_analysis,
            "cost_of_inaction": self._calculate_cost_of_inaction(severity_dist, business_context),
            "investment_priorities": self._prioritize_security_investments(severity_dist),
            "budget_allocation": self._recommend_budget_allocation(severity_dist)
        }
    
    def _calculate_immediate_remediation_cost(self, severity_dist: Dict[str, int]) -> Dict[str, Any]:
        """Calculate immediate remediation costs"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        # Cost estimates per vulnerability type
        critical_cost = critical_count * 15000  # $15K per critical vuln
        high_cost = high_count * 8000  # $8K per high vuln
        
        total_cost = critical_cost + high_cost
        
        return {
            "critical_vulnerabilities": {"count": critical_count, "cost": critical_cost},
            "high_vulnerabilities": {"count": high_count, "cost": high_cost},
            "total_immediate_cost": total_cost,
            "timeline": "30-90 days"
        }
    
    def _estimate_annual_security_budget(
        self,
        severity_dist: Dict[str, int],
        business_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Estimate recommended annual security budget"""
        revenue = business_context.get("annual_revenue", 100)  # Default $100M
        employee_count = business_context.get("employee_count", 500)
        
        # Industry standard: 3-10% of IT budget, IT budget typically 3-8% of revenue
        base_security_budget = revenue * 0.05 * 0.06  # 6% of 5% of revenue
        
        # Adjust based on risk level
        risk_multiplier = 1.0
        if severity_dist.get("critical", 0) > 0:
            risk_multiplier = 1.5
        elif severity_dist.get("high", 0) > 3:
            risk_multiplier = 1.3
        
        recommended_budget = base_security_budget * risk_multiplier
        
        return {
            "recommended_annual_budget": recommended_budget * 1000000,  # Convert to dollars
            "per_employee_cost": (recommended_budget * 1000000) / employee_count,
            "percentage_of_revenue": (recommended_budget * 100),
            "budget_breakdown": {
                "personnel": recommended_budget * 0.6 * 1000000,
                "technology": recommended_budget * 0.25 * 1000000,
                "training": recommended_budget * 0.1 * 1000000,
                "compliance": recommended_budget * 0.05 * 1000000
            }
        }
    
    def _calculate_security_roi(
        self,
        severity_dist: Dict[str, int],
        business_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate security investment ROI"""
        revenue = business_context.get("annual_revenue", 100)
        
        # Potential loss from security incidents
        potential_annual_loss = revenue * 0.02 * 1000000  # 2% of revenue
        
        # Security investment
        security_investment = revenue * 0.05 * 0.06 * 1000000  # 6% of 5% of revenue
        
        # Risk reduction from security investment (estimated)
        risk_reduction = 0.8  # 80% risk reduction
        
        annual_savings = potential_annual_loss * risk_reduction
        roi_percentage = ((annual_savings - security_investment) / security_investment) * 100
        
        return {
            "potential_annual_loss": potential_annual_loss,
            "security_investment": security_investment,
            "annual_savings": annual_savings,
            "roi_percentage": roi_percentage,
            "payback_period_months": (security_investment / (annual_savings / 12)) if annual_savings > 0 else 0
        }
    
    def _calculate_cost_of_inaction(
        self,
        severity_dist: Dict[str, int],
        business_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate cost of not addressing security issues"""
        revenue = business_context.get("annual_revenue", 100)
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        # Probability of incident based on vulnerability count
        incident_probability = min(0.9, (critical_count * 0.3) + (high_count * 0.1))
        
        # Potential incident costs
        data_breach_cost = revenue * 0.05 * 1000000  # 5% of revenue
        downtime_cost = revenue * 0.02 * 1000000  # 2% of revenue
        regulatory_fines = revenue * 0.04 * 1000000  # 4% of revenue (for regulated industries)
        
        expected_annual_cost = (data_breach_cost + downtime_cost + regulatory_fines) * incident_probability
        
        return {
            "incident_probability": incident_probability,
            "potential_data_breach_cost": data_breach_cost,
            "potential_downtime_cost": downtime_cost,
            "potential_regulatory_fines": regulatory_fines,
            "expected_annual_cost": expected_annual_cost,
            "five_year_risk": expected_annual_cost * 5
        }
    
    def _prioritize_security_investments(self, severity_dist: Dict[str, int]) -> List[Dict[str, Any]]:
        """Prioritize security investments"""
        priorities = []
        
        if severity_dist.get("critical", 0) > 0:
            priorities.append({
                "priority": 1,
                "investment": "Emergency Vulnerability Remediation",
                "cost": "$100K-$500K",
                "timeline": "Immediate",
                "impact": "Eliminate critical business risks"
            })
        
        if severity_dist.get("high", 0) > 0:
            priorities.append({
                "priority": 2,
                "investment": "Web Application Firewall & Monitoring",
                "cost": "$200K-$800K",
                "timeline": "1-3 months",
                "impact": "Immediate protection and visibility"
            })
        
        priorities.extend([
            {
                "priority": 3,
                "investment": "Security Team Expansion",
                "cost": "$300K-$1.5M annually",
                "timeline": "3-6 months",
                "impact": "Sustainable security operations"
            },
            {
                "priority": 4,
                "investment": "DevSecOps Implementation",
                "cost": "$500K-$2M",
                "timeline": "6-12 months",
                "impact": "Prevent future vulnerabilities"
            },
            {
                "priority": 5,
                "investment": "Security Awareness Program",
                "cost": "$100K-$300K annually",
                "timeline": "Ongoing",
                "impact": "Reduce human risk factors"
            }
        ])
        
        return priorities
    
    def _recommend_budget_allocation(self, severity_dist: Dict[str, int]) -> Dict[str, float]:
        """Recommend security budget allocation"""
        if severity_dist.get("critical", 0) > 0:
            # Crisis mode allocation
            return {
                "immediate_remediation": 0.4,
                "personnel": 0.3,
                "technology": 0.2,
                "training": 0.05,
                "compliance": 0.05
            }
        elif severity_dist.get("high", 0) > 3:
            # High-risk allocation
            return {
                "immediate_remediation": 0.25,
                "personnel": 0.35,
                "technology": 0.25,
                "training": 0.1,
                "compliance": 0.05
            }
        else:
            # Standard allocation
            return {
                "immediate_remediation": 0.15,
                "personnel": 0.4,
                "technology": 0.25,
                "training": 0.15,
                "compliance": 0.05
            }
    
    def _assess_compliance_status(
        self,
        vulnerability_report: Dict[str, Any],
        business_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess compliance status"""
        regulations = business_context.get("applicable_regulations", [])
        severity_dist = vulnerability_report.get("statistics", {}).get("severity_distribution", {})
        
        compliance_status = {}
        
        for regulation in regulations:
            status = self._assess_regulation_compliance(regulation, severity_dist)
            compliance_status[regulation] = status
        
        overall_compliance = self._calculate_overall_compliance(compliance_status)
        
        return {
            "overall_compliance_score": overall_compliance,
            "regulation_status": compliance_status,
            "compliance_risks": self._identify_compliance_risks(regulations, severity_dist),
            "remediation_requirements": self._get_compliance_remediation_requirements(regulations, severity_dist)
        }
    
    def _assess_regulation_compliance(self, regulation: str, severity_dist: Dict[str, int]) -> Dict[str, Any]:
        """Assess compliance with specific regulation"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        # Regulation-specific compliance assessment
        if regulation in ["GDPR", "CCPA"]:
            if critical_count > 0:
                status = "Non-Compliant"
                risk = "High"
            elif high_count > 2:
                status = "At Risk"
                risk = "Medium"
            else:
                status = "Compliant"
                risk = "Low"
        elif regulation in ["PCI-DSS"]:
            if critical_count > 0 or high_count > 1:
                status = "Non-Compliant"
                risk = "High"
            else:
                status = "Compliant"
                risk = "Low"
        else:
            # Generic assessment
            if critical_count > 0:
                status = "At Risk"
                risk = "Medium"
            else:
                status = "Compliant"
                risk = "Low"
        
        return {
            "status": status,
            "risk_level": risk,
            "critical_issues": critical_count,
            "high_issues": high_count
        }
    
    def _calculate_overall_compliance(self, compliance_status: Dict[str, Dict[str, Any]]) -> int:
        """Calculate overall compliance score"""
        if not compliance_status:
            return 100
        
        total_score = 0
        for regulation, status in compliance_status.items():
            if status["status"] == "Compliant":
                total_score += 100
            elif status["status"] == "At Risk":
                total_score += 60
            else:  # Non-Compliant
                total_score += 20
        
        return total_score // len(compliance_status)
    
    def _identify_compliance_risks(
        self,
        regulations: List[str],
        severity_dist: Dict[str, int]
    ) -> List[str]:
        """Identify compliance risks"""
        risks = []
        
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        if critical_count > 0:
            risks.append("Critical vulnerabilities may constitute compliance violations")
        
        if "GDPR" in regulations and high_count > 0:
            risks.append("Data protection vulnerabilities risk GDPR fines up to 4% of revenue")
        
        if "PCI-DSS" in regulations and (critical_count > 0 or high_count > 1):
            risks.append("Payment card data security violations risk PCI-DSS non-compliance")
        
        if "HIPAA" in regulations and critical_count > 0:
            risks.append("Healthcare data vulnerabilities risk HIPAA violations and penalties")
        
        return risks
    
    def _get_compliance_remediation_requirements(
        self,
        regulations: List[str],
        severity_dist: Dict[str, int]
    ) -> List[str]:
        """Get compliance remediation requirements"""
        requirements = []
        
        if severity_dist.get("critical", 0) > 0:
            requirements.append("Immediate remediation of all critical vulnerabilities")
        
        if "GDPR" in regulations:
            requirements.append("Implement data protection impact assessment (DPIA)")
            requirements.append("Ensure data breach notification procedures")
        
        if "PCI-DSS" in regulations:
            requirements.append("Quarterly vulnerability scans and annual penetration testing")
            requirements.append("Implement network segmentation for cardholder data")
        
        requirements.extend([
            "Document all remediation activities",
            "Implement continuous compliance monitoring",
            "Conduct regular compliance assessments"
        ])
        
        return requirements
    
    def _generate_strategic_recommendations(
        self,
        vulnerability_report: Dict[str, Any],
        business_impact: BusinessImpactAssessment,
        business_context: Dict[str, Any]
    ) -> List[str]:
        """Generate strategic security recommendations"""
        recommendations = []
        
        severity_dist = vulnerability_report.get("statistics", {}).get("severity_distribution", {})
        
        # Immediate strategic actions
        if business_impact.overall_risk_level == "CRITICAL":
            recommendations.append("Establish executive-level security crisis management team")
            recommendations.append("Implement emergency security budget allocation process")
        
        # Governance recommendations
        recommendations.extend([
            "Establish Board-level cybersecurity oversight committee",
            "Implement quarterly security risk reporting to executive leadership",
            "Develop comprehensive cybersecurity strategy aligned with business objectives"
        ])
        
        # Organizational recommendations
        if severity_dist.get("critical", 0) > 0 or severity_dist.get("high", 0) > 5:
            recommendations.append("Consider hiring Chief Information Security Officer (CISO)")
        
        recommendations.extend([
            "Integrate security requirements into all technology procurement decisions",
            "Establish security metrics and KPIs for business performance measurement",
            "Implement third-party risk management program for vendors and partners"
        ])
        
        # Technology strategy
        recommendations.extend([
            "Adopt zero-trust security architecture principles",
            "Implement security-by-design in all development processes",
            "Establish cloud security strategy and governance framework"
        ])
        
        return recommendations
    
    def _define_next_steps(
        self,
        vulnerability_report: Dict[str, Any],
        business_impact: BusinessImpactAssessment
    ) -> List[str]:
        """Define immediate next steps"""
        next_steps = []
        
        severity_dist = vulnerability_report.get("statistics", {}).get("severity_distribution", {})
        
        # Immediate actions
        if severity_dist.get("critical", 0) > 0:
            next_steps.extend([
                "Schedule emergency executive meeting within 24 hours",
                "Activate incident response team and security vendors",
                "Approve emergency budget for critical vulnerability remediation"
            ])
        
        # Short-term actions
        next_steps.extend([
            "Review and approve recommended security investments",
            "Establish security steering committee with executive sponsorship",
            "Engage qualified security vendors for immediate remediation support",
            "Schedule follow-up security assessment in 90 days"
        ])
        
        # Process establishment
        next_steps.extend([
            "Implement monthly security risk reporting to executive team",
            "Establish security metrics dashboard for ongoing monitoring",
            "Schedule quarterly Board-level cybersecurity briefings"
        ])
        
        return next_steps
    
    async def export_executive_report(
        self,
        report: ExecutiveReport,
        format_type: str = "json",
        output_path: Optional[str] = None
    ) -> str:
        """Export executive report"""
        try:
            if format_type.lower() == "json":
                content = json.dumps(asdict(report), indent=2, default=str)
                extension = "json"
            else:
                raise ValueError(f"Unsupported format: {format_type}")
            
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"executive_security_report_{timestamp}.{extension}"
            
            with open(output_path, 'w') as f:
                f.write(content)
            
            logger.info(f"✅ Executive report exported to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"❌ Executive report export failed: {e}")
            raise


class BusinessImpactCalculator:
    """Business impact calculation utilities"""
    
    def calculate_financial_impact(
        self,
        severity_distribution: Dict[str, int],
        annual_revenue: float,
        industry: str
    ) -> Dict[str, Any]:
        """Calculate detailed financial impact"""
        # Industry-specific multipliers
        industry_multipliers = {
            "financial": 1.5,
            "healthcare": 1.4,
            "government": 1.3,
            "retail": 1.2,
            "technology": 1.1,
            "manufacturing": 1.0
        }
        
        multiplier = industry_multipliers.get(industry, 1.0)
        
        # Base impact calculations
        critical_impact = severity_distribution.get("critical", 0) * 0.05 * annual_revenue * multiplier
        high_impact = severity_distribution.get("high", 0) * 0.02 * annual_revenue * multiplier
        medium_impact = severity_distribution.get("medium", 0) * 0.005 * annual_revenue * multiplier
        
        total_potential_impact = critical_impact + high_impact + medium_impact
        
        return {
            "total_potential_impact": total_potential_impact,
            "critical_impact": critical_impact,
            "high_impact": high_impact,
            "medium_impact": medium_impact,
            "industry_multiplier": multiplier
        }
