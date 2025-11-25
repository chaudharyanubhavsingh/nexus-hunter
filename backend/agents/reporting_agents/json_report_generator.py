"""
JSON Report Generator
====================

Structured JSON report generation for API consumption, integration,
and automated processing of security assessment results.
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional

from loguru import logger
from agents.base import BaseAgent


class JSONReportGenerator(BaseAgent):
    """Structured JSON report generator"""
    
    def __init__(self):
        super().__init__("JSONReportGenerator")
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        try:
            # For JSON generator, we expect report data in config
            report_data = config.get("report_data", {}) if config else {}
            output_path = config.get("output_path") if config else None
            format_type = config.get("format_type", "detailed") if config else "detailed"
            
            # Generate JSON report
            json_path = await self.generate_json_report(report_data, output_path, format_type)
            
            return {
                "agent": "JSONReportGenerator",
                "success": True,
                "json_path": json_path,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"JSON report generation failed: {e}")
            return {
                "agent": "JSONReportGenerator",
                "success": False, 
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        
    async def generate_json_report(
        self,
        report_data: Dict[str, Any],
        output_path: Optional[str] = None,
        format_type: str = "detailed"
    ) -> str:
        """Generate structured JSON report"""
        try:
            logger.info("📋 Generating JSON report")
            
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"security_report_{timestamp}.json"
            
            # Generate report based on format type
            if format_type == "summary":
                json_data = self._generate_summary_report(report_data)
            elif format_type == "api":
                json_data = self._generate_api_report(report_data)
            else:  # detailed
                json_data = self._generate_detailed_report(report_data)
            
            # Write JSON file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, default=str, ensure_ascii=False)
            
            logger.info(f"✅ JSON report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"❌ JSON report generation failed: {e}")
            raise
    
    def _generate_detailed_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed JSON report"""
        return {
            "report_info": {
                "version": "1.0",
                "generated_at": datetime.now().isoformat(),
                "generator": "Nexus Hunter JSON Report Generator",
                "format": "detailed"
            },
            "scan_metadata": report_data.get("metadata", {}),
            "executive_summary": report_data.get("executive_summary", {}),
            "statistics": report_data.get("statistics", {}),
            "vulnerabilities": self._process_vulnerabilities(report_data.get("vulnerabilities", [])),
            "recommendations": report_data.get("recommendations", []),
            "appendices": report_data.get("appendices", {}),
            "compliance_status": self._extract_compliance_status(report_data),
            "risk_assessment": self._generate_risk_assessment(report_data)
        }
    
    def _generate_summary_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary JSON report"""
        statistics = report_data.get("statistics", {})
        severity_dist = statistics.get("severity_distribution", {})
        
        return {
            "report_info": {
                "version": "1.0",
                "generated_at": datetime.now().isoformat(),
                "format": "summary"
            },
            "target": report_data.get("metadata", {}).get("target", "Unknown"),
            "scan_date": report_data.get("metadata", {}).get("start_time", "Unknown"),
            "total_vulnerabilities": statistics.get("total_vulnerabilities", 0),
            "severity_breakdown": severity_dist,
            "risk_level": self._calculate_overall_risk_level(severity_dist),
            "top_vulnerabilities": self._get_top_vulnerabilities(report_data.get("vulnerabilities", []), 5),
            "key_recommendations": report_data.get("recommendations", [])[:5],
            "systems_affected": statistics.get("unique_affected_systems", 0)
        }
    
    def _generate_api_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate API-friendly JSON report"""
        statistics = report_data.get("statistics", {})
        
        return {
            "api_version": "v1",
            "timestamp": datetime.now().isoformat(),
            "scan_id": report_data.get("metadata", {}).get("scan_id", "unknown"),
            "target": report_data.get("metadata", {}).get("target", "unknown"),
            "status": "completed",
            "results": {
                "summary": {
                    "total_vulnerabilities": statistics.get("total_vulnerabilities", 0),
                    "severity_counts": statistics.get("severity_distribution", {}),
                    "risk_score": self._calculate_risk_score(statistics),
                    "compliance_score": self._calculate_compliance_score(report_data)
                },
                "vulnerabilities": [
                    self._format_vulnerability_for_api(vuln) 
                    for vuln in report_data.get("vulnerabilities", [])
                ],
                "recommendations": [
                    {
                        "id": i + 1,
                        "priority": self._get_recommendation_priority(i),
                        "description": rec,
                        "category": "security"
                    }
                    for i, rec in enumerate(report_data.get("recommendations", []))
                ]
            },
            "metadata": {
                "scan_duration": report_data.get("metadata", {}).get("duration_seconds", 0),
                "tools_used": report_data.get("metadata", {}).get("tools_used", []),
                "scan_type": report_data.get("metadata", {}).get("scan_type", "comprehensive")
            }
        }
    
    def _process_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process vulnerabilities for detailed report"""
        processed = []
        
        for vuln in vulnerabilities:
            processed_vuln = {
                "id": vuln.get("id", "unknown"),
                "title": vuln.get("title", vuln.get("name", "Unknown Vulnerability")),
                "description": vuln.get("description", "No description available"),
                "severity": self._normalize_severity(vuln.get("severity", "Medium")),
                "category": vuln.get("category", "Unknown"),
                "cvss_score": self._process_cvss_score(vuln.get("cvss_score", {})),
                "cwe_id": vuln.get("cwe_id"),
                "owasp_category": vuln.get("owasp_category"),
                "affected_systems": vuln.get("affected_urls", []),
                "evidence": vuln.get("evidence", []),
                "impact": vuln.get("impact", "Unknown impact"),
                "likelihood": vuln.get("likelihood", "Unknown"),
                "risk_rating": vuln.get("risk_rating", "Unknown"),
                "remediation": vuln.get("remediation", "Consult security team"),
                "references": vuln.get("references", []),
                "discovered_by": vuln.get("discovered_by", "Unknown"),
                "discovery_date": vuln.get("discovery_date", datetime.now().isoformat())
            }
            processed.append(processed_vuln)
        
        return processed
    
    def _normalize_severity(self, severity: Any) -> str:
        """Normalize severity to standard format"""
        if isinstance(severity, dict):
            return severity.get("value", "Medium")
        return str(severity).title()
    
    def _process_cvss_score(self, cvss_data: Any) -> Dict[str, Any]:
        """Process CVSS score data"""
        if isinstance(cvss_data, dict):
            return {
                "base_score": cvss_data.get("base_score", 0.0),
                "temporal_score": cvss_data.get("temporal_score"),
                "environmental_score": cvss_data.get("environmental_score"),
                "vector_string": cvss_data.get("vector_string", ""),
                "severity": cvss_data.get("severity", "Unknown")
            }
        elif isinstance(cvss_data, (int, float)):
            return {
                "base_score": float(cvss_data),
                "severity": self._score_to_severity(float(cvss_data))
            }
        else:
            return {
                "base_score": 0.0,
                "severity": "Unknown"
            }
    
    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity"""
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        else:
            return "None"
    
    def _extract_compliance_status(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract compliance status information"""
        # This would be enhanced with actual compliance data
        return {
            "frameworks_assessed": ["OWASP Top 10", "CWE Top 25"],
            "compliance_score": 75,  # Placeholder
            "gaps_identified": [],
            "recommendations": []
        }
    
    def _generate_risk_assessment(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk assessment summary"""
        statistics = report_data.get("statistics", {})
        severity_dist = statistics.get("severity_distribution", {})
        
        return {
            "overall_risk_level": self._calculate_overall_risk_level(severity_dist),
            "risk_score": self._calculate_risk_score(statistics),
            "business_impact": self._assess_business_impact(severity_dist),
            "likelihood_assessment": self._assess_likelihood(severity_dist),
            "risk_factors": self._identify_risk_factors(report_data),
            "mitigation_priority": self._calculate_mitigation_priority(severity_dist)
        }
    
    def _calculate_overall_risk_level(self, severity_dist: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        medium_count = severity_dist.get("medium", 0)
        
        if critical_count > 0:
            return "Critical"
        elif high_count > 3:
            return "High"
        elif high_count > 0 or medium_count > 10:
            return "Medium"
        else:
            return "Low"
    
    def _calculate_risk_score(self, statistics: Dict[str, Any]) -> int:
        """Calculate numerical risk score (0-100)"""
        severity_dist = statistics.get("severity_distribution", {})
        
        score = (
            severity_dist.get("critical", 0) * 25 +
            severity_dist.get("high", 0) * 15 +
            severity_dist.get("medium", 0) * 5 +
            severity_dist.get("low", 0) * 1
        )
        
        return min(100, score)
    
    def _calculate_compliance_score(self, report_data: Dict[str, Any]) -> int:
        """Calculate compliance score"""
        # Simplified compliance scoring
        statistics = report_data.get("statistics", {})
        severity_dist = statistics.get("severity_distribution", {})
        
        total_issues = sum(severity_dist.values())
        if total_issues == 0:
            return 100
        
        # Deduct points based on severity
        deductions = (
            severity_dist.get("critical", 0) * 20 +
            severity_dist.get("high", 0) * 10 +
            severity_dist.get("medium", 0) * 5 +
            severity_dist.get("low", 0) * 1
        )
        
        return max(0, 100 - deductions)
    
    def _get_top_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]], count: int) -> List[Dict[str, Any]]:
        """Get top vulnerabilities by severity"""
        # Sort by severity weight
        severity_weights = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
        
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_weights.get(self._normalize_severity(v.get("severity", "Medium")), 0),
            reverse=True
        )
        
        return [
            {
                "id": vuln.get("id", "unknown"),
                "title": vuln.get("title", vuln.get("name", "Unknown")),
                "severity": self._normalize_severity(vuln.get("severity", "Medium")),
                "category": vuln.get("category", "Unknown"),
                "cvss_score": self._extract_cvss_base_score(vuln.get("cvss_score", {}))
            }
            for vuln in sorted_vulns[:count]
        ]
    
    def _extract_cvss_base_score(self, cvss_data: Any) -> float:
        """Extract CVSS base score"""
        if isinstance(cvss_data, dict):
            return cvss_data.get("base_score", 0.0)
        elif isinstance(cvss_data, (int, float)):
            return float(cvss_data)
        else:
            return 0.0
    
    def _format_vulnerability_for_api(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Format vulnerability for API consumption"""
        return {
            "id": vuln.get("id", "unknown"),
            "title": vuln.get("title", vuln.get("name", "Unknown")),
            "severity": self._normalize_severity(vuln.get("severity", "Medium")),
            "category": vuln.get("category", "Unknown"),
            "cvss_score": self._extract_cvss_base_score(vuln.get("cvss_score", {})),
            "cwe_id": vuln.get("cwe_id"),
            "affected_systems_count": len(vuln.get("affected_urls", [])),
            "risk_rating": vuln.get("risk_rating", "Unknown"),
            "remediation_available": bool(vuln.get("remediation"))
        }
    
    def _get_recommendation_priority(self, index: int) -> str:
        """Get recommendation priority based on index"""
        if index < 3:
            return "high"
        elif index < 7:
            return "medium"
        else:
            return "low"
    
    def _assess_business_impact(self, severity_dist: Dict[str, int]) -> str:
        """Assess business impact level"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        if critical_count > 0:
            return "Severe"
        elif high_count > 3:
            return "High"
        elif high_count > 0:
            return "Medium"
        else:
            return "Low"
    
    def _assess_likelihood(self, severity_dist: Dict[str, int]) -> str:
        """Assess likelihood of exploitation"""
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        if critical_count > 2:
            return "Very High"
        elif critical_count > 0 or high_count > 5:
            return "High"
        elif high_count > 0:
            return "Medium"
        else:
            return "Low"
    
    def _identify_risk_factors(self, report_data: Dict[str, Any]) -> List[str]:
        """Identify key risk factors"""
        risk_factors = []
        statistics = report_data.get("statistics", {})
        severity_dist = statistics.get("severity_distribution", {})
        category_dist = statistics.get("category_distribution", {})
        
        # Severity-based factors
        if severity_dist.get("critical", 0) > 0:
            risk_factors.append("Critical vulnerabilities present")
        
        if severity_dist.get("high", 0) > 5:
            risk_factors.append("High number of high-severity vulnerabilities")
        
        # Category-based factors
        if category_dist.get("Injection", 0) > 0:
            risk_factors.append("Injection vulnerabilities detected")
        
        if category_dist.get("Broken Authentication", 0) > 0:
            risk_factors.append("Authentication security issues")
        
        if category_dist.get("Sensitive Data Exposure", 0) > 0:
            risk_factors.append("Sensitive data exposure risks")
        
        # System-based factors
        systems_affected = statistics.get("unique_affected_systems", 0)
        if systems_affected > 10:
            risk_factors.append("Multiple systems affected")
        
        return risk_factors
    
    def _calculate_mitigation_priority(self, severity_dist: Dict[str, int]) -> List[str]:
        """Calculate mitigation priority order"""
        priorities = []
        
        if severity_dist.get("critical", 0) > 0:
            priorities.append("Address critical vulnerabilities immediately")
        
        if severity_dist.get("high", 0) > 0:
            priorities.append("Remediate high-severity vulnerabilities within 1-4 weeks")
        
        if severity_dist.get("medium", 0) > 0:
            priorities.append("Plan medium-severity vulnerability fixes within 1-3 months")
        
        priorities.extend([
            "Implement security monitoring and alerting",
            "Establish regular security testing schedule",
            "Conduct security awareness training"
        ])
        
        return priorities
    
    async def generate_sarif_report(
        self,
        report_data: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> str:
        """Generate SARIF (Static Analysis Results Interchange Format) report"""
        try:
            logger.info("📋 Generating SARIF report")
            
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"security_report_{timestamp}.sarif"
            
            # Generate SARIF format
            sarif_data = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "Nexus Hunter",
                                "version": "1.0.0",
                                "informationUri": "https://nexus-hunter.com",
                                "rules": self._generate_sarif_rules(report_data)
                            }
                        },
                        "results": self._generate_sarif_results(report_data)
                    }
                ]
            }
            
            # Write SARIF file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(sarif_data, f, indent=2, default=str)
            
            logger.info(f"✅ SARIF report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"❌ SARIF report generation failed: {e}")
            raise
    
    def _generate_sarif_rules(self, report_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate SARIF rules from vulnerabilities"""
        rules = []
        vulnerabilities = report_data.get("vulnerabilities", [])
        
        # Create unique rules based on vulnerability categories
        seen_categories = set()
        
        for vuln in vulnerabilities:
            category = vuln.get("category", "Unknown")
            if category not in seen_categories:
                seen_categories.add(category)
                
                rule = {
                    "id": f"NEXUS-{category.upper().replace(' ', '_')}",
                    "name": category,
                    "shortDescription": {
                        "text": f"{category} vulnerability"
                    },
                    "fullDescription": {
                        "text": f"Detects {category.lower()} vulnerabilities in the application"
                    },
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(vuln.get("severity", "Medium"))
                    }
                }
                rules.append(rule)
        
        return rules
    
    def _generate_sarif_results(self, report_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate SARIF results from vulnerabilities"""
        results = []
        vulnerabilities = report_data.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            result = {
                "ruleId": f"NEXUS-{vuln.get('category', 'UNKNOWN').upper().replace(' ', '_')}",
                "message": {
                    "text": vuln.get("title", vuln.get("name", "Unknown vulnerability"))
                },
                "level": self._severity_to_sarif_level(vuln.get("severity", "Medium")),
                "locations": self._generate_sarif_locations(vuln.get("affected_urls", [])),
                "properties": {
                    "severity": self._normalize_severity(vuln.get("severity", "Medium")),
                    "category": vuln.get("category", "Unknown"),
                    "cwe": vuln.get("cwe_id"),
                    "cvss_score": self._extract_cvss_base_score(vuln.get("cvss_score", {}))
                }
            }
            results.append(result)
        
        return results
    
    def _severity_to_sarif_level(self, severity: Any) -> str:
        """Convert severity to SARIF level"""
        severity_str = self._normalize_severity(severity).lower()
        
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note"
        }
        
        return mapping.get(severity_str, "warning")
    
    def _generate_sarif_locations(self, affected_urls: List[str]) -> List[Dict[str, Any]]:
        """Generate SARIF locations from affected URLs"""
        locations = []
        
        for url in affected_urls[:5]:  # Limit to 5 locations
            location = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": url
                    }
                }
            }
            locations.append(location)
        
        return locations if locations else [{"message": {"text": "No specific location identified"}}]
