"""
HTML Report Generator
====================

Advanced HTML report generation with interactive charts, responsive design,
and professional styling for web-based security reports.
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional

from loguru import logger
from agents.base import BaseAgent


class HTMLReportGenerator(BaseAgent):
    """Professional HTML report generator"""
    
    def __init__(self):
        super().__init__("HTMLReportGenerator")
        self.template = self._get_html_template()
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        try:
            # For HTML generator, we expect report data in config
            report_data = config.get("report_data", {}) if config else {}
            output_path = config.get("output_path") if config else None
            include_charts = config.get("include_charts", True) if config else True
            
            # Generate HTML report
            html_path = await self.generate_html_report(report_data, output_path, include_charts)
            
            return {
                "agent": "HTMLReportGenerator",
                "success": True,
                "html_path": html_path,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"HTML report generation failed: {e}")
            return {
                "agent": "HTMLReportGenerator", 
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        
    def _get_html_template(self) -> str:
        """Get HTML report template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 0;
            text-align: center;
            margin-bottom: 30px;
            border-radius: 10px;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .card h2 {
            color: #2d3748;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            border-left: 4px solid #3182ce;
        }
        
        .stat-card.critical {
            border-left-color: #e53e3e;
        }
        
        .stat-card.high {
            border-left-color: #dd6b20;
        }
        
        .stat-card.medium {
            border-left-color: #d69e2e;
        }
        
        .stat-card.low {
            border-left-color: #38a169;
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #2d3748;
        }
        
        .stat-label {
            color: #718096;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .vulnerability {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }
        
        .vulnerability h3 {
            color: #2d3748;
            margin-bottom: 10px;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }
        
        .severity-critical {
            background-color: #e53e3e;
        }
        
        .severity-high {
            background-color: #dd6b20;
        }
        
        .severity-medium {
            background-color: #d69e2e;
        }
        
        .severity-low {
            background-color: #38a169;
        }
        
        .severity-info {
            background-color: #3182ce;
        }
        
        .chart-container {
            position: relative;
            height: 400px;
            margin: 20px 0;
        }
        
        .recommendations {
            background: #e6fffa;
            border-left: 4px solid #38a169;
            padding: 20px;
            margin: 20px 0;
        }
        
        .recommendations h3 {
            color: #2d3748;
            margin-bottom: 15px;
        }
        
        .recommendations ul {
            list-style-type: none;
        }
        
        .recommendations li {
            padding: 8px 0;
            border-bottom: 1px solid #b2f5ea;
        }
        
        .recommendations li:before {
            content: "✓ ";
            color: #38a169;
            font-weight: bold;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #718096;
            border-top: 1px solid #e2e8f0;
            margin-top: 40px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <p>Comprehensive Vulnerability Analysis</p>
        </div>
        
        <!-- REPORT_CONTENT -->
        
        <div class="footer">
            <p>Generated by Nexus Hunter Security Platform on {timestamp}</p>
            <p>This report contains confidential security information</p>
        </div>
    </div>
    
    <!-- CHART_SCRIPTS -->
</body>
</html>
        """
    
    async def generate_html_report(
        self,
        report_data: Dict[str, Any],
        output_path: Optional[str] = None,
        include_charts: bool = True
    ) -> str:
        """Generate comprehensive HTML security report"""
        try:
            logger.info("🌐 Generating HTML report")
            
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"security_report_{timestamp}.html"
            
            # Generate report content
            content = self._generate_report_content(report_data, include_charts)
            
            # Generate chart scripts
            chart_scripts = self._generate_chart_scripts(report_data) if include_charts else ""
            
            # Replace placeholders in template
            html_content = self.template.replace("<!-- REPORT_CONTENT -->", content)
            html_content = html_content.replace("<!-- CHART_SCRIPTS -->", chart_scripts)
            html_content = html_content.replace("{timestamp}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            # Write HTML file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"✅ HTML report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"❌ HTML report generation failed: {e}")
            raise
    
    def _generate_report_content(self, report_data: Dict[str, Any], include_charts: bool) -> str:
        """Generate main report content"""
        content = []
        
        # Metadata
        metadata = report_data.get("metadata", {})
        statistics = report_data.get("statistics", {})
        
        # Report overview
        content.append(f"""
        <div class="card">
            <h2>Assessment Overview</h2>
            <p><strong>Target:</strong> {metadata.get('target', 'Unknown')}</p>
            <p><strong>Assessment Date:</strong> {metadata.get('start_time', 'Unknown')[:10]}</p>
            <p><strong>Duration:</strong> {metadata.get('duration_seconds', 0) // 3600}h {(metadata.get('duration_seconds', 0) % 3600) // 60}m</p>
            <p><strong>Conducted By:</strong> {metadata.get('tester_name', 'Nexus Hunter')}</p>
            <p><strong>Total Vulnerabilities:</strong> {statistics.get('total_vulnerabilities', 0)}</p>
        </div>
        """)
        
        # Statistics cards
        severity_dist = statistics.get("severity_distribution", {})
        content.append(self._generate_stats_cards(severity_dist))
        
        # Charts section
        if include_charts:
            content.append(f"""
            <div class="card">
                <h2>Vulnerability Distribution</h2>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            """)
        
        # Executive summary
        exec_summary = report_data.get("executive_summary", {})
        if exec_summary:
            content.append(self._generate_executive_summary(exec_summary))
        
        # Top vulnerabilities
        vulnerabilities = report_data.get("vulnerabilities", [])
        if vulnerabilities:
            content.append(self._generate_vulnerabilities_section(vulnerabilities[:10]))
        
        # Recommendations
        recommendations = report_data.get("recommendations", [])
        if recommendations:
            content.append(self._generate_recommendations_section(recommendations))
        
        return "\n".join(content)
    
    def _generate_stats_cards(self, severity_dist: Dict[str, int]) -> str:
        """Generate statistics cards"""
        return f"""
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-number">{severity_dist.get('critical', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{severity_dist.get('high', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">{severity_dist.get('medium', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">{severity_dist.get('low', 0)}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        """
    
    def _generate_executive_summary(self, exec_summary: Dict[str, Any]) -> str:
        """Generate executive summary section"""
        content = ['<div class="card">', '<h2>Executive Summary</h2>']
        
        # Key findings
        key_findings = exec_summary.get("key_findings", [])
        if key_findings:
            content.append("<h3>Key Findings</h3>")
            content.append("<ul>")
            for finding in key_findings[:5]:
                content.append(f"<li>{finding}</li>")
            content.append("</ul>")
        
        # Business impact
        business_impact = exec_summary.get("business_impact", "")
        if business_impact:
            content.append("<h3>Business Impact</h3>")
            content.append(f"<p>{business_impact}</p>")
        
        content.append("</div>")
        return "\n".join(content)
    
    def _generate_vulnerabilities_section(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate vulnerabilities section"""
        content = ['<div class="card">', '<h2>Top Vulnerabilities</h2>']
        
        for i, vuln in enumerate(vulnerabilities, 1):
            title = vuln.get("title", vuln.get("name", f"Vulnerability {i}"))
            severity = vuln.get("severity", "Unknown")
            description = vuln.get("description", "No description available")
            
            # Truncate long descriptions
            if len(description) > 300:
                description = description[:300] + "..."
            
            severity_class = f"severity-{severity.lower()}" if severity.lower() in ['critical', 'high', 'medium', 'low', 'info'] else "severity-medium"
            
            content.append(f"""
            <div class="vulnerability">
                <h3>{title}</h3>
                <span class="severity-badge {severity_class}">{severity}</span>
                <p>{description}</p>
            </div>
            """)
        
        content.append("</div>")
        return "\n".join(content)
    
    def _generate_recommendations_section(self, recommendations: List[str]) -> str:
        """Generate recommendations section"""
        content = [
            '<div class="recommendations">',
            '<h3>Security Recommendations</h3>',
            '<ul>'
        ]
        
        for rec in recommendations[:10]:  # Top 10 recommendations
            content.append(f"<li>{rec}</li>")
        
        content.extend(['</ul>', '</div>'])
        return "\n".join(content)
    
    def _generate_chart_scripts(self, report_data: Dict[str, Any]) -> str:
        """Generate JavaScript for charts"""
        statistics = report_data.get("statistics", {})
        severity_dist = statistics.get("severity_distribution", {})
        
        # Filter out zero values
        chart_data = {k: v for k, v in severity_dist.items() if v > 0}
        
        if not chart_data:
            return ""
        
        labels = list(chart_data.keys())
        data = list(chart_data.values())
        
        # Color mapping for severity levels
        colors = {
            'critical': '#e53e3e',
            'high': '#dd6b20',
            'medium': '#d69e2e',
            'low': '#38a169',
            'info': '#3182ce'
        }
        
        background_colors = [colors.get(label.lower(), '#718096') for label in labels]
        
        return f"""
        <script>
            document.addEventListener('DOMContentLoaded', function() {{
                const ctx = document.getElementById('severityChart');
                if (ctx) {{
                    new Chart(ctx, {{
                        type: 'doughnut',
                        data: {{
                            labels: {json.dumps([label.title() for label in labels])},
                            datasets: [{{
                                data: {json.dumps(data)},
                                backgroundColor: {json.dumps(background_colors)},
                                borderWidth: 2,
                                borderColor: '#ffffff'
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {{
                                legend: {{
                                    position: 'bottom',
                                    labels: {{
                                        padding: 20,
                                        usePointStyle: true
                                    }}
                                }},
                                title: {{
                                    display: true,
                                    text: 'Vulnerability Distribution by Severity',
                                    font: {{
                                        size: 16,
                                        weight: 'bold'
                                    }}
                                }}
                            }}
                        }}
                    }});
                }}
            }});
        </script>
        """
    
    async def generate_dashboard_html(
        self,
        report_data: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> str:
        """Generate interactive security dashboard"""
        try:
            logger.info("📊 Generating security dashboard")
            
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"security_dashboard_{timestamp}.html"
            
            # Generate dashboard-specific content
            dashboard_content = self._generate_dashboard_content(report_data)
            
            # Use dashboard template
            dashboard_template = self._get_dashboard_template()
            html_content = dashboard_template.replace("<!-- DASHBOARD_CONTENT -->", dashboard_content)
            html_content = html_content.replace("{timestamp}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            # Write HTML file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"✅ Security dashboard generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"❌ Dashboard generation failed: {e}")
            raise
    
    def _get_dashboard_template(self) -> str:
        """Get dashboard HTML template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            padding: 20px;
        }
        
        .widget {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .widget h3 {
            margin-top: 0;
            color: #333;
        }
        
        .metric {
            font-size: 2em;
            font-weight: bold;
            color: #2c5aa0;
        }
        
        .chart-widget {
            height: 300px;
        }
        
        .alert {
            background: #fee;
            border: 1px solid #fcc;
            border-radius: 4px;
            padding: 10px;
            margin: 10px 0;
        }
        
        .alert.critical {
            background: #fee;
            border-color: #e53e3e;
            color: #c53030;
        }
    </style>
</head>
<body>
    <h1 style="text-align: center; padding: 20px; margin: 0; background: #2c5aa0; color: white;">
        Security Dashboard
    </h1>
    
    <div class="dashboard">
        <!-- DASHBOARD_CONTENT -->
    </div>
    
    <div style="text-align: center; padding: 20px; color: #666;">
        Generated on {timestamp} by Nexus Hunter
    </div>
</body>
</html>
        """
    
    def _generate_dashboard_content(self, report_data: Dict[str, Any]) -> str:
        """Generate dashboard content"""
        content = []
        statistics = report_data.get("statistics", {})
        severity_dist = statistics.get("severity_distribution", {})
        
        # Key metrics widget
        total_vulns = statistics.get("total_vulnerabilities", 0)
        critical_count = severity_dist.get("critical", 0)
        high_count = severity_dist.get("high", 0)
        
        content.append(f"""
        <div class="widget">
            <h3>Key Metrics</h3>
            <div class="metric">{total_vulns}</div>
            <p>Total Vulnerabilities</p>
            {f'<div class="alert critical">⚠️ {critical_count} Critical Issues</div>' if critical_count > 0 else ''}
            {f'<div class="alert">⚠️ {high_count} High Priority Issues</div>' if high_count > 0 else ''}
        </div>
        """)
        
        # Risk level widget
        risk_level = "LOW"
        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 3:
            risk_level = "HIGH"
        elif high_count > 0:
            risk_level = "MEDIUM"
        
        content.append(f"""
        <div class="widget">
            <h3>Overall Risk Level</h3>
            <div class="metric" style="color: {'#e53e3e' if risk_level == 'CRITICAL' else '#dd6b20' if risk_level == 'HIGH' else '#d69e2e' if risk_level == 'MEDIUM' else '#38a169'}">{risk_level}</div>
            <p>Current Security Posture</p>
        </div>
        """)
        
        # Systems affected widget
        systems_affected = statistics.get("unique_affected_systems", 0)
        content.append(f"""
        <div class="widget">
            <h3>Systems Affected</h3>
            <div class="metric">{systems_affected}</div>
            <p>Unique Systems with Vulnerabilities</p>
        </div>
        """)
        
        return "\n".join(content)
