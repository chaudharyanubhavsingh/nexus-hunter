"""
PDF Report Generator
===================

Advanced PDF report generation with professional formatting.
"""

import os
from datetime import datetime
from typing import Dict, List, Any, Optional

from loguru import logger
from agents.base import BaseAgent

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class PDFReportGenerator(BaseAgent):
    """Professional PDF report generator"""
    
    def __init__(self):
        super().__init__("PDFReportGenerator")
    
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main execution method required by BaseAgent"""
        try:
            # For PDF generator, we expect report data in config
            report_data = config.get("report_data", {}) if config else {}
            output_path = config.get("output_path") if config else None
            
            # Generate PDF report
            pdf_path = await self.generate_pdf_report(report_data, output_path)
            
            return {
                "agent": "PDFReportGenerator",
                "success": True,
                "pdf_path": pdf_path,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"PDF report generation failed: {e}")
            return {
                "agent": "PDFReportGenerator",
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        
    async def generate_pdf_report(
        self,
        report_data: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> str:
        """Generate PDF report from vulnerability data"""
        try:
            if not REPORTLAB_AVAILABLE:
                return await self._generate_text_report(report_data, output_path)
            
            logger.info("📄 Generating PDF report")
            
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"security_report_{timestamp}.pdf"
            
            # Create PDF
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            story.append(Paragraph("SECURITY ASSESSMENT REPORT", styles['Title']))
            story.append(Spacer(1, 12))
            
            # Summary
            metadata = report_data.get("metadata", {})
            story.append(Paragraph(f"Target: {metadata.get('target', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", styles['Normal']))
            story.append(Spacer(1, 12))
            
            # Statistics
            statistics = report_data.get("statistics", {})
            severity_dist = statistics.get("severity_distribution", {})
            
            story.append(Paragraph("VULNERABILITY SUMMARY", styles['Heading2']))
            story.append(Paragraph(f"Critical: {severity_dist.get('critical', 0)}", styles['Normal']))
            story.append(Paragraph(f"High: {severity_dist.get('high', 0)}", styles['Normal']))
            story.append(Paragraph(f"Medium: {severity_dist.get('medium', 0)}", styles['Normal']))
            story.append(Paragraph(f"Low: {severity_dist.get('low', 0)}", styles['Normal']))
            story.append(Spacer(1, 12))
            
            # Vulnerabilities
            vulnerabilities = report_data.get("vulnerabilities", [])[:10]  # Limit for PDF size
            if vulnerabilities:
                story.append(Paragraph("TOP VULNERABILITIES", styles['Heading2']))
                for i, vuln in enumerate(vulnerabilities, 1):
                    title = vuln.get("title", vuln.get("name", f"Vulnerability {i}"))
                    severity = vuln.get("severity", "Unknown")
                    story.append(Paragraph(f"{i}. {title} ({severity})", styles['Normal']))
                    
                    description = vuln.get("description", "No description available")
                    story.append(Paragraph(description[:200] + "...", styles['Normal']))
                    story.append(Spacer(1, 6))
            
            # Build PDF
            doc.build(story)
            
            logger.info(f"✅ PDF report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"❌ PDF generation failed: {e}")
            return await self._generate_text_report(report_data, output_path)
    
    async def _generate_text_report(
        self,
        report_data: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> str:
        """Generate fallback text report"""
        try:
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"security_report_{timestamp}.txt"
            
            lines = []
            metadata = report_data.get("metadata", {})
            statistics = report_data.get("statistics", {})
            
            # Header
            lines.extend([
                "=" * 60,
                "SECURITY ASSESSMENT REPORT".center(60),
                "=" * 60,
                "",
                f"Target: {metadata.get('target', 'Unknown')}",
                f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                ""
            ])
            
            # Summary
            severity_dist = statistics.get("severity_distribution", {})
            lines.extend([
                "VULNERABILITY SUMMARY:",
                f"  Critical: {severity_dist.get('critical', 0)}",
                f"  High: {severity_dist.get('high', 0)}",
                f"  Medium: {severity_dist.get('medium', 0)}",
                f"  Low: {severity_dist.get('low', 0)}",
                f"  Total: {statistics.get('total_vulnerabilities', 0)}",
                ""
            ])
            
            # Top vulnerabilities
            vulnerabilities = report_data.get("vulnerabilities", [])[:10]
            if vulnerabilities:
                lines.extend([
                    "TOP VULNERABILITIES:",
                    "-" * 30,
                    ""
                ])
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    title = vuln.get("title", vuln.get("name", f"Vulnerability {i}"))
                    severity = vuln.get("severity", "Unknown")
                    lines.extend([
                        f"{i}. {title}",
                        f"   Severity: {severity}",
                        f"   Description: {vuln.get('description', 'No description')[:100]}...",
                        ""
                    ])
            
            # Write file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(lines))
            
            logger.info(f"✅ Text report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"❌ Text report generation failed: {e}")
            raise