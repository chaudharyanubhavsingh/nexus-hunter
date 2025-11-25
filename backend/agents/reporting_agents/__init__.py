"""
Reporting Agents
================

This module contains all reporting and documentation agents.
These agents are responsible for:
- Vulnerability report generation
- Executive summaries  
- Technical documentation
- Disclosure documents
- Compliance reports
- Risk assessments
- Remediation guidance
"""

from .vulnerability_report_agent import VulnerabilityReportAgent
from .executive_report_agent import ExecutiveReportAgent
from .technical_report_agent import TechnicalReportAgent
from .disclosure_report_agent import DisclosureReportAgent
from .pdf_report_generator import PDFReportGenerator
from .html_report_generator import HTMLReportGenerator
from .json_report_generator import JSONReportGenerator

__all__ = [
    'VulnerabilityReportAgent',
    'ExecutiveReportAgent',
    'TechnicalReportAgent',
    'DisclosureReportAgent',
    'PDFReportGenerator',
    'HTMLReportGenerator',
    'JSONReportGenerator'
]

# Report types for the orchestrator
REPORTING_AGENTS = {
    'vulnerability_reports': [VulnerabilityReportAgent],
    'executive_reports': [ExecutiveReportAgent],
    'technical_reports': [TechnicalReportAgent],
    'disclosure_reports': [DisclosureReportAgent],
    'format_generators': [PDFReportGenerator, HTMLReportGenerator, JSONReportGenerator]
}
