"""
CVSS Calculator and Severity Rating System
Based on CVSS v3.1 scoring methodology
"""

from typing import Dict, Tuple
from enum import Enum


class VulnerabilityType(Enum):
    """Vulnerability type classifications"""
    SQL_INJECTION = "SQL Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    COMMAND_INJECTION = "Command Injection"
    TEMPLATE_INJECTION = "Template Injection"
    XSS_REFLECTED = "Reflected XSS"
    XSS_STORED = "Stored XSS"
    XSS_DOM = "DOM XSS"
    SSRF = "SSRF"
    XXE = "XXE"
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    FILE_UPLOAD = "File Upload"
    DESERIALIZATION = "Insecure Deserialization"
    LDAP_INJECTION = "LDAP Injection"
    BUSINESS_LOGIC = "Business Logic Flaw"
    PRICE_MANIPULATION = "Price Manipulation"
    RACE_CONDITION = "Race Condition"
    AUTH_BYPASS = "Authentication Bypass"
    SESSION_FIXATION = "Session Fixation"
    IDOR = "IDOR"
    CSRF = "CSRF"


# CVSS Base Scores and Severity Mappings
VULNERABILITY_CVSS_SCORES = {
    # Critical (9.0-10.0)
    VulnerabilityType.COMMAND_INJECTION: (9.8, "CRITICAL"),
    VulnerabilityType.DESERIALIZATION: (9.8, "CRITICAL"),
    
    # High (7.0-8.9)
    VulnerabilityType.SQL_INJECTION: (8.6, "HIGH"),
    VulnerabilityType.NOSQL_INJECTION: (8.1, "HIGH"),
    VulnerabilityType.TEMPLATE_INJECTION: (8.8, "HIGH"),
    VulnerabilityType.XXE: (8.2, "HIGH"),
    VulnerabilityType.FILE_UPLOAD: (8.8, "HIGH"),
    VulnerabilityType.SSRF: (8.5, "HIGH"),
    VulnerabilityType.RFI: (8.6, "HIGH"),
    VulnerabilityType.AUTH_BYPASS: (8.1, "HIGH"),
    
    # Medium (4.0-6.9)
    VulnerabilityType.XSS_STORED: (6.1, "MEDIUM"),
    VulnerabilityType.LFI: (6.5, "MEDIUM"),
    VulnerabilityType.LDAP_INJECTION: (6.5, "MEDIUM"),
    VulnerabilityType.BUSINESS_LOGIC: (5.3, "MEDIUM"),
    VulnerabilityType.PRICE_MANIPULATION: (6.5, "MEDIUM"),
    VulnerabilityType.SESSION_FIXATION: (5.9, "MEDIUM"),
    VulnerabilityType.IDOR: (5.3, "MEDIUM"),
    
    # Low (0.1-3.9)
    VulnerabilityType.XSS_REFLECTED: (3.1, "LOW"),
    VulnerabilityType.XSS_DOM: (3.7, "LOW"),
    VulnerabilityType.RACE_CONDITION: (3.7, "LOW"),
    VulnerabilityType.CSRF: (3.5, "LOW"),
}


def calculate_cvss_score(
    vuln_type: str,
    has_authentication: bool = False,
    network_accessible: bool = True,
    data_exposure: bool = False,
    code_execution: bool = False,
    privilege_escalation: bool = False
) -> Tuple[float, str]:
    """
    Calculate CVSS score based on vulnerability type and context
    
    Args:
        vuln_type: Type of vulnerability
        has_authentication: Whether authentication is required
        network_accessible: Whether vulnerability is accessible over network
        data_exposure: Whether sensitive data is exposed
        code_execution: Whether remote code execution is possible
        privilege_escalation: Whether privilege escalation is possible
    
    Returns:
        Tuple of (CVSS score, severity level)
    """
    # Get base score
    base_score = 5.0
    severity = "MEDIUM"
    
    # Match vulnerability type
    for vuln_enum in VulnerabilityType:
        if vuln_enum.value.lower() in vuln_type.lower():
            base_score, severity = VULNERABILITY_CVSS_SCORES.get(vuln_enum, (5.0, "MEDIUM"))
            break
    
    # Adjust based on context
    modifiers = 0.0
    
    # Authentication requirement reduces score
    if has_authentication:
        modifiers -= 1.5
    
    # Network accessibility increases score
    if not network_accessible:
        modifiers -= 2.0
    
    # Impact modifiers
    if code_execution:
        modifiers += 1.0
    if data_exposure:
        modifiers += 0.5
    if privilege_escalation:
        modifiers += 1.5
    
    # Calculate final score
    final_score = max(0.1, min(10.0, base_score + modifiers))
    
    # Determine severity based on final score
    if final_score >= 9.0:
        final_severity = "CRITICAL"
    elif final_score >= 7.0:
        final_severity = "HIGH"
    elif final_score >= 4.0:
        final_severity = "MEDIUM"
    else:
        final_severity = "LOW"
    
    return round(final_score, 1), final_severity


def get_severity_for_vulnerability(vuln_type: str, context: Dict = None) -> Tuple[float, str]:
    """
    Get appropriate severity and CVSS score for a vulnerability
    
    Args:
        vuln_type: Type of vulnerability (e.g., "SQL Injection", "XSS")
        context: Optional context dict with additional information
    
    Returns:
        Tuple of (CVSS score, severity level)
    """
    context = context or {}
    
    return calculate_cvss_score(
        vuln_type=vuln_type,
        has_authentication=context.get('requires_auth', False),
        network_accessible=context.get('network_accessible', True),
        data_exposure=context.get('data_exposure', False),
        code_execution=context.get('code_execution', False),
        privilege_escalation=context.get('privilege_escalation', False)
    )


# Quick reference mapping for common vulnerability types
QUICK_SEVERITY_MAP = {
    "SQL Injection": ("HIGH", 8.6),
    "NoSQL Injection": ("HIGH", 8.1),
    "Command Injection": ("CRITICAL", 9.8),
    "Template Injection": ("HIGH", 8.8),
    "SSRF": ("HIGH", 8.5),
    "XXE": ("HIGH", 8.2),
    "File Upload": ("HIGH", 8.8),
    "Local File Inclusion": ("MEDIUM", 6.5),
    "Remote File Inclusion": ("HIGH", 8.6),
    "Reflected XSS": ("LOW", 3.1),
    "Stored XSS": ("MEDIUM", 6.1),
    "DOM XSS": ("LOW", 3.7),
    "Insecure Deserialization": ("CRITICAL", 9.8),
    "LDAP Injection": ("MEDIUM", 6.5),
    "Business Logic": ("MEDIUM", 5.3),
    "Price Manipulation": ("MEDIUM", 6.5),
    "Race Condition": ("LOW", 3.7),
    "Authentication Bypass": ("HIGH", 8.1),
    "Session Fixation": ("MEDIUM", 5.9),
    "IDOR": ("MEDIUM", 5.3),
    "CSRF": ("LOW", 3.5),
}


def get_quick_severity(vuln_type: str) -> Tuple[str, float]:
    """
    Quick lookup for severity and CVSS score
    
    Args:
        vuln_type: Type of vulnerability
    
    Returns:
        Tuple of (severity, CVSS score)
    """
    for known_type, (severity, cvss) in QUICK_SEVERITY_MAP.items():
        if known_type.lower() in vuln_type.lower():
            return severity, cvss
    
    # Default to MEDIUM if unknown
    return "MEDIUM", 5.0




