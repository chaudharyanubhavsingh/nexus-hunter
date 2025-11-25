"""
Quick script to update severity ratings in all vulnerability findings
"""

# Severity mappings based on CVSS v3.1
SEVERITY_MAPPINGS = {
    "SQL Injection": {"severity": "high", "cvss": 8.6},
    "NoSQL Injection": {"severity": "high", "cvss": 8.1},
    "Command Injection": {"severity": "critical", "cvss": 9.8},
    "Template Injection": {"severity": "high", "cvss": 8.8},
    "SSRF": {"severity": "high", "cvss": 8.5},
    "File Upload": {"severity": "high", "cvss": 8.8},
    "Local File Inclusion": {"severity": "medium", "cvss": 6.5},
    "Reflected XSS": {"severity": "low", "cvss": 3.1},
    "Stored XSS": {"severity": "medium", "cvss": 6.1},
    "DOM XSS": {"severity": "low", "cvss": 3.7},
}

# Files to update and their patterns
AGENT_FILES = {
    "sql_injection_agent.py": "SQL Injection",
    "nosql_injection_agent.py": "NoSQL Injection",
    "enhanced_command_injection_agent.py": "Command Injection",
    "template_injection_agent.py": "Template Injection",
    "ssrf_agent.py": "SSRF",
    "file_upload_agent.py": "File Upload",
    "lfi_agent.py": "Local File Inclusion",
    "xss_agent.py": ["Reflected XSS", "Stored XSS", "DOM XSS"],
}

print("Severity Rating Reference:")
print("=" * 60)
for vuln_type, ratings in SEVERITY_MAPPINGS.items():
    print(f"{vuln_type:30} → {ratings['severity'].upper():10} (CVSS {ratings['cvss']})")
print("=" * 60)




