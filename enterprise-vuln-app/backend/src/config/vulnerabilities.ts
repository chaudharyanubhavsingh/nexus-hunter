/**
 * VulnCorp Enterprise - Vulnerability Management Configuration
 * ==========================================================
 * 
 * This file defines all vulnerability types that can be toggled on/off
 * for comprehensive security testing with Nexus Hunter
 */

export interface VulnerabilityConfig {
  id: string;
  name: string;
  category: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  enabled: boolean;
  endpoints: string[];
  payloadExamples: string[];
  nexusHunterAgent: string;
  cweId?: string;
  ovaspTop10?: string;
}

export const VULNERABILITY_CATEGORIES = {
  INJECTION: 'Injection Vulnerabilities',
  BROKEN_AUTH: 'Broken Authentication',
  SENSITIVE_DATA: 'Sensitive Data Exposure',
  XXE: 'XML External Entities',
  BROKEN_ACCESS: 'Broken Access Control',
  SECURITY_MISCONFIG: 'Security Misconfiguration',
  XSS: 'Cross-Site Scripting',
  DESERIALIZATION: 'Insecure Deserialization',
  COMPONENTS: 'Components with Known Vulnerabilities',
  LOGGING: 'Insufficient Logging & Monitoring',
  BUSINESS_LOGIC: 'Business Logic Vulnerabilities',
  API_SECURITY: 'API Security Issues',
  CRYPTO: 'Cryptographic Issues',
  FILE_UPLOAD: 'File Upload Vulnerabilities',
  WEBSOCKET: 'WebSocket Security Issues'
};

export const DEFAULT_VULNERABILITIES: VulnerabilityConfig[] = [
  // ================ INJECTION VULNERABILITIES ================
  {
    id: 'sql_injection_basic',
    name: 'SQL Injection - Basic',
    category: VULNERABILITY_CATEGORIES.INJECTION,
    description: 'Basic SQL injection in login and search forms',
    severity: 'CRITICAL',
    enabled: true,
    endpoints: ['/api/auth/login', '/api/users/search', '/api/products/search'],
    payloadExamples: ["admin' OR '1'='1' --", "'; DROP TABLE users; --"],
    nexusHunterAgent: 'sql_injection_agent',
    cweId: 'CWE-89',
    ovaspTop10: 'A03:2021'
  },
  {
    id: 'sql_injection_union',
    name: 'SQL Injection - Union Based',
    category: VULNERABILITY_CATEGORIES.INJECTION,
    description: 'Union-based SQL injection for data extraction',
    severity: 'CRITICAL',
    enabled: true,
    endpoints: ['/api/reports/generate', '/api/finance/statements'],
    payloadExamples: ["' UNION SELECT username,password FROM users --"],
    nexusHunterAgent: 'sql_injection_agent',
    cweId: 'CWE-89',
    ovaspTop10: 'A03:2021'
  },
  {
    id: 'sql_injection_blind',
    name: 'SQL Injection - Blind',
    category: VULNERABILITY_CATEGORIES.INJECTION,
    description: 'Blind SQL injection with time delays',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/hr/employees/details', '/api/crm/customers/profile'],
    payloadExamples: ["1'; WAITFOR DELAY '00:00:05' --"],
    nexusHunterAgent: 'sql_injection_agent',
    cweId: 'CWE-89',
    ovaspTop10: 'A03:2021'
  },
  {
    id: 'nosql_injection',
    name: 'NoSQL Injection',
    category: VULNERABILITY_CATEGORIES.INJECTION,
    description: 'NoSQL injection in MongoDB queries',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/inventory/search', '/api/documents/query'],
    payloadExamples: ['{"$ne": null}', '{"$regex": ".*"}'],
    nexusHunterAgent: 'nosql_injection_agent',
    cweId: 'CWE-943'
  },
  {
    id: 'ldap_injection',
    name: 'LDAP Injection',
    category: VULNERABILITY_CATEGORIES.INJECTION,
    description: 'LDAP injection in directory services',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/auth/ldap', '/api/hr/directory'],
    payloadExamples: ['admin*)(uid=*))(|(uid=*', '*)(uid=*))(|(uid=*'],
    nexusHunterAgent: 'ldap_injection_agent',
    cweId: 'CWE-90'
  },
  {
    id: 'command_injection',
    name: 'Command Injection',
    category: VULNERABILITY_CATEGORIES.INJECTION,
    description: 'OS command injection vulnerabilities',
    severity: 'CRITICAL',
    enabled: true,
    endpoints: ['/api/system/ping', '/api/tools/network', '/api/files/convert'],
    payloadExamples: ['127.0.0.1; whoami', '127.0.0.1 && cat /etc/passwd'],
    nexusHunterAgent: 'enhanced_command_injection_agent',
    cweId: 'CWE-78',
    ovaspTop10: 'A03:2021'
  },
  {
    id: 'template_injection',
    name: 'Template Injection',
    category: VULNERABILITY_CATEGORIES.INJECTION,
    description: 'Server-side template injection',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/reports/template', '/api/notifications/custom'],
    payloadExamples: ['{{7*7}}', '${7*7}', '<%=7*7%>'],
    nexusHunterAgent: 'template_injection_agent',
    cweId: 'CWE-94'
  },

  // ================ CROSS-SITE SCRIPTING ================
  {
    id: 'xss_reflected',
    name: 'XSS - Reflected',
    category: VULNERABILITY_CATEGORIES.XSS,
    description: 'Reflected XSS in search parameters',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/search', '/api/feedback/display', '/api/errors/show'],
    payloadExamples: ['<script>alert("XSS")</script>', '<img src=x onerror=alert("XSS")>'],
    nexusHunterAgent: 'xss_agent',
    cweId: 'CWE-79',
    ovaspTop10: 'A03:2021'
  },
  {
    id: 'xss_stored',
    name: 'XSS - Stored',
    category: VULNERABILITY_CATEGORIES.XSS,
    description: 'Stored XSS in comments and posts',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/comments/add', '/api/hr/notes', '/api/crm/feedback'],
    payloadExamples: ['<script>alert("Stored XSS")</script>'],
    nexusHunterAgent: 'advanced_xss_agent',
    cweId: 'CWE-79',
    ovaspTop10: 'A03:2021'
  },
  {
    id: 'xss_dom',
    name: 'XSS - DOM Based',
    category: VULNERABILITY_CATEGORIES.XSS,
    description: 'DOM-based XSS vulnerabilities',
    severity: 'MEDIUM',
    enabled: true,
    endpoints: ['/api/dashboard/widget', '/api/reports/view'],
    payloadExamples: ['javascript:alert("DOM XSS")'],
    nexusHunterAgent: 'advanced_xss_agent',
    cweId: 'CWE-79',
    ovaspTop10: 'A03:2021'
  },

  // ================ AUTHENTICATION & ACCESS CONTROL ================
  {
    id: 'auth_bypass',
    name: 'Authentication Bypass',
    category: VULNERABILITY_CATEGORIES.BROKEN_AUTH,
    description: 'Authentication mechanism bypass',
    severity: 'CRITICAL',
    enabled: true,
    endpoints: ['/api/auth/verify', '/api/admin/access'],
    payloadExamples: [],
    nexusHunterAgent: 'business_logic_agent',
    cweId: 'CWE-287',
    ovaspTop10: 'A07:2021'
  },
  {
    id: 'jwt_vulnerabilities',
    name: 'JWT Security Issues',
    category: VULNERABILITY_CATEGORIES.BROKEN_AUTH,
    description: 'JWT token manipulation and bypass',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/auth/jwt', '/api/profile/update'],
    payloadExamples: [],
    nexusHunterAgent: 'jwt_security_agent',
    cweId: 'CWE-287'
  },
  {
    id: 'session_fixation',
    name: 'Session Fixation',
    category: VULNERABILITY_CATEGORIES.BROKEN_AUTH,
    description: 'Session ID fixation vulnerabilities',
    severity: 'MEDIUM',
    enabled: true,
    endpoints: ['/api/auth/session'],
    payloadExamples: [],
    nexusHunterAgent: 'business_logic_agent',
    cweId: 'CWE-384'
  },

  // ================ FILE OPERATIONS ================
  {
    id: 'file_upload_unrestricted',
    name: 'Unrestricted File Upload',
    category: VULNERABILITY_CATEGORIES.FILE_UPLOAD,
    description: 'Unrestricted file upload allowing malicious files',
    severity: 'CRITICAL',
    enabled: true,
    endpoints: ['/api/files/upload', '/api/hr/resume', '/api/documents/add'],
    payloadExamples: ['shell.php', 'malware.exe'],
    nexusHunterAgent: 'file_upload_agent',
    cweId: 'CWE-434',
    ovaspTop10: 'A04:2021'
  },
  {
    id: 'lfi',
    name: 'Local File Inclusion',
    category: VULNERABILITY_CATEGORIES.FILE_UPLOAD,
    description: 'Local file inclusion vulnerabilities',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/files/view', '/api/documents/download', '/api/reports/export'],
    payloadExamples: ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini'],
    nexusHunterAgent: 'lfi_agent',
    cweId: 'CWE-22',
    ovaspTop10: 'A01:2021'
  },
  {
    id: 'path_traversal',
    name: 'Path Traversal',
    category: VULNERABILITY_CATEGORIES.FILE_UPLOAD,
    description: 'Directory traversal vulnerabilities',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/files/download', '/api/backup/restore'],
    payloadExamples: ['../../../../etc/passwd'],
    nexusHunterAgent: 'lfi_agent',
    cweId: 'CWE-22'
  },

  // ================ API SECURITY ================
  {
    id: 'api_broken_auth',
    name: 'API Broken Authentication',
    category: VULNERABILITY_CATEGORIES.API_SECURITY,
    description: 'API authentication bypass vulnerabilities',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/v1/admin', '/api/v2/internal'],
    payloadExamples: [],
    nexusHunterAgent: 'api_security_agent',
    cweId: 'CWE-287'
  },
  {
    id: 'api_excessive_exposure',
    name: 'Excessive Data Exposure',
    category: VULNERABILITY_CATEGORIES.API_SECURITY,
    description: 'API returns sensitive data unnecessarily',
    severity: 'MEDIUM',
    enabled: true,
    endpoints: ['/api/users/list', '/api/employees/all'],
    payloadExamples: [],
    nexusHunterAgent: 'api_security_agent',
    cweId: 'CWE-200'
  },
  {
    id: 'api_rate_limiting',
    name: 'Lack of Rate Limiting',
    category: VULNERABILITY_CATEGORIES.API_SECURITY,
    description: 'API endpoints without proper rate limiting',
    severity: 'MEDIUM',
    enabled: true,
    endpoints: ['/api/auth/login', '/api/password/reset'],
    payloadExamples: [],
    nexusHunterAgent: 'api_security_agent',
    cweId: 'CWE-770'
  },

  // ================ SERVER-SIDE REQUEST FORGERY ================
  {
    id: 'ssrf_basic',
    name: 'SSRF - Basic',
    category: VULNERABILITY_CATEGORIES.SECURITY_MISCONFIG,
    description: 'Server-Side Request Forgery vulnerabilities',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/fetch/url', '/api/webhooks/test', '/api/integrations/callback'],
    payloadExamples: ['http://localhost:80', 'http://169.254.169.254/'],
    nexusHunterAgent: 'ssrf_agent',
    cweId: 'CWE-918',
    ovaspTop10: 'A10:2021'
  },

  // ================ XML VULNERABILITIES ================
  {
    id: 'xxe_basic',
    name: 'XXE - Basic',
    category: VULNERABILITY_CATEGORIES.XXE,
    description: 'XML External Entity injection',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/xml/parse', '/api/files/import', '/api/config/update'],
    payloadExamples: ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'],
    nexusHunterAgent: 'xxe_agent',
    cweId: 'CWE-611',
    ovaspTop10: 'A05:2021'
  },

  // ================ DESERIALIZATION ================
  {
    id: 'deserialization',
    name: 'Insecure Deserialization',
    category: VULNERABILITY_CATEGORIES.DESERIALIZATION,
    description: 'Insecure object deserialization',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/session/restore', '/api/cache/load'],
    payloadExamples: [],
    nexusHunterAgent: 'deserialization_agent',
    cweId: 'CWE-502',
    ovaspTop10: 'A08:2021'
  },

  // ================ BUSINESS LOGIC ================
  {
    id: 'price_manipulation',
    name: 'Price Manipulation',
    category: VULNERABILITY_CATEGORIES.BUSINESS_LOGIC,
    description: 'Business logic flaws allowing price manipulation',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/orders/create', '/api/cart/checkout'],
    payloadExamples: [],
    nexusHunterAgent: 'business_logic_agent',
    cweId: 'CWE-840'
  },
  {
    id: 'race_conditions',
    name: 'Race Conditions',
    category: VULNERABILITY_CATEGORIES.BUSINESS_LOGIC,
    description: 'Race condition vulnerabilities',
    severity: 'MEDIUM',
    enabled: true,
    endpoints: ['/api/payments/process', '/api/inventory/reserve'],
    payloadExamples: [],
    nexusHunterAgent: 'business_logic_agent',
    cweId: 'CWE-362'
  },

  // ================ WEBSOCKET SECURITY ================
  {
    id: 'websocket_auth',
    name: 'WebSocket Authentication Bypass',
    category: VULNERABILITY_CATEGORIES.WEBSOCKET,
    description: 'WebSocket connections without proper authentication',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/ws/chat', '/ws/notifications'],
    payloadExamples: [],
    nexusHunterAgent: 'websocket_security_agent',
    cweId: 'CWE-287'
  },

  // ================ CRYPTOGRAPHIC ISSUES ================
  {
    id: 'weak_crypto',
    name: 'Weak Cryptographic Implementation',
    category: VULNERABILITY_CATEGORIES.CRYPTO,
    description: 'Weak encryption algorithms and implementations',
    severity: 'MEDIUM',
    enabled: true,
    endpoints: ['/api/auth/encrypt', '/api/data/secure'],
    payloadExamples: [],
    nexusHunterAgent: 'ssl_tls_agent',
    cweId: 'CWE-327'
  },

  // ================ INFORMATION DISCLOSURE ================
  {
    id: 'info_disclosure',
    name: 'Sensitive Information Disclosure',
    category: VULNERABILITY_CATEGORIES.SENSITIVE_DATA,
    description: 'Exposure of sensitive information',
    severity: 'MEDIUM',
    enabled: true,
    endpoints: ['/api/debug/info', '/api/system/status', '/api/config/show'],
    payloadExamples: [],
    nexusHunterAgent: 'secrets_agent',
    cweId: 'CWE-200',
    ovaspTop10: 'A02:2021'
  },

  // ================ AI/ML SECURITY ================
  {
    id: 'ai_model_extraction',
    name: 'AI Model Extraction',
    category: VULNERABILITY_CATEGORIES.COMPONENTS,
    description: 'AI/ML model extraction vulnerabilities',
    severity: 'MEDIUM',
    enabled: true,
    endpoints: ['/api/ai/predict', '/api/ml/model'],
    payloadExamples: [],
    nexusHunterAgent: 'ai_ml_security_agent',
    cweId: 'CWE-200'
  },

  // ================ SUPPLY CHAIN ================
  {
    id: 'supply_chain',
    name: 'Supply Chain Vulnerabilities',
    category: VULNERABILITY_CATEGORIES.COMPONENTS,
    description: 'Dependencies with known vulnerabilities',
    severity: 'HIGH',
    enabled: true,
    endpoints: ['/api/dependencies/check'],
    payloadExamples: [],
    nexusHunterAgent: 'supply_chain_security_agent',
    cweId: 'CWE-1104',
    ovaspTop10: 'A06:2021'
  }
];

export class VulnerabilityManager {
  private static instance: VulnerabilityManager;
  private vulnerabilities: Map<string, VulnerabilityConfig> = new Map();
  
  private constructor() {
    this.loadDefaultVulnerabilities();
  }
  
  public static getInstance(): VulnerabilityManager {
    if (!VulnerabilityManager.instance) {
      VulnerabilityManager.instance = new VulnerabilityManager();
    }
    return VulnerabilityManager.instance;
  }
  
  private loadDefaultVulnerabilities(): void {
    DEFAULT_VULNERABILITIES.forEach(vuln => {
      this.vulnerabilities.set(vuln.id, vuln);
    });
  }
  
  public isVulnerabilityEnabled(id: string): boolean {
    const vuln = this.vulnerabilities.get(id);
    return vuln ? vuln.enabled : false;
  }
  
  public toggleVulnerability(id: string): boolean {
    const vuln = this.vulnerabilities.get(id);
    if (vuln) {
      vuln.enabled = !vuln.enabled;
      return vuln.enabled;
    }
    return false;
  }
  
  public getVulnerability(id: string): VulnerabilityConfig | undefined {
    return this.vulnerabilities.get(id);
  }
  
  public getAllVulnerabilities(): VulnerabilityConfig[] {
    return Array.from(this.vulnerabilities.values());
  }
  
  public getVulnerabilitiesByCategory(category: string): VulnerabilityConfig[] {
    return Array.from(this.vulnerabilities.values())
      .filter(vuln => vuln.category === category);
  }
  
  public getEnabledVulnerabilities(): VulnerabilityConfig[] {
    return Array.from(this.vulnerabilities.values())
      .filter(vuln => vuln.enabled);
  }
}

export default VulnerabilityManager;

