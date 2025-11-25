# 🏢 VulnCorp Enterprise - Comprehensive Vulnerable Application

**The Ultimate Enterprise-Grade Vulnerable Application for Security Testing**

*Built specifically for testing Nexus Hunter's 42+ security agents and capabilities*

---

## 🎯 **PURPOSE**

VulnCorp Enterprise is a fully-featured, enterprise-level vulnerable web application designed to comprehensively test every aspect of modern security scanning tools. It contains **EVERY** type of vulnerability that can exist in real-world enterprise applications.

## 🏗️ **ENTERPRISE ARCHITECTURE**

### **Technology Stack**
- **Frontend**: React 18 + TypeScript + Tailwind CSS
- **Backend API**: Node.js + Express + TypeScript  
- **Real-time**: WebSocket + Socket.IO
- **Database**: MySQL 8.0 with realistic enterprise data
- **Authentication**: JWT + Session-based + OAuth2
- **File Storage**: Local + Cloud simulation
- **Microservices**: Multiple service layers

### **Application Modules**
1. **👤 User Management** - Authentication, profiles, roles
2. **💼 Human Resources** - Employee data, payroll, benefits
3. **💰 Finance** - Accounting, invoices, payments, banking
4. **🛒 E-Commerce** - Products, orders, inventory, shipping
5. **📊 CRM** - Customer data, leads, sales pipeline  
6. **📈 Analytics** - Reports, dashboards, data visualization
7. **⚙️ Admin Panel** - System configuration, user management
8. **📱 API Gateway** - REST/GraphQL APIs, microservices
9. **💬 Communication** - Chat, notifications, messaging
10. **📁 Document Management** - File upload, sharing, collaboration

---

## 🚨 **VULNERABILITY COVERAGE (42+ Types)**

### **📊 INJECTION ATTACKS**
| Vulnerability | Implementation | Agent Coverage |
|---------------|---------------|----------------|
| **SQL Injection** | Union, Error-based, Blind, Time-based across all endpoints | SQLInjectionAgent, SQLMapAgent |
| **NoSQL Injection** | MongoDB, Redis injection in search/filters | NoSQLInjectionAgent |
| **Command Injection** | OS command execution with bypass techniques | EnhancedCommandInjectionAgent, RCEAgent |
| **LDAP Injection** | Directory service query manipulation | LDAPInjectionAgent |
| **Template Injection** | Jinja2, Handlebars, Twig server-side injection | TemplateInjectionAgent |
| **XXE Injection** | XML external entity processing | XXEAgent |

### **🔐 AUTHENTICATION & SESSION**
| Vulnerability | Implementation | Agent Coverage |
|---------------|---------------|----------------|
| **JWT Vulnerabilities** | Weak secrets, algorithm confusion, claims manipulation | JWTSecurityAgent |
| **Session Management** | Fixation, hijacking, weak tokens | AuthenticationAgent |
| **OAuth2 Flaws** | Authorization code interception, PKCE bypass | OAuth2Agent |
| **Password Reset** | Token leakage, brute force, enumeration | BusinessLogicAgent |
| **Multi-Factor Bypass** | 2FA bypass, backup code abuse | AuthenticationAgent |

### **💻 WEB APPLICATION**
| Vulnerability | Implementation | Agent Coverage |
|---------------|---------------|----------------|
| **Cross-Site Scripting** | Reflected, Stored, DOM-based, CSP bypass | XSSAgent, AdvancedXSSAgent |
| **CSRF** | State changing operations without tokens | CSRFAgent |
| **SSRF** | Internal network access, cloud metadata | SSRFAgent |
| **LFI/RFI** | Local/remote file inclusion, path traversal | LFIAgent |
| **File Upload** | PHP/ASP webshells, unrestricted uploads | FileUploadAgent |
| **Deserialization** | Unsafe object deserialization | DeserializationAgent |

### **📱 MODERN WEB & APIs**
| Vulnerability | Implementation | Agent Coverage |
|---------------|---------------|----------------|
| **API Security** | Mass assignment, rate limit bypass, BOLA/BFLA | APISecurityAgent |
| **GraphQL** | Introspection, query complexity, injection | GraphQLSecurityAgent |
| **WebSocket** | Message injection, authentication bypass | WebSocketSecurityAgent |
| **CORS** | Misconfigured cross-origin policies | CORSSecurityAgent |
| **Content Security Policy** | CSP bypass techniques | CSPBypassAgent |

### **🏢 BUSINESS LOGIC**
| Vulnerability | Implementation | Agent Coverage |
|---------------|---------------|----------------|
| **Price Manipulation** | Negative prices, currency manipulation | BusinessLogicAgent |
| **Workflow Bypass** | Multi-step process bypass | BusinessLogicAgent |
| **Race Conditions** | Concurrent request exploitation | RaceConditionAgent |
| **Privilege Escalation** | Horizontal/vertical privilege bypass | PrivilegeEscalationAgent |
| **Order Manipulation** | Quantity limits, discount abuse | EcommerceSecurityAgent |

### **🔧 INFRASTRUCTURE**
| Vulnerability | Implementation | Agent Coverage |
|---------------|---------------|----------------|
| **SSL/TLS Issues** | Weak ciphers, certificate validation | SSLTLSAgent |
| **Secrets Exposure** | Hardcoded keys, environment leaks | SecretsAgent |
| **Supply Chain** | Vulnerable dependencies, SCA issues | SupplyChainSecurityAgent |
| **AI/ML Security** | Model manipulation, prompt injection | AIMLSecurityAgent |
| **Container Security** | Docker misconfigurations | ContainerSecurityAgent |

---

## 🗄️ **DATABASE SCHEMA**

### **Realistic Enterprise Data**
- **10,000+ Users** across different roles and departments
- **50,000+ Products** with inventory, pricing, categories
- **25,000+ Orders** with payment, shipping, status tracking
- **15,000+ Employees** with HR data, payroll, benefits
- **100,000+ Financial Records** - invoices, payments, transactions
- **75,000+ Customer Records** - CRM data, interactions, leads
- **200,000+ Log Entries** - audit trails, system events

### **Vulnerable Database Design**
```sql
-- Intentionally vulnerable tables for testing
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(100), -- MD5 hashed passwords
    email VARCHAR(100),
    role VARCHAR(20),
    api_key VARCHAR(100), -- Exposed in responses
    reset_token VARCHAR(100) -- Predictable tokens
);

-- SQL injection playground
CREATE TABLE products (
    id INT PRIMARY KEY,
    name VARCHAR(200),
    price DECIMAL(10,2),
    description TEXT,
    category_id INT
);

-- NoSQL equivalent collections for MongoDB testing
```

---

## 🚀 **GETTING STARTED**

### **Prerequisites**
- Node.js 18+
- MySQL 8.0
- Docker (optional)
- Git

### **Quick Setup**
```bash
# Clone and setup
cd nexus-hunter/enterprise-vuln-app
npm install

# Setup database
npm run setup:database

# Populate demo data
npm run seed:data

# Start all services
npm run dev:all
```

### **Access Points**
- **Frontend**: http://localhost:3000
- **API**: http://localhost:3001
- **GraphQL**: http://localhost:3001/graphql
- **WebSocket**: ws://localhost:3002
- **Admin Panel**: http://localhost:3000/admin

---

## 🎯 **TESTING WITH NEXUS HUNTER**

### **Perfect Integration**
This application is specifically designed to work with all 42+ Nexus Hunter agents:

```bash
# Test individual vulnerability types
nexus-hunter scan --type sql_injection --target http://localhost:3000
nexus-hunter scan --type xss --target http://localhost:3000
nexus-hunter scan --type business_logic --target http://localhost:3000

# Full enterprise audit
nexus-hunter scan --type full --target http://localhost:3000

# Category testing
nexus-hunter scan --type vuln_category --target http://localhost:3000
nexus-hunter scan --type exploit_category --target http://localhost:3000
```

### **Expected Results**
- **200+ Unique Vulnerabilities** across all categories
- **Critical, High, Medium, Low** severity findings
- **100% Agent Coverage** - every Nexus Hunter agent will find issues
- **Realistic Enterprise Context** - proper business logic testing

---

## ⚠️ **SECURITY NOTICE**

**🚨 FOR TESTING ONLY - DO NOT DEPLOY IN PRODUCTION**

This application contains **intentional security vulnerabilities** for educational and testing purposes. It should only be used in isolated, controlled environments for:

- Security tool testing
- Penetration testing training
- Vulnerability research
- Security awareness training

---

## 📋 **VULNERABILITY CHECKLIST**

### **Implementation Status**
- [ ] **SQL Injection** - All types across all endpoints
- [ ] **XSS** - Reflected, Stored, DOM-based with CSP bypass
- [ ] **Command Injection** - OS-specific with WAF bypass
- [ ] **Authentication** - JWT, Session, OAuth2 vulnerabilities  
- [ ] **File Upload** - Webshell upload in multiple languages
- [ ] **Business Logic** - Price manipulation, workflow bypass
- [ ] **API Security** - REST/GraphQL vulnerabilities
- [ ] **WebSocket** - Real-time communication flaws
- [ ] **Infrastructure** - SSL/TLS, secrets, supply chain
- [ ] **Modern Attacks** - AI/ML, container, cloud vulnerabilities

---

## 🤝 **CONTRIBUTING**

This is part of the Nexus Hunter project. Contributions should focus on:
1. **Adding new vulnerability types** as new agents are developed
2. **Improving realism** of enterprise scenarios
3. **Expanding demo data** for better testing coverage
4. **Performance optimization** for large-scale testing

---

**Built with ❤️ by the Nexus Hunter Security Team**
*"The most comprehensive vulnerable enterprise application ever created"*

