/**
 * VulnCorp Enterprise Backend Server
 * ==================================
 * 
 * A comprehensive enterprise-level vulnerable application designed for 
 * security testing with Nexus Hunter. Contains 40+ vulnerability types
 * across multiple enterprise modules with toggle controls.
 * 
 * Enterprise Modules:
 * - HR Management System
 * - Financial Management 
 * - CRM (Customer Relationship Management)
 * - Inventory Management
 * - Document Management System
 * - API Gateway & Microservices
 * - Admin Panel & User Management
 * - Real-time Communication (WebSockets)
 * 
 * Security Features:
 * - Vulnerability Management Dashboard
 * - Toggle-based vulnerability controls
 * - Multiple authentication mechanisms
 * - Complex business logic workflows
 * - Multi-database architecture
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3002;

// Import vulnerability management system
const VulnerabilityManager = require('./config/vulnerabilities').VulnerabilityManager;
const vulnManager = VulnerabilityManager.getInstance();

// ================ DATABASE CONFIGURATION ================
const DATABASE_CONFIG = {
  mysql: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306'),
    user: process.env.DB_USER || 'root', 
    password: process.env.DB_PASSWORD || 'root',
    database: process.env.DB_NAME || 'vulncorp_enterprise',
    multipleStatements: true, // Intentionally vulnerable
    ssl: false // Intentionally insecure
  },
  mongodb: {
    url: process.env.MONGO_URL || 'mongodb://localhost:27017/vulncorp',
    options: {
      useNewUrlParser: false, // Intentionally vulnerable
      useUnifiedTopology: false // Intentionally vulnerable
    }
  },
  postgresql: {
    host: process.env.PG_HOST || 'localhost',
    port: parseInt(process.env.PG_PORT || '5432'),
    user: process.env.PG_USER || 'postgres',
    password: process.env.PG_PASSWORD || 'postgres',
    database: process.env.PG_DB || 'vulncorp_pg'
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD || undefined
  }
};

// ================ MIDDLEWARE SETUP ================
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key', 'X-Custom-Header']
}));

// Intentionally vulnerable security headers
app.use(helmet({
  contentSecurityPolicy: false, // Vulnerable to XSS
  hsts: false, // No HTTPS enforcement
  frameguard: false, // Clickjacking possible
  xssFilter: false, // XSS protection disabled
  noSniff: false // MIME sniffing enabled
}));

app.use(morgan('combined')); // Detailed logging for testing

// Handle raw text/XML for XXE testing on specific endpoint
app.use('/api/documents/parse', express.text({ type: '*/*', limit: '50mb' }));

app.use(express.json({ limit: '50mb' })); // Large payload limit
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.raw({ type: 'application/octet-stream', limit: '50mb' }));

// File upload configuration (intentionally vulnerable)
const storage = multer.diskStorage({
  destination: function (req: any, file: any, cb: any) {
    cb(null, './uploads/') // No path validation
  },
  filename: function (req: any, file: any, cb: any) {
    cb(null, file.originalname) // No filename sanitization
  }
});
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB limit
  }
  // No file type validation
});

// ================ VULNERABILITY MANAGEMENT API ================
app.get('/api/vulnerabilities', (req: any, res: any) => {
  const vulnerabilities = vulnManager.getAllVulnerabilities();
  res.json({
    success: true,
    total: vulnerabilities.length,
    enabled: vulnerabilities.filter(v => v.enabled).length,
    vulnerabilities: vulnerabilities
  });
});

app.get('/api/vulnerabilities/categories', (req: any, res: any) => {
  const vulnerabilities = vulnManager.getAllVulnerabilities();
  const categories: any = {};
  
  vulnerabilities.forEach(vuln => {
    if (!categories[vuln.category]) {
      categories[vuln.category] = {
        name: vuln.category,
        count: 0,
        enabled: 0,
        vulnerabilities: []
      };
    }
    categories[vuln.category].count++;
    if (vuln.enabled) categories[vuln.category].enabled++;
    categories[vuln.category].vulnerabilities.push(vuln);
  });
  
  res.json({
    success: true,
    categories: Object.values(categories)
  });
});

app.post('/api/vulnerabilities/:id/toggle', (req: any, res: any) => {
  const { id } = req.params;
  const newState = vulnManager.toggleVulnerability(id);
  const vulnerability = vulnManager.getVulnerability(id);
  
  if (!vulnerability) {
    return res.status(404).json({
      success: false,
      error: 'Vulnerability not found'
    });
  }
  
  res.json({
    success: true,
    vulnerability: {
      ...vulnerability,
      enabled: newState
    },
    message: `Vulnerability ${id} ${newState ? 'enabled' : 'disabled'}`
  });
});

// ================ SQL INJECTION VULNERABILITIES ================
app.get('/api/vulnerable/sql/search', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('sql_injection_basic')) {
    return res.status(200).json({ message: 'SQL Injection vulnerability is disabled' });
  }
  
  const { q } = req.query;
  
  // Intentionally vulnerable SQL query - Direct concatenation
  const query = `SELECT id, name, email, role FROM users WHERE name LIKE '%${q}%' OR email LIKE '%${q}%'`;
  
  console.log(`[VULNERABLE] Executing SQL Query: ${query}`);
  
  // Simulate database response
  res.json({
    success: true,
    query: query, // Exposing query for testing
    results: [
      { id: 1, name: 'John Admin', email: 'admin@vulncorp.com', role: 'administrator' },
      { id: 2, name: 'Jane User', email: 'jane@vulncorp.com', role: 'user' }
    ],
    vulnerability: 'sql_injection_basic',
    payloadDetected: q?.includes("'") || q?.includes('"') || q?.includes('--')
  });
});

app.post('/api/vulnerable/sql/login', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('sql_injection_basic')) {
    return res.status(401).json({ error: 'SQL Injection vulnerability is disabled' });
  }
  
  const { username, password } = req.body;
  
  // Intentionally vulnerable - Direct SQL injection
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  console.log(`[VULNERABLE] Login Query: ${query}`);
  
  // Simulate bypass conditions
  if (username?.includes("'") || username?.includes('--') || 
      password?.includes("'") || password?.includes('--')) {
    console.log('[VULNERABLE] SQL Injection detected - Bypass successful!');
    return res.json({
      success: true,
      user: { id: 1, username: 'admin', role: 'administrator' },
      token: 'vulnerable-jwt-token-12345',
      message: 'Authentication bypassed via SQL injection',
      vulnerability: 'sql_injection_basic'
    });
  }
  
  res.status(401).json({
    success: false,
    error: 'Invalid credentials'
  });
});

app.post('/api/vulnerable/sql/union', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('sql_injection_union')) {
    return res.status(200).json({ message: 'Union SQL Injection vulnerability is disabled' });
  }
  
  const { id } = req.body;
  
  // Vulnerable to Union-based SQL injection
  const query = `SELECT name, description, price FROM products WHERE id = ${id}`;
  
  console.log(`[VULNERABLE] Union SQL Query: ${query}`);
  
  res.json({
    success: true,
    query: query,
    data: [
      { name: 'Product A', description: 'Sample product', price: 99.99 }
    ],
    vulnerability: 'sql_injection_union',
    hint: "Try: 1 UNION SELECT username,password,email FROM users--"
  });
});

// ================ XSS VULNERABILITIES ================
app.get('/api/vulnerable/xss/search', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('xss_reflected')) {
    return res.status(200).json({ message: 'Reflected XSS vulnerability is disabled' });
  }
  
  const { q } = req.query;
  
  // Intentionally vulnerable - No input sanitization
  res.send(`
    <html>
    <head><title>Search Results</title></head>
    <body>
      <h1>Search Results for: ${q}</h1>
      <p>No results found for query: ${q}</p>
      <div id="results">
        <!-- Results would appear here -->
        Search term: ${q}
      </div>
      <script>
        console.log('Search executed for: ${q}');
      </script>
    </body>
    </html>
  `);
});

app.post('/api/vulnerable/xss/comment', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('xss_stored')) {
    return res.status(200).json({ message: 'Stored XSS vulnerability is disabled' });
  }
  
  const { author, comment } = req.body;
  
  // Store comment without sanitization (vulnerable to stored XSS)
  const commentData = {
    id: Date.now(),
    author: author,
    comment: comment, // No sanitization
    timestamp: new Date().toISOString()
  };
  
  console.log(`[VULNERABLE] Stored XSS Comment: ${JSON.stringify(commentData)}`);
  
  res.json({
    success: true,
    comment: commentData,
    vulnerability: 'xss_stored',
    html: `<div class="comment">
      <strong>${author}</strong>: ${comment}
      <small>${commentData.timestamp}</small>
    </div>`
  });
});

// ================ COMMAND INJECTION VULNERABILITIES ================
app.post('/api/vulnerable/rce/ping', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('command_injection')) {
    return res.status(200).json({ message: 'Command Injection vulnerability is disabled' });
  }
  
  const { host } = req.body;
  
  // Intentionally vulnerable - Direct command execution
  const command = `ping -c 1 ${host}`;
  
  console.log(`[VULNERABLE] Executing Command: ${command}`);
  
  // Simulate command injection detection
  if (host?.includes(';') || host?.includes('&&') || host?.includes('||') || 
      host?.includes('`') || host?.includes('$')) {
    console.log('[VULNERABLE] Command Injection detected!');
    
    res.json({
      success: true,
      command: command,
      output: `PING ${host} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.045 ms\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin`,
      vulnerability: 'command_injection',
      injectionDetected: true,
      message: 'Command injection successful - additional commands executed'
    });
  } else {
    res.json({
      success: true,
      command: command,
      output: `PING ${host} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.045 ms`,
      vulnerability: 'command_injection'
    });
  }
});

// ================ FILE UPLOAD VULNERABILITIES ================
app.post('/api/vulnerable/upload', upload.single('file'), async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('file_upload_unrestricted')) {
    return res.status(200).json({ message: 'File Upload vulnerability is disabled' });
  }
  
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  console.log(`[VULNERABLE] File uploaded: ${JSON.stringify(req.file)}`);
  
  // Intentionally vulnerable - No file type validation
  const dangerousExtensions = ['.php', '.jsp', '.asp', '.exe', '.sh', '.bat', '.py'];
  const fileExtension = path.extname(req.file.originalname).toLowerCase();
  
  res.json({
    success: true,
    file: {
      name: req.file.originalname,
      size: req.file.size,
      path: req.file.path,
      extension: fileExtension
    },
    vulnerability: 'file_upload_unrestricted',
    dangerousFile: dangerousExtensions.includes(fileExtension),
    message: dangerousExtensions.includes(fileExtension) ? 
      'WARNING: Potentially dangerous file uploaded!' : 'File uploaded successfully'
  });
});

// ================ LOCAL FILE INCLUSION ================
app.get('/api/vulnerable/files/view', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('lfi')) {
    return res.status(200).json({ message: 'LFI vulnerability is disabled' });
  }
  
  const { file } = req.query;
  
  if (!file) {
    return res.status(400).json({ error: 'File parameter required' });
  }
  
  console.log(`[VULNERABLE] Attempting to read file: ${file}`);
  
  try {
    // Intentionally vulnerable - No path validation
    const filePath = `./${file}`;
    const content = await fs.readFile(filePath, 'utf8');
    
    res.json({
      success: true,
      file: file,
      content: content,
      vulnerability: 'lfi',
      message: 'File read successfully'
    });
  } catch (error: any) {
    res.json({
      success: false,
      file: file,
      error: error.message,
      vulnerability: 'lfi',
      attempted: true
    });
  }
});

// ================ SSRF VULNERABILITIES ================
app.post('/api/vulnerable/ssrf/fetch', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('ssrf_basic')) {
    return res.status(200).json({ message: 'SSRF vulnerability is disabled' });
  }
  
  const { url } = req.body;
  
  console.log(`[VULNERABLE] SSRF attempt to: ${url}`);
  
  // Simulate SSRF vulnerability
  const internalUrls = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', '192.168.', '10.'];
  const isInternalUrl = internalUrls.some(internal => url?.includes(internal));
  
  if (isInternalUrl) {
    console.log('[VULNERABLE] SSRF to internal resource detected!');
    
    res.json({
      success: true,
      url: url,
      response: {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: 'Internal server response',
          metadata: { instance_id: 'i-1234567890abcdef0', region: 'us-east-1' },
          credentials: { access_key: 'AKIA...', secret_key: 'wJalrXUt...' }
        })
      },
      vulnerability: 'ssrf_basic',
      internalAccess: true,
      message: 'SSRF successful - internal resource accessed'
    });
  } else {
    res.json({
      success: true,
      url: url,
      response: { status: 200, body: 'External resource response' },
      vulnerability: 'ssrf_basic'
    });
  }
});

// ================ BUSINESS LOGIC VULNERABILITIES ================
app.post('/api/vulnerable/business/purchase', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('price_manipulation')) {
    return res.status(200).json({ message: 'Price Manipulation vulnerability is disabled' });
  }
  
  const { productId, quantity, price } = req.body;
  
  // Intentionally vulnerable - Trust client-side price
  const totalAmount = price * quantity;
  
  console.log(`[VULNERABLE] Purchase attempt - Product: ${productId}, Quantity: ${quantity}, Price: ${price}, Total: ${totalAmount}`);
  
  if (price < 0 || totalAmount < 0) {
    console.log('[VULNERABLE] Negative price manipulation detected!');
    
    return res.json({
      success: true,
      order: {
        id: `ORDER-${Date.now()}`,
        productId,
        quantity,
        price,
        total: totalAmount,
        status: 'completed'
      },
      vulnerability: 'price_manipulation',
      manipulation: true,
      message: 'Order processed with negative amount - business logic bypassed!'
    });
  }
  
  res.json({
    success: true,
    order: {
      id: `ORDER-${Date.now()}`,
      productId,
      quantity,
      price,
      total: totalAmount,
      status: 'completed'
    },
    vulnerability: 'price_manipulation'
  });
});

// ================ XXE VULNERABILITIES ================
app.post('/api/vulnerable/xml/parse', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('xxe_basic')) {
    return res.status(200).json({ message: 'XXE vulnerability is disabled' });
  }
  
  const xmlData = req.body;
  
  console.log(`[VULNERABLE] XML Parsing: ${JSON.stringify(xmlData)}`);
  
  // Simulate XXE vulnerability detection
  if (typeof xmlData === 'string' && 
      (xmlData.includes('<!ENTITY') || xmlData.includes('SYSTEM') || xmlData.includes('file://'))) {
    console.log('[VULNERABLE] XXE attack detected!');
    
    res.json({
      success: true,
      xml: xmlData,
      parsed: {
        message: 'XML parsed successfully',
        extractedData: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin'
      },
      vulnerability: 'xxe_basic',
      xxeDetected: true,
      message: 'XXE exploitation successful - file content extracted'
    });
  }
  
  res.json({
    success: true,
    xml: xmlData,
    parsed: { message: 'XML parsed normally' },
    vulnerability: 'xxe_basic'
  });
});

// ================ JWT VULNERABILITIES ================
app.post('/api/vulnerable/jwt/verify', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('jwt_vulnerabilities')) {
    return res.status(401).json({ error: 'JWT vulnerability is disabled' });
  }
  
  const { token } = req.body;
  
  console.log(`[VULNERABLE] JWT Verification: ${token}`);
  
  try {
    // Intentionally vulnerable - No signature verification
    const decoded = jwt.decode(token);
    
    if (decoded) {
      console.log('[VULNERABLE] JWT bypassed - no signature verification!');
      
      res.json({
        success: true,
        decoded: decoded,
        vulnerability: 'jwt_vulnerabilities',
        bypassed: true,
        message: 'JWT accepted without signature verification'
      });
    } else {
      res.status(401).json({ error: 'Invalid token format' });
    }
  } catch (error: any) {
    res.status(401).json({ 
      error: error.message,
      vulnerability: 'jwt_vulnerabilities' 
    });
  }
});

// ================ HEALTH & STATUS ENDPOINTS ================
app.get('/api/health', (req: any, res: any) => {
  const enabledVulns = vulnManager.getEnabledVulnerabilities();
  
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '2.0.0-enterprise',
    environment: process.env.NODE_ENV || 'development',
    vulnerabilities: {
      total: vulnManager.getAllVulnerabilities().length,
      enabled: enabledVulns.length,
      categories: [...new Set(enabledVulns.map(v => v.category))].length
    },
    modules: {
      hr: 'active',
      finance: 'active', 
      crm: 'active',
      inventory: 'active',
      documents: 'active',
      admin: 'active'
    },
    databases: DATABASE_CONFIG,
    system: {
      platform: process.platform,
      nodeVersion: process.version,
      memory: process.memoryUsage()
    }
  });
});

app.get('/api/system/info', (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('info_disclosure')) {
    return res.status(200).json({ message: 'Information Disclosure vulnerability is disabled' });
  }
  
  // Intentionally vulnerable - Exposing sensitive system information
  res.json({
    success: true,
    system: {
      hostname: require('os').hostname(),
      platform: process.platform,
      architecture: process.arch,
      nodeVersion: process.version,
      pid: process.pid,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      environment: process.env,
      loadAverage: require('os').loadavg(),
      networkInterfaces: require('os').networkInterfaces(),
      users: [
        { username: 'admin', role: 'administrator', password: 'admin123' },
        { username: 'dbuser', role: 'database', password: 'db_pass_2023' }
      ]
    },
    vulnerability: 'info_disclosure',
    message: 'Sensitive system information exposed'
  });
});

// ================ ENTERPRISE MODULE ENDPOINTS ================

// HR Management Module
app.get('/api/hr/employees/search', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('sql_injection_basic')) {
    return res.status(200).json({ message: 'HR SQL Injection vulnerability is disabled' });
  }
  
  const { q } = req.query;
  const query = `SELECT id, name, position, salary FROM employees WHERE name LIKE '%${q}%'`;
  
  console.log(`[VULNERABLE] HR Employee Search: ${query}`);
  
  res.json({
    success: true,
    query: query,
    employees: [
      { id: 1, name: 'John Manager', position: 'HR Manager', salary: 75000 },
      { id: 2, name: 'Jane Smith', position: 'Recruiter', salary: 55000 }
    ],
    vulnerability: 'sql_injection_basic'
  });
});

app.post('/api/hr/payroll/details', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('lfi')) {
    return res.status(200).json({ message: 'HR LFI vulnerability is disabled' });
  }
  
  const { employeeId } = req.body;
  
  console.log(`[VULNERABLE] HR Payroll LFI attempt: ${employeeId}`);
  
  if (employeeId?.includes('../')) {
    console.log('[VULNERABLE] LFI detected in HR payroll!');
    
    res.json({
      success: true,
      employeeId: employeeId,
      payrollData: 'root:x:0:0:root:/root:/bin/bash\\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash',
      vulnerability: 'lfi',
      lfiDetected: true,
      message: 'LFI successful - system files accessed'
    });
  } else {
    res.json({
      success: true,
      employeeId: employeeId,
      payrollData: { salary: 65000, bonuses: 5000, taxes: 15000 }
    });
  }
});

app.post('/api/hr/notes', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('xss_stored')) {
    return res.status(200).json({ message: 'HR XSS vulnerability is disabled' });
  }
  
  const { note } = req.body;
  
  console.log(`[VULNERABLE] HR Notes XSS: ${note}`);
  
  res.json({
    success: true,
    note: note,
    html: `<div class="hr-note">${note}</div>`,
    vulnerability: 'xss_stored',
    timestamp: new Date().toISOString()
  });
});

// Finance Module
app.post('/api/finance/transfer', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('price_manipulation')) {
    return res.status(200).json({ message: 'Finance Price Manipulation vulnerability is disabled' });
  }
  
  const { amount, account } = req.body;
  
  console.log(`[VULNERABLE] Finance Transfer: ${amount} to ${account}`);
  
  if (amount < 0) {
    console.log('[VULNERABLE] Negative amount transfer detected!');
    
    res.json({
      success: true,
      transfer: { amount, account, fee: amount * 0.02 },
      vulnerability: 'price_manipulation',
      manipulation: true,
      message: 'Negative transfer processed - business logic bypassed!'
    });
  } else {
    res.json({
      success: true,
      transfer: { amount, account, fee: amount * 0.02 }
    });
  }
});

app.get('/api/finance/statements', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('lfi')) {
    return res.status(200).json({ message: 'Finance LFI vulnerability is disabled' });
  }
  
  const { file } = req.query;
  
  console.log(`[VULNERABLE] Finance Statements LFI: ${file}`);
  
  if (file?.includes('../')) {
    res.json({
      success: true,
      file: file,
      content: 'Database credentials: db_user:finance_pass_2023\\nAPI Keys: fin_api_key_xyz789',
      vulnerability: 'lfi'
    });
  } else {
    res.json({
      success: true,
      statements: [
        { date: '2023-09-01', balance: 125000, transactions: 45 },
        { date: '2023-09-02', balance: 127500, transactions: 32 }
      ]
    });
  }
});

app.post('/api/finance/reports', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('template_injection')) {
    return res.status(200).json({ message: 'Template Injection vulnerability is disabled' });
  }
  
  const { template } = req.body;
  
  console.log(`[VULNERABLE] Finance Reports Template Injection: ${template}`);
  
  if (template?.includes('{{') || template?.includes('${')) {
    console.log('[VULNERABLE] Template injection detected!');
    
    res.json({
      success: true,
      template: template,
      rendered: '49', // 7*7
      vulnerability: 'template_injection',
      injectionDetected: true,
      message: 'Template injection successful - code executed'
    });
  } else {
    res.json({
      success: true,
      template: template,
      rendered: 'Financial Report Generated'
    });
  }
});

// CRM Module
app.post('/api/crm/customers/search', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('nosql_injection')) {
    return res.status(200).json({ message: 'NoSQL Injection vulnerability is disabled' });
  }
  
  const searchQuery = req.body;
  
  console.log(`[VULNERABLE] CRM NoSQL Search: ${JSON.stringify(searchQuery)}`);
  
  if (searchQuery['$ne'] || searchQuery['$regex'] || searchQuery['$where']) {
    console.log('[VULNERABLE] NoSQL injection detected!');
    
    res.json({
      success: true,
      query: searchQuery,
      customers: [
        { id: 1, name: 'Secret Customer', email: 'admin@internal.com', ssn: '123-45-6789' },
        { id: 2, name: 'VIP Client', email: 'ceo@competitor.com', ssn: '987-65-4321' }
      ],
      vulnerability: 'nosql_injection',
      injectionDetected: true,
      message: 'NoSQL injection successful - sensitive data exposed'
    });
  } else {
    res.json({
      success: true,
      customers: [
        { id: 1, name: 'John Customer', email: 'john@example.com' }
      ]
    });
  }
});

app.post('/api/crm/feedback', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('xss_stored')) {
    return res.status(200).json({ message: 'CRM XSS vulnerability is disabled' });
  }
  
  const { comment } = req.body;
  
  console.log(`[VULNERABLE] CRM Feedback XSS: ${comment}`);
  
  res.json({
    success: true,
    feedback: {
      id: Date.now(),
      comment: comment,
      html: `<div class="feedback">${comment}</div>`,
      timestamp: new Date().toISOString()
    },
    vulnerability: 'xss_stored'
  });
});

app.get('/api/crm/export', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('ssrf_basic')) {
    return res.status(200).json({ message: 'CRM SSRF vulnerability is disabled' });
  }
  
  const { customers, format, callback } = req.query;
  
  console.log(`[VULNERABLE] CRM Export SSRF: ${callback}`);
  
  if (callback && (callback.includes('http://') || callback.includes('https://'))) {
    console.log('[VULNERABLE] SSRF detected in CRM export!');
    res.json({
      success: true,
      export: {
        customers: customers,
        format: format,
        callback: callback,
        data: 'Customer data exported',
        callbackResponse: 'Internal server response: 192.168.1.100:3306'
      },
      vulnerability: 'ssrf_basic',
      ssrfDetected: true,
      message: 'SSRF successful - internal network accessed'
    });
  } else {
    res.json({
      success: true,
      export: {
        customers: customers,
        format: format,
        data: 'Standard customer export'
      }
    });
  }
});

// Inventory Module
app.post('/api/inventory/search', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('nosql_injection')) {
    return res.status(200).json({ message: 'Inventory NoSQL vulnerability is disabled' });
  }
  
  const searchQuery = req.body;
  
  console.log(`[VULNERABLE] Inventory MongoDB Search: ${JSON.stringify(searchQuery)}`);
  
  if (searchQuery['$where'] || searchQuery['$regex']) {
    res.json({
      success: true,
      products: [
        { id: 1, name: 'Hidden Product', price: -999, cost: 10 },
        { id: 2, name: 'Free Item', price: 0, cost: 500 }
      ],
      vulnerability: 'nosql_injection'
    });
  } else {
    res.json({
      success: true,
      products: [
        { id: 1, name: 'Widget A', price: 29.99, stock: 100 }
      ]
    });
  }
});

app.post('/api/inventory/update', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('race_conditions')) {
    return res.status(200).json({ message: 'Inventory Race Condition vulnerability is disabled' });
  }
  
  const { productId, quantity } = req.body;
  
  console.log(`[VULNERABLE] Inventory Update: Product ${productId}, Quantity ${quantity}`);
  
  if (quantity < -999999) {
    console.log('[VULNERABLE] Negative inventory manipulation detected!');
    
    res.json({
      success: true,
      update: { productId, quantity, newStock: quantity },
      vulnerability: 'race_conditions',
      manipulation: true,
      message: 'Negative inventory allowed - business logic bypassed'
    });
  } else {
    res.json({
      success: true,
      update: { productId, quantity, newStock: Math.max(0, 100 + quantity) }
    });
  }
});

app.get('/api/inventory/export', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('path_traversal')) {
    return res.status(200).json({ message: 'Inventory Path Traversal vulnerability is disabled' });
  }
  
  const { format, file } = req.query;
  
  console.log(`[VULNERABLE] Inventory Export: ${format}, File: ${file}`);
  
  if (file?.includes('../') || file?.includes('..\\')) {
    console.log('[VULNERABLE] Path traversal detected in inventory export!');
    res.json({
      success: true,
      format: format,
      file: file,
      data: 'Sensitive inventory data: secret_supplier_list.txt\\nAdmin credentials: inv_admin:secret123',
      vulnerability: 'path_traversal',
      traversalDetected: true,
      message: 'Path traversal successful - sensitive files accessed'
    });
  } else {
    res.json({
      success: true,
      format: format,
      data: 'Standard inventory export data'
    });
  }
});

// Documents Module  
app.post('/api/documents/upload', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('file_upload_unrestricted')) {
    return res.status(200).json({ message: 'Document Upload vulnerability is disabled' });
  }
  
  const { filename } = req.body;
  
  console.log(`[VULNERABLE] Document Upload: ${filename}`);
  
  if (filename?.includes('../') || filename?.endsWith('.exe') || filename?.endsWith('.php')) {
    console.log('[VULNERABLE] Dangerous file upload detected!');
    
    res.json({
      success: true,
      filename: filename,
      path: `/uploads/${filename}`,
      vulnerability: 'file_upload_unrestricted',
      dangerous: true,
      message: 'Dangerous file uploaded successfully!'
    });
  } else {
    res.json({
      success: true,
      filename: filename,
      path: `/uploads/${filename}`
    });
  }
});

app.get('/api/documents/view', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('lfi')) {
    return res.status(200).json({ message: 'Document LFI vulnerability is disabled' });
  }
  
  const { file } = req.query;
  
  console.log(`[VULNERABLE] Document View LFI: ${file}`);
  
  if (file?.includes('../')) {
    res.json({
      success: true,
      file: file,
      content: 'Database Config:\\nhost=localhost\\nuser=doc_admin\\npass=docs_secret_2023',
      vulnerability: 'lfi'
    });
  } else {
    res.json({
      success: true,
      content: 'Regular document content'
    });
  }
});

app.post('/api/documents/parse', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('xxe_basic')) {
    return res.status(200).json({ message: 'Documents XXE vulnerability is disabled' });
  }
  
  const xmlData = req.body;
  
  console.log(`[VULNERABLE] Document XML Parse XXE: ${JSON.stringify(xmlData).substring(0, 100)}...`);
  
  if (typeof xmlData === 'string' && xmlData.includes('<!ENTITY')) {
    console.log('[VULNERABLE] XXE detected in document parser!');
    res.json({
      success: true,
      xmlData: xmlData,
      parsed: {
        entities: 'root:x:0:0:root:/root:/bin/bash\\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash',
        files: '/etc/passwd content exposed'
      },
      vulnerability: 'xxe_basic',
      xxeDetected: true,
      message: 'XXE successful - external entities processed'
    });
  } else {
    res.json({
      success: true,
      xmlData: xmlData,
      parsed: 'Standard XML document parsed successfully'
    });
  }
});

// Admin Panel
app.post('/api/admin/users', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('auth_bypass')) {
    return res.status(200).json({ message: 'Admin Privilege Escalation vulnerability is disabled' });
  }
  
  const { username, password, role } = req.body;
  
  console.log(`[VULNERABLE] Admin User Creation: ${username} with role ${role}`);
  
  if (role === 'superadmin' || role === 'admin') {
    console.log('[VULNERABLE] Privilege escalation detected!');
    
    res.json({
      success: true,
      user: { id: Date.now(), username, role },
      vulnerability: 'auth_bypass',
      escalation: true,
      message: 'Superadmin user created - privilege escalation successful!'
    });
  } else {
    res.json({
      success: true,
      user: { id: Date.now(), username, role: 'user' }
    });
  }
});

app.post('/api/admin/execute', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('command_injection')) {
    return res.status(200).json({ message: 'Admin Command Injection vulnerability is disabled' });
  }
  
  const { command } = req.body;
  
  console.log(`[VULNERABLE] Admin Command Execution: ${command}`);
  
  res.json({
    success: true,
    command: command,
    output: 'root:x:0:0:root:/root:/bin/bash\\nadmin\\nuid=0(root) gid=0(root) groups=0(root)',
    vulnerability: 'command_injection',
    executed: true,
    message: 'Command executed with admin privileges'
  });
});

app.get('/api/admin/backup', async (req: any, res: any) => {
  if (!vulnManager.isVulnerabilityEnabled('path_traversal')) {
    return res.status(200).json({ message: 'Admin Path Traversal vulnerability is disabled' });
  }
  
  const { path } = req.query;
  
  console.log(`[VULNERABLE] Admin Backup Path Traversal: ${path}`);
  
  if (path?.includes('../') || path?.includes('..\\')) {
    console.log('[VULNERABLE] Path traversal detected in admin backup!');
    res.json({
      success: true,
      path: path,
      files: [
        '/etc/passwd',
        '/etc/shadow',
        '/var/log/auth.log',
        '/root/.ssh/id_rsa'
      ],
      vulnerability: 'path_traversal',
      traversalDetected: true,
      message: 'Admin path traversal successful - system files accessed'
    });
  } else {
    res.json({
      success: true,
      path: path,
      files: ['backup1.zip', 'backup2.zip'],
      message: 'Standard backup files listed'
    });
  }
});

// ================ ERROR HANDLING & STARTUP ================
app.use((err: any, req: any, res: any, next: any) => {
  console.error('Error:', err);
  
  // Intentionally verbose error messages for testing
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    request: {
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: req.body
    }
  });
});

// Start the server
app.listen(PORT, () => {
  const totalVulns = vulnManager.getAllVulnerabilities().length;
  const enabledVulns = vulnManager.getEnabledVulnerabilities().length;
  
  console.log(`
🏢 ===============================================
   VulnCorp Enterprise Backend Server v2.0.0
🏢 ===============================================

🚀 Server Status: RUNNING
📍 URL: http://localhost:${PORT}
🌐 Health Check: http://localhost:${PORT}/api/health

⚠️  WARNING: INTENTIONALLY VULNERABLE APPLICATION!
    FOR SECURITY TESTING PURPOSES ONLY

🎯 Vulnerability Management:
   📊 Total Vulnerabilities: ${totalVulns}
   ✅ Currently Enabled: ${enabledVulns}
   🎛️  Management: http://localhost:${PORT}/api/vulnerabilities

🏗️  Enterprise Modules Available:
   👥 HR Management System
   💰 Financial Management
   🤝 CRM (Customer Relations)
   📦 Inventory Management  
   📄 Document Management
   🔐 Admin Panel & User Management
   🌐 API Gateway & Microservices
   💬 Real-time Communication

🔧 Testing Endpoints:
   🎯 Vulnerability Toggle: POST /api/vulnerabilities/:id/toggle
   📋 List All Vulnerabilities: GET /api/vulnerabilities
   🏥 Health Status: GET /api/health
   ℹ️  System Information: GET /api/system/info

🧪 Active Vulnerability Categories:`);

  vulnManager.getEnabledVulnerabilities().forEach((vuln: any) => {
    console.log(`   ✅ ${vuln.name} (${vuln.severity})`);
  });

  console.log(`
🎯 Ready for Nexus Hunter Security Testing!
===============================================
  `);
});

module.exports = app;