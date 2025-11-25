# 🚀 VulnCorp Enterprise - Quick Start Guide

**Get your vulnerable enterprise application running in 5 minutes!**

---

## ⚡ **INSTANT SETUP**

### **One-Command Setup**
```bash
cd enterprise-vuln-app
./setup.sh
```

That's it! The setup script will:
- ✅ Check all prerequisites  
- ✅ Install dependencies
- ✅ Configure databases
- ✅ Initialize demo data
- ✅ Start all services

### **Manual Setup (if needed)**
```bash
# 1. Install dependencies
npm run setup:deps

# 2. Start database services
docker-compose up -d

# 3. Initialize databases
npm run setup:database
npm run seed:data

# 4. Start the application
npm run dev
```

---

## 🎯 **IMMEDIATE TESTING**

### **Verify Installation**
```bash
curl http://localhost:3001/api/health
# Should return system information (with intentional info disclosure)
```

### **Test Major Vulnerabilities**

**SQL Injection:**
```bash
curl "http://localhost:3001/api/vulnerable/sql/search?q=test' UNION SELECT 1,version(),user(),4 --"
```

**XSS:**
```bash
curl "http://localhost:3001/api/vulnerable/xss/search?q=<script>alert('XSS')</script>"
```

**Command Injection:**
```bash
curl -X POST http://localhost:3001/api/vulnerable/rce/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1; whoami"}'
```

---

## 🌐 **ACCESS POINTS**

| Service | URL | Purpose |
|---------|-----|---------|
| **Main API** | http://localhost:3001 | Primary application backend |
| **Vulnerability Lab** | http://localhost:3001/api/vulnerable/* | All vulnerability endpoints |
| **Admin Panel** | http://localhost:3001/api/admin/* | Administrative functions |
| **WebSocket** | ws://localhost:3002 | Real-time communication |
| **Health Check** | http://localhost:3001/api/health | System status (with info disclosure) |

---

## 🎪 **VULNERABILITY PLAYGROUND**

### **Interactive Testing**
```bash
# XSS Playground
curl http://localhost:3001/api/vulnerable/xss/playground

# SQL Injection Testing
curl http://localhost:3001/api/vulnerable/sql/playground

# Command Injection Lab  
curl http://localhost:3001/api/vulnerable/rce/playground
```

---

## 🔧 **NEXUS HUNTER INTEGRATION**

### **Ready-to-Scan Targets**
```bash
# Full enterprise security audit
nexus-hunter scan --type full --target http://localhost:3001

# Quick vulnerability assessment
nexus-hunter scan --type vulnerability --target http://localhost:3001

# Specific vulnerability testing
nexus-hunter scan --agent sql_injection --target http://localhost:3001/api/vulnerable/sql
nexus-hunter scan --agent xss --target http://localhost:3001/api/vulnerable/xss
nexus-hunter scan --agent rce --target http://localhost:3001/api/vulnerable/rce
```

### **Expected Results**
- **200+ Vulnerabilities** across all categories
- **42+ Agent Types** will find issues
- **Critical to Low** severity findings
- **100% Agent Success** rate

---

## 📊 **MONITORING & LOGS**

### **Real-time Monitoring**
```bash
# Watch application logs
tail -f logs/combined.log

# Watch security events
tail -f logs/security.log

# Watch error logs  
tail -f logs/error.log
```

### **Database Activity**
```bash
# MySQL query logs
docker exec vulncorp-mysql tail -f /var/log/mysql/general.log

# Redis monitoring
docker exec vulncorp-redis redis-cli monitor
```

---

## 🛠️ **TROUBLESHOOTING**

### **Common Issues**

**Port Already in Use:**
```bash
# Kill processes on required ports
sudo lsof -ti:3001 | xargs kill -9
sudo lsof -ti:3002 | xargs kill -9
sudo lsof -ti:3306 | xargs kill -9
```

**Database Connection Failed:**
```bash
# Restart database services
docker-compose down
docker-compose up -d
sleep 30  # Wait for databases to start
```

**Permission Errors:**
```bash
# Fix file permissions
chmod +x setup.sh
chmod 755 uploads/
chmod 755 logs/
```

---

## ⚠️ **SECURITY WARNINGS**

### **🔒 ISOLATION REQUIREMENTS**
- ❌ **NEVER use in production**
- ❌ **NEVER expose to public networks**  
- ❌ **NEVER deploy on shared servers**
- ✅ **Only use in isolated test environments**
- ✅ **Use for security research only**
- ✅ **Perfect for Nexus Hunter testing**

### **🧱 NETWORK ISOLATION**
```bash
# Recommended: Use isolated network
docker network create vulncorp-isolated
docker-compose up -d  # Uses isolated network by default
```

---

## 📋 **QUICK REFERENCE**

### **Service Commands**
```bash
npm run dev          # Start all services
npm run dev:backend  # Backend only
npm run stop         # Stop all services
npm run clean        # Clean and reset
npm run logs         # View logs
```

### **Database Commands**
```bash
npm run db:reset     # Reset databases
npm run db:seed      # Reseed demo data
npm run db:backup    # Backup data
npm run db:restore   # Restore data
```

### **Testing Commands**  
```bash
npm run test         # Run test suite
npm run test:vulns   # Test vulnerabilities
npm run test:agents  # Test agent endpoints
```

---

## 🎉 **YOU'RE READY!**

VulnCorp Enterprise is now running and ready for comprehensive security testing with Nexus Hunter!

**Next Steps:**
1. 🔍 **Explore** the vulnerability endpoints
2. 🧪 **Test** with Nexus Hunter agents  
3. 📊 **Analyze** the scan results
4. 🛡️ **Develop** new security capabilities

**Happy hacking! (ethically, of course) 😄**

---

*Built with ❤️ by the Nexus Hunter Security Team*  
*"The most comprehensive vulnerable enterprise application ever created"*

