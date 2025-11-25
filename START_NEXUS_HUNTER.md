# 🚀 START NEXUS HUNTER - Quick Reference

## Prerequisites
- Node.js installed
- Python 3.8+ installed
- Terminal access

---

## 🎯 OPTION 1: Quick Start (All Services)

### Terminal 1: Start Vulnerable App (Target)
```bash
cd /Users/anubhav.chaudhary/Desktop/Personal/nexus-hunter/enterprise-vuln-app/backend
npm install  # First time only
npm run dev
```
**Expected**: Server running on `http://localhost:3003`

---

### Terminal 2: Start Nexus Hunter Backend
```bash
cd /Users/anubhav.chaudhary/Desktop/Personal/nexus-hunter/backend
source venv/bin/activate || source vuln_env/bin/activate
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
**Expected**: Backend API running on `http://localhost:8000`

---

### Terminal 3: Start Nexus Hunter Frontend
```bash
cd /Users/anubhav.chaudhary/Desktop/Personal/nexus-hunter/frontend
npm install  # First time only
npm start
```
**Expected**: Frontend UI running on `http://localhost:3000`

---

## 🎯 OPTION 2: Background Mode (All at Once)

```bash
cd /Users/anubhav.chaudhary/Desktop/Personal/nexus-hunter

# Kill any existing processes
lsof -ti:3003 | xargs kill -9 2>/dev/null || true
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
lsof -ti:3000 | xargs kill -9 2>/dev/null || true

# Start Vulnerable App
cd enterprise-vuln-app/backend
npm run dev > /tmp/vuln-app.log 2>&1 &
echo "✅ Vulnerable App starting on port 3003..."

# Start Backend
cd ../../backend
source venv/bin/activate 2>/dev/null || source vuln_env/bin/activate
python -m uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/nexus-backend.log 2>&1 &
echo "✅ Backend starting on port 8000..."

# Start Frontend
cd ../frontend
npm start > /tmp/nexus-frontend.log 2>&1 &
echo "✅ Frontend starting on port 3000..."

sleep 10
echo ""
echo "🎉 All services started!"
echo "   Vulnerable App: http://localhost:3003"
echo "   Backend API:    http://localhost:8000"
echo "   Frontend UI:    http://localhost:3000"
echo ""
echo "📋 View logs:"
echo "   tail -f /tmp/vuln-app.log"
echo "   tail -f /tmp/nexus-backend.log"
echo "   tail -f /tmp/nexus-frontend.log"
```

---

## 🛑 Stop All Services

```bash
# Kill all services
lsof -ti:3003 | xargs kill -9 2>/dev/null || true
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
lsof -ti:3000 | xargs kill -9 2>/dev/null || true

echo "✅ All services stopped"
```

---

## 🧪 Quick Test After Starting

```bash
# Wait for services to start
sleep 15

# Test Vulnerable App
curl -s http://localhost:3003/api/vulnerabilities | python3 -m json.tool | head -20

# Test Backend
curl -s http://localhost:8000/api/health | python3 -m json.tool

# Test Frontend
curl -s http://localhost:3000 | grep -q "Nexus Hunter" && echo "✅ Frontend is running" || echo "❌ Frontend not ready"
```

---

## 📊 Run a Full Scan (After All Services Started)

```bash
# Step 1: Create target (if not exists)
curl -X POST "http://localhost:8000/api/targets/" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Vulnerable Test App",
    "domain": "localhost:3003",
    "description": "Local vulnerable application for testing"
  }' | python3 -c "import sys, json; data=json.load(sys.stdin); print(f'Target ID: {data.get(\"id\")}')"

# Step 2: Create scan (use the Target ID from above)
curl -X POST "http://localhost:8000/api/scans/" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "YOUR_TARGET_ID_HERE",
    "scan_type": "full",
    "name": "Test Scan"
  }' | python3 -c "import sys, json; print(f'Scan ID: {json.load(sys.stdin).get(\"id\")}')"

# Wait 3 minutes for scan to complete
echo "⏳ Waiting for scan to complete..."
sleep 180

# Check results
cd /Users/anubhav.chaudhary/Desktop/Personal/nexus-hunter/backend
python3 << 'EOF'
import sqlite3, json

conn = sqlite3.connect('nexus_hunter.db')
cursor = conn.cursor()

cursor.execute("SELECT name, status, results FROM scans ORDER BY created_at DESC LIMIT 1")
row = cursor.fetchone()

if row:
    name, status, results_str = row
    print(f"\n{'='*80}")
    print(f"🎯 SCAN RESULTS")
    print(f"{'='*80}\n")
    print(f"Name: {name}")
    print(f"Status: {status}\n")
    
    if results_str:
        results = json.loads(results_str)
        vulns = []
        for agent, data in results.items():
            if agent != 'ReconAgent' and isinstance(data, dict):
                v = data.get('vulnerabilities', [])
                if v:
                    vulns.extend(v)
        
        print(f"🎯 DETECTED: {len(vulns)}/29 ({int(len(vulns)/29*100)}%)\n")
        
        # Severity distribution
        severity_dist = {}
        for v in vulns:
            s = v.get('severity', 'unknown').upper()
            severity_dist[s] = severity_dist.get(s, 0) + 1
        
        print("📊 SEVERITY:")
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_dist.get(s, 0)
            if count > 0:
                print(f"  {s}: {count}")

conn.close()
EOF
```

---

## 🔍 Troubleshooting

### Port Already in Use
```bash
# Check what's using the ports
lsof -i :3003
lsof -i :8000
lsof -i :3000

# Kill specific port
lsof -ti:3003 | xargs kill -9
```

### Backend Not Starting
```bash
# Check Python environment
cd /Users/anubhav.chaudhary/Desktop/Personal/nexus-hunter/backend
source venv/bin/activate || source vuln_env/bin/activate
python --version  # Should be 3.8+

# Reinstall dependencies
pip install -r requirements.txt
```

### Frontend Not Starting
```bash
# Clear cache and reinstall
cd /Users/anubhav.chaudhary/Desktop/Personal/nexus-hunter/frontend
rm -rf node_modules package-lock.json
npm install
npm start
```

### Vulnerable App Not Starting
```bash
cd /Users/anubhav.chaudhary/Desktop/Personal/nexus-hunter/enterprise-vuln-app/backend
rm -rf node_modules package-lock.json
npm install
npm run dev
```

---

## 📋 Service URLs

| Service | URL | Purpose |
|---------|-----|---------|
| **Frontend** | http://localhost:3000 | Main UI Dashboard |
| **Backend API** | http://localhost:8000 | REST API |
| **Backend Docs** | http://localhost:8000/docs | API Documentation |
| **Vulnerable App** | http://localhost:3003 | Target Application |
| **Vuln App API** | http://localhost:3003/api/vulnerabilities | List of vulnerabilities |

---

## 🎯 Current Status

**Detection Rate**: 24/29 (82%)  
**Agents Fixed**: 8/10 (SQL, NoSQL, CMD, Template, SSRF, File Upload, LFI, XXE)  
**CVSS Coverage**: 95%  
**Scan Time**: ~3 minutes  

**Working Agents:**
- ✅ SQL Injection (6 vulns) - CVSS 8.6 HIGH
- ✅ NoSQL Injection (8 vulns) - CVSS 8.1 HIGH
- ✅ Command Injection (1 vuln) - CVSS 9.8 CRITICAL
- ✅ Template Injection (1 vuln) - CVSS 8.8 HIGH
- ✅ SSRF (1 vuln) - CVSS 8.5 HIGH
- ✅ File Upload (1 vuln) - CVSS 8.8 HIGH
- ✅ LFI (4 vulns) - CVSS 6.5 MEDIUM
- ✅ XXE (2 vulns) - CVSS 8.2 HIGH

---

## 🎉 Quick Start Summary

**Fastest way to get started:**

```bash
# Terminal 1
cd /Users/anubhav.chaudhary/Desktop/Personal/nexus-hunter/enterprise-vuln-app/backend && npm run dev

# Terminal 2
cd /Users/anubhav.chaudhary/Desktop/Personal/nexus-hunter/backend && source venv/bin/activate && python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 3
cd /Users/anubhav.chaudhary/Desktop/Personal/nexus-hunter/frontend && npm start
```

Then open **http://localhost:3000** in your browser! 🚀


