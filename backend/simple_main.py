"""
Simplified Nexus Hunter API for testing
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict
import uuid
import json
from datetime import datetime
import asyncio

app = FastAPI(
    title="Nexus Hunter API",
    description="Autonomous Security Intelligence Platform",
    version="1.0.0"
)

# Middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for demo
targets_db = []
scans_db = []
vulnerabilities_db = []

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except:
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections.copy():
            try:
                await connection.send_text(message)
            except:
                self.disconnect(connection)

manager = ConnectionManager()

# Models
class CreateTargetRequest(BaseModel):
    name: str
    domain: str
    scope: str

class Target(BaseModel):
    id: str
    name: str
    domain: str
    scope: str
    is_active: bool = True
    created_at: str
    updated_at: str

class CreateScanRequest(BaseModel):
    name: str
    target_id: str
    type: str
    config: Optional[dict] = None

class Scan(BaseModel):
    id: str
    name: str
    target_id: str
    type: str
    status: str
    progress: int
    config: Optional[dict] = None
    results: Optional[dict] = None
    created_at: str
    updated_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

class Vulnerability(BaseModel):
    id: str
    scan_id: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    url: Optional[str] = None
    poc: Optional[str] = None
    evidence: Optional[str] = None
    category: str
    confidence: int
    false_positive: bool = False
    created_at: str

# Routes
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/targets", response_model=List[Target])
async def get_targets():
    return targets_db

@app.post("/api/targets", response_model=Target)
async def create_target(request: CreateTargetRequest):
    target = Target(
        id=str(uuid.uuid4()),
        name=request.name,
        domain=request.domain,
        scope=request.scope,
        is_active=True,
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat()
    )
    targets_db.append(target.dict())
    return target

@app.get("/api/targets/{target_id}", response_model=Target)
async def get_target(target_id: str):
    target = next((t for t in targets_db if t["id"] == target_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target

@app.put("/api/targets/{target_id}", response_model=Target)
async def update_target(target_id: str, request: CreateTargetRequest):
    target = next((t for t in targets_db if t["id"] == target_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    target.update({
        "name": request.name,
        "domain": request.domain,
        "scope": request.scope,
        "updated_at": datetime.now().isoformat()
    })
    return target

@app.delete("/api/targets/{target_id}")
async def delete_target(target_id: str):
    global targets_db
    target = next((t for t in targets_db if t["id"] == target_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    targets_db = [t for t in targets_db if t["id"] != target_id]
    return {"message": "Target deleted successfully"}

@app.get("/api/scans", response_model=List[Scan])
async def get_scans():
    return scans_db

@app.post("/api/scans", response_model=Scan)
async def create_scan(request: CreateScanRequest):
    # Validate target exists
    target = next((t for t in targets_db if t["id"] == request.target_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    scan = Scan(
        id=str(uuid.uuid4()),
        name=request.name,
        target_id=request.target_id,
        type=request.type,
        status="pending",
        progress=0,
        config=request.config,
        results=None,
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat(),
        started_at=datetime.now().isoformat()
    )
    scans_db.append(scan.dict())
    
    # Simulate scan progress
    asyncio.create_task(simulate_scan(scan.id))
    
    return scan

async def simulate_scan(scan_id: str):
    """Simulate a scan with progress updates"""
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan:
        return
    
    # Simulate scan phases
    phases = [
        ("running", 20, "Initializing scan..."),
        ("running", 40, "Discovering subdomains..."),
        ("running", 60, "Port scanning..."),
        ("running", 80, "Vulnerability testing..."),
        ("completed", 100, "Scan completed")
    ]
    
    for status, progress, message in phases:
        await asyncio.sleep(2)  # Simulate work
        scan["status"] = status
        scan["progress"] = progress
        scan["updated_at"] = datetime.now().isoformat()
        
        # Broadcast scan update via WebSocket
        update_message = json.dumps({
            "type": "scan_update",
            "data": {
                "scan_id": scan_id,
                "status": status,
                "progress": progress,
                "message": message
            }
        })
        await manager.broadcast(update_message)
        
        if status == "completed":
            scan["completed_at"] = datetime.now().isoformat()
            # Add sample vulnerabilities
            sample_vuln = {
                "id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "title": "SQL Injection Vulnerability",
                "description": "Potential SQL injection found in login form",
                "severity": "high",
                "category": "injection",
                "confidence": 85,
                "false_positive": False,
                "created_at": datetime.now().isoformat()
            }
            vulnerabilities_db.append(sample_vuln)
            scan["results"] = {
                "vulnerabilities": [sample_vuln],
                "summary": {
                    "total": 1,
                    "critical": 0,
                    "high": 1,
                    "medium": 0,
                    "low": 0
                }
            }

@app.get("/api/scans/{scan_id}", response_model=Scan)
async def get_scan(scan_id: str):
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan["status"] in ["running", "pending"]:
        scan["status"] = "cancelled"
        scan["updated_at"] = datetime.now().isoformat()
        return {"message": "Scan cancelled successfully"}
    
    raise HTTPException(status_code=400, detail="Cannot cancel scan in current status")

@app.get("/api/scans/{scan_id}/progress")
async def get_scan_progress(scan_id: str):
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "progress": scan["progress"],
        "status": scan["status"],
        "current_phase": "Vulnerability testing" if scan["progress"] < 100 else "Completed"
    }

@app.get("/api/vulnerabilities", response_model=List[Vulnerability])
async def get_vulnerabilities(scan_id: Optional[str] = None):
    if scan_id:
        return [v for v in vulnerabilities_db if v["scan_id"] == scan_id]
    return vulnerabilities_db

@app.get("/api/reports")
async def get_reports(scan_id: Optional[str] = None):
    # Return sample report data
    completed_scans = [s for s in scans_db if s["status"] == "completed"]
    if scan_id:
        completed_scans = [s for s in completed_scans if s["id"] == scan_id]
    
    reports = []
    for scan in completed_scans:
        reports.extend([
            {
                "id": f"{scan['id']}_executive",
                "type": "executive",
                "name": f"Executive Summary - {scan['name']}",
                "scan_id": scan["id"],
                "created_at": scan["completed_at"]
            },
            {
                "id": f"{scan['id']}_technical",
                "type": "technical", 
                "name": f"Technical Report - {scan['name']}",
                "scan_id": scan["id"],
                "created_at": scan["completed_at"]
            }
        ])
    
    return reports

@app.get("/api/reports/{scan_id}/executive-summary")
async def get_executive_summary(scan_id: str, format: str = "markdown"):
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if format == "markdown":
        return f"# Executive Summary\n\nScan: {scan['name']}\nStatus: {scan['status']}\nVulnerabilities found: {len(scan.get('results', {}).get('vulnerabilities', []))}"
    else:
        return f"<h1>Executive Summary</h1><p>Scan: {scan['name']}</p><p>Status: {scan['status']}</p>"

@app.get("/api/reports/{scan_id}/download")
async def download_report(scan_id: str, report_type: str, format: str):
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Return sample report content
    content = f"Report for scan {scan['name']} in {format} format"
    return {"message": "Report downloaded", "content": content}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo back any messages for now
            await manager.send_personal_message(f"Echo: {data}", websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 