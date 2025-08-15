"""
Scan management API endpoints
"""

import asyncio
from typing import Dict, List, Any, Optional
from uuid import UUID, uuid4
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel
from loguru import logger

from core.database import get_db_session
from models.scan import Scan, ScanStatus, ScanType, Target
from agents.base import AgentOrchestrator
from agents.recon_agent import ReconAgent
from agents.exploit_agent import ExploitAgent
from agents.report_agent import ReportAgent
from core.websocket_manager import WebSocketManager
from core.redis_client import RedisClient

router = APIRouter()

# Global agent orchestrator
orchestrator = AgentOrchestrator()
orchestrator.register_agent(ReconAgent())
orchestrator.register_agent(ExploitAgent())
orchestrator.register_agent(ReportAgent())


# Pydantic models for requests/responses
class ScanCreateRequest(BaseModel):
    name: str
    target_id: UUID
    scan_type: ScanType
    config: Optional[Dict[str, Any]] = None


class ScanResponse(BaseModel):
    id: UUID
    name: str
    target_id: UUID
    scan_type: ScanType
    status: ScanStatus
    progress_percentage: int
    results: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    scans: List[ScanResponse]
    total: int
    page: int
    size: int


@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_request: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new security scan"""
    try:
        # Verify target exists
        target_query = select(Target).where(Target.id == scan_request.target_id)
        target_result = await db.execute(target_query)
        target = target_result.scalar_one_or_none()
        
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Create scan record
        scan = Scan(
            name=scan_request.name,
            target_id=scan_request.target_id,
            scan_type=scan_request.scan_type,
            config=scan_request.config or {},
            status=ScanStatus.PENDING
        )
        
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        # Start scan in background
        background_tasks.add_task(execute_scan, scan.id, target.domain)
        
        logger.info(f"🚀 Created scan {scan.id} for target {target.domain}")
        
        return ScanResponse.from_orm(scan)
        
    except Exception as e:
        logger.error(f"Failed to create scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    page: int = 1,
    size: int = 20,
    status: Optional[ScanStatus] = None,
    db: AsyncSession = Depends(get_db_session)
):
    """List all scans with pagination"""
    try:
        offset = (page - 1) * size
        
        # Build query
        query = select(Scan)
        if status:
            query = query.where(Scan.status == status)
        
        query = query.offset(offset).limit(size).order_by(Scan.created_at.desc())
        
        # Execute query
        result = await db.execute(query)
        scans = result.scalars().all()
        
        # Get total count
        count_query = select(Scan)
        if status:
            count_query = count_query.where(Scan.status == status)
        
        total_result = await db.execute(count_query)
        total = len(total_result.scalars().all())
        
        scan_responses = [ScanResponse.from_orm(scan) for scan in scans]
        
        return ScanListResponse(
            scans=scan_responses,
            total=total,
            page=page,
            size=size
        )
        
    except Exception as e:
        logger.error(f"Failed to list scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """Get a specific scan by ID"""
    try:
        query = select(Scan).where(Scan.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return ScanResponse.from_orm(scan)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """Cancel a running scan"""
    try:
        # Get scan
        query = select(Scan).where(Scan.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
            raise HTTPException(status_code=400, detail="Scan cannot be cancelled")
        
        # Cancel agents
        orchestrator.cancel_all()
        
        # Update scan status
        scan.status = ScanStatus.CANCELLED
        await db.commit()
        
        # Broadcast cancellation
        await WebSocketManager.broadcast_scan_update(
            str(scan_id), "cancelled", {"message": "Scan cancelled by user"}
        )
        
        logger.info(f"🛑 Cancelled scan {scan_id}")
        
        return {"message": "Scan cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/progress")
async def get_scan_progress(scan_id: UUID):
    """Get real-time scan progress"""
    try:
        # Get progress from Redis cache
        progress_data = await RedisClient.get(f"scan_progress:{scan_id}")
        
        if not progress_data:
            return {"progress": 0, "status": "No progress data available"}
        
        return progress_data
        
    except Exception as e:
        logger.error(f"Failed to get scan progress {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/results")
async def get_scan_results(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """Get detailed scan results"""
    try:
        # Get scan from database
        query = select(Scan).where(Scan.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Also get results from Redis cache for real-time data
        cached_results = await RedisClient.get(f"scan_results:{scan_id}")
        
        return {
            "scan_id": scan_id,
            "status": scan.status,
            "results": scan.results or {},
            "cached_results": cached_results or {},
            "vulnerabilities_count": len(scan.vulnerabilities) if scan.vulnerabilities else 0,
            "findings_count": len(scan.findings) if scan.findings else 0
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan results {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def execute_scan(scan_id: UUID, target_domain: str):
    """Execute scan in background using agent orchestrator"""
    try:
        logger.info(f"🚀 Starting background scan execution: {scan_id}")
        
        # Update scan status to running
        async with get_db_session() as db:
            update_query = update(Scan).where(Scan.id == scan_id).values(
                status=ScanStatus.RUNNING,
                progress_percentage=0
            )
            await db.execute(update_query)
            await db.commit()
        
        # Broadcast scan start
        await WebSocketManager.broadcast_scan_update(
            str(scan_id), "running", {"message": "Scan execution started"}
        )
        
        # Set up progress callback
        async def progress_callback(step: str, data: Dict[str, Any]):
            # Cache progress in Redis
            progress_data = {
                "step": step,
                "data": data,
                "timestamp": asyncio.get_event_loop().time()
            }
            await RedisClient.set(f"scan_progress:{scan_id}", progress_data, expire=3600)
            
            # Broadcast via WebSocket
            await WebSocketManager.broadcast_scan_update(str(scan_id), step, data)
        
        # Configure agents with progress callback
        for agent in orchestrator.agents.values():
            agent.set_progress_callback(progress_callback)
        
        # Execute agents sequentially
        agent_names = ["ReconAgent", "ExploitAgent", "ReportAgent"]
        results = await orchestrator.execute_sequential(
            agent_names, 
            target_domain=target_domain,
            scan_id=str(scan_id)
        )
        
        # Save results to Redis and database
        await RedisClient.set(f"scan_results:{scan_id}", results, expire=86400)  # 24 hours
        
        async with get_db_session() as db:
            update_query = update(Scan).where(Scan.id == scan_id).values(
                status=ScanStatus.COMPLETED,
                progress_percentage=100,
                results=results
            )
            await db.execute(update_query)
            await db.commit()
        
        # Broadcast completion
        await WebSocketManager.broadcast_scan_update(
            str(scan_id), "completed", {
                "message": "Scan completed successfully",
                "results_summary": {
                    "vulnerabilities": len(results.get("ExploitAgent", {}).get("vulnerabilities", [])),
                    "subdomains": len(results.get("ReconAgent", {}).get("subdomains", [])),
                    "reports_generated": len(results.get("ReportAgent", {}).get("reports", {}))
                }
            }
        )
        
        logger.info(f"✅ Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Scan {scan_id} failed: {e}")
        
        # Update scan status to failed
        try:
            async with get_db_session() as db:
                update_query = update(Scan).where(Scan.id == scan_id).values(
                    status=ScanStatus.FAILED,
                    error_message=str(e)
                )
                await db.execute(update_query)
                await db.commit()
            
            # Broadcast failure
            await WebSocketManager.broadcast_scan_update(
                str(scan_id), "failed", {"message": f"Scan failed: {str(e)}"}
            )
            
        except Exception as db_error:
            logger.error(f"Failed to update scan status: {db_error}")


@router.post("/{scan_id}/retry")
async def retry_scan(
    scan_id: UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session)
):
    """Retry a failed scan"""
    try:
        # Get scan and target
        query = select(Scan).where(Scan.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if scan.status not in [ScanStatus.FAILED, ScanStatus.CANCELLED]:
            raise HTTPException(status_code=400, detail="Only failed or cancelled scans can be retried")
        
        # Get target domain
        target_query = select(Target).where(Target.id == scan.target_id)
        target_result = await db.execute(target_query)
        target = target_result.scalar_one_or_none()
        
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Reset scan status
        scan.status = ScanStatus.PENDING
        scan.error_message = None
        scan.progress_percentage = 0
        await db.commit()
        
        # Start scan in background
        background_tasks.add_task(execute_scan, scan_id, target.domain)
        
        logger.info(f"🔄 Retrying scan {scan_id}")
        
        return {"message": "Scan retry initiated"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retry scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e)) 


@router.get("/vulnerabilities/", response_model=List[Dict[str, Any]])
async def get_vulnerabilities(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db_session)
):
    """Get all vulnerabilities from completed scans"""
    try:
        # Query all scans with results
        query = select(Scan).where(Scan.status == ScanStatus.COMPLETED)
        result = await db.execute(query)
        scans = result.scalars().all()
        
        vulnerabilities = []
        for scan in scans:
            if scan.results and 'vulnerabilities' in scan.results:
                for vuln in scan.results['vulnerabilities']:
                    vuln_data = {
                        'id': f"{scan.id}_{vuln.get('id', len(vulnerabilities))}",
                        'scan_id': scan.id,
                        'scan_name': scan.name,
                        'title': vuln.get('title', 'Unknown'),
                        'severity': vuln.get('severity', 'info'),
                        'description': vuln.get('description', ''),
                        'found_at': scan.updated_at.isoformat(),
                        'target_id': scan.target_id
                    }
                    vulnerabilities.append(vuln_data)
        
        # Apply pagination
        total = len(vulnerabilities)
        vulnerabilities = vulnerabilities[skip:skip + limit]
        
        return vulnerabilities
        
    except Exception as e:
        logger.error(f"Error fetching vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e)) 