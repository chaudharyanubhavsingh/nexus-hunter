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
from core.database import Database
from core.stuck_scan_monitor import stuck_scan_monitor
from core.notification_system import notification_system
from core.auto_scan_scheduler import auto_scan_scheduler
from core.concurrent_scan_manager import concurrent_scan_manager
from core.settings_persistence import settings_persistence

router = APIRouter()

@router.get("/system-status")
async def early_system_status():
    try:
        cm_status = concurrent_scan_manager.get_scan_status()
        safe_cm = {k: (list(v) if isinstance(v, set) else v) for k, v in cm_status.items()}
        return {
            "stuck_scan_monitor": {
                "running": bool(stuck_scan_monitor.is_running),
                "current_timeout": int(stuck_scan_monitor.get_current_timeout()),
            },
            "notification_system": {
                "enabled": bool(notification_system.notifications_enabled),
                "recent_notifications": []
            },
            "auto_scan_scheduler": {
                "enabled": bool(auto_scan_scheduler.auto_scan_enabled),
                "running": bool(auto_scan_scheduler.is_running),
                "scheduled_scans": int(len(auto_scan_scheduler.scheduled_scans or {})),
            },
            "concurrent_scan_manager": safe_cm,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception:
        return {
            "stuck_scan_monitor": {"running": False, "current_timeout": 3600},
            "notification_system": {"enabled": False, "recent_notifications": []},
            "auto_scan_scheduler": {
                "enabled": settings_persistence.get("auto_scan_enabled", False),
                "running": False,
                "scheduled_scans": 0,
            },
            "concurrent_scan_manager": {
                "max_concurrent_scans": settings_persistence.get("concurrent_scans", 3),
                "current_running_scans": 0,
                "running_scan_ids": [],
                "queued_scans": 0,
                "queue_details": [],
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

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
        
        # Check if this is a scheduled scan
        config = scan_request.config or {}
        schedule_type = config.get('schedule_type', 'immediate')
        
        if schedule_type == 'scheduled':
            # Create scheduled scan instead of immediate execution
            try:
                from core.auto_scan_scheduler import auto_scan_scheduler, ScheduleType
                
                # Get schedule frequency (once, daily, weekly, monthly)
                schedule_frequency = config.get('schedule_frequency', 'once')
                
                # Convert to enum
                if schedule_frequency == 'daily':
                    sched_type = ScheduleType.DAILY
                elif schedule_frequency == 'weekly':
                    sched_type = ScheduleType.WEEKLY
                elif schedule_frequency == 'monthly':
                    sched_type = ScheduleType.MONTHLY
                else:  # 'once' or fallback
                    sched_type = ScheduleType.ONCE
                
                # Get scheduled time
                scheduled_time = config.get('scheduled_time', '')
                if scheduled_time and 'T' in scheduled_time:
                    # Extract time from datetime-local format (YYYY-MM-DDTHH:MM)
                    scheduled_time = scheduled_time.split('T')[1]
                else:
                    # Default to current time + 1 hour if no time specified
                    from datetime import datetime, timedelta
                    default_time = datetime.now() + timedelta(hours=1)
                    scheduled_time = default_time.strftime('%H:%M')
                
                # Create the scheduled scan
                schedule_id = await auto_scan_scheduler.add_scheduled_scan(
                    target_id=str(scan_request.target_id),
                    scan_type=scan_request.scan_type,
                    schedule_type=sched_type,
                    schedule_time=scheduled_time,
                    config={k: v for k, v in config.items() if k not in ['schedule_type', 'scheduled_time', 'recurrence_pattern']}
                )
                
                logger.info(f"📅 Created scheduled scan {schedule_id} for target {target.domain}")
                
                # Create a mock scan response for scheduled scans to satisfy the response model
                from datetime import datetime
                from uuid import uuid4
                mock_scan_response = ScanResponse(
                    id=str(uuid4()),  # Generate a temporary UUID
                    name=f"Scheduled: {scan_request.name}",
                    target_id=scan_request.target_id,
                    scan_type=scan_request.scan_type,
                    status=ScanStatus.SCHEDULED,  # We'll need to add this status
                    progress_percentage=0,
                    config=config,
                    total_steps=0,
                    completed_steps=0,
                    results={"schedule_id": schedule_id, "schedule_type": schedule_frequency, "message": "Scan scheduled successfully"},
                    error_message=None,
                    started_at=None,
                    completed_at=None,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                return mock_scan_response
                
            except Exception as e:
                logger.error(f"Failed to create scheduled scan: {e}")
                # Fall back to immediate scan if scheduling fails
                logger.warning(f"Falling back to immediate execution due to scheduling error")
                schedule_type = 'immediate'
        
        if schedule_type == 'immediate':
            # Create immediate scan record
            scan = Scan(
                name=scan_request.name,
                target_id=scan_request.target_id,
                scan_type=scan_request.scan_type,
                config=config,
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
        
        # Update scan status
        scan.status = ScanStatus.CANCELLED
        await db.commit()
        
        # Broadcast cancellation
        await WebSocketManager.manager.broadcast({
            "type": "scan_update",
            "data": {
                "scan_id": str(scan_id),
                "status": "cancelled",
                "message": "Scan cancelled by user"
            }
        })
        
        logger.info(f"🛑 Cancelled scan {scan_id}")
        
        return {"message": "Scan cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """Delete a failed or cancelled scan"""
    try:
        # Get scan
        query = select(Scan).where(Scan.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if scan.status in [ScanStatus.PENDING, ScanStatus.RUNNING]:
            raise HTTPException(status_code=400, detail="Cannot delete running scan. Cancel it first.")
        
        # Delete scan
        await db.delete(scan)
        await db.commit()
        
        logger.info(f"🗑️ Deleted scan {scan_id}")
        
        return {"message": "Scan deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete scan {scan_id}: {e}")
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
    """Execute scan in background - simplified version for testing"""
    try:
        logger.info(f"🚀 Starting background scan execution: {scan_id}")
        
        # Update scan status to running
        async with Database.get_session() as db:
            update_query = update(Scan).where(Scan.id == scan_id).values(
                status=ScanStatus.RUNNING,
                progress_percentage=5,
                started_at=datetime.now().isoformat()
            )
            await db.execute(update_query)
            await db.commit()
        
        logger.info(f"✅ Updated scan {scan_id} status to RUNNING")
        
        # Broadcast scan start
        await WebSocketManager.manager.broadcast({
            "type": "scan_update",
            "data": {
                "scan_id": str(scan_id),
                "status": "running",
                "progress": 5,
                "message": "Scan execution started"
            }
        })
        
        # Notify scan started
        try:
            await notification_system.notify_scan_started(str(scan_id), str(scan_id), target_domain)
        except Exception as notify_err:
            logger.error(f"Failed to send start notification: {notify_err}")
        
        # Simulate scan progress
        progress_steps = [
            (10, "Initializing target analysis..."),
            (25, "Discovering subdomains..."),
            (40, "Port scanning in progress..."),
            (60, "Running vulnerability tests..."),
            (80, "Analyzing security findings..."),
            (95, "Generating report...")
        ]
        
        # Simulate scan execution with progress updates
        for progress, message in progress_steps:
            try:
                await asyncio.sleep(2)  # Simulate work being done
                
                # Check for cancellation before updating progress
                async with Database.get_session() as db:
                    current = await db.execute(select(Scan.status).where(Scan.id == scan_id))
                    current_status = current.scalar_one_or_none()
                    if current_status == ScanStatus.CANCELLED:
                        logger.info(f"🛑 Scan {scan_id} was cancelled. Stopping execution.")
                        await WebSocketManager.manager.broadcast({
                            "type": "scan_update",
                            "data": {
                                "scan_id": str(scan_id),
                                "status": "cancelled",
                                "message": "Scan cancelled by user"
                            }
                        })
                        return
                
                # Update progress in database
                async with Database.get_session() as db:
                    update_query = update(Scan).where(Scan.id == scan_id).values(
                        progress_percentage=progress
                    )
                    await db.execute(update_query)
                    await db.commit()
                
                # Broadcast progress update (keep status as running and progress < 100)
                await WebSocketManager.manager.broadcast({
                    "type": "scan_update",
                    "data": {
                        "scan_id": str(scan_id),
                        "status": "running",
                        "progress": progress,
                        "message": message
                    }
                })
                
                logger.info(f"📊 Scan {scan_id} progress: {progress}% - {message}")
                
            except Exception as step_error:
                logger.error(f"❌ Error in scan step {progress}% for {scan_id}: {step_error}")
                # Continue to next step rather than failing entire scan
                continue
        
        # Before marking completed, ensure not cancelled in the meantime
        async with Database.get_session() as db:
            current = await db.execute(select(Scan.status).where(Scan.id == scan_id))
            current_status = current.scalar_one_or_none()
            if current_status == ScanStatus.CANCELLED:
                logger.info(f"🛑 Scan {scan_id} was cancelled before completion. Aborting completion update.")
                await WebSocketManager.manager.broadcast({
                    "type": "scan_update",
                    "data": {
                        "scan_id": str(scan_id),
                        "status": "cancelled",
                        "message": "Scan cancelled by user"
                    }
                })
                return
        
        # Generate fake results
        fake_results = {
            "scan_id": str(scan_id),
            "target_domain": target_domain,
            "scan_type": "reconnaissance",
            "vulnerabilities": [
                {
                    "id": "vuln_001",
                    "title": "Example Security Finding",
                    "severity": "medium",
                    "description": "This is a simulated vulnerability for testing purposes.",
                    "cvss_score": 6.5,
                    "recommendation": "Apply security patches and follow best practices."
                }
            ],
            "subdomains": [
                f"www.{target_domain}",
                f"api.{target_domain}",
                f"admin.{target_domain}"
            ],
            "open_ports": [80, 443, 22],
            "technologies": ["nginx", "ssl"],
            "total_requests": 150,
            "scan_duration": "14 seconds",
            # Add ReportAgent results for proper report generation
            "ReportAgent": {
                "report_id": f"report_{scan_id}",
                "reports": {
                    "technical_report": f"""# Technical Security Assessment Report

## Target Information
- **Domain**: {target_domain}
- **Scan Type**: Reconnaissance
- **Scan Duration**: 14 seconds
- **Total Requests**: 150

## Executive Summary
This technical assessment identified **1 medium-severity vulnerability** on {target_domain}. The target runs nginx with SSL encryption and exposes standard web services on ports 80 and 443.

## Findings Summary
- **Total Vulnerabilities**: 1
- **Critical**: 0
- **High**: 0  
- **Medium**: 1
- **Low**: 0

## Detailed Findings

### Finding #1: Example Security Finding
- **Severity**: Medium
- **CVSS Score**: 6.5
- **Description**: This is a simulated vulnerability for testing purposes.
- **Recommendation**: Apply security patches and follow best practices.

## Technical Details

### Subdomain Enumeration
- www.{target_domain}
- api.{target_domain}
- admin.{target_domain}

### Port Scan Results
- Port 80: HTTP (Open)
- Port 443: HTTPS (Open)
- Port 22: SSH (Open)

### Technology Stack
- Web Server: nginx
- Encryption: SSL/TLS

## Risk Assessment
The identified vulnerabilities pose a **MEDIUM** risk to the organization. Immediate attention is recommended for the medium-severity finding.

## Recommendations
1. Apply security patches promptly
2. Follow security best practices
3. Regular security assessments
4. Monitor for new vulnerabilities

---
*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
""",
                    "executive_summary": f"""# Executive Summary - Security Assessment

## Overview
**Target**: {target_domain}  
**Assessment Date**: {datetime.now().strftime('%Y-%m-%d')}  
**Assessment Type**: Reconnaissance Scan

## Key Findings
Our security assessment of {target_domain} identified **1 medium-severity vulnerability** that requires attention.

## Risk Level: MEDIUM 🟡

### Summary Statistics
- **Total Issues Found**: 1
- **Critical Issues**: 0
- **High Risk Issues**: 0
- **Medium Risk Issues**: 1
- **Low Risk Issues**: 0

## Business Impact
The identified vulnerability poses a moderate risk to your organization's security posture. While not immediately critical, it should be addressed within the next 30 days.

## Immediate Actions Required
1. **Review medium-severity finding**: Example Security Finding (CVSS: 6.5)
2. **Apply recommended patches**
3. **Implement security best practices**

## Technical Infrastructure
- **Subdomains Identified**: 3
- **Open Ports**: 3 (HTTP, HTTPS, SSH)
- **Technologies**: nginx, SSL

## Next Steps
We recommend addressing the identified vulnerability and implementing a regular security assessment schedule to maintain your security posture.

For technical details, please refer to the complete technical report.

---
*This executive summary is intended for management and decision-makers.*
""",
                    "disclosure_document": f"""# Responsible Disclosure Report

## Contact Information
**Security Team**: {target_domain}  
**Report Date**: {datetime.now().strftime('%Y-%m-%d')}  
**Severity**: Medium

## Issue Description
During our security assessment, we identified a vulnerability in your system that we believe you should be aware of.

## Vulnerability Details
- **Title**: Example Security Finding
- **Severity**: Medium (CVSS: 6.5)
- **Type**: Security Configuration Issue
- **Affected Asset**: {target_domain}

## Technical Summary
This is a simulated vulnerability for testing purposes. In a real scenario, this section would contain technical details about the vulnerability.

## Proof of Concept
[Technical details and proof of concept would be included here in a real disclosure]

## Recommended Actions
1. Apply security patches and follow best practices
2. Review security configurations
3. Consider implementing additional security measures

## Timeline
- **Discovery Date**: {datetime.now().strftime('%Y-%m-%d')}
- **Initial Contact**: {datetime.now().strftime('%Y-%m-%d')}
- **Recommended Fix Date**: Within 30 days

## Our Commitment
We are committed to responsible disclosure and will:
- Keep this information confidential until you have had time to address it
- Provide technical assistance if needed
- Coordinate on appropriate disclosure timeline

Please acknowledge receipt of this report and let us know your intended timeline for addressing the issue.

## Contact
For questions about this disclosure, please contact:
- Email: security@example.com
- Encrypted communication: [PGP key details]

Thank you for your attention to this matter.

---
*This report is provided in the spirit of improving cybersecurity.*
"""
                },
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "target": target_domain,
                    "findings_count": 1,
                    "critical_findings": 0,
                    "scan_type": "reconnaissance"
                },
                "delivery_methods": ["download", "email"]
            }
        }
        
        # Save final results with additional error handling
        try:
            async with Database.get_session() as db:
                update_query = update(Scan).where(Scan.id == scan_id).values(
                    status=ScanStatus.COMPLETED,
                    progress_percentage=100,
                    results=fake_results,
                    completed_at=datetime.now().isoformat()
                )
                await db.execute(update_query)
                await db.commit()
            
            # Broadcast completion
            await WebSocketManager.manager.broadcast({
                "type": "scan_completed",
                "data": {
                    "scan_id": str(scan_id),
                    "status": "completed",
                    "results": fake_results,
                    "completed_at": datetime.now().isoformat(),
                    "message": "Scan completed successfully!"
                }
            })
            
            # Send notification
            try:
                # prefer scan.name from DB if available
                scan_name = str(scan_id)
                findings_count = 0
                try:
                    details = fake_results.get("report", {}).get("summary", {})
                    findings_count = int(details.get("findings_count", 0))
                    scan_name = fake_results.get("report", {}).get("details", {}).get("scan_id", scan_name)
                except Exception:
                    pass
                await notification_system.notify_scan_completed(str(scan_id), scan_name, findings_count)
            except Exception as notify_err:
                logger.error(f"Failed to send completion notification: {notify_err}")
        
        except Exception as completion_error:
            logger.error(f"❌ Error completing scan {scan_id}: {completion_error}")
            # Try to mark as failed if completion update fails
            try:
                async with Database.get_session() as db:
                    update_query = update(Scan).where(Scan.id == scan_id).values(
                        status=ScanStatus.FAILED,
                        error_message=f"Completion error: {str(completion_error)}"
                    )
                    await db.execute(update_query)
                    await db.commit()
            except Exception as fallback_error:
                logger.error(f"❌ Failed to update scan status after completion error: {fallback_error}")
        
        logger.info(f"✅ Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Scan {scan_id} failed: {e}")
        import traceback
        traceback.print_exc()
        
        # Update scan status to failed
        try:
            async with Database.get_session() as db:
                update_query = update(Scan).where(Scan.id == scan_id).values(
                    status=ScanStatus.FAILED,
                    error_message=str(e),
                    progress_percentage=0
                )
                await db.execute(update_query)
                await db.commit()
            
            # Broadcast failure
            await WebSocketManager.manager.broadcast({
                "type": "scan_failed",
                "data": {
                    "scan_id": str(scan_id),
                    "status": "failed",
                    "message": f"Scan failed: {str(e)}"
                }
            })

            # Send failure notification
            try:
                await notification_system.notify_scan_failed(str(scan_id), str(scan_id), str(e))
            except Exception as notify_err:
                logger.error(f"Failed to send failure notification: {notify_err}")
        
        except Exception as db_error:
            logger.error(f"Failed to update scan status after error: {db_error}")


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


@router.post("/fix-stuck-scans")
async def fix_stuck_scans(db: AsyncSession = Depends(get_db_session)):
    """Fix scans that are stuck in running state"""
    try:
        # Find scans that have been running for more than 10 minutes without update
        from datetime import datetime, timedelta
        
        # Get all running scans (simplified check for now)
        stuck_query = select(Scan).where(Scan.status == ScanStatus.RUNNING)
        stuck_result = await db.execute(stuck_query)
        stuck_scans = stuck_result.scalars().all()
        
        fixed_count = 0
        for scan in stuck_scans:
            # Update stuck scan to failed status
            update_query = update(Scan).where(Scan.id == scan.id).values(
                status=ScanStatus.FAILED,
                error_message="Scan execution timeout - reset by system"
            )
            await db.execute(update_query)
            fixed_count += 1
            
            # Broadcast failure
            await WebSocketManager.manager.broadcast({
                "type": "scan_failed",
                "data": {
                    "scan_id": str(scan.id),
                    "status": "failed",
                    "message": "Scan reset due to timeout"
                }
            })
            
            logger.info(f"🔧 Fixed stuck scan {scan.id}")
        
        await db.commit()
        
        return {
            "message": f"Fixed {fixed_count} stuck scans",
            "fixed_scans": [str(scan.id) for scan in stuck_scans]
        }
        
    except Exception as e:
        logger.error(f"Failed to fix stuck scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/intelligent-stuck-check")
async def intelligent_stuck_check():
    """
    Perform an intelligent check for stuck scans using the smart monitoring system.
    This uses advanced logic to distinguish truly stuck scans from slow but working ones.
    """
    try:
        result = await stuck_scan_monitor.force_check_now()
        
        return {
            "message": "Intelligent stuck scan check completed",
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in intelligent stuck check: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to perform intelligent stuck check: {str(e)}")


@router.get("/monitor-status")
async def get_monitor_status():
    """Get the status of the stuck scan monitor."""
    try:
        current_timeout = stuck_scan_monitor.get_current_timeout()
        return {
            "monitor_running": stuck_scan_monitor.is_running,
            "scan_timeout_config": current_timeout,
            "scan_type_multipliers": stuck_scan_monitor.scan_type_multipliers,
            "min_progress_intervals": stuck_scan_monitor.min_progress_intervals,
            "check_interval_seconds": max(current_timeout // 4, 300)
        }
    except Exception as e:
        logger.error(f"Error getting monitor status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get monitor status: {str(e)}")


class ScanSettingsUpdate(BaseModel):
    scan_timeout: Optional[int] = None
    notifications: Optional[bool] = None
    auto_scan: Optional[bool] = None
    concurrent_scans: Optional[int] = None


@router.post("/update-settings")
async def update_scan_settings(settings: ScanSettingsUpdate):
    """
    Dynamically update scan settings without restarting the server.
    """
    try:
        updates_applied = []
        
        if settings.scan_timeout is not None:
            success = await stuck_scan_monitor.update_scan_timeout(settings.scan_timeout)
            if success:
                updates_applied.append(f"scan_timeout: {settings.scan_timeout}s")
            else:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid scan timeout: {settings.scan_timeout}. Must be between 300-7200 seconds."
                )
        
        if settings.notifications is not None:
            await notification_system.enable_notifications(settings.notifications)
            updates_applied.append(f"notifications: {'enabled' if settings.notifications else 'disabled'}")
        
        if settings.auto_scan is not None:
            await auto_scan_scheduler.enable_auto_scan(settings.auto_scan)
            updates_applied.append(f"auto_scan: {'enabled' if settings.auto_scan else 'disabled'}")
        
        if settings.concurrent_scans is not None:
            try:
                await concurrent_scan_manager.set_concurrent_limit(settings.concurrent_scans)
                updates_applied.append(f"concurrent_scans: {settings.concurrent_scans}")
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
        
        if not updates_applied:
            return {"message": "No settings to update"}
        
        return {
            "message": "Settings updated successfully",
            "updates_applied": updates_applied,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating scan settings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update settings: {str(e)}")


@router.get("/system-status")
async def get_system_status():
    """Get comprehensive system status including all managers (always JSON-serializable)."""
    try:
        # Build safe concurrent scan status
        cm_status = concurrent_scan_manager.get_scan_status()
        safe_cm_status: Dict[str, Any] = {}
        for k, v in cm_status.items():
            if isinstance(v, set):
                safe_cm_status[k] = list(v)
            else:
                safe_cm_status[k] = v
        
        return {
            "stuck_scan_monitor": {
                "running": bool(stuck_scan_monitor.is_running),
                "current_timeout": int(stuck_scan_monitor.get_current_timeout()),
            },
            "notification_system": {
                "enabled": bool(notification_system.notifications_enabled),
                # Keep notifications out to avoid serialization issues
                "recent_notifications": []
            },
            "auto_scan_scheduler": {
                "enabled": bool(auto_scan_scheduler.auto_scan_enabled),
                "running": bool(auto_scan_scheduler.is_running),
                "scheduled_scans": int(len(auto_scan_scheduler.scheduled_scans or {})),
            },
            "concurrent_scan_manager": safe_cm_status,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception:
        # Minimal safe fallback; leverage persisted values if present
        return {
            "stuck_scan_monitor": {"running": False, "current_timeout": 3600},
            "notification_system": {"enabled": False, "recent_notifications": []},
            "auto_scan_scheduler": {
                "enabled": settings_persistence.get("auto_scan_enabled", False),
                "running": False,
                "scheduled_scans": 0,
            },
            "concurrent_scan_manager": {
                "max_concurrent_scans": settings_persistence.get("concurrent_scans", 3),
                "current_running_scans": 0,
                "running_scan_ids": [],
                "queued_scans": 0,
                "queue_details": [],
            },
            "timestamp": datetime.utcnow().isoformat(),
        }


@router.post("/schedules")
async def create_scheduled_scan(
    target_id: str,
    scan_type: str,
    schedule_type: str,
    schedule_time: str = "02:00",
    config: Optional[Dict[str, Any]] = None
):
    """Create a new scheduled scan."""
    try:
        from core.auto_scan_scheduler import ScheduleType
        
        schedule_type_enum = ScheduleType(schedule_type)
        schedule_id = await auto_scan_scheduler.add_scheduled_scan(
            target_id=target_id,
            scan_type=scan_type,
            schedule_type=schedule_type_enum,
            schedule_time=schedule_time,
            config=config or {}
        )
        
        return {
            "message": "Scheduled scan created",
            "schedule_id": schedule_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating scheduled scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create scheduled scan: {str(e)}")


@router.get("/schedules")
async def get_scheduled_scans():
    """Get all scheduled scans."""
    try:
        return {
            "schedules": auto_scan_scheduler.get_scheduled_scans(),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting scheduled scans: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get scheduled scans: {str(e)}")


@router.delete("/schedules/{schedule_id}")
async def delete_scheduled_scan(schedule_id: str):
    """Delete a scheduled scan."""
    try:
        await auto_scan_scheduler.remove_scheduled_scan(schedule_id)
        return {
            "message": "Scheduled scan deleted",
            "schedule_id": schedule_id,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error deleting scheduled scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete scheduled scan: {str(e)}") 