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
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    config: Optional[Dict[str, Any]] = None

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
        # Normalize/validate some optional advanced fields (best-effort)
        try:
            headers = config.get('custom_headers')
            if isinstance(headers, str):
                import json as _json
                try:
                    config['custom_headers'] = _json.loads(headers)
                except Exception:
                    pass
            auth = config.get('auth')
            if isinstance(auth, str):
                import json as _json
                try:
                    config['auth'] = _json.loads(auth)
                except Exception:
                    pass
            # Coerce numbers
            if 'rate_limit' in config:
                try:
                    config['rate_limit'] = int(config.get('rate_limit'))
                except Exception:
                    pass
            if 'max_concurrent_requests' in config:
                try:
                    config['max_concurrent_requests'] = int(config.get('max_concurrent_requests'))
                except Exception:
                    pass
        except Exception:
            pass
        
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
        
        # Avoid accessing relationships in async context to prevent greenlet errors
        def safe_count_vulns(res: Optional[Dict[str, Any]]) -> int:
            try:
                if not isinstance(res, dict):
                    return 0
                # Try ReportAgent structure first
                ra = res.get("ReportAgent") or {}
                meta_findings = ra.get("metadata", {}).get("findings_count")
                if isinstance(meta_findings, int):
                    return meta_findings
                vulns = res.get("vulnerabilities")
                if isinstance(vulns, list):
                    return len(vulns)
                return 0
            except Exception:
                return 0
        
        vulnerabilities_count = safe_count_vulns(scan.results)
        findings_count = 0
        try:
            if isinstance(scan.results, dict):
                findings = scan.results.get("findings")
                if isinstance(findings, list):
                    findings_count = len(findings)
        except Exception:
            findings_count = 0
        
        return {
            "scan_id": str(scan_id),
            "status": scan.status,
            "results": scan.results or {},
            "cached_results": cached_results or {},
            "vulnerabilities_count": vulnerabilities_count,
            "findings_count": findings_count
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan results {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def execute_scan(scan_id: UUID, target_domain: str):
    """Execute scan using Agentic AI - Real intelligent scanning"""
    try:
        logger.info(f"🤖 Starting Agentic AI scan execution: {scan_id}")
        
        # Get scan details for configuration
        async with Database.get_session() as db:
            scan_query = select(Scan).where(Scan.id == scan_id)
            scan_result = await db.execute(scan_query)
            scan = scan_result.scalar_one_or_none()
            
            if not scan:
                raise Exception(f"Scan {scan_id} not found")
            
            # Update scan status to running
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
                "message": "🤖 AI-powered scan initiated - Analyzing target...",
                "started_at": datetime.now().isoformat()
            }
        })
        
        # Notify scan started
        try:
            await notification_system.notify_scan_started(str(scan_id), str(scan_id), target_domain)
        except Exception as notify_err:
            logger.error(f"Failed to send start notification: {notify_err}")
        
        # Initialize Enhanced Professional Scan Orchestrator
        from agents.agentic_ai.enhanced_scan_orchestrator import EnhancedScanOrchestrator
        scan_orchestrator = EnhancedScanOrchestrator()
        
        # Prepare scan configuration for professional assessment
        scan_config = scan.config or {}
        scan_config.update({
            "scan_id": str(scan_id),
            "professional_mode": True,
            "ai_guided": True,
            "comprehensive_analysis": True
        })
        
        # Map scan type to professional capabilities
        scan_type_mapping = {
            "reconnaissance": "reconnaissance",
            "vulnerability": "vulnerability", 
            "full": "full",
            # New professional scan types
            "deep_recon": "deep_recon",
            "secrets_scan": "secrets_scan",
            "web_security": "web_security", 
            "exploitation": "vulnerability_exploitation",  # Map to orchestrator's workflow name
            "zero_day_hunt": "zero_day_hunt"
        }
        
        professional_scan_type = scan_type_mapping.get(scan.scan_type.value, "reconnaissance")
        
        # Professional progress callback for enhanced orchestrator
        async def progress_callback(progress_percentage: int, status_message: str):
            try:
                # Check for cancellation
                async with Database.get_session() as db:
                    current = await db.execute(select(Scan.status).where(Scan.id == scan_id))
                    current_status = current.scalar_one_or_none()
                    if current_status == ScanStatus.CANCELLED:
                        logger.info(f"🛑 Professional scan {scan_id} cancelled at {progress_percentage}%")
                        await WebSocketManager.manager.broadcast({
                            "type": "scan_update",
                            "data": {
                                "scan_id": str(scan_id),
                                "status": "cancelled",
                                "progress": progress_percentage,
                                "message": f"Professional {professional_scan_type} scan cancelled"
                            }
                        })
                        return False  # Signal cancellation
                
                # Update progress in database
                if progress_percentage > 0:
                    async with Database.get_session() as db:
                        update_query = update(Scan).where(Scan.id == scan_id).values(
                                progress_percentage=int(progress_percentage)
                        )
                        await db.execute(update_query)
                        await db.commit()
                
                # Broadcast professional scan progress
                await WebSocketManager.manager.broadcast({
                    "type": "scan_update",
                    "data": {
                        "scan_id": str(scan_id),
                        "status": "running",
                        "progress": int(progress_percentage),
                        "message": f"🤖 {status_message}",
                        "phase": status_message
                    }
                })
                
                logger.info(f"🤖 Agentic Scan {scan_id}: {status_message} - {progress_percentage}%")
                return True  # Continue execution
                
            except Exception as e:
                logger.error(f"Progress callback error: {e}")
                return True
        
        # Execute Professional Security Assessment
        logger.info(f"🚀 Executing professional {professional_scan_type} assessment with enhanced AI orchestration...")
        
        # Execute the professional scan using the orchestrator WITH GLOBAL TIMEOUT
        import asyncio as async_lib  # Import locally to avoid scoping issues
        try:
            orchestration_results = await async_lib.wait_for(
                scan_orchestrator.orchestrate_scan(
                    scan_type=professional_scan_type,
                    target_domain=target_domain,
                    config=scan_config,
                    progress_callback=progress_callback
                ),
                timeout=1800  # 30 minutes max for entire scan (INCREASED to allow agents to run)
            )
        except async_lib.TimeoutError:
            logger.error(f"❌ Scan {scan_id} timed out after 30 minutes")
            orchestration_results = {
                "success": False,
                "error": "Scan timed out after 30 minutes",
                "scan_type": professional_scan_type,
                "target": target_domain,
                "timeout": True,
                # Provide minimal fallback data
                "ReconAgent": {"urls": [f"http://{target_domain}"], "timeout": True},
                "ExploitAgent": {"vulnerabilities": [], "timeout": True}
            }
        
        # Check one final time for cancellation before completion
        async with Database.get_session() as db:
            current = await db.execute(select(Scan.status).where(Scan.id == scan_id))
            current_status = current.scalar_one_or_none()
            if current_status == ScanStatus.CANCELLED:
                logger.info(f"🛑 Scan {scan_id} was cancelled before completion")
                await WebSocketManager.manager.broadcast({
                    "type": "scan_update",
                    "data": {
                        "scan_id": str(scan_id),
                        "status": "cancelled",
                        "message": "Scan cancelled by user"
                    }
                })
                return
        
        # Process and enhance results with intelligent analysis
        def make_serializable(obj):
            """Convert objects to JSON-serializable format"""
            if hasattr(obj, '__dict__'):
                # Convert objects with __dict__ to dictionary
                return {k: make_serializable(v) for k, v in obj.__dict__.items() if not k.startswith('_')}
            elif isinstance(obj, dict):
                return {k: make_serializable(v) for k, v in obj.items()}
            elif isinstance(obj, (list, tuple)):
                return [make_serializable(item) for item in obj]
            elif isinstance(obj, (str, int, float, bool)) or obj is None:
                return obj
            else:
                # Convert other objects to string representation
                return str(obj)
        
        # Make orchestration_results JSON serializable  
        serializable_orchestration_results = make_serializable(orchestration_results)
        
        enhanced_results = {
            **serializable_orchestration_results,
            "scan_id": str(scan_id),
            "target_domain": target_domain,
            "scan_type": scan.scan_type.value,
            "agentic_ai_powered": True,
            "intelligent_analysis": True,
            "attack_surface_mapped": True,
            "zero_day_attempts": serializable_orchestration_results.get("metadata", {}).get("zero_day_attempts", 0),
            "professional_assessment": serializable_orchestration_results.get("metadata", {}).get("professional_assessment", True),
            "enhanced_orchestration": True
        }
        
        # Save final results with additional error handling
        try:
            async with Database.get_session() as db:
                update_query = update(Scan).where(Scan.id == scan_id).values(
                    status=ScanStatus.COMPLETED,
                    progress_percentage=100,
                    results=enhanced_results,
                    completed_at=datetime.now().isoformat()
                )
                await db.execute(update_query)
                await db.commit()
            
            # Broadcast completion with AI enhancement indicators
            await WebSocketManager.manager.broadcast({
                "type": "scan_completed",
                "data": {
                    "scan_id": str(scan_id),
                    "status": "completed",
                    "results": enhanced_results,
                    "completed_at": datetime.now().isoformat(),
                    "message": "🤖 AI-powered scan completed successfully!",
                    "ai_enhanced": True,
                    "intelligent_findings": len(enhanced_results.get("vulnerabilities", [])),
                    "attack_surface_discovered": len(enhanced_results.get("subdomains", []))
                }
            })
            
            # Send notification with intelligent summary
            try:
                scan_name = scan.name if hasattr(scan, 'name') else str(scan_id)
                findings_count = len(enhanced_results.get("vulnerabilities", []))
                
                # Add AI-specific metrics to notification
                ai_summary = {
                    "total_vulnerabilities": findings_count,
                    "subdomains_discovered": len(enhanced_results.get("subdomains", [])),
                    "secrets_found": len(enhanced_results.get("secrets", [])),
                    "risk_score": enhanced_results.get("metadata", {}).get("risk_score", 0),
                    "ai_powered": True
                }
                
                await notification_system.notify_scan_completed(str(scan_id), scan_name, findings_count)
                
            except Exception as notify_err:
                logger.error(f"Failed to send completion notification: {notify_err}")
            
            # Auto-generate all report types using agentic system
            # TODO: Re-enable when agentic report generation is implemented
            # try:
            #     logger.info(f"🤖 Starting auto-generation of agentic reports for scan {scan_id}")
            #     
            #     # Import agentic report generation
            #     from api.endpoints.reports import execute_agentic_report_generation
            #     
            #     # Create background task for agentic report generation
            #     import asyncio
            #     asyncio.create_task(
            #         execute_agentic_report_generation(
            #             generation_id=f"auto-{scan_id}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            #             scan_data=enhanced_results,
            #             target_domain=target_domain,
            #             report_types=["executive", "technical", "disclosure"],
            #             format="html",
            #             config={
            #                 "auto_generated": True,
            #                 "professional_standards": True,
            #                 "intelligent_orchestration": True
            #             },
            #             scan_id=scan_id
            #         )
            #     )
            #     
            #     logger.info(f"✅ Auto-report generation initiated for scan {scan_id}")
            #     
            # except Exception as report_err:
            #     logger.error(f"Failed to start auto-report generation: {report_err}")
            pass  # Auto-report generation disabled for now
                # Don't fail the scan if report generation fails
        
        except Exception as completion_error:
            logger.error(f"❌ Error completing agentic scan {scan_id}: {completion_error}")
            # Try to mark as failed if completion update fails
            try:
                async with Database.get_session() as db:
                    update_query = update(Scan).where(Scan.id == scan_id).values(
                        status=ScanStatus.FAILED,
                        error_message=f"Agentic AI scan completion error: {str(completion_error)}"
                    )
                    await db.execute(update_query)
                    await db.commit()
            except Exception as fallback_error:
                logger.error(f"❌ Failed to update scan status after completion error: {fallback_error}")
        
        logger.info(f"✅ Agentic AI Scan {scan_id} completed successfully with intelligent analysis")
        
    except Exception as e:
        logger.error(f"❌ Agentic AI Scan {scan_id} failed: {e}")
        import traceback
        traceback.print_exc()
        
        # Update scan status to failed
        try:
            async with Database.get_session() as db:
                update_query = update(Scan).where(Scan.id == scan_id).values(
                    status=ScanStatus.FAILED,
                    error_message=f"Agentic AI scan failed: {str(e)}",
                    progress_percentage=0
                )
                await db.execute(update_query)
                await db.commit()
            
            # Broadcast failure with AI context
            await WebSocketManager.manager.broadcast({
                "type": "scan_failed",
                "data": {
                    "scan_id": str(scan_id),
                    "status": "failed",
                    "message": f"🤖 AI-powered scan failed: {str(e)}",
                    "ai_enhanced": True
                }
            })

            # Send failure notification
            try:
                await notification_system.notify_scan_failed(str(scan_id), str(scan_id), f"AI scan failed: {str(e)}")
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
    """Get all scheduled scans (match frontend expectations)."""
    try:
        # Return the raw schedules dict for compatibility with frontend page
        schedules = auto_scan_scheduler.get_scheduled_scans()
        return schedules
    except Exception as e:
        logger.error(f"Error getting scheduled scans: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get scheduled scans: {str(e)}")


@router.post("/schedules/{schedule_id}/execute")
async def execute_scheduled_scan_now(schedule_id: str):
    """Execute a scheduled scan immediately (manual trigger)."""
    try:
        await auto_scan_scheduler.execute_now(schedule_id)
        return {"message": "Scheduled scan executed", "schedule_id": schedule_id}
    except KeyError:
        raise HTTPException(status_code=404, detail="Schedule not found")
    except Exception as e:
        logger.error(f"Error executing scheduled scan now: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to execute scheduled scan: {str(e)}")


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