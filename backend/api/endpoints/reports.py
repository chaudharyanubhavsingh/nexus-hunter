"""
Report generation and retrieval endpoints
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update
from loguru import logger

from core.database import get_db_session
from models.scan import Scan

router = APIRouter()


class ReportResponse(BaseModel):
    scan_id: UUID
    report_type: str
    content: str
    metadata: Dict[str, Any]


@router.get("/")
async def get_all_reports(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db_session)
):
    """List reports derived from completed scans with results."""
    try:
        query = select(Scan).where(Scan.status == "COMPLETED").offset(skip).limit(limit)
        result = await db.execute(query)
        scans = result.scalars().all()
        return {"reports": [s.results for s in scans if s.results]}
    except Exception as e:
        logger.error(f"Failed to get reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}")
async def get_scan_reports(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """Get reports for a specific scan."""
    try:
        query = select(Scan).where(Scan.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan.results or {}
    except Exception as e:
        logger.error(f"Failed to get reports for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{scan_id}")
async def delete_report(
    scan_id: UUID,
    permanent: bool = False,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Delete report data for a scan.
    - If permanent=False (default): clear results so reports disappear but keep scan.
    - If permanent=True: delete the scan record entirely (and thus all reports).
    """
    try:
        query = select(Scan).where(Scan.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if permanent:
            await db.execute(delete(Scan).where(Scan.id == scan_id))
            await db.commit()
            logger.info(f"🗑️ Permanently deleted scan and its reports: {scan_id}")
            return {"message": "Scan and reports deleted permanently"}
        else:
            await db.execute(
                update(Scan).where(Scan.id == scan_id).values(results=None)
            )
            await db.commit()
            logger.info(f"🧹 Cleared report results for scan: {scan_id}")
            return {"message": "Report data cleared"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete/clear report for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e)) 