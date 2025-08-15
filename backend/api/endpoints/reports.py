"""
Report management API endpoints
"""

from typing import Dict, Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from loguru import logger
import io

from core.database import get_db_session
from models.scan import Scan
from core.redis_client import RedisClient

router = APIRouter()


class ReportResponse(BaseModel):
    report_id: str
    scan_id: UUID
    report_types: list
    generated_at: str
    metadata: Dict[str, Any]


@router.get("/{scan_id}")
async def get_scan_reports(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """Get all available reports for a scan"""
    try:
        # Verify scan exists
        query = select(Scan).where(Scan.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get report data from Redis or scan results
        report_key = f"scan_results:{scan_id}"
        report_data = await RedisClient.get(report_key)
        
        if not report_data and scan.results:
            report_data = scan.results
        
        if not report_data:
            raise HTTPException(status_code=404, detail="No reports found for this scan")
        
        # Extract report agent results
        report_agent_data = report_data.get("ReportAgent", {})
        
        if not report_agent_data:
            raise HTTPException(status_code=404, detail="Report generation not completed")
        
        return {
            "scan_id": scan_id,
            "report_id": report_agent_data.get("report_id", "unknown"),
            "available_reports": list(report_agent_data.get("reports", {}).keys()),
            "metadata": report_agent_data.get("metadata", {}),
            "delivery_methods": report_agent_data.get("delivery_methods", [])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get reports for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/executive")
async def get_executive_summary(
    scan_id: UUID,
    format: str = "markdown",
    db: AsyncSession = Depends(get_db_session)
):
    """Get executive summary report"""
    try:
        report_data = await get_report_data(scan_id, db)
        report_agent_data = report_data.get("ReportAgent", {})
        
        executive_report = report_agent_data.get("reports", {}).get("executive_summary")
        
        if not executive_report:
            raise HTTPException(status_code=404, detail="Executive summary not found")
        
        if format.lower() == "html":
            # Convert to HTML if requested
            html_report = report_agent_data.get("reports", {}).get("html_report", "")
            return Response(content=html_report, media_type="text/html")
        
        return Response(content=executive_report, media_type="text/plain")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get executive summary for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/technical")
async def get_technical_report(
    scan_id: UUID,
    format: str = "markdown",
    db: AsyncSession = Depends(get_db_session)
):
    """Get detailed technical report"""
    try:
        report_data = await get_report_data(scan_id, db)
        report_agent_data = report_data.get("ReportAgent", {})
        
        technical_report = report_agent_data.get("reports", {}).get("technical_report")
        
        if not technical_report:
            raise HTTPException(status_code=404, detail="Technical report not found")
        
        if format.lower() == "html":
            html_report = report_agent_data.get("reports", {}).get("html_report", "")
            return Response(content=html_report, media_type="text/html")
        
        return Response(content=technical_report, media_type="text/plain")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get technical report for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/json")
async def get_json_report(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """Get report in JSON format"""
    try:
        report_data = await get_report_data(scan_id, db)
        report_agent_data = report_data.get("ReportAgent", {})
        
        json_report = report_agent_data.get("reports", {}).get("json_report")
        
        if not json_report:
            raise HTTPException(status_code=404, detail="JSON report not found")
        
        return Response(content=json_report, media_type="application/json")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get JSON report for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/disclosure/{disclosure_type}")
async def get_disclosure_email(
    scan_id: UUID,
    disclosure_type: str,
    db: AsyncSession = Depends(get_db_session)
):
    """Get responsible disclosure email template"""
    try:
        report_data = await get_report_data(scan_id, db)
        report_agent_data = report_data.get("ReportAgent", {})
        
        disclosure_emails = report_agent_data.get("reports", {}).get("disclosure_emails", {})
        
        if disclosure_type not in disclosure_emails:
            available_types = list(disclosure_emails.keys())
            raise HTTPException(
                status_code=404, 
                detail=f"Disclosure type '{disclosure_type}' not found. Available: {available_types}"
            )
        
        email_content = disclosure_emails[disclosure_type]
        
        return Response(content=email_content, media_type="text/plain")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get disclosure email for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/download/{report_type}")
async def download_report(
    scan_id: UUID,
    report_type: str,
    format: str = "markdown",
    db: AsyncSession = Depends(get_db_session)
):
    """Download a report as a file"""
    try:
        report_data = await get_report_data(scan_id, db)
        report_agent_data = report_data.get("ReportAgent", {})
        
        # Get the appropriate report content
        reports = report_agent_data.get("reports", {})
        
        if report_type == "executive":
            content = reports.get("executive_summary", "")
            filename = f"nexus_executive_summary_{scan_id}.md"
            media_type = "text/markdown"
        elif report_type == "technical":
            content = reports.get("technical_report", "")
            filename = f"nexus_technical_report_{scan_id}.md"
            media_type = "text/markdown"
        elif report_type == "json":
            content = reports.get("json_report", "{}")
            filename = f"nexus_report_{scan_id}.json"
            media_type = "application/json"
        elif report_type == "html":
            content = reports.get("html_report", "")
            filename = f"nexus_report_{scan_id}.html"
            media_type = "text/html"
        else:
            raise HTTPException(status_code=400, detail="Invalid report type")
        
        if not content:
            raise HTTPException(status_code=404, detail=f"Report type '{report_type}' not found")
        
        # Create file stream
        file_stream = io.StringIO(content)
        
        return StreamingResponse(
            io.BytesIO(content.encode('utf-8')),
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to download report for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/vulnerabilities")
async def get_vulnerability_summary(
    scan_id: UUID,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db_session)
):
    """Get vulnerability summary from scan reports"""
    try:
        report_data = await get_report_data(scan_id, db)
        
        # Extract vulnerability data from both exploit agent and report agent
        exploit_data = report_data.get("ExploitAgent", {})
        report_metadata = report_data.get("ReportAgent", {}).get("metadata", {})
        
        vulnerabilities = exploit_data.get("vulnerabilities", [])
        
        # Filter by severity if specified
        if severity:
            vulnerabilities = [v for v in vulnerabilities if v.get("severity", "").lower() == severity.lower()]
        
        # Group by severity
        severity_counts = {}
        categories = set()
        
        for vuln in vulnerabilities:
            vuln_severity = vuln.get("severity", "unknown")
            vuln_category = vuln.get("category", "unknown")
            
            severity_counts[vuln_severity] = severity_counts.get(vuln_severity, 0) + 1
            categories.add(vuln_category)
        
        return {
            "scan_id": scan_id,
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": severity_counts,
            "categories": list(categories),
            "vulnerabilities": vulnerabilities,
            "risk_assessment": report_metadata.get("risk_assessment", {}),
            "filtered_by_severity": severity
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get vulnerability summary for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def get_report_data(scan_id: UUID, db: AsyncSession) -> Dict[str, Any]:
    """Helper function to get report data from Redis or database"""
    # Verify scan exists
    query = select(Scan).where(Scan.id == scan_id)
    result = await db.execute(query)
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get report data from Redis first, then fallback to database
    report_key = f"scan_results:{scan_id}"
    report_data = await RedisClient.get(report_key)
    
    if not report_data and scan.results:
        report_data = scan.results
    
    if not report_data:
        raise HTTPException(status_code=404, detail="No report data found for this scan")
    
    return report_data 