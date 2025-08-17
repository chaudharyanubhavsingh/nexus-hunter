"""
Report generation and retrieval endpoints
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update
from loguru import logger

from core.database import get_db_session
from models.scan import Scan, ScanStatus

router = APIRouter()


class ReportResponse(BaseModel):
    scan_id: UUID
    report_type: str
    content: str
    metadata: Dict[str, Any]


def _build_analysis_from_results(results: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(results, dict):
        return {
            'target_info': {'domain': 'unknown', 'subdomains_discovered': 0, 'technologies_identified': 0, 'ports_discovered': 0},
            'scan_summary': {'total_vulnerabilities': 0, 'critical_count': 0, 'high_count': 0, 'medium_count': 0, 'low_count': 0},
            'vulnerabilities': [],
            'risk_assessment': {'overall_risk': 'Low', 'risk_score': 0, 'key_concerns': [], 'immediate_actions': []},
            'recommendations': [],
        }
    vulns = results.get('vulnerabilities', []) or []
    medium = len([v for v in vulns if (v.get('severity') or '').lower() == 'medium'])
    high = len([v for v in vulns if (v.get('severity') or '').lower() == 'high'])
    critical = len([v for v in vulns if (v.get('severity') or '').lower() == 'critical'])
    analysis = {
        'target_info': {
            'domain': results.get('target_domain', 'unknown'),
            'subdomains_discovered': len(results.get('subdomains', []) or []),
            'technologies_identified': len(results.get('technologies', []) or []),
            'ports_discovered': len(results.get('open_ports', []) or []),
        },
        'scan_summary': {
            'total_vulnerabilities': len(vulns),
            'critical_count': critical,
            'high_count': high,
            'medium_count': medium,
            'low_count': len(vulns) - (critical + high + medium),
        },
        'vulnerabilities': vulns,
        'risk_assessment': {
            'overall_risk': 'Medium' if medium or high or critical else 'Low',
            'risk_score': 50 if medium else 0,
            'key_concerns': [f"{len(vulns)} issues detected"],
            'immediate_actions': ['Review and remediate findings'],
        },
        'recommendations': [
            {'category': 'Immediate Actions', 'priority': 'High', 'recommendation': 'Address identified issues promptly'},
            {'category': 'Monitoring', 'priority': 'Medium', 'recommendation': 'Establish continuous security monitoring'},
        ],
    }
    return analysis


@router.get("/")
async def get_all_reports(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db_session)
):
    """List reports derived from completed scans with results."""
    try:
        query = select(Scan).where(Scan.status == ScanStatus.COMPLETED).offset(skip).limit(limit)
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


def _extract_report(scan: Scan, kind: str) -> str:
    """Extract a specific report string from saved scan results, supporting multiple shapes."""
    if not scan or not scan.results:
        return ""

    results = scan.results

    # Newer structure produced by ReportAgent in execute_scan
    try:
        ra = results.get("ReportAgent") or {}
        reports = ra.get("reports") or {}
        if kind == "executive":
            return reports.get("executive_summary") or ""
        if kind == "technical":
            return reports.get("technical_report") or ""
        if kind == "disclosure":
            # Pick general disclosure if present
            emails = reports.get("disclosure_emails") or {}
            return emails.get("general_disclosure") or ""
    except Exception:
        pass

    # Flat structure fallback
    if kind == "executive":
        return results.get("executive_summary") or results.get("executive") or ""
    if kind == "technical":
        return results.get("technical_report") or results.get("technical") or ""
    if kind == "disclosure":
        return results.get("disclosure_document") or results.get("disclosure") or ""

    return ""


@router.get("/{scan_id}/executive-summary")
async def get_executive_summary(scan_id: UUID, format: str = "markdown", db: AsyncSession = Depends(get_db_session)):
    """Get executive summary report with enhanced HTML and PDF support."""
    try:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if format == "html":
            from agents.report_agent import ReportAgent
            agent = ReportAgent()
            analysis = _build_analysis_from_results(scan.results or {})
            # Use the enhanced comprehensive HTML report
            html = await agent._generate_html_report(analysis)
            return Response(content=html, media_type="text/html")
        else:
            content = _extract_report(scan, "executive")
            if not content:
                raise HTTPException(status_code=404, detail="Executive summary not available")
            return Response(content=content, media_type="text/markdown")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get executive summary for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/executive")
async def get_executive_report(scan_id: UUID, format: str = "html", db: AsyncSession = Depends(get_db_session)):
    """Alternative endpoint for executive report (matches frontend expectations)."""
    try:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if format == "html":
            from agents.report_agent import ReportAgent
            agent = ReportAgent()
            analysis = _build_analysis_from_results(scan.results or {})
            # Use the enhanced comprehensive HTML report
            html = await agent._generate_html_report(analysis)
            return Response(content=html, media_type="text/html")
        else:
            content = _extract_report(scan, "executive")
            if not content:
                raise HTTPException(status_code=404, detail="Executive report not available")
            return Response(content=content, media_type="text/markdown")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get executive report for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/technical-report")
async def get_technical_report(scan_id: UUID, format: str = "markdown", db: AsyncSession = Depends(get_db_session)):
    """Get technical report with enhanced HTML and PDF support."""
    try:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if format == "html":
            from agents.report_agent import ReportAgent
            agent = ReportAgent()
            analysis = _build_analysis_from_results(scan.results or {})
            # Use the enhanced comprehensive HTML report with all styling and features
            html = await agent._generate_html_report(analysis)
            return Response(content=html, media_type="text/html")
        else:
            content = _extract_report(scan, "technical")
            if not content:
                raise HTTPException(status_code=404, detail="Technical report not available")
            return Response(content=content, media_type="text/markdown")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get technical report for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/disclosure-email")
async def get_disclosure_email(scan_id: UUID, db: AsyncSession = Depends(get_db_session)):
    """Get disclosure email content."""
    try:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        content = _extract_report(scan, "disclosure")
        if not content:
            raise HTTPException(status_code=404, detail="Disclosure email not available")
        return Response(content=content, media_type="text/plain")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get disclosure email for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/disclosure")
async def get_disclosure_report(scan_id: UUID, format: str = "html", db: AsyncSession = Depends(get_db_session)):
    """Alternative disclosure endpoint (matches frontend expectations)."""
    try:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if format == "html":
            from agents.report_agent import ReportAgent
            agent = ReportAgent()
            analysis = _build_analysis_from_results(scan.results or {})
            # Use the enhanced comprehensive HTML report
            html = await agent._generate_html_report(analysis)
            return Response(content=html, media_type="text/html")
        else:
            content = _extract_report(scan, "disclosure")
            if not content:
                raise HTTPException(status_code=404, detail="Disclosure report not available")
            return Response(content=content, media_type="text/plain")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get disclosure report for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/technical")
async def get_technical_report_alias(scan_id: UUID, format: str = "html", db: AsyncSession = Depends(get_db_session)):
    """Alternative technical report endpoint (matches frontend expectations)."""
    try:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if format == "html":
            from agents.report_agent import ReportAgent
            agent = ReportAgent()
            analysis = _build_analysis_from_results(scan.results or {})
            # Use the enhanced comprehensive HTML report with all styling and features
            html = await agent._generate_html_report(analysis)
            return Response(content=html, media_type="text/html")
        else:
            content = _extract_report(scan, "technical")
            if not content:
                raise HTTPException(status_code=404, detail="Technical report not available")
            return Response(content=content, media_type="text/markdown")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get technical report for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/download/{report_type}")
async def download_report(scan_id: UUID, report_type: str, format: str = "pdf", db: AsyncSession = Depends(get_db_session)):
    """
    Download a report with enhanced styling. Supported report_type: 'technical' or 'executive'.
    Enhanced PDF generation with exact HTML-to-PDF matching using Playwright.
    """
    try:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        kind = "technical" if report_type.lower().startswith("tech") else "executive"
        
        # Enhanced report generation using the comprehensive ReportAgent
        from agents.report_agent import ReportAgent
        agent = ReportAgent()
        analysis = _build_analysis_from_results(scan.results or {})
        
        filename = f"nexus-hunter-{kind}-security-assessment.{format}"

        if format == "html":
            # Enhanced HTML report with all styling and features
            html = await agent._generate_html_report(analysis)
            return Response(
                content=html, 
                media_type="text/html", 
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Content-Type": "text/html; charset=utf-8"
                }
            )
        elif format in ("markdown", "md"):
            # Fallback to basic markdown
            content = _extract_report(scan, kind)
            if not content:
                # Generate markdown from analysis if not available
                content = await agent._generate_technical_report(analysis)
            return Response(
                content=content, 
                media_type="text/markdown", 
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Content-Type": "text/markdown; charset=utf-8"
                }
            )
        else:
            # Enhanced PDF generation with exact HTML-to-PDF matching
            try:
                logger.info(f"Generating enhanced PDF for {kind} report using Playwright...")
                pdf_bytes = await agent.generate_pdf(analysis)
                logger.info(f"Enhanced PDF generated successfully: {len(pdf_bytes):,} bytes")
                return Response(
                    content=pdf_bytes, 
                    media_type="application/pdf", 
                    headers={
                        "Content-Disposition": f'attachment; filename="{filename}"',
                        "Content-Type": "application/pdf"
                    }
                )
            except Exception as pdf_error:
                logger.error(f"Enhanced PDF generation failed: {pdf_error}")
                # Fallback to basic content
                content = _extract_report(scan, kind)
                if not content:
                    content = f"Enhanced PDF generation failed. Report type: {kind}"
                binary = content.encode("utf-8", errors="ignore")
                return Response(
                    content=binary, 
                    media_type="application/pdf", 
                    headers={
                        "Content-Disposition": f'attachment; filename="{filename}"',
                        "Content-Type": "application/pdf"
                    }
                )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to download enhanced report for {scan_id}: {e}")
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