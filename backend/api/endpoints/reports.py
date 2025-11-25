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
    # Extract vulnerabilities from both flat format and agent-specific format
    vulns = []
    
    # Check for flat vulnerabilities array (legacy format)
    if 'vulnerabilities' in results and isinstance(results['vulnerabilities'], list):
        vulns.extend(results['vulnerabilities'])
    
    # Check agent-specific results (new format)
    for agent_name, agent_results in results.items():
        if isinstance(agent_results, dict) and 'vulnerabilities' in agent_results:
            agent_vulns = agent_results['vulnerabilities']
            if isinstance(agent_vulns, list):
                vulns.extend(agent_vulns)
    
    # Enhance vulnerability data with proper titles and formatting
    enhanced_vulns = []
    for i, vuln in enumerate(vulns):
        if isinstance(vuln, dict):
            enhanced_vuln = vuln.copy()
            
            # Generate proper title if missing or N/A
            if not enhanced_vuln.get('title') or enhanced_vuln.get('title') in ['N/A', 'Unknown', '']:
                vuln_type = enhanced_vuln.get('vulnerability_type', 'security_issue')
                url = enhanced_vuln.get('url', 'Unknown Location')
                parameter = enhanced_vuln.get('parameter', '')
                
                # Create meaningful titles based on vulnerability type
                if vuln_type == 'confirmed_sql_injection':
                    param_info = f" (parameter: {parameter})" if parameter else ""
                    enhanced_vuln['title'] = f"SQL Injection in {url}{param_info}"
                elif vuln_type == 'local_file_inclusion' or 'lfi' in vuln_type.lower():
                    param_info = f" (parameter: {parameter})" if parameter else ""
                    enhanced_vuln['title'] = f"Local File Inclusion in {url}{param_info}"
                elif 'xss' in vuln_type.lower() or enhanced_vuln.get('xss_type'):
                    param_info = f" (parameter: {parameter})" if parameter else ""
                    enhanced_vuln['title'] = f"Cross-Site Scripting (XSS) in {url}{param_info}"
                elif vuln_type == 'command_injection' or 'rce' in vuln_type.lower():
                    param_info = f" (parameter: {parameter})" if parameter else ""
                    enhanced_vuln['title'] = f"Command Injection in {url}{param_info}"
                elif vuln_type == 'ssrf' or 'server_side_request_forgery' in vuln_type.lower():
                    param_info = f" (parameter: {parameter})" if parameter else ""
                    enhanced_vuln['title'] = f"Server-Side Request Forgery in {url}{param_info}"
                else:
                    # Use vulnerability type as title with proper formatting
                    type_name = vuln_type.replace('_', ' ').title()
                    if type_name in ['N/A', 'Security Issue', '']:
                        type_name = 'Security Vulnerability'
                    param_info = f" (parameter: {parameter})" if parameter else ""
                    enhanced_vuln['title'] = f"{type_name} in {url}{param_info}"
            
            # Generate description if missing or N/A
            if not enhanced_vuln.get('description') or enhanced_vuln.get('description') in ['N/A', 'Unknown', '']:
                vuln_type = enhanced_vuln.get('vulnerability_type', 'security_issue')
                payload = enhanced_vuln.get('payload', enhanced_vuln.get('payload_used', ''))
                evidence = enhanced_vuln.get('evidence', '')
                
                if vuln_type == 'confirmed_sql_injection':
                    enhanced_vuln['description'] = f"SQL injection vulnerability confirmed. Payload: {payload[:100]}{'...' if len(payload) > 100 else ''}"
                elif vuln_type == 'local_file_inclusion' or 'lfi' in vuln_type.lower():
                    file_detected = enhanced_vuln.get('file_detected', enhanced_vuln.get('file_path', 'system files'))
                    enhanced_vuln['description'] = f"Local file inclusion vulnerability allowing access to {file_detected}"
                elif 'xss' in vuln_type.lower():
                    xss_type = enhanced_vuln.get('xss_type', 'reflected')
                    enhanced_vuln['description'] = f"Cross-site scripting ({xss_type}) vulnerability allowing script injection"
                elif vuln_type == 'command_injection' or 'rce' in vuln_type.lower():
                    enhanced_vuln['description'] = f"Command injection vulnerability allowing remote code execution"
                elif vuln_type == 'ssrf':
                    enhanced_vuln['description'] = f"Server-side request forgery vulnerability allowing internal network access"
                else:
                    # Generic description with available evidence
                    desc = f"Security vulnerability of type {vuln_type.replace('_', ' ')}"
                    if evidence:
                        desc += f". Evidence: {evidence[:100]}{'...' if len(evidence) > 100 else ''}"
                    enhanced_vuln['description'] = desc
            
            # Ensure severity is properly formatted
            if enhanced_vuln.get('severity'):
                severity = enhanced_vuln['severity'].upper()
                # Map any non-standard severities
                if severity not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    if 'crit' in severity.lower():
                        severity = 'CRITICAL'
                    elif 'high' in severity.lower():
                        severity = 'HIGH'
                    elif 'med' in severity.lower():
                        severity = 'MEDIUM'
                    else:
                        severity = 'MEDIUM'  # Default for unknown
                enhanced_vuln['severity'] = severity
            else:
                # Assign severity based on vulnerability type if missing
                vuln_type = enhanced_vuln.get('vulnerability_type', '')
                if vuln_type == 'confirmed_sql_injection':
                    enhanced_vuln['severity'] = 'CRITICAL'
                elif 'command_injection' in vuln_type or 'rce' in vuln_type:
                    enhanced_vuln['severity'] = 'CRITICAL'
                elif 'xss' in vuln_type.lower():
                    enhanced_vuln['severity'] = 'HIGH'
                elif 'lfi' in vuln_type.lower():
                    enhanced_vuln['severity'] = 'HIGH'
                elif 'ssrf' in vuln_type.lower():
                    enhanced_vuln['severity'] = 'HIGH'
                else:
                    enhanced_vuln['severity'] = 'MEDIUM'
            
            # Add vulnerability ID for tracking
            enhanced_vuln['id'] = f"NEXUS-{i+1:03d}"
            
            # Ensure URL is properly formatted
            if enhanced_vuln.get('url') and not enhanced_vuln['url'].startswith(('http://', 'https://')):
                enhanced_vuln['url'] = f"http://{enhanced_vuln['url']}"
            
            enhanced_vulns.append(enhanced_vuln)
        # Skip non-dict items (like string keys that were mistakenly added)
        # Don't append vuln if it's not a dict
    
    # Use enhanced vulnerabilities for counting (filter out any non-dict items)
    vulns = [v for v in enhanced_vulns if isinstance(v, dict)]
    medium = len([v for v in vulns if (v.get('severity') or '').lower() == 'medium'])
    high = len([v for v in vulns if (v.get('severity') or '').lower() == 'high'])
    critical = len([v for v in vulns if (v.get('severity') or '').lower() == 'critical'])
    # Extract recon data from agent-specific results
    recon_data = results.get('ReconAgent', {})
    exploit_data = results.get('ExploitAgent', {})
    
    # Get recon statistics from main fields and agent_results
    subdomains = recon_data.get('subdomains', []) or []
    technologies = recon_data.get('technologies', {}) or {}
    ports = recon_data.get('ports', {}) or {}
    urls = recon_data.get('urls', []) or []
    services = recon_data.get('services', {}) or {}
    
    # Also check agent_results for additional data
    agent_results = recon_data.get('agent_results', {})
    if agent_results:
        # Check service_detection for additional data
        service_detection = agent_results.get('service_detection', {})
        if service_detection:
            # Merge technologies and services from service_detection
            sd_technologies = service_detection.get('technologies', {})
            sd_services = service_detection.get('services', {})
            if isinstance(sd_technologies, dict):
                technologies.update(sd_technologies)
            if isinstance(sd_services, dict):
                services.update(sd_services)
                
            # Check sub-agents for port information
            sd_agent_results = service_detection.get('agent_results', {})
            for agent_name, agent_data in sd_agent_results.items():
                if isinstance(agent_data, dict):
                    agent_ports = agent_data.get('ports', {})
                    agent_services = agent_data.get('services', {})
                    agent_technologies = agent_data.get('technologies', {})
                    
                    if isinstance(agent_ports, dict):
                        ports.update(agent_ports)
                    if isinstance(agent_services, dict):
                        services.update(agent_services)
                    if isinstance(agent_technologies, dict):
                        technologies.update(agent_technologies)
    
    # For localhost targets, infer basic information
    target_domain = results.get('target_domain', results.get('target', 'unknown'))
    if '127.0.0.1' in target_domain or 'localhost' in target_domain:
        # Extract port from target (e.g., "127.0.0.1:3002")
        if ':' in target_domain:
            port = target_domain.split(':')[-1]
            if port.isdigit():
                ports[port] = 'open'
                services[port] = 'http'
                technologies['web_server'] = 'detected'
    
    # Count discovered items
    subdomains_count = len(subdomains) if isinstance(subdomains, list) else 0
    technologies_count = len(technologies) if isinstance(technologies, dict) else 0
    ports_count = len(ports) if isinstance(ports, dict) else 0
    urls_count = len(urls) if isinstance(urls, list) else 0
    services_count = len(services) if isinstance(services, dict) else 0
    
    analysis = {
        'target_info': {
            'domain': target_domain,
            'subdomains_discovered': subdomains_count,
            'technologies_identified': technologies_count,
            'ports_discovered': ports_count,
            'urls_discovered': urls_count,
            'services_discovered': services_count,
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
        
        reports = []
        for scan in scans:
            if scan.results:
                # Count vulnerabilities from results
                vuln_count = 0
                if isinstance(scan.results, dict):
                    for agent_name, agent_results in scan.results.items():
                        if isinstance(agent_results, dict) and 'vulnerabilities' in agent_results:
                            vulns = agent_results['vulnerabilities']
                            if isinstance(vulns, list):
                                vuln_count += len(vulns)
                
                report = {
                    "scan_id": str(scan.id),
                    "target_id": str(scan.target_id),
                    "scan_name": scan.name,
                    "report_type": "comprehensive",
                    "status": "completed",
                    "findings_count": vuln_count,
                    "created_at": scan.completed_at.isoformat() if scan.completed_at and hasattr(scan.completed_at, 'isoformat') else (scan.created_at.isoformat() if scan.created_at and hasattr(scan.created_at, 'isoformat') else str(scan.created_at)),
                    "results": scan.results
                }
                reports.append(report)
        
        return reports
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
        
        if not scan.results:
            return []
        
        # Parse results if it's a JSON string (CRITICAL FIX)
        import json
        scan_results = scan.results
        if isinstance(scan_results, str):
            try:
                scan_results = json.loads(scan_results)
            except json.JSONDecodeError:
                scan_results = {}
        
        # Count vulnerabilities from results
        vuln_count = 0
        if isinstance(scan_results, dict):
            for agent_name, agent_results in scan_results.items():
                if isinstance(agent_results, dict) and 'vulnerabilities' in agent_results:
                    vulns = agent_results['vulnerabilities']
                    if isinstance(vulns, list):
                        vuln_count += len(vulns)
        
        # Build analysis for reports
        analysis = _build_analysis_from_results(scan_results)
        vuln_count = analysis.get('scan_summary', {}).get('total_vulnerabilities', vuln_count)
        
        # Generate different report types for this specific scan
        reports = []
        report_types = ["executive", "technical", "comprehensive"]
        
        for report_type in report_types:
            report = {
                "scan_id": str(scan.id),
                "target_id": str(scan.target_id),
                "scan_name": scan.name,
                "report_type": report_type,
                "status": "completed" if scan.status == ScanStatus.COMPLETED else "pending",
                "findings_count": vuln_count,
                "created_at": scan.completed_at.isoformat() if scan.completed_at and hasattr(scan.completed_at, 'isoformat') else (scan.created_at.isoformat() if scan.created_at and hasattr(scan.created_at, 'isoformat') else str(scan.created_at)),
                "analysis": analysis  # Include analysis in report
            }
            reports.append(report)
        
        return reports
    except Exception as e:
        logger.error(f"Failed to get scan reports: {e}")
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
            # Generate executive-focused HTML report
            html = await agent._generate_html_report(analysis, report_type="executive")
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
        
        # Parse results if it's a JSON string (CRITICAL FIX)
        import json
        scan_results = scan.results or {}
        if isinstance(scan_results, str):
            try:
                scan_results = json.loads(scan_results)
            except json.JSONDecodeError:
                scan_results = {}
        
        if format == "html":
            from agents.report_agent import ReportAgent
            agent = ReportAgent()
            analysis = _build_analysis_from_results(scan_results)
            # Generate executive-focused HTML report
            html = await agent._generate_html_report(analysis, report_type="executive")
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
            # Generate technical-focused HTML report
            html = await agent._generate_html_report(analysis, report_type="technical")
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
            # Generate disclosure-focused HTML report
            html = await agent._generate_html_report(analysis, report_type="disclosure")
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
        
        # Parse results if it's a JSON string (CRITICAL FIX)
        import json
        scan_results = scan.results or {}
        if isinstance(scan_results, str):
            try:
                scan_results = json.loads(scan_results)
            except json.JSONDecodeError:
                scan_results = {}
        
        if format == "html":
            from agents.report_agent import ReportAgent
            agent = ReportAgent()
            analysis = _build_analysis_from_results(scan_results)
            # Generate technical-focused HTML report
            html = await agent._generate_html_report(analysis, report_type="technical")
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
            # Enhanced HTML report with all styling and features - type-specific
            html = await agent._generate_html_report(analysis, report_type=kind)
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
                pdf_bytes = await agent.generate_pdf(analysis, report_type=kind)
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