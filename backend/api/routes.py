"""
Main API routes for Nexus Hunter
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.endpoints import scans, targets, websocket_endpoint, reports
from core.database import get_db_session

# Create main API router
api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(targets.router, prefix="/targets", tags=["targets"])
api_router.include_router(scans.router, prefix="/scans", tags=["AI-powered scans"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(websocket_endpoint.router, prefix="/ws", tags=["websocket"])

# Add vulnerabilities endpoint (using the scans vulnerabilities endpoint)
@api_router.get("/vulnerabilities/")
async def get_all_vulnerabilities(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db_session)):
    """Get all vulnerabilities - redirects to scans vulnerabilities endpoint"""
    from api.endpoints.scans import get_vulnerabilities
    
    return await get_vulnerabilities(skip=skip, limit=limit, db=db) 