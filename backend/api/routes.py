"""
Main API routes for Nexus Hunter
"""

from fastapi import APIRouter

from api.endpoints import scans, targets, websocket_endpoint, reports

# Create main API router
api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(targets.router, prefix="/targets", tags=["targets"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(websocket_endpoint.router, prefix="/ws", tags=["websocket"]) 