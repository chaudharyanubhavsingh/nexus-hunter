"""
Nexus Hunter - Autonomous Bug Bounty Intelligence Platform
Main FastAPI application entry point
"""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

from core.config import get_settings
from core.database import Database
from core.redis_client import RedisClient
from api.routes import api_router
from core.websocket_manager import WebSocketManager
from core.stuck_scan_monitor import stuck_scan_monitor
from core.notification_system import notification_system
from core.auto_scan_scheduler import auto_scan_scheduler
from core.concurrent_scan_manager import concurrent_scan_manager
from core.system_initializer import system_initializer

# Import AI Brain components
from agents.agentic_ai.background_service import start_background_ai, stop_background_ai
from agents.agentic_ai.ai_brain import ai_brain


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan events with professional system initialization"""
    logger.info("🚀 Nexus Hunter Professional Cybersecurity Platform starting...")
    
    # Run comprehensive system initialization
    system_health = await system_initializer.initialize_system()
    
    if system_health.status.value == "failed":
        logger.error("❌ System initialization failed - check logs for details")
        raise Exception(f"System startup failed: {system_health.message}")
    
    # Initialize remaining services based on what's available
    try:
        # Start intelligent stuck scan monitor (if database is available)
        if system_initializer.all_components["database"].status.value == "available":
            await stuck_scan_monitor.start_monitoring()
            logger.info("✅ Stuck scan monitor started")
        
        # Initialize notification system
        await notification_system.enable_notifications(True)
        logger.info("✅ Notification system initialized")
        
        # Start auto-scan scheduler (if database is available)
        if system_initializer.all_components["database"].status.value == "available":
            await auto_scan_scheduler.start_scheduler()
            logger.info("✅ Auto-scan scheduler initialized")
        
        # Start AI Brain background service
        logger.info("🧠 Starting AI Brain background service...")
        try:
            # Start AI Brain in background task
            ai_task = asyncio.create_task(start_background_ai())
            logger.info("✅ AI Brain background service started")
        except Exception as ai_error:
            logger.warning(f"⚠️ AI Brain service failed to start: {ai_error}")
            # Continue without AI Brain
        
        # Send startup notification based on system status
        if system_health.status.value == "ready":
            await notification_system.notify_system_alert(
                "🎯 Professional Platform Ready",
                "Nexus Hunter cybersecurity platform is fully operational with all tools available",
            )
        elif system_health.status.value == "degraded":
            await notification_system.notify_system_alert(
                "⚠️ Platform Started (Partial Mode)",
                f"Nexus Hunter started with some limitations: {system_health.message}",
            )
        else:
            await notification_system.notify_system_alert(
                "🚀 Platform Started",
                f"Nexus Hunter initialized in {system_health.status.value} mode",
            )
    
    except Exception as startup_error:
        logger.warning(f"⚠️ Some services failed to start: {startup_error}")
        # Continue with degraded functionality
    
    logger.info(f"🎯 Nexus Hunter ready in {system_health.status.value} mode")
    
    yield
    
    # Cleanup
    logger.info("🔄 Nexus Hunter shutting down...")
    
    try:
        # Send shutdown notification
        await notification_system.notify_system_alert(
            "System Shutdown",
            "Nexus Hunter is shutting down gracefully",
        )
    except:
        pass  # Ignore notification errors during shutdown
    
    try:
        # Stop monitoring services
        await stuck_scan_monitor.stop_monitoring()
        await auto_scan_scheduler.stop_scheduler()
        
        # Stop AI Brain background service
        logger.info("🧠 Stopping AI Brain background service...")
        try:
            await stop_background_ai()
            logger.info("✅ AI Brain background service stopped")
        except Exception as ai_error:
            logger.warning(f"⚠️ AI Brain service stop error: {ai_error}")
        
        # Disconnect core services (handled by system initializer)
        await Database.disconnect()
        await RedisClient.disconnect()
        
    except Exception as cleanup_error:
        logger.warning(f"Cleanup warning: {cleanup_error}")
    
    logger.info("✅ Professional cybersecurity platform shutdown completed")


def create_application() -> FastAPI:
    """Create and configure the FastAPI application"""
    settings = get_settings()
    
    app = FastAPI(
        title="Nexus Hunter API",
        description="Autonomous Bug Bounty Intelligence Platform",
        version="1.0.0",
        docs_url="/api/docs" if settings.environment == "development" else None,
        redoc_url="/api/redoc" if settings.environment == "development" else None,
        lifespan=lifespan,
    )
    
    # Add middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include API router
    app.include_router(api_router, prefix="/api")
    
    # Global exception handler
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request, exc):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.detail,
                "status_code": exc.status_code,
                "timestamp": asyncio.get_event_loop().time(),
            },
        )
    
    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Health check endpoint"""
        return {
            "status": "healthy",
            "service": "nexus-hunter",
            "version": "1.0.0",
            "environment": settings.environment,
        }
    
    # System status endpoint for UI
    @app.get("/api/system/status")
    async def get_system_status():
        """Get comprehensive system status for UI navbar"""
        try:
            return await system_initializer.health_check()
        except Exception as e:
            logger.error(f"Failed to get system status: {e}")
            return {
                "status": "failed",
                "message": f"Status check failed: {str(e)}",
                "progress_percentage": 0,
                "components": {},
                "summary": {
                    "total_components": 0,
                    "available": 0,
                    "failed": 1,
                    "installing": 0
                }
            }

    # Test endpoint to simulate different system states
    @app.get("/api/system/simulate/{status}")
    async def simulate_system_status(status: str):
        """Simulate different system statuses for UI testing"""
        if status == "initializing":
            return {
                "status": "initializing",
                "message": "Professional cybersecurity platform initializing...",
                "progress_percentage": 25,
                "components": {},
                "summary": {"total_components": 8, "available": 1, "failed": 0, "installing": 3}
            }
        elif status == "setting_up":
            return {
                "status": "setting_up", 
                "message": "Setting up security tools and services...",
                "progress_percentage": 65,
                "components": {},
                "summary": {"total_components": 8, "available": 3, "failed": 1, "installing": 4}
            }
        elif status == "degraded":
            return {
                "status": "degraded",
                "message": "Platform operational with some limitations",
                "progress_percentage": 100,
                "components": {},
                "summary": {"total_components": 8, "available": 4, "failed": 4, "installing": 0}
            }
        else:
            return await get_system_status()
    
    logger.info("🌐 Nexus Hunter API initialized")
    return app


# Create the application instance
app = create_application()


if __name__ == "__main__":
    import uvicorn
    
    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.environment == "development",
        log_level="info",
    ) 