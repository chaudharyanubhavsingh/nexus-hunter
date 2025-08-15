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


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan events"""
    logger.info("🚀 Nexus Hunter starting up...")
    
    # Initialize database
    await Database.connect()
    logger.info("✅ Database connected")
    
    # Create database tables
    await Database.create_tables()
    logger.info("✅ Database tables created")
    
    # Initialize Redis
    await RedisClient.connect()
    logger.info("✅ Redis connected")
    
    # Initialize WebSocket manager
    WebSocketManager.initialize()
    logger.info("✅ WebSocket manager initialized")
    
    yield
    
    # Cleanup
    logger.info("🔄 Nexus Hunter shutting down...")
    await Database.disconnect()
    await RedisClient.disconnect()
    logger.info("✅ Cleanup completed")


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