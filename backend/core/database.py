"""
Database connection and session management for Nexus Hunter
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from loguru import logger

from core.config import get_settings

# Create the declarative base
Base = declarative_base()


class Database:
    """Database connection manager"""
    
    engine = None
    sessionmaker = None
    
    @classmethod
    async def connect(cls) -> None:
        """Initialize database connection"""
        settings = get_settings()
        
        # Handle SQLite vs PostgreSQL URLs
        db_url = settings.database_url
        if db_url.startswith("sqlite:"):
            # Convert sqlite:/// to sqlite+aiosqlite:///
            db_url = db_url.replace("sqlite:", "sqlite+aiosqlite:")
            cls.engine = create_async_engine(
                db_url,
                echo=settings.debug,
                future=True,
            )
        else:
            cls.engine = create_async_engine(
                db_url,
                echo=settings.debug,
                pool_size=20,
                max_overflow=0,
                pool_pre_ping=True,
                pool_recycle=300,
            )
        
        cls.sessionmaker = async_sessionmaker(
            cls.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        
        # Set up connection event listeners
        @event.listens_for(cls.engine.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            """Set SQLite pragmas if using SQLite"""
            if "sqlite" in settings.database_url:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
        
        logger.info(f"🗄️ Database engine created: {settings.database_url}")
    
    @classmethod
    async def disconnect(cls) -> None:
        """Close database connection"""
        if cls.engine:
            await cls.engine.dispose()
            logger.info("🗄️ Database disconnected")
    
    @classmethod
    @asynccontextmanager
    async def get_session(cls) -> AsyncGenerator[AsyncSession, None]:
        """Get database session"""
        if not cls.sessionmaker:
            raise RuntimeError("Database not initialized. Call Database.connect() first.")
        
        async with cls.sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()


# Dependency for FastAPI
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for database session"""
    async with Database.get_session() as session:
        yield session 