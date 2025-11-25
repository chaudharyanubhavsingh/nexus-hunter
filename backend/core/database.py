"""
Professional Database Connection Manager for Cybersecurity Platform
Enhanced with intelligent concurrency handling and fallback mechanisms
"""

import asyncio
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
from urllib.parse import urlparse

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from fastapi import HTTPException
from loguru import logger

from core.config import get_settings

# Create the declarative base
Base = declarative_base()


class Database:
    """
    Professional Database Connection Manager
    Enhanced with concurrency handling and intelligent fallback
    """
    
    engine = None
    sessionmaker = None
    database_type: str = "unknown"
    is_sqlite: bool = False
    connection_retries: int = 0
    max_retries: int = 3
    
    @classmethod
    async def connect(cls) -> None:
        """Initialize database connection with enhanced concurrency support"""
        settings = get_settings()
        db_url = settings.database_url
        
        # Determine database type
        parsed_url = urlparse(db_url)
        cls.database_type = parsed_url.scheme
        cls.is_sqlite = "sqlite" in db_url.lower()
        
        # Enhanced SQLite configuration for concurrency
        if cls.is_sqlite:
            # Convert sqlite:/// to sqlite+aiosqlite:///
            if db_url.startswith("sqlite:"):
                db_url = db_url.replace("sqlite:", "sqlite+aiosqlite:")
            
            # SQLite-specific engine with concurrency optimizations
            cls.engine = create_async_engine(
                db_url,
                echo=settings.debug,
                future=True,
                # SQLite connection pool settings
                pool_size=1,  # SQLite works best with single connection per pool
                max_overflow=20,  # Allow overflow connections for concurrency
                pool_timeout=30,  # Wait up to 30 seconds for connection
                pool_recycle=3600,  # Recycle connections every hour
                pool_pre_ping=True,  # Validate connections before use
                # Connection arguments for SQLite
                connect_args={
                    "timeout": 20,  # SQLite connection timeout
                    "check_same_thread": False,
                }
            )
            logger.info("🗄️ SQLite database configured with enhanced concurrency support")
            
        else:
            # PostgreSQL or other database engines
            cls.engine = create_async_engine(
                db_url,
                echo=settings.debug,
                pool_size=20,
                max_overflow=10,
                pool_pre_ping=True,
                pool_recycle=300,
                pool_timeout=30,
            )
            logger.info(f"🗄️ {cls.database_type.upper()} database engine configured")
        
        cls.sessionmaker = async_sessionmaker(
            cls.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            # Enhanced session configuration
            autoflush=True,
            autocommit=False,
        )
        
        # Enhanced SQLite pragmas for concurrency
        if cls.is_sqlite:
            @event.listens_for(cls.engine.sync_engine, "connect")
            def set_sqlite_concurrency_pragmas(dbapi_connection, connection_record):
                """Set SQLite pragmas for enhanced concurrency"""
                cursor = dbapi_connection.cursor()
                
                # Essential pragmas for concurrency
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging for better concurrency
                cursor.execute("PRAGMA synchronous=NORMAL")  # Balance between safety and performance
                cursor.execute("PRAGMA cache_size=10000")  # Larger cache for better performance
                cursor.execute("PRAGMA temp_store=MEMORY")  # Store temp tables in memory
                cursor.execute("PRAGMA mmap_size=268435456")  # 256MB memory-mapped I/O
                cursor.execute("PRAGMA busy_timeout=30000")  # 30-second busy timeout
                cursor.execute("PRAGMA wal_autocheckpoint=1000")  # Auto-checkpoint every 1000 pages
                
                cursor.close()
                logger.debug("✅ SQLite concurrency pragmas applied")
        
        logger.info(f"🗄️ Professional database engine ready: {db_url[:50]}...")
    
    @classmethod
    async def create_tables(cls) -> None:
        """Create all database tables"""
        # Import models to register them with Base
        from models.scan import Target, Scan, Finding  # noqa
        from models.base import BaseModel  # noqa
        
        if not cls.engine:
            raise RuntimeError("Database not connected. Call Database.connect() first.")
        
        async with cls.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("🗄️ Database tables created")
    
    @classmethod
    async def disconnect(cls) -> None:
        """Close database connection"""
        if cls.engine:
            await cls.engine.dispose()
            logger.info("🗄️ Database disconnected")
    
    @classmethod
    @asynccontextmanager
    async def get_session(cls, auto_retry: bool = True, max_retries: int = 3) -> AsyncGenerator[AsyncSession, None]:
        """
        Get database session with intelligent retry logic for concurrency conflicts
        """
        if not cls.sessionmaker:
            raise RuntimeError("Database not initialized. Call Database.connect() first.")
        
        retry_count = 0
        while retry_count <= max_retries:
            try:
                async with cls.sessionmaker() as session:
                    try:
                        yield session
                        await session.commit()
                        return  # Success, exit retry loop
                        
                    except (OperationalError, SQLAlchemyError) as e:
                        await session.rollback()
                        
                        # Check if this is a retryable error (database locked, etc.)
                        if (auto_retry and retry_count < max_retries and 
                            cls._is_retryable_error(e)):
                            retry_count += 1
                            retry_delay = min(0.1 * (2 ** retry_count), 2.0)  # Exponential backoff, max 2s
                            logger.warning(f"⚠️ Database conflict (attempt {retry_count}/{max_retries}), retrying in {retry_delay:.2f}s: {str(e)[:100]}")
                            await asyncio.sleep(retry_delay)
                            continue
                        else:
                            raise
                            
                    except Exception as e:
                        await session.rollback()
                        raise
                        
            except Exception as e:
                if retry_count >= max_retries:
                    logger.error(f"❌ Database operation failed after {max_retries} retries: {e}")
                    raise
                # Continue retry loop for retryable errors
                continue
                
        # Should not reach here, but safety check
        raise RuntimeError(f"Database operation failed after {max_retries} retries")
    
    @classmethod
    def _is_retryable_error(cls, error: Exception) -> bool:
        """Check if database error is retryable"""
        error_str = str(error).lower()
        retryable_patterns = [
            "database is locked",
            "database or disk is full", 
            "disk i/o error",
            "cannot start a transaction within a transaction",
            "connection pool is full",
            "connection was invalidated",
            "server closed the connection unexpectedly",
            "timeout expired",
            "deadlock detected"
        ]
        
        return any(pattern in error_str for pattern in retryable_patterns)
    
    @classmethod
    async def execute_with_retry(cls, query, params=None, max_retries: int = 3):
        """Execute a query with automatic retry logic"""
        retry_count = 0
        
        while retry_count <= max_retries:
            try:
                async with cls.get_session(auto_retry=False) as session:
                    if params:
                        result = await session.execute(text(query), params)
                    else:
                        result = await session.execute(text(query))
                    await session.commit()
                    return result
                    
            except Exception as e:
                if retry_count >= max_retries or not cls._is_retryable_error(e):
                    raise
                    
                retry_count += 1
                retry_delay = min(0.1 * (2 ** retry_count), 1.0)
                logger.warning(f"⚠️ Query retry {retry_count}/{max_retries} in {retry_delay:.2f}s")
                await asyncio.sleep(retry_delay)
    
    @classmethod
    async def health_check(cls) -> dict:
        """Perform database health check"""
        if not cls.engine:
            return {
                "status": "not_connected",
                "database_type": "unknown",
                "error": "Database engine not initialized"
            }
        
        try:
            start_time = time.time()
            async with cls.get_session(auto_retry=False, max_retries=1) as session:
                await session.execute(text("SELECT 1"))
            
            response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            
            return {
                "status": "healthy",
                "database_type": cls.database_type,
                "is_sqlite": cls.is_sqlite,
                "response_time_ms": round(response_time, 2),
                "connection_pool_size": cls.engine.pool.size() if hasattr(cls.engine.pool, 'size') else 'unknown',
                "checked_out_connections": cls.engine.pool.checkedout() if hasattr(cls.engine.pool, 'checkedout') else 'unknown'
            }
            
        except Exception as e:
            return {
                "status": "unhealthy", 
                "database_type": cls.database_type,
                "is_sqlite": cls.is_sqlite,
                "error": str(e),
                "connection_retries": cls.connection_retries
            }
    
    @classmethod
    def get_database_info(cls) -> dict:
        """Get database configuration information"""
        return {
            "database_type": cls.database_type,
            "is_sqlite": cls.is_sqlite,
            "engine_configured": cls.engine is not None,
            "sessionmaker_configured": cls.sessionmaker is not None,
            "max_retries": cls.max_retries,
            "connection_retries": cls.connection_retries
        }


# Dependency for FastAPI
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for database session - simplified for better exception handling
    """
    if not Database.sessionmaker:
        raise RuntimeError("Database not initialized. Call Database.connect() first.")
    
    async with Database.sessionmaker() as session:
        yield session 