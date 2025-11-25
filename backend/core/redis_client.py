"""
Professional Redis Client with Intelligent Fallback
Enhanced for cybersecurity platform reliability
"""

import asyncio
import json
import time
from typing import Any, Dict, Optional, Union

from loguru import logger

# Try importing Redis, fall back to memory if not available
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("⚠️ Redis library not available - using memory fallback")

from core.config import get_settings


class MemoryFallback:
    """In-memory fallback when Redis is unavailable"""
    
    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._expiry: Dict[str, float] = {}
        self.connected = True
        
    def _cleanup_expired(self):
        """Remove expired keys"""
        current_time = time.time()
        expired_keys = [
            key for key, expiry_time in self._expiry.items() 
            if current_time > expiry_time
        ]
        for key in expired_keys:
            self._data.pop(key, None)
            self._expiry.pop(key, None)
    
    async def ping(self):
        """Memory fallback ping"""
        return True
        
    async def set(self, key: str, value: Any, ex: Optional[int] = None) -> bool:
        """Set value with optional expiration"""
        self._cleanup_expired()
        self._data[key] = value
        if ex:
            self._expiry[key] = time.time() + ex
        return True
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value by key"""
        self._cleanup_expired()
        return self._data.get(key)
    
    async def delete(self, key: str) -> bool:
        """Delete key"""
        deleted = key in self._data
        self._data.pop(key, None)
        self._expiry.pop(key, None)
        return deleted
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        self._cleanup_expired()
        return key in self._data
    
    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment value"""
        self._cleanup_expired()
        current = self._data.get(key, 0)
        try:
            new_value = int(current) + amount
        except (ValueError, TypeError):
            new_value = amount
        self._data[key] = new_value
        return new_value
    
    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration for key"""
        if key in self._data:
            self._expiry[key] = time.time() + seconds
            return True
        return False
    
    async def publish(self, channel: str, message: Any):
        """Memory fallback for pub/sub (no-op)"""
        logger.debug(f"Memory fallback: Would publish to {channel}")
        return 1
    
    async def close(self):
        """Close connection (no-op for memory)"""
        pass


class RedisClient:
    """
    Professional Redis Client Manager with Intelligent Fallback
    Automatically switches to memory fallback when Redis is unavailable
    """
    
    client: Optional[Union[redis.Redis, MemoryFallback]] = None
    fallback_mode: bool = False
    connection_attempts: int = 0
    max_connection_attempts: int = 3
    
    @classmethod
    async def connect(cls) -> None:
        """Initialize Redis connection with intelligent fallback"""
        settings = get_settings()
        
        # Try Redis connection first
        if REDIS_AVAILABLE and not cls.fallback_mode:
            cls.connection_attempts += 1
            try:
                cls.client = redis.from_url(
                    settings.redis_url,
                    password=settings.redis_password,
                    encoding="utf-8",
                    decode_responses=True,
                    max_connections=20,
                    socket_keepalive=True,
                    socket_keepalive_options={},
                    health_check_interval=30,
                    socket_connect_timeout=5,  # 5 second timeout
                    socket_timeout=5,
                    retry_on_timeout=True
                )
                
                # Test connection with timeout
                await asyncio.wait_for(cls.client.ping(), timeout=5.0)
                logger.info(f"✅ Redis connected: {settings.redis_url}")
                cls.fallback_mode = False
                return
                
            except Exception as e:
                logger.warning(f"⚠️ Redis connection attempt {cls.connection_attempts} failed: {e}")
                
                if cls.connection_attempts >= cls.max_connection_attempts:
                    logger.warning("📦 Maximum Redis connection attempts reached, switching to memory fallback")
                    cls.fallback_mode = True
                else:
                    # Try one more time after a short delay
                    await asyncio.sleep(1)
                    try:
                        await asyncio.wait_for(cls.client.ping(), timeout=3.0)
                        logger.info(f"✅ Redis connected on retry: {settings.redis_url}")
                        return
                    except:
                        cls.fallback_mode = True
        
        # Use memory fallback
        cls.client = MemoryFallback()
        logger.info("🧠 Using high-performance memory fallback for caching")
        cls.fallback_mode = True
    
    @classmethod 
    async def ping(cls) -> bool:
        """Test Redis connection"""
        if not cls.client:
            return False
        try:
            await cls.client.ping()
            return True
        except Exception:
            return False
    
    @classmethod
    async def disconnect(cls) -> None:
        """Close Redis connection"""
        if cls.client:
            await cls.client.close()
            if cls.fallback_mode:
                logger.info("🧠 Memory fallback disconnected")
            else:
                logger.info("📡 Redis disconnected")
    
    @classmethod
    async def set(
        cls, 
        key: str, 
        value: Union[str, dict, list], 
        expire: Optional[int] = None
    ) -> bool:
        """Set a value with intelligent fallback handling"""
        if not cls.client:
            logger.warning("Redis/Memory client not connected")
            return False
        
        try:
            # Handle JSON serialization for complex types
            if isinstance(value, (dict, list)) and not cls.fallback_mode:
                value = json.dumps(value)
            elif isinstance(value, (dict, list)) and cls.fallback_mode:
                # Memory fallback handles objects directly
                pass
            
            return await cls.client.set(key, value, ex=expire)
            
        except Exception as e:
            logger.error(f"Failed to set key {key}: {e}")
            return False
    
    @classmethod
    async def get(cls, key: str, parse_json: bool = True) -> Optional[Any]:
        """Get a value with intelligent fallback handling"""
        if not cls.client:
            logger.warning("Redis/Memory client not connected")
            return None
        
        try:
            value = await cls.client.get(key)
            if value is None:
                return None
            
            # Handle JSON parsing for Redis (memory fallback stores objects directly)
            if parse_json and not cls.fallback_mode:
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    return value
            
            return value
            
        except Exception as e:
            logger.error(f"Failed to get key {key}: {e}")
            return None
    
    @classmethod
    async def delete(cls, key: str) -> bool:
        """Delete a key with intelligent fallback handling"""
        if not cls.client:
            return False
        
        try:
            return bool(await cls.client.delete(key))
        except Exception as e:
            logger.error(f"Failed to delete key {key}: {e}")
            return False
    
    @classmethod
    async def exists(cls, key: str) -> bool:
        """Check if a key exists with intelligent fallback handling"""
        if not cls.client:
            return False
        
        try:
            return bool(await cls.client.exists(key))
        except Exception as e:
            logger.error(f"Failed to check key existence {key}: {e}")
            return False
    
    @classmethod
    async def publish(cls, channel: str, message: Union[str, dict]) -> None:
        """Publish a message with intelligent fallback handling"""
        if not cls.client:
            return
        
        try:
            if isinstance(message, dict):
                message = json.dumps(message)
            
            await cls.client.publish(channel, message)
            
        except Exception as e:
            logger.error(f"Failed to publish to channel {channel}: {e}")
    
    @classmethod
    async def subscribe(cls, channel: str):
        """Subscribe to a Redis channel (Redis only)"""
        if not cls.client or cls.fallback_mode:
            logger.warning("Pub/Sub not available in memory fallback mode")
            return None
        
        try:
            pubsub = cls.client.pubsub()
            await pubsub.subscribe(channel)
            return pubsub
        except Exception as e:
            logger.error(f"Failed to subscribe to channel {channel}: {e}")
            return None
    
    @classmethod
    async def incr(cls, key: str, amount: int = 1) -> int:
        """Increment a value with intelligent fallback handling"""
        if not cls.client:
            return 0
        
        try:
            return await cls.client.incr(key, amount)
        except Exception as e:
            logger.error(f"Failed to increment key {key}: {e}")
            return 0
    
    @classmethod
    async def expire(cls, key: str, seconds: int) -> bool:
        """Set expiration time with intelligent fallback handling"""
        if not cls.client:
            return False
        
        try:
            return await cls.client.expire(key, seconds)
        except Exception as e:
            logger.error(f"Failed to set expiration for key {key}: {e}")
            return False
    
    @classmethod
    def is_connected(cls) -> bool:
        """Check if Redis/Memory client is connected"""
        return cls.client is not None
    
    @classmethod
    def is_fallback_mode(cls) -> bool:
        """Check if running in memory fallback mode"""
        return cls.fallback_mode
    
    @classmethod
    def get_mode_info(cls) -> Dict[str, Any]:
        """Get connection mode information"""
        return {
            "connected": cls.is_connected(),
            "fallback_mode": cls.is_fallback_mode(),
            "connection_attempts": cls.connection_attempts,
            "mode": "memory_fallback" if cls.fallback_mode else "redis"
        } 