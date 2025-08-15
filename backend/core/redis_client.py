"""
Redis client for caching and real-time features
"""

import json
from typing import Any, Optional, Union

import redis.asyncio as redis
from loguru import logger

from core.config import get_settings


class RedisClient:
    """Redis client manager"""
    
    client: Optional[redis.Redis] = None
    
    @classmethod
    async def connect(cls) -> None:
        """Initialize Redis connection"""
        settings = get_settings()
        
        cls.client = redis.from_url(
            settings.redis_url,
            password=settings.redis_password,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
            socket_keepalive=True,
            socket_keepalive_options={},
            health_check_interval=30,
        )
        
        # Test connection
        try:
            await cls.client.ping()
            logger.info(f"📡 Redis connected: {settings.redis_url}")
        except Exception as e:
            logger.error(f"❌ Redis connection failed: {e}")
            raise
    
    @classmethod
    async def disconnect(cls) -> None:
        """Close Redis connection"""
        if cls.client:
            await cls.client.close()
            logger.info("📡 Redis disconnected")
    
    @classmethod
    async def set(
        cls, 
        key: str, 
        value: Union[str, dict, list], 
        expire: Optional[int] = None
    ) -> bool:
        """Set a value in Redis"""
        if not cls.client:
            raise RuntimeError("Redis not connected")
        
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        
        return await cls.client.set(key, value, ex=expire)
    
    @classmethod
    async def get(cls, key: str, parse_json: bool = True) -> Optional[Any]:
        """Get a value from Redis"""
        if not cls.client:
            raise RuntimeError("Redis not connected")
        
        value = await cls.client.get(key)
        if value is None:
            return None
        
        if parse_json:
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return value
        
        return value
    
    @classmethod
    async def delete(cls, key: str) -> bool:
        """Delete a key from Redis"""
        if not cls.client:
            raise RuntimeError("Redis not connected")
        
        return bool(await cls.client.delete(key))
    
    @classmethod
    async def exists(cls, key: str) -> bool:
        """Check if a key exists in Redis"""
        if not cls.client:
            raise RuntimeError("Redis not connected")
        
        return bool(await cls.client.exists(key))
    
    @classmethod
    async def publish(cls, channel: str, message: Union[str, dict]) -> None:
        """Publish a message to a Redis channel"""
        if not cls.client:
            raise RuntimeError("Redis not connected")
        
        if isinstance(message, dict):
            message = json.dumps(message)
        
        await cls.client.publish(channel, message)
    
    @classmethod
    async def subscribe(cls, channel: str):
        """Subscribe to a Redis channel"""
        if not cls.client:
            raise RuntimeError("Redis not connected")
        
        pubsub = cls.client.pubsub()
        await pubsub.subscribe(channel)
        return pubsub
    
    @classmethod
    async def incr(cls, key: str, amount: int = 1) -> int:
        """Increment a value in Redis"""
        if not cls.client:
            raise RuntimeError("Redis not connected")
        
        return await cls.client.incr(key, amount)
    
    @classmethod
    async def expire(cls, key: str, seconds: int) -> bool:
        """Set expiration time for a key"""
        if not cls.client:
            raise RuntimeError("Redis not connected")
        
        return await cls.client.expire(key, seconds) 