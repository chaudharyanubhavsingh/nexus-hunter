"""
Professional WebSocket Manager for Real-time Cybersecurity Communications
Enhanced with intelligent error handling and fallback mechanisms
"""

import asyncio
import json
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import WebSocket
from loguru import logger


class ConnectionManager:
    """Professional WebSocket Connection Manager with Enhanced Resilience"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_metadata: Dict[str, dict] = {}
        self.failed_connections: Dict[str, int] = {}  # Track failed connection attempts
        self.max_retry_attempts = 3
        self.message_queue: Dict[str, List[dict]] = {}  # Queue messages for offline clients
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, client_id: str = None) -> str:
        """Accept a WebSocket connection with enhanced error handling"""
        try:
            await websocket.accept()
            
            if not client_id:
                client_id = str(uuid4())
            
            async with self._lock:
                self.active_connections[client_id] = websocket
                self.connection_metadata[client_id] = {
                    "connected_at": asyncio.get_event_loop().time(),
                    "user_id": None,
                    "subscriptions": set(),
                    "last_ping": asyncio.get_event_loop().time()
                }
                
                # Clear any previous failed connection tracking
                if client_id in self.failed_connections:
                    del self.failed_connections[client_id]
            
            logger.info(f"🔌 Professional WebSocket connected: {client_id}")
            
            # Send any queued messages
            if client_id in self.message_queue:
                await self._send_queued_messages(client_id)
            
            return client_id
            
        except Exception as e:
            logger.error(f"❌ WebSocket connection failed for {client_id}: {e}")
            raise
    
    def disconnect(self, client_id: str):
        """Remove a WebSocket connection safely"""
        try:
            if client_id in self.active_connections:
                del self.active_connections[client_id]
            if client_id in self.connection_metadata:
                del self.connection_metadata[client_id]
            logger.info(f"🔌 WebSocket disconnected: {client_id}")
        except Exception as e:
            logger.error(f"Error during disconnect for {client_id}: {e}")
    
    async def send_personal_message(self, message: dict, client_id: str, queue_if_offline: bool = True):
        """Send a message to a specific client with enhanced error handling"""
        if client_id not in self.active_connections:
            if queue_if_offline:
                await self._queue_message(client_id, message)
            return False
        
        websocket = self.active_connections[client_id]
        
        try:
            message_text = json.dumps(message, default=str)  # Handle non-serializable objects
            await asyncio.wait_for(websocket.send_text(message_text), timeout=5.0)
            return True
            
        except asyncio.TimeoutError:
            logger.warning(f"⏰ Message timeout for client {client_id}")
            await self._handle_failed_connection(client_id)
            return False
        except Exception as e:
            logger.error(f"❌ Failed to send message to {client_id}: {e}")
            await self._handle_failed_connection(client_id)
            return False
    
    async def broadcast_to_all(self, message: dict, exclude_client: str = None, timeout: float = 3.0):
        """Broadcast with enhanced error handling and timeout"""
        if not self.active_connections:
            logger.debug("📡 No active WebSocket connections for broadcast")
            return
        
        try:
            message_text = json.dumps(message, default=str)
        except Exception as e:
            logger.error(f"❌ Failed to serialize broadcast message: {e}")
            return
        
        disconnected_clients = []
        successful_broadcasts = 0
        
        # Create tasks for concurrent sending
        tasks = []
        client_ids = []
        
        for client_id, websocket in self.active_connections.items():
            if client_id == exclude_client:
                continue
            
            task = asyncio.create_task(self._send_with_timeout(websocket, message_text, timeout))
            tasks.append(task)
            client_ids.append(client_id)
        
        # Wait for all sends to complete
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                client_id = client_ids[i]
                if isinstance(result, Exception):
                    logger.error(f"❌ Broadcast failed to {client_id}: {result}")
                    disconnected_clients.append(client_id)
                else:
                    successful_broadcasts += 1
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            self.disconnect(client_id)
        
        logger.debug(f"📡 Broadcast sent to {successful_broadcasts} clients, {len(disconnected_clients)} failed")
    
    async def broadcast(self, message: dict, exclude_client: str = None):
        """Backward compatibility alias for broadcast_to_all"""
        await self.broadcast_to_all(message, exclude_client)
    
    async def send_to_subscription(self, message: dict, subscription: str):
        """Send message to subscribed clients with enhanced error handling"""
        if not self.active_connections:
            return
        
        try:
            message_text = json.dumps(message, default=str)
        except Exception as e:
            logger.error(f"❌ Failed to serialize subscription message: {e}")
            return
        
        disconnected_clients = []
        sent_count = 0
        
        for client_id, websocket in self.active_connections.items():
            if (client_id in self.connection_metadata and 
                subscription in self.connection_metadata[client_id]["subscriptions"]):
                
                try:
                    await asyncio.wait_for(websocket.send_text(message_text), timeout=3.0)
                    sent_count += 1
                except Exception as e:
                    logger.error(f"❌ Failed to send subscription message to {client_id}: {e}")
                    disconnected_clients.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            self.disconnect(client_id)
        
        logger.debug(f"📨 Subscription message sent to {sent_count} clients")
    
    def subscribe_client(self, client_id: str, subscription: str):
        """Subscribe a client to a topic"""
        if client_id in self.connection_metadata:
            self.connection_metadata[client_id]["subscriptions"].add(subscription)
            logger.debug(f"📝 Client {client_id} subscribed to {subscription}")
    
    def unsubscribe_client(self, client_id: str, subscription: str):
        """Unsubscribe a client from a topic"""
        if client_id in self.connection_metadata:
            self.connection_metadata[client_id]["subscriptions"].discard(subscription)
            logger.debug(f"📝 Client {client_id} unsubscribed from {subscription}")
    
    def get_active_connections_count(self) -> int:
        """Get the number of active connections"""
        return len(self.active_connections)
    
    def get_connection_info(self) -> Dict[str, any]:
        """Get detailed connection information"""
        return {
            "active_connections": self.get_active_connections_count(),
            "failed_connections": len(self.failed_connections),
            "queued_messages": sum(len(queue) for queue in self.message_queue.values()),
            "subscriptions": sum(
                len(meta["subscriptions"]) 
                for meta in self.connection_metadata.values()
            )
        }
    
    async def _send_with_timeout(self, websocket: WebSocket, message: str, timeout: float) -> None:
        """Send message with timeout"""
        await asyncio.wait_for(websocket.send_text(message), timeout=timeout)
    
    async def _handle_failed_connection(self, client_id: str):
        """Handle failed connection with retry logic"""
        if client_id not in self.failed_connections:
            self.failed_connections[client_id] = 0
        
        self.failed_connections[client_id] += 1
        
        if self.failed_connections[client_id] >= self.max_retry_attempts:
            logger.warning(f"⚠️ Max retry attempts reached for client {client_id}, disconnecting")
            self.disconnect(client_id)
    
    async def _queue_message(self, client_id: str, message: dict):
        """Queue message for offline client"""
        if client_id not in self.message_queue:
            self.message_queue[client_id] = []
        
        self.message_queue[client_id].append(message)
        
        # Limit queue size to prevent memory issues
        if len(self.message_queue[client_id]) > 100:
            self.message_queue[client_id] = self.message_queue[client_id][-50:]  # Keep last 50
    
    async def _send_queued_messages(self, client_id: str):
        """Send queued messages to newly connected client"""
        if client_id not in self.message_queue:
            return
        
        messages = self.message_queue.pop(client_id, [])
        
        for message in messages:
            await self.send_personal_message(message, client_id, queue_if_offline=False)
        
        logger.info(f"📨 Sent {len(messages)} queued messages to {client_id}")


class WebSocketManager:
    """
    Professional Global WebSocket Manager
    Enhanced with intelligent error handling and resilience
    """
    
    manager: Optional[ConnectionManager] = None
    boot_id: str = None
    _initialization_lock = asyncio.Lock()
    
    @classmethod
    async def initialize(cls):
        """Initialize the WebSocket manager with enhanced error handling"""
        async with cls._initialization_lock:
            try:
                cls.manager = ConnectionManager()
                cls.boot_id = str(uuid4())
                logger.info("🌐 Professional WebSocket manager initialized")
                logger.info(f"🆔 WebSocket boot_id: {cls.boot_id}")
                return True
            except Exception as e:
                logger.error(f"❌ Failed to initialize WebSocket manager: {e}")
                return False
    
    @classmethod
    async def ensure_initialized(cls):
        """Ensure WebSocket manager is initialized before use"""
        if cls.manager is None:
            await cls.initialize()
    
    @classmethod
    async def broadcast_to_all(cls, message: dict, exclude_client: str = None):
        """Broadcast to all connected clients with error handling"""
        await cls.ensure_initialized()
        
        if cls.manager:
            try:
                await cls.manager.broadcast_to_all(message, exclude_client)
            except Exception as e:
                logger.error(f"❌ Failed to broadcast message: {e}")
        else:
            logger.warning("⚠️ WebSocket manager not available for broadcast")
    
    @classmethod  
    async def broadcast(cls, message: dict, exclude_client: str = None):
        """Backward compatibility alias"""
        await cls.broadcast_to_all(message, exclude_client)
    
    @classmethod
    async def broadcast_scan_update(cls, scan_id: str, status: str, data: dict = None):
        """Broadcast scan status update with enhanced error handling"""
        await cls.ensure_initialized()
        
        if not cls.manager:
            logger.debug(f"📊 Scan update (no WebSocket): {scan_id} -> {status}")
            return
        
        try:
            message = {
                "type": "scan_update",
                "scan_id": scan_id,
                "status": status,
                "data": data or {},
                "timestamp": asyncio.get_event_loop().time(),
                "boot_id": cls.boot_id
            }
            
            # Send to specific scan subscription and global scan updates
            await cls.manager.send_to_subscription(message, f"scan:{scan_id}")
            await cls.manager.send_to_subscription(message, "scans")
            
        except Exception as e:
            logger.error(f"❌ Failed to broadcast scan update: {e}")
    
    @classmethod
    async def broadcast_vulnerability_found(cls, scan_id: str, vulnerability: dict):
        """Broadcast vulnerability discovery with enhanced error handling"""
        await cls.ensure_initialized()
        
        if not cls.manager:
            logger.debug(f"🔍 Vulnerability found (no WebSocket): {scan_id}")
            return
        
        try:
            message = {
                "type": "vulnerability_found",
                "scan_id": scan_id,
                "vulnerability": vulnerability,
                "timestamp": asyncio.get_event_loop().time(),
                "boot_id": cls.boot_id
            }
            
            # Send to scan-specific and vulnerability subscriptions
            await cls.manager.send_to_subscription(message, f"scan:{scan_id}")
            await cls.manager.send_to_subscription(message, "vulnerabilities")
            
            # Also broadcast to all for critical vulnerabilities
            if vulnerability.get("severity", "").lower() in ["critical", "high"]:
                await cls.manager.broadcast_to_all(message)
                
        except Exception as e:
            logger.error(f"❌ Failed to broadcast vulnerability: {e}")
    
    @classmethod
    async def broadcast_system_status(cls, status: dict):
        """Broadcast system status update with enhanced error handling"""
        await cls.ensure_initialized()
        
        if not cls.manager:
            logger.debug("🔧 System status update (no WebSocket)")
            return
        
        try:
            message = {
                "type": "system_status",
                "status": status,
                "timestamp": asyncio.get_event_loop().time(),
                "boot_id": cls.boot_id
            }
            
            await cls.manager.broadcast_to_all(message)
            
        except Exception as e:
            logger.error(f"❌ Failed to broadcast system status: {e}")
    
    @classmethod
    async def broadcast_agent_progress(cls, agent_name: str, phase: str, data: dict = None):
        """Broadcast agent progress updates"""
        await cls.ensure_initialized()
        
        if not cls.manager:
            return
        
        try:
            message = {
                "type": "agent_progress",
                "agent_name": agent_name,
                "phase": phase,
                "data": data or {},
                "timestamp": asyncio.get_event_loop().time(),
                "boot_id": cls.boot_id
            }
            
            await cls.manager.send_to_subscription(message, f"agent:{agent_name}")
            await cls.manager.send_to_subscription(message, "agents")
            
        except Exception as e:
            logger.error(f"❌ Failed to broadcast agent progress: {e}")
    
    @classmethod
    def get_boot_id(cls) -> str:
        """Get the current boot ID"""
        return cls.boot_id or "unknown"
    
    @classmethod
    def get_connection_stats(cls) -> Dict[str, any]:
        """Get WebSocket connection statistics"""
        if not cls.manager:
            return {
                "initialized": False,
                "active_connections": 0,
                "error": "WebSocket manager not initialized"
            }
        
        try:
            return {
                "initialized": True,
                "boot_id": cls.boot_id,
                **cls.manager.get_connection_info()
            }
        except Exception as e:
            return {
                "initialized": True,
                "error": str(e),
                "active_connections": 0
            }
    
    @classmethod
    def is_available(cls) -> bool:
        """Check if WebSocket manager is available and functioning"""
        return cls.manager is not None 