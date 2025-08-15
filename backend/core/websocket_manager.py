"""
WebSocket manager for real-time communication
"""

import json
from typing import Dict, List
from uuid import uuid4

from fastapi import WebSocket
from loguru import logger


class ConnectionManager:
    """Manages WebSocket connections"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_metadata: Dict[str, dict] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str = None) -> str:
        """Accept a WebSocket connection"""
        await websocket.accept()
        
        if not client_id:
            client_id = str(uuid4())
        
        self.active_connections[client_id] = websocket
        self.connection_metadata[client_id] = {
            "connected_at": None,
            "user_id": None,
            "subscriptions": set(),
        }
        
        logger.info(f"🔌 WebSocket connected: {client_id}")
        return client_id
    
    def disconnect(self, client_id: str):
        """Remove a WebSocket connection"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            del self.connection_metadata[client_id]
            logger.info(f"🔌 WebSocket disconnected: {client_id}")
    
    async def send_personal_message(self, message: dict, client_id: str):
        """Send a message to a specific client"""
        if client_id in self.active_connections:
            websocket = self.active_connections[client_id]
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.error(f"Failed to send message to {client_id}: {e}")
                self.disconnect(client_id)
    
    async def broadcast(self, message: dict, exclude_client: str = None):
        """Broadcast a message to all connected clients"""
        message_text = json.dumps(message)
        disconnected_clients = []
        
        for client_id, websocket in self.active_connections.items():
            if client_id == exclude_client:
                continue
                
            try:
                await websocket.send_text(message_text)
            except Exception as e:
                logger.error(f"Failed to broadcast to {client_id}: {e}")
                disconnected_clients.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            self.disconnect(client_id)
    
    async def send_to_subscription(self, message: dict, subscription: str):
        """Send message to clients subscribed to a specific topic"""
        message_text = json.dumps(message)
        disconnected_clients = []
        
        for client_id, websocket in self.active_connections.items():
            if subscription in self.connection_metadata[client_id]["subscriptions"]:
                try:
                    await websocket.send_text(message_text)
                except Exception as e:
                    logger.error(f"Failed to send to {client_id}: {e}")
                    disconnected_clients.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            self.disconnect(client_id)
    
    def subscribe_client(self, client_id: str, subscription: str):
        """Subscribe a client to a topic"""
        if client_id in self.connection_metadata:
            self.connection_metadata[client_id]["subscriptions"].add(subscription)
    
    def unsubscribe_client(self, client_id: str, subscription: str):
        """Unsubscribe a client from a topic"""
        if client_id in self.connection_metadata:
            self.connection_metadata[client_id]["subscriptions"].discard(subscription)
    
    def get_active_connections_count(self) -> int:
        """Get the number of active connections"""
        return len(self.active_connections)


class WebSocketManager:
    """Global WebSocket manager"""
    
    manager: ConnectionManager = None
    
    @classmethod
    def initialize(cls):
        """Initialize the WebSocket manager"""
        cls.manager = ConnectionManager()
        logger.info("🌐 WebSocket manager initialized")
    
    @classmethod
    async def broadcast_scan_update(cls, scan_id: str, status: str, data: dict = None):
        """Broadcast scan status update"""
        message = {
            "type": "scan_update",
            "scan_id": scan_id,
            "status": status,
            "data": data or {},
            "timestamp": None,  # Will be set by frontend
        }
        
        await cls.manager.send_to_subscription(message, f"scan:{scan_id}")
    
    @classmethod
    async def broadcast_vulnerability_found(cls, scan_id: str, vulnerability: dict):
        """Broadcast when a vulnerability is found"""
        message = {
            "type": "vulnerability_found",
            "scan_id": scan_id,
            "vulnerability": vulnerability,
            "timestamp": None,
        }
        
        await cls.manager.send_to_subscription(message, f"scan:{scan_id}")
        await cls.manager.send_to_subscription(message, "vulnerabilities")
    
    @classmethod
    async def broadcast_system_status(cls, status: dict):
        """Broadcast system status update"""
        message = {
            "type": "system_status",
            "status": status,
            "timestamp": None,
        }
        
        await cls.manager.broadcast(message) 