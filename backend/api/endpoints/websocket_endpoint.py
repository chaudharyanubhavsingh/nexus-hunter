"""
WebSocket endpoints for real-time communication
"""

import json
from typing import Dict, Any
from uuid import uuid4

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from loguru import logger

from core.websocket_manager import WebSocketManager

router = APIRouter()


@router.websocket("")
async def websocket_simple(websocket: WebSocket):
    """Simple WebSocket endpoint for frontend connectivity"""
    await websocket.accept()
    client_id = str(uuid4())
    
    try:
        # Add to connection manager
        WebSocketManager.manager.active_connections[client_id] = websocket
        logger.info(f"🔌 Simple WebSocket client connected: {client_id}")
        
        # Send connection status
        await websocket.send_text(json.dumps({
            "type": "connection_status",
            "status": "connected",
            "client_id": client_id
        }))
        
        # Keep connection alive and handle messages
        while True:
            try:
                # Wait for messages from client
                data = await websocket.receive_text()
                
                # Echo back for now
                await websocket.send_text(json.dumps({
                    "type": "echo",
                    "data": f"Echo: {data}"
                }))
                
            except WebSocketDisconnect:
                logger.info(f"🔌 Simple WebSocket client disconnected: {client_id}")
                break
                
    except Exception as e:
        logger.error(f"Simple WebSocket error: {e}")
        
    finally:
        # Clean up
        if client_id in WebSocketManager.manager.active_connections:
            del WebSocketManager.manager.active_connections[client_id]


@router.websocket("/connect")
async def websocket_endpoint(websocket: WebSocket):
    """Main WebSocket endpoint for real-time communication"""
    client_id = None
    
    try:
        # Accept connection
        client_id = await WebSocketManager.manager.connect(websocket)
        logger.info(f"🔌 WebSocket client connected: {client_id}")
        
        # Send welcome message
        welcome_message = {
            "type": "connection_established",
            "client_id": client_id,
            "message": "Connected to Nexus Hunter real-time feed",
            "timestamp": None
        }
        await WebSocketManager.manager.send_personal_message(welcome_message, client_id)
        
        # Listen for incoming messages
        while True:
            try:
                # Receive message from client
                data = await websocket.receive_text()
                message = json.loads(data)
                
                # Handle different message types
                await handle_client_message(client_id, message)
                
            except WebSocketDisconnect:
                logger.info(f"🔌 WebSocket client disconnected: {client_id}")
                break
                
            except json.JSONDecodeError:
                error_message = {
                    "type": "error",
                    "message": "Invalid JSON format",
                    "timestamp": None
                }
                await WebSocketManager.manager.send_personal_message(error_message, client_id)
                
            except Exception as e:
                logger.error(f"Error handling WebSocket message: {e}")
                error_message = {
                    "type": "error",
                    "message": f"Message handling error: {str(e)}",
                    "timestamp": None
                }
                await WebSocketManager.manager.send_personal_message(error_message, client_id)
                
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
        
    finally:
        if client_id:
            WebSocketManager.manager.disconnect(client_id)


async def handle_client_message(client_id: str, message: Dict[str, Any]):
    """Handle incoming messages from WebSocket clients"""
    
    message_type = message.get("type")
    
    if message_type == "subscribe":
        # Subscribe to specific topics
        topics = message.get("topics", [])
        for topic in topics:
            WebSocketManager.manager.subscribe_client(client_id, topic)
        
        response = {
            "type": "subscription_confirmed",
            "topics": topics,
            "message": f"Subscribed to {len(topics)} topics",
            "timestamp": None
        }
        await WebSocketManager.manager.send_personal_message(response, client_id)
        
    elif message_type == "unsubscribe":
        # Unsubscribe from specific topics
        topics = message.get("topics", [])
        for topic in topics:
            WebSocketManager.manager.unsubscribe_client(client_id, topic)
        
        response = {
            "type": "unsubscription_confirmed",
            "topics": topics,
            "message": f"Unsubscribed from {len(topics)} topics",
            "timestamp": None
        }
        await WebSocketManager.manager.send_personal_message(response, client_id)
        
    elif message_type == "ping":
        # Respond to ping with pong
        response = {
            "type": "pong",
            "message": "Connection alive",
            "timestamp": None
        }
        await WebSocketManager.manager.send_personal_message(response, client_id)
        
    elif message_type == "get_status":
        # Send current system status
        status = {
            "type": "system_status",
            "data": {
                "active_connections": WebSocketManager.manager.get_active_connections_count(),
                "server_status": "online",
                "version": "1.0.0"
            },
            "timestamp": None
        }
        await WebSocketManager.manager.send_personal_message(status, client_id)
        
    else:
        # Unknown message type
        error_response = {
            "type": "error",
            "message": f"Unknown message type: {message_type}",
            "timestamp": None
        }
        await WebSocketManager.manager.send_personal_message(error_response, client_id)


@router.websocket("/scan/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for specific scan updates"""
    client_id = None
    
    try:
        # Accept connection
        client_id = await WebSocketManager.manager.connect(websocket)
        
        # Auto-subscribe to scan updates
        WebSocketManager.manager.subscribe_client(client_id, f"scan:{scan_id}")
        
        logger.info(f"🔌 Client {client_id} connected to scan {scan_id}")
        
        # Send initial message
        welcome_message = {
            "type": "scan_connection_established",
            "scan_id": scan_id,
            "client_id": client_id,
            "message": f"Connected to scan {scan_id} updates",
            "timestamp": None
        }
        await WebSocketManager.manager.send_personal_message(welcome_message, client_id)
        
        # Keep connection alive
        while True:
            try:
                # Receive any client messages (like ping)
                data = await websocket.receive_text()
                message = json.loads(data)
                
                if message.get("type") == "ping":
                    pong_response = {
                        "type": "pong",
                        "scan_id": scan_id,
                        "timestamp": None
                    }
                    await WebSocketManager.manager.send_personal_message(pong_response, client_id)
                    
            except WebSocketDisconnect:
                logger.info(f"🔌 Scan WebSocket client disconnected: {client_id}")
                break
                
            except Exception as e:
                logger.error(f"Error in scan WebSocket: {e}")
                break
                
    except Exception as e:
        logger.error(f"Scan WebSocket connection error: {e}")
        
    finally:
        if client_id:
            WebSocketManager.manager.disconnect(client_id) 