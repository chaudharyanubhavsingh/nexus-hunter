"""
Notification System for Nexus Hunter

Handles notifications for scan completion, vulnerabilities, and system events.
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from enum import Enum
from dataclasses import dataclass
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import Database
from core.websocket_manager import WebSocketManager
from core.config import get_settings
from core.settings_persistence import settings_persistence

logger = logging.getLogger(__name__)

class NotificationType(Enum):
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_STARTED = "scan_started"
    VULNERABILITY_FOUND = "vulnerability_found"
    CRITICAL_VULNERABILITY = "critical_vulnerability"
    SYSTEM_ALERT = "system_alert"

class NotificationPriority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Notification:
    id: str
    type: NotificationType
    priority: NotificationPriority
    title: str
    message: str
    data: Dict[str, Any]
    timestamp: datetime
    read: bool = False

class NotificationSystem:
    """
    Advanced notification system for real-time alerts and updates.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.websocket_manager = WebSocketManager()
        self.notifications_enabled = bool(settings_persistence.get("notifications_enabled", True))
        self.notification_history: List[Notification] = []
        self.max_history = 100
    
    async def enable_notifications(self, enabled: bool):
        """Enable or disable notifications."""
        self.notifications_enabled = enabled
        settings_persistence.set("notifications_enabled", enabled)
        logger.info(f"🔔 Notifications {'enabled' if enabled else 'disabled'}")
    
    async def send_notification(
        self,
        notification_type: NotificationType,
        title: str,
        message: str,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Send a notification through all enabled channels."""
        
        if not self.notifications_enabled:
            return ""
        
        notification_id = f"notif_{datetime.utcnow().timestamp()}"
        notification = Notification(
            id=notification_id,
            type=notification_type,
            priority=priority,
            title=title,
            message=message,
            data=data or {},
            timestamp=datetime.utcnow()
        )
        
        # Add to history
        self.notification_history.append(notification)
        if len(self.notification_history) > self.max_history:
            self.notification_history.pop(0)
        
        # Send via WebSocket
        await self._send_websocket_notification(notification)
        
        # Log the notification
        priority_emoji = {
            NotificationPriority.LOW: "ℹ️",
            NotificationPriority.MEDIUM: "📢",
            NotificationPriority.HIGH: "⚠️",
            NotificationPriority.CRITICAL: "🚨"
        }
        
        logger.info(f"{priority_emoji[priority]} {title}: {message}")
        
        return notification_id
    
    async def _send_websocket_notification(self, notification: Notification):
        """Send notification via WebSocket to connected clients."""
        try:
            await self.websocket_manager.broadcast_to_all({
                "type": "notification",
                "data": {
                    "id": notification.id,
                    "type": notification.type.value,
                    "priority": notification.priority.value,
                    "title": notification.title,
                    "message": notification.message,
                    "timestamp": notification.timestamp.isoformat(),
                    "data": notification.data
                }
            })
        except Exception as e:
            logger.error(f"Failed to send WebSocket notification: {e}")
    
    async def notify_scan_started(self, scan_id: str, scan_name: str, target_domain: str):
        """Notify about scan start."""
        await self.send_notification(
            NotificationType.SCAN_STARTED,
            f"Scan Started: {scan_name}",
            f"Scan started for {target_domain}",
            NotificationPriority.LOW,
            {"scan_id": scan_id, "target": target_domain}
        )
    
    async def notify_scan_completed(self, scan_id: str, scan_name: str, findings_count: int):
        """Notify about completed scan."""
        priority = NotificationPriority.HIGH if findings_count > 0 else NotificationPriority.MEDIUM
        
        await self.send_notification(
            NotificationType.SCAN_COMPLETED,
            f"Scan Completed: {scan_name}",
            f"Scan completed with {findings_count} findings",
            priority,
            {"scan_id": scan_id, "findings_count": findings_count}
        )
    
    async def notify_scan_failed(self, scan_id: str, scan_name: str, error: str):
        """Notify about failed scan."""
        await self.send_notification(
            NotificationType.SCAN_FAILED,
            f"Scan Failed: {scan_name}",
            f"Scan failed: {error}",
            NotificationPriority.HIGH,
            {"scan_id": scan_id, "error": error}
        )
    
    async def notify_vulnerability_found(self, scan_id: str, vulnerability: Dict[str, Any]):
        """Notify about vulnerability found."""
        severity = vulnerability.get('severity', 'medium').lower()
        
        if severity == 'critical':
            priority = NotificationPriority.CRITICAL
            notification_type = NotificationType.CRITICAL_VULNERABILITY
            title = f"🚨 Critical Vulnerability Found"
        else:
            priority = NotificationPriority.HIGH
            notification_type = NotificationType.VULNERABILITY_FOUND
            title = f"⚠️ {severity.title()} Vulnerability Found"
        
        await self.send_notification(
            notification_type,
            title,
            vulnerability.get('title', 'New vulnerability detected'),
            priority,
            {"scan_id": scan_id, "vulnerability": vulnerability}
        )
    
    async def notify_system_alert(self, title: str, message: str, priority: NotificationPriority = NotificationPriority.HIGH):
        """Send system alert notification."""
        await self.send_notification(
            NotificationType.SYSTEM_ALERT,
            title,
            message,
            priority
        )
    
    def get_recent_notifications(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent notification history."""
        return [
            {
                "id": n.id,
                "type": n.type.value,
                "priority": n.priority.value,
                "title": n.title,
                "message": n.message,
                "timestamp": n.timestamp.isoformat(),
                "data": n.data,
                "read": n.read
            }
            for n in self.notification_history[-limit:]
        ]
    
    async def mark_notification_read(self, notification_id: str):
        for n in self.notification_history:
            if n.id == notification_id:
                n.read = True
                break

notification_system = NotificationSystem() 