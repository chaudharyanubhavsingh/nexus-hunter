"""
Concurrent Scan Manager for Nexus Hunter

Manages the number of simultaneous scans to prevent resource overload.
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Optional, Set
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import Database
from core.notification_system import notification_system
from core.config import get_settings
from core.settings_persistence import settings_persistence

logger = logging.getLogger(__name__)

class ConcurrentScanManager:
    """
    Manages concurrent scan execution to prevent resource overload.
    """
    
    def __init__(self):
        self.settings = get_settings()
        # Restore persisted limit or default to 3
        self.max_concurrent_scans = int(settings_persistence.get("concurrent_scans", 3))
        self.running_scans: Set[str] = set()
        self.scan_queue: List[Dict[str, any]] = []
        self.is_processing_queue = False
    
    async def set_concurrent_limit(self, limit: int):
        """Set the maximum number of concurrent scans."""
        if limit < 1 or limit > 10:
            raise ValueError("Concurrent scan limit must be between 1 and 10")
        
        old_limit = self.max_concurrent_scans
        self.max_concurrent_scans = limit
        # Persist
        settings_persistence.set("concurrent_scans", limit)
        
        logger.info(f"🔄 Updated concurrent scan limit: {old_limit} → {limit}")
        
        # Process queue if we increased the limit
        if limit > old_limit:
            await self._process_scan_queue()
    
    async def can_start_scan(self) -> bool:
        """Check if a new scan can be started."""
        current_count = await self._get_current_running_scans()
        return current_count < self.max_concurrent_scans
    
    async def request_scan_slot(self, scan_id: str, scan_data: Dict[str, any]) -> bool:
        """
        Request a slot to start a scan.
        
        Returns:
            True if scan can start immediately, False if queued
        """
        if await self.can_start_scan():
            self.running_scans.add(scan_id)
            logger.info(f"🚀 Scan {scan_id} started immediately ({len(self.running_scans)}/{self.max_concurrent_scans})")
            return True
        else:
            # Add to queue
            self.scan_queue.append({
                "scan_id": scan_id,
                "scan_data": scan_data,
                "queued_at": datetime.utcnow()
            })
            
            queue_position = len(self.scan_queue)
            logger.info(f"⏳ Scan {scan_id} queued (position: {queue_position})")
            
            await notification_system.notify_system_alert(
                "Scan Queued",
                f"Scan queued due to concurrent limit. Position: {queue_position}",
            )
            
            return False
    
    async def release_scan_slot(self, scan_id: str):
        """Release a scan slot when scan completes."""
        if scan_id in self.running_scans:
            self.running_scans.remove(scan_id)
            logger.info(f"✅ Scan {scan_id} completed, slot released ({len(self.running_scans)}/{self.max_concurrent_scans})")
            
            # Process queue to start next scan
            await self._process_scan_queue()
    
    async def _process_scan_queue(self):
        """Process the scan queue to start pending scans."""
        if self.is_processing_queue or not self.scan_queue:
            return
        
        self.is_processing_queue = True
        
        try:
            while self.scan_queue and await self.can_start_scan():
                queued_scan = self.scan_queue.pop(0)
                scan_id = queued_scan["scan_id"]
                
                self.running_scans.add(scan_id)
                
                logger.info(f"🚀 Starting queued scan {scan_id} ({len(self.running_scans)}/{self.max_concurrent_scans})")
                
                # Trigger scan execution
                await self._execute_queued_scan(queued_scan)
                
        except Exception as e:
            logger.error(f"Error processing scan queue: {e}")
        finally:
            self.is_processing_queue = False
    
    async def _execute_queued_scan(self, queued_scan: Dict[str, any]):
        """Execute a queued scan."""
        try:
            scan_id = queued_scan["scan_id"]
            scan_data = queued_scan["scan_data"]
            
            # Import here to avoid circular imports
            from api.endpoints.scans import execute_scan
            
            # Create a background task for the scan
            asyncio.create_task(execute_scan(scan_id, scan_data))
            
            await notification_system.notify_system_alert(
                "Queued Scan Started",
                f"Scan {scan_id} started from queue",
            )
            
        except Exception as e:
            logger.error(f"Failed to execute queued scan: {e}")
            # Release the slot if execution failed
            await self.release_scan_slot(queued_scan["scan_id"])
    
    async def _get_current_running_scans(self) -> int:
        """Get the current number of running scans from database."""
        try:
            await Database.connect()
            async with Database.get_session() as db:
                # Import here to avoid circular imports
                from models.scan import Scan
                
                query = select(func.count(Scan.id)).where(
                    Scan.status.in_(['RUNNING', 'PENDING'])
                )
                result = await db.execute(query)
                count = result.scalar() or 0
                
                # Sync our internal state with database
                # (In case of restarts or inconsistencies)
                if len(self.running_scans) != count:
                    logger.warning(f"Sync: Internal count ({len(self.running_scans)}) != DB count ({count})")
                    # We'll trust the database count for now
                
                return count
                
        except Exception as e:
            logger.error(f"Error getting current running scans: {e}")
            return len(self.running_scans)  # Fallback to internal count
        finally:
            await Database.disconnect()
    
    def get_scan_status(self) -> Dict[str, any]:
        """Get current scan status and queue information."""
        return {
            "max_concurrent_scans": self.max_concurrent_scans,
            "current_running_scans": len(self.running_scans),
            "running_scan_ids": list(self.running_scans),
            "queued_scans": len(self.scan_queue),
            "queue_details": [
                {
                    "scan_id": item["scan_id"],
                    "queued_at": item["queued_at"].isoformat(),
                    "waiting_time_minutes": (datetime.utcnow() - item["queued_at"]).total_seconds() / 60
                }
                for item in self.scan_queue
            ]
        }
    
    async def cancel_queued_scan(self, scan_id: str) -> bool:
        """Cancel a queued scan."""
        for i, queued_scan in enumerate(self.scan_queue):
            if queued_scan["scan_id"] == scan_id:
                removed_scan = self.scan_queue.pop(i)
                logger.info(f"❌ Cancelled queued scan {scan_id}")
                
                await notification_system.notify_system_alert(
                    "Queued Scan Cancelled",
                    f"Scan {scan_id} removed from queue",
                )
                
                return True
        
        return False
    
    async def force_stop_scan(self, scan_id: str) -> bool:
        """Force stop a running scan (emergency use)."""
        if scan_id in self.running_scans:
            self.running_scans.remove(scan_id)
            logger.warning(f"🛑 Force stopped scan {scan_id}")
            
            await notification_system.notify_system_alert(
                "Scan Force Stopped",
                f"Scan {scan_id} was force stopped",
            )
            
            # Process queue to start next scan
            await self._process_scan_queue()
            
            return True
        
        return False
    
    def clear_queue(self):
        """Clear all queued scans (emergency use)."""
        cleared_count = len(self.scan_queue)
        self.scan_queue.clear()
        
        logger.warning(f"🗑️ Cleared scan queue ({cleared_count} scans)")
        
        return cleared_count

# Global instance
concurrent_scan_manager = ConcurrentScanManager() 