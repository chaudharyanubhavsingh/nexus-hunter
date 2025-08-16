"""
Intelligent Stuck Scan Monitor

This module provides smart detection of truly stuck scans vs legitimately slow scans.
It considers scan type, progress patterns, and activity indicators.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import Database
from core.config import get_settings
from core.websocket_manager import WebSocketManager
from models.scan import Scan

logger = logging.getLogger(__name__)

class StuckScanMonitor:
    """
    Intelligent monitor for detecting and handling stuck scans.
    
    Uses multiple indicators to determine if a scan is truly stuck:
    - Time since last progress update
    - Progress stagnation patterns  
    - Scan type considerations
    - Activity patterns
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.websocket_manager = WebSocketManager()
        self.is_running = False
        self._task: Optional[asyncio.Task] = None
        
        # Dynamic settings that can be updated at runtime
        self._current_scan_timeout = self.settings.scan_timeout
        self._settings_check_counter = 0
        
        # Scan type timeouts (multipliers of base timeout)
        self.scan_type_multipliers = {
            'reconnaissance': 1.0,      # Standard timeout
            'vulnerability': 1.5,      # 50% longer
            'exploitation': 2.0,       # 2x longer (more complex)
            'full': 2.5,              # 2.5x longer (comprehensive)
            'custom': 1.2             # 20% longer (unknown complexity)
        }
        
        # Minimum progress intervals (seconds) before considering stuck
        self.min_progress_intervals = {
            'reconnaissance': 300,     # 5 minutes
            'vulnerability': 600,     # 10 minutes  
            'exploitation': 900,      # 15 minutes
            'full': 1200,             # 20 minutes
            'custom': 600             # 10 minutes
        }
    
    async def start_monitoring(self):
        """Start the background monitoring task."""
        if self.is_running:
            logger.warning("Stuck scan monitor is already running")
            return
        
        self.is_running = True
        # Check every 25% of the scan timeout (more frequent than timeout)
        check_interval = max(self.settings.scan_timeout // 4, 300)  # At least 5 minutes
        
        logger.info(f"🔍 Starting stuck scan monitor (interval: {check_interval}s, timeout: {self.settings.scan_timeout}s)")
        
        self._task = asyncio.create_task(self._monitoring_loop(check_interval))
    
    async def stop_monitoring(self):
        """Stop the background monitoring task."""
        if not self.is_running:
            return
        
        self.is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        logger.info("🔍 Stuck scan monitor stopped")
    
    async def _monitoring_loop(self, check_interval: int):
        """Main monitoring loop with dynamic settings reload."""
        while self.is_running:
            try:
                # Check for settings updates every 10 monitoring cycles
                self._settings_check_counter += 1
                if self._settings_check_counter >= 10:
                    await self._reload_settings()
                    self._settings_check_counter = 0
                
                await self._check_stuck_scans()
                await asyncio.sleep(check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in stuck scan monitoring: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying
    
    async def _check_stuck_scans(self):
        """Check for and handle stuck scans using intelligent logic."""
        try:
            await Database.connect()
            async with Database.get_session() as db:
                # Get all active scans
                query = select(Scan).where(Scan.status.in_(['RUNNING', 'PENDING']))
                result = await db.execute(query)
                active_scans = result.scalars().all()
                
                if not active_scans:
                    return
                
                logger.debug(f"🔍 Checking {len(active_scans)} active scans for stuck conditions")
                
                stuck_scans = []
                for scan in active_scans:
                    if await self._is_scan_stuck(scan):
                        stuck_scans.append(scan)
                
                if stuck_scans:
                    logger.warning(f"🚨 Found {len(stuck_scans)} stuck scans")
                    await self._handle_stuck_scans(db, stuck_scans)
                else:
                    logger.debug("✅ All active scans appear to be working normally")
                    
        except Exception as e:
            logger.error(f"Error checking stuck scans: {e}")
        finally:
            await Database.disconnect()
    
    async def _is_scan_stuck(self, scan: Scan) -> bool:
        """
        Determine if a scan is truly stuck using intelligent analysis.
        
        A scan is considered stuck if:
        1. It has exceeded the timeout for its type
        2. Progress hasn't updated in a reasonable time
        3. No signs of activity (progress stagnation)
        """
        now = datetime.utcnow()
        scan_type = scan.scan_type or 'custom'
        
        # Calculate type-specific timeout using current dynamic setting
        base_timeout = self._current_scan_timeout
        type_multiplier = self.scan_type_multipliers.get(scan_type, 1.2)
        max_duration = base_timeout * type_multiplier
        
        # Check overall duration
        start_time = scan.started_at or scan.created_at
        if start_time:
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time.replace('Z', ''))
            
            total_duration = (now - start_time).total_seconds()
            
            # Hard timeout - if scan has been running way too long
            if total_duration > max_duration:
                logger.warning(f"🚨 Scan {scan.id} exceeded maximum duration: {total_duration:.0f}s > {max_duration:.0f}s")
                return True
        
        # Check progress stagnation
        if scan.updated_at:
            if isinstance(scan.updated_at, str):
                updated_at = datetime.fromisoformat(scan.updated_at.replace('Z', ''))
            else:
                updated_at = scan.updated_at
            
            time_since_update = (now - updated_at).total_seconds()
            min_interval = self.min_progress_intervals.get(scan_type, 600)
            
            # If no progress update in a reasonable time for this scan type
            if time_since_update > min_interval:
                logger.warning(f"🚨 Scan {scan.id} no progress update for {time_since_update:.0f}s (limit: {min_interval}s)")
                return True
        
        # Check for progress patterns (e.g., stuck at same percentage)
        if scan.progress_percentage is not None:
            # If scan is at 0% progress for too long
            if scan.progress_percentage == 0 and start_time:
                zero_progress_duration = (now - start_time).total_seconds()
                if zero_progress_duration > 900:  # 15 minutes at 0%
                    logger.warning(f"🚨 Scan {scan.id} stuck at 0% for {zero_progress_duration:.0f}s")
                    return True
            
            # If scan is very close to completion but hasn't finished
            if scan.progress_percentage >= 95:
                completion_stall_limit = 1800  # 30 minutes at 95%+
                if scan.updated_at:
                    if isinstance(scan.updated_at, str):
                        updated_at = datetime.fromisoformat(scan.updated_at.replace('Z', ''))
                    else:
                        updated_at = scan.updated_at
                    
                    stall_duration = (now - updated_at).total_seconds()
                    if stall_duration > completion_stall_limit:
                        logger.warning(f"🚨 Scan {scan.id} stalled at {scan.progress_percentage}% for {stall_duration:.0f}s")
                        return True
        
        return False
    
    async def _handle_stuck_scans(self, db: AsyncSession, stuck_scans: List[Scan]):
        """Handle detected stuck scans by marking them as failed."""
        for scan in stuck_scans:
            try:
                # Update scan to failed status
                error_msg = f"Scan terminated: Detected as stuck by intelligent monitoring system"
                
                update_query = update(Scan).where(Scan.id == scan.id).values(
                    status='FAILED',
                    error_message=error_msg,
                    completed_at=datetime.utcnow()
                    # Don't set updated_at explicitly - let SQLAlchemy handle it
                )
                
                await db.execute(update_query)
                await db.commit()
                
                logger.info(f"🔧 Marked stuck scan {scan.id} ({scan.name}) as FAILED")
                
                # Broadcast the change via WebSocket
                try:
                    await self.websocket_manager.broadcast_to_all({
                        "type": "scan_failed",
                        "data": {
                            "scan_id": str(scan.id),
                            "message": error_msg,
                            "reason": "stuck_scan_detected"
                        }
                    })
                except Exception as ws_error:
                    logger.error(f"Failed to broadcast stuck scan update: {ws_error}")
                
            except Exception as e:
                logger.error(f"Failed to handle stuck scan {scan.id}: {e}")
                # Continue with other scans even if one fails
    
    async def force_check_now(self) -> Dict[str, any]:
        """
        Force an immediate check for stuck scans.
        Returns summary of actions taken.
        """
        logger.info("🔍 Force checking for stuck scans...")
        
        try:
            await Database.connect()
            async with Database.get_session() as db:
                query = select(Scan).where(Scan.status.in_(['RUNNING', 'PENDING']))
                result = await db.execute(query)
                active_scans = result.scalars().all()
                
                stuck_scans = []
                for scan in active_scans:
                    if await self._is_scan_stuck(scan):
                        stuck_scans.append(scan)
                
                if stuck_scans:
                    await self._handle_stuck_scans(db, stuck_scans)
                
                return {
                    "checked_scans": len(active_scans),
                    "stuck_scans_found": len(stuck_scans),
                    "stuck_scan_ids": [str(s.id) for s in stuck_scans],
                    "action": "marked_as_failed" if stuck_scans else "no_action_needed"
                }
                
        except Exception as e:
            logger.error(f"Error in force check: {e}")
            return {"error": str(e)}
        finally:
            await Database.disconnect()
    
    async def _reload_settings(self):
        """Reload settings from database/config to pick up dynamic changes."""
        try:
            # Reload settings to get any updates
            self.settings = get_settings()
            old_timeout = self._current_scan_timeout
            self._current_scan_timeout = self.settings.scan_timeout
            
            if old_timeout != self._current_scan_timeout:
                logger.info(f"🔄 Updated scan timeout: {old_timeout}s → {self._current_scan_timeout}s")
                
        except Exception as e:
            logger.error(f"Error reloading settings: {e}")
    
    async def update_scan_timeout(self, new_timeout: int) -> bool:
        """
        Dynamically update the scan timeout setting.
        
        Args:
            new_timeout: New timeout in seconds
            
        Returns:
            bool: True if update was successful
        """
        try:
            if new_timeout < 300 or new_timeout > 7200:
                raise ValueError("Timeout must be between 300 and 7200 seconds")
            
            old_timeout = self._current_scan_timeout
            self._current_scan_timeout = new_timeout
            
            logger.info(f"🔄 Dynamically updated scan timeout: {old_timeout}s → {new_timeout}s")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update scan timeout: {e}")
            return False
    
    def get_current_timeout(self) -> int:
        """Get the current dynamic timeout setting."""
        return self._current_scan_timeout

# Global instance
stuck_scan_monitor = StuckScanMonitor() 