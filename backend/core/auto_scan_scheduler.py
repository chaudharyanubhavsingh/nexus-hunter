"""
Auto-Scan Scheduler for Nexus Hunter

Automatically schedules and executes scans based on user configuration.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from enum import Enum
from dataclasses import dataclass
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import Database
from core.notification_system import notification_system
from core.config import get_settings
from core.settings_persistence import settings_persistence

logger = logging.getLogger(__name__)

class ScheduleType(Enum):
    ONCE = "once"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"

@dataclass
class ScheduledScan:
    id: str
    target_id: str
    scan_type: str
    schedule_type: ScheduleType
    schedule_time: str  # Format: "14:30" for time of day
    schedule_days: List[int]  # [0,1,2,3,4,5,6] for Monday-Sunday, empty for daily
    enabled: bool
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    config: Dict[str, Any]

class AutoScanScheduler:
    """
    Intelligent auto-scan scheduler that manages recurring scans.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.is_running = False
        self._task: Optional[asyncio.Task] = None
        self.scheduled_scans: Dict[str, ScheduledScan] = {}
        # Load auto-scan state from persistence
        self.auto_scan_enabled = settings_persistence.get("auto_scan_enabled", False)
        self.check_interval = 60  # Check every minute
    
    async def start_scheduler(self):
        """Start the auto-scan scheduler."""
        if self.is_running:
            logger.warning("Auto-scan scheduler is already running")
            return
        
        self.is_running = True
        logger.info("🕐 Starting auto-scan scheduler")
        
        # Load scheduled scans from storage (could be database or config)
        await self._load_scheduled_scans()
        
        self._task = asyncio.create_task(self._scheduler_loop())
    
    async def stop_scheduler(self):
        """Stop the auto-scan scheduler."""
        if not self.is_running:
            return
        
        self.is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        logger.info("🕐 Auto-scan scheduler stopped")
    
    async def enable_auto_scan(self, enabled: bool):
        """Enable or disable auto-scanning."""
        old_state = self.auto_scan_enabled
        self.auto_scan_enabled = enabled
        
        # Persist the setting
        settings_persistence.set("auto_scan_enabled", enabled)
        
        logger.info(f"🕐 Auto-scan {'enabled' if enabled else 'disabled'} (was: {'enabled' if old_state else 'disabled'})")
        
        # Always ensure scheduler is running if we have any scheduling capability
        if not self.is_running:
            await self.start_scheduler()
            
        # Send notification about state change
        from core.notification_system import notification_system
        await notification_system.notify_system_alert(
            "Auto-Scan Status Changed",
            f"Auto-scan scheduling has been {'enabled' if enabled else 'disabled'}",
        )
    
    async def _scheduler_loop(self):
        """Main scheduler loop."""
        logger.info("🕐 Auto-scan scheduler loop started")
        
        while self.is_running:
            try:
                # Always check scheduled scans regardless of auto_scan_enabled
                # auto_scan_enabled controls creation of new schedules, not execution of existing ones
                await self._check_and_execute_scans()
                
                # Wait for the check interval
                await asyncio.sleep(self.check_interval)
                
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                await asyncio.sleep(self.check_interval)
        
        logger.info("🕐 Scheduler loop ended")
    
    async def _check_and_execute_scans(self):
        """Check for scheduled scans that need to be executed."""
        current_time = datetime.utcnow()
        executed_scans = []
        
        logger.debug(f"🕐 Checking {len(self.scheduled_scans)} scheduled scans at {current_time}")
        
        for schedule_id, scheduled_scan in list(self.scheduled_scans.items()):
            if self._should_execute_scan(scheduled_scan, current_time):
                logger.info(f"🕐 Executing scheduled scan: {schedule_id} for target {scheduled_scan.target_id}")
                
                try:
                    # Execute the scan
                    await self._execute_scheduled_scan(scheduled_scan)
                    executed_scans.append(schedule_id)
                    
                    # Update schedule timing or remove if one-time
                    await self._update_schedule_timing(scheduled_scan, current_time)
                    
                except Exception as e:
                    logger.error(f"Failed to execute scheduled scan {schedule_id}: {e}")
        
        if executed_scans:
            logger.info(f"🎯 Executed {len(executed_scans)} scheduled scans")
        elif self.scheduled_scans:
            logger.debug(f"🕐 No scans ready for execution. Next checks: {[(sid, scan.next_run) for sid, scan in self.scheduled_scans.items()]}")
    
    def _should_execute_scan(self, scheduled_scan: ScheduledScan, current_time: datetime) -> bool:
        """Check if a scheduled scan should be executed now."""
        should_execute = scheduled_scan.next_run <= current_time
        if should_execute:
            logger.debug(f"🎯 Scan {scheduled_scan.id} ready: next_run={scheduled_scan.next_run} <= current_time={current_time}")
        return should_execute
    
    async def _execute_scheduled_scan(self, scheduled_scan: ScheduledScan):
        """Execute a scheduled scan."""
        try:
            logger.info(f"🕐 Executing scheduled scan for target {scheduled_scan.target_id}")
            
            # Import here to avoid circular imports
            from models.scan import Scan, ScanStatus, Target
            from api.endpoints.scans import execute_scan
            from uuid import UUID
            from sqlalchemy import select
            
            # Create scan record directly
            await Database.connect()
            async with Database.get_session() as db:
                # Create immediate scan
                scan = Scan(
                    name=f"Auto-scan {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
                    target_id=UUID(scheduled_scan.target_id),
                    scan_type=scheduled_scan.scan_type,
                    config=scheduled_scan.config,
                    status=ScanStatus.PENDING
                )
                
                db.add(scan)
                await db.commit()
                await db.refresh(scan)
                
                # Get target domain for execution
                target_query = select(Target).where(Target.id == UUID(scheduled_scan.target_id))
                target_result = await db.execute(target_query)
                target = target_result.scalar_one_or_none()
                
                if target:
                    # Execute scan in background
                    import asyncio
                    asyncio.create_task(execute_scan(scan.id, target.domain))
                    
                    logger.info(f"🚀 Started scheduled scan {scan.id} for {target.domain}")
                    
                    await notification_system.notify_system_alert(
                        "Auto-Scan Started",
                        f"Scheduled scan '{scan.name}' started for {target.domain}",
                    )
                else:
                    logger.error(f"Target {scheduled_scan.target_id} not found for scheduled scan")
                    
        except Exception as e:
            logger.error(f"Failed to execute scheduled scan {scheduled_scan.id}: {e}")
            await notification_system.notify_system_alert(
                "Auto-Scan Failed",
                f"Failed to start scheduled scan: {str(e)}",
            )
    
    async def _update_schedule_timing(self, scheduled_scan: ScheduledScan, current_time: datetime):
        """Update the next run time for a scheduled scan."""
        scheduled_scan.last_run = current_time
        
        if scheduled_scan.schedule_type == ScheduleType.ONCE:
            scheduled_scan.enabled = False
            scheduled_scan.next_run = None
        elif scheduled_scan.schedule_type == ScheduleType.DAILY:
            scheduled_scan.next_run = current_time + timedelta(days=1)
        elif scheduled_scan.schedule_type == ScheduleType.WEEKLY:
            scheduled_scan.next_run = current_time + timedelta(weeks=1)
        elif scheduled_scan.schedule_type == ScheduleType.MONTHLY:
            # Approximate monthly (30 days)
            scheduled_scan.next_run = current_time + timedelta(days=30)
        
        # Save updated schedule
        await self._save_scheduled_scan(scheduled_scan)
    
    async def add_scheduled_scan(
        self,
        target_id: str,
        scan_type: str,
        schedule_type: ScheduleType,
        schedule_time: str = "02:00",  # Default to 2 AM
        schedule_days: Optional[List[int]] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Add a new scheduled scan."""
        
        schedule_id = f"schedule_{datetime.utcnow().timestamp()}"
        
        scheduled_scan = ScheduledScan(
            id=schedule_id,
            target_id=target_id,
            scan_type=scan_type,
            schedule_type=schedule_type,
            schedule_time=schedule_time,
            schedule_days=schedule_days or [],
            enabled=True,
            last_run=None,
            next_run=self._calculate_next_run(schedule_type, schedule_time),
            config=config or {}
        )
        
        self.scheduled_scans[schedule_id] = scheduled_scan
        await self._save_scheduled_scan(scheduled_scan)
        
        logger.info(f"📅 Added scheduled scan {schedule_id} for target {target_id}")
        return schedule_id
    
    def _calculate_next_run(self, schedule_type: ScheduleType, schedule_time: str) -> datetime:
        """Calculate the next run time for a schedule."""
        current_time = datetime.utcnow()
        
        try:
            hour, minute = map(int, schedule_time.split(':'))
            today_run = current_time.replace(hour=hour, minute=minute, second=0, microsecond=0)
            
            if schedule_type == ScheduleType.ONCE:
                return today_run if today_run > current_time else today_run + timedelta(days=1)
            elif schedule_type == ScheduleType.DAILY:
                return today_run if today_run > current_time else today_run + timedelta(days=1)
            elif schedule_type == ScheduleType.WEEKLY:
                days_ahead = 7 - current_time.weekday()  # Next week same day
                return today_run + timedelta(days=days_ahead)
            elif schedule_type == ScheduleType.MONTHLY:
                next_month = today_run + timedelta(days=30)
                return next_month
        except ValueError:
            logger.error(f"Invalid schedule time format: {schedule_time}")
            return current_time + timedelta(hours=1)  # Default to 1 hour from now
        
        return current_time + timedelta(hours=1)
    
    async def remove_scheduled_scan(self, schedule_id: str):
        """Remove a scheduled scan."""
        if schedule_id in self.scheduled_scans:
            del self.scheduled_scans[schedule_id]
            await self._delete_scheduled_scan(schedule_id)
            logger.info(f"📅 Removed scheduled scan {schedule_id}")
    
    async def update_scheduled_scan(self, schedule_id: str, **kwargs):
        """Update a scheduled scan."""
        if schedule_id in self.scheduled_scans:
            scheduled_scan = self.scheduled_scans[schedule_id]
            
            for key, value in kwargs.items():
                if hasattr(scheduled_scan, key):
                    setattr(scheduled_scan, key, value)
            
            # Recalculate next run if schedule changed
            if 'schedule_type' in kwargs or 'schedule_time' in kwargs:
                scheduled_scan.next_run = self._calculate_next_run(
                    scheduled_scan.schedule_type,
                    scheduled_scan.schedule_time
                )
            
            await self._save_scheduled_scan(scheduled_scan)
            logger.info(f"📅 Updated scheduled scan {schedule_id}")
    
    def get_scheduled_scans(self) -> List[Dict[str, Any]]:
        """Get all scheduled scans."""
        return [
            {
                "id": scan.id,
                "target_id": scan.target_id,
                "scan_type": scan.scan_type,
                "schedule_type": scan.schedule_type.value,
                "schedule_time": scan.schedule_time,
                "schedule_days": scan.schedule_days,
                "enabled": scan.enabled,
                "last_run": scan.last_run.isoformat() if scan.last_run else None,
                "next_run": scan.next_run.isoformat() if scan.next_run else None,
                "config": scan.config
            }
            for scan in self.scheduled_scans.values()
        ]
    
    async def execute_now(self, schedule_id: str) -> None:
        """Manually execute a scheduled scan immediately."""
        if schedule_id not in self.scheduled_scans:
            raise KeyError(schedule_id)
        scheduled_scan = self.scheduled_scans[schedule_id]
        await self._execute_scheduled_scan(scheduled_scan)
    
    async def _load_scheduled_scans(self):
        """Load scheduled scans from storage."""
        # In a real implementation, this would load from database
        # For now, we'll start with an empty dictionary
        self.scheduled_scans = {}
        logger.info("📅 Loaded scheduled scans from storage")
    
    async def _save_scheduled_scan(self, scheduled_scan: ScheduledScan):
        """Save a scheduled scan to storage."""
        # In a real implementation, this would save to database
        # For now, we'll just keep it in memory
        pass
    
    async def _delete_scheduled_scan(self, schedule_id: str):
        """Delete a scheduled scan from storage."""
        # In a real implementation, this would delete from database
        pass

# Global instance
auto_scan_scheduler = AutoScanScheduler() 