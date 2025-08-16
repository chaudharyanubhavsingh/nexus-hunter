"""
Settings Persistence for Nexus Hunter

Simple file-based persistence for system settings to maintain state across restarts.
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

class SettingsPersistence:
    """
    Simple file-based settings persistence.
    """
    
    def __init__(self, settings_file: str = "nexus_settings.json"):
        self.settings_file = Path(settings_file)
        self.settings: Dict[str, Any] = {}
        self.load_settings()
    
    def load_settings(self):
        """Load settings from file."""
        try:
            if self.settings_file.exists():
                with open(self.settings_file, 'r') as f:
                    self.settings = json.load(f)
                logger.info(f"📁 Loaded settings from {self.settings_file}")
            else:
                self.settings = self._get_default_settings()
                self.save_settings()
                logger.info(f"📁 Created default settings file: {self.settings_file}")
        except Exception as e:
            logger.error(f"Failed to load settings: {e}")
            self.settings = self._get_default_settings()
    
    def save_settings(self):
        """Save settings to file."""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
            logger.debug(f"💾 Saved settings to {self.settings_file}")
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
    
    def _get_default_settings(self) -> Dict[str, Any]:
        """Get default settings."""
        return {
            "auto_scan_enabled": False,
            "notifications_enabled": True,
            "concurrent_scans": 3,
            "scan_timeout": 3600,
            "last_updated": "never"
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a setting value."""
        return self.settings.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set a setting value."""
        self.settings[key] = value
        self.save_settings()
    
    def update(self, updates: Dict[str, Any]):
        """Update multiple settings."""
        self.settings.update(updates)
        self.save_settings()
    
    def get_all(self) -> Dict[str, Any]:
        """Get all settings."""
        return self.settings.copy()

# Global instance
settings_persistence = SettingsPersistence() 