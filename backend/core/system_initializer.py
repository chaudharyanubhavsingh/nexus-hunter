"""
System Initialization and Health Check Manager

Validates all system components on startup and provides real-time status
for a professional cybersecurity platform experience.
"""

import asyncio
import logging
import os
import shutil
import subprocess
import time
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from core.redis_client import RedisClient
from core.database import Database
from core.websocket_manager import WebSocketManager
from sqlalchemy import text

logger = logging.getLogger(__name__)


class ComponentStatus(Enum):
    """Status of system components"""
    CHECKING = "checking"
    AVAILABLE = "available"
    INSTALLING = "installing"
    FAILED = "failed"
    DISABLED = "disabled"


class SystemStatus(Enum):
    """Overall system status"""
    INITIALIZING = "initializing"
    SETTING_UP = "setting_up"
    READY = "ready"
    DEGRADED = "degraded"
    FAILED = "failed"


@dataclass
class ComponentCheck:
    """Individual component check result"""
    name: str
    status: ComponentStatus
    version: Optional[str] = None
    error: Optional[str] = None
    required: bool = True
    install_command: Optional[str] = None
    check_command: Optional[str] = None
    last_checked: Optional[datetime] = None


@dataclass
class SystemHealth:
    """Overall system health status"""
    status: SystemStatus
    components: Dict[str, ComponentCheck] = field(default_factory=dict)
    startup_time: Optional[datetime] = None
    ready_time: Optional[datetime] = None
    message: str = ""
    progress_percentage: int = 0


class SystemInitializer:
    """
    Professional System Initialization Manager
    Ensures all cybersecurity tools and services are ready before allowing operations
    """
    
    def __init__(self):
        self.health = SystemHealth(status=SystemStatus.INITIALIZING)
        self.redis_client = None
        self.websocket_manager = None
        self.database = None
        self.initialization_lock = asyncio.Lock()
        
        # Get tool paths
        go_bin_path = os.path.expanduser("~/go/bin")
        python_bin_path = os.path.expanduser("~/Library/Python/3.9/bin")
        
        # Define required security tools with full paths
        self.security_tools = {
            # Core Go-based tools
            "subfinder": ComponentCheck(
                name="Subfinder",
                status=ComponentStatus.CHECKING,
                check_command=f"{go_bin_path}/subfinder -version",
                install_command="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                required=False  # Has built-in fallback
            ),
            "nuclei": ComponentCheck(
                name="Nuclei",
                status=ComponentStatus.CHECKING,
                check_command=f"{go_bin_path}/nuclei -version",
                install_command="go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
                required=False  # Has built-in fallback
            ),
            "naabu": ComponentCheck(
                name="Naabu",
                status=ComponentStatus.CHECKING,
                check_command=f"{go_bin_path}/naabu -version",
                install_command="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
                required=False  # Has built-in fallback
            ),
            "httpx": ComponentCheck(
                name="HTTPX",
                status=ComponentStatus.CHECKING,
                check_command=f"{go_bin_path}/httpx -version",
                install_command="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                required=False  # Has built-in fallback
            ),
            "gau": ComponentCheck(
                name="GAU",
                status=ComponentStatus.CHECKING,
                check_command=f"{go_bin_path}/gau --help",
                install_command="go install github.com/lc/gau/v2/cmd/gau@latest",
                required=False  # Has built-in fallback
            ),
            
            # Python-based tools
            "wafw00f": ComponentCheck(
                name="Wafw00f",
                status=ComponentStatus.CHECKING,
                check_command=f"{python_bin_path}/wafw00f --help",
                install_command="pip3 install wafw00f",
                required=False  # Has built-in fallback
            ),
            "dnstwist": ComponentCheck(
                name="DNS Twister",
                status=ComponentStatus.CHECKING,
                check_command=f"{python_bin_path}/dnstwist --help",
                install_command="pip3 install dnstwist",
                required=False  # Has built-in fallback
            ),
            
            # API-based tools (no installation needed)
            "sslmate": ComponentCheck(
                name="SSLMate CT API",
                status=ComponentStatus.AVAILABLE,  # API-based, always available
                required=False
            ),
            
            # Advanced reconnaissance tools
            "masscan": ComponentCheck(
                name="Masscan",
                status=ComponentStatus.CHECKING,
                check_command="/opt/homebrew/bin/masscan --version",
                install_command="brew install masscan",
                required=False
            ),
            "assetfinder": ComponentCheck(
                name="AssetFinder",
                status=ComponentStatus.CHECKING,
                check_command=f"{go_bin_path}/assetfinder --help",
                install_command="go install github.com/tomnomnom/assetfinder@latest",
                required=False
            ),
            "katana": ComponentCheck(
                name="Katana",
                status=ComponentStatus.CHECKING,
                check_command=f"{go_bin_path}/katana --help",
                install_command="go install github.com/projectdiscovery/katana/cmd/katana@latest",
                required=False
            ),
            
            # Advanced vulnerability testing
            "sqlmap": ComponentCheck(
                name="SQLMap",
                status=ComponentStatus.CHECKING,
                check_command=f"python3 {os.path.expanduser('~/sqlmap/sqlmap.py')} --version",
                install_command="git clone https://github.com/sqlmapproject/sqlmap.git ~/sqlmap",
                required=False
            ),
            "theharvester": ComponentCheck(
                name="theHarvester",
                status=ComponentStatus.FAILED,  # Mark as failed by default since it's hard to install
                check_command=None,  # Skip automatic checking
                install_command="echo 'theHarvester requires manual installation from GitHub'",
                required=False
            ),
            "hashcat": ComponentCheck(
                name="Hashcat",
                status=ComponentStatus.CHECKING,
                check_command="/opt/homebrew/bin/hashcat --version",
                install_command="brew install hashcat",
                required=False
            )
        }
        
        # Define core services
        self.core_services = {
            "database": ComponentCheck(
                name="Database",
                status=ComponentStatus.CHECKING,
                required=True
            ),
            "redis": ComponentCheck(
                name="Redis",
                status=ComponentStatus.CHECKING,
                required=True
            ),
            "websocket": ComponentCheck(
                name="WebSocket Manager",
                status=ComponentStatus.CHECKING,
                required=True
            ),
            "ai_intelligence": ComponentCheck(
                name="AI Intelligence System",
                status=ComponentStatus.CHECKING,
                required=True
            )
        }
        
        # Combine all components
        self.all_components = {**self.security_tools, **self.core_services}
    
    async def initialize_system(self) -> SystemHealth:
        """
        Complete system initialization with professional validation
        """
        async with self.initialization_lock:
            logger.info("🚀 Starting Professional Cybersecurity Platform Initialization")
            self.health.startup_time = datetime.now()
            self.health.status = SystemStatus.INITIALIZING
            
            try:
                # Phase 1: Check Core Services (30%)
                await self._update_progress("Validating core services...", 10)
                await self._check_core_services()
                
                # Phase 2: Check Security Tools (60%)  
                await self._update_progress("Validating security tools...", 40)
                await self._check_security_tools()
                
                # Phase 3: Install Missing Tools (80%)
                await self._update_progress("Setting up missing components...", 60)
                await self._setup_missing_tools()
                
                # Phase 4: Final Validation (95%)
                await self._update_progress("Final system validation...", 85)
                await self._final_validation()
                
                # Phase 5: System Ready (100%)
                await self._update_progress("Professional cybersecurity platform ready!", 100)
                self.health.status = SystemStatus.READY
                self.health.ready_time = datetime.now()
                
                logger.info("✅ Professional Cybersecurity Platform Initialized Successfully")
                return self.health
                
            except Exception as e:
                logger.error(f"❌ System initialization failed: {e}")
                self.health.status = SystemStatus.FAILED
                self.health.message = f"Initialization failed: {str(e)}"
                return self.health
    
    async def _check_core_services(self):
        """Initialize and check critical core services"""
        # Database Check - Initialize and Connect
        try:
            logger.info("🔍 Initializing database connection...")
            
            # First, initialize the database connection
            await Database.connect()
            logger.info("✅ Database connection established")
            
            # Then create tables if needed
            await Database.create_tables()
            logger.info("✅ Database tables verified")
            
            # Finally, test the connection
            async with Database.get_session() as db:
                await db.execute(text("SELECT 1"))
            
            self.all_components["database"].status = ComponentStatus.AVAILABLE
            self.all_components["database"].version = Database.database_type
            self.all_components["database"].last_checked = datetime.now()
            logger.info("✅ Database: Fully operational")
            
        except Exception as e:
            self.all_components["database"].status = ComponentStatus.FAILED
            self.all_components["database"].error = str(e)
            logger.error(f"❌ Database initialization failed: {e}")
        
        # Redis Check - Initialize and Connect
        try:
            logger.info("🔍 Initializing Redis connection...")
            await RedisClient.connect()
            
            # Test the connection
            if await RedisClient.ping():
                self.all_components["redis"].status = ComponentStatus.AVAILABLE
                self.all_components["redis"].version = "Redis" if not RedisClient.is_fallback_mode() else "Memory Fallback"
                self.all_components["redis"].last_checked = datetime.now()
                logger.info("✅ Redis: Connected and operational")
            else:
                raise Exception("Redis ping failed")
            
        except Exception as e:
            self.all_components["redis"].status = ComponentStatus.FAILED
            self.all_components["redis"].error = str(e)
            logger.warning(f"⚠️ Redis connection failed: {e} - Using memory fallback")
        
        # WebSocket Manager Check
        try:
            logger.info("🔍 Checking WebSocket manager...")
            self.websocket_manager = WebSocketManager.manager
            self.all_components["websocket"].status = ComponentStatus.AVAILABLE
            self.all_components["websocket"].last_checked = datetime.now()
            logger.info("✅ WebSocket Manager: Ready")
        except Exception as e:
            self.all_components["websocket"].status = ComponentStatus.FAILED
            self.all_components["websocket"].error = str(e)
            logger.error(f"❌ WebSocket Manager: {e}")
        
        # AI Intelligence Check
        try:
            logger.info("🔍 Checking AI Intelligence System...")
            from agents.prompt_engineering.cybersecurity_llm import cyber_llm
            # Test AI intelligence
            test_guidance = await cyber_llm.get_agent_guidance(
                "reconnaissance", 
                "planning", 
                {"target": "test.com", "test_mode": True}
            )
            self.all_components["ai_intelligence"].status = ComponentStatus.AVAILABLE
            self.all_components["ai_intelligence"].version = "Professional Grade"
            self.all_components["ai_intelligence"].last_checked = datetime.now()
            logger.info("✅ AI Intelligence System: Professional cybersecurity experts ready")
        except Exception as e:
            self.all_components["ai_intelligence"].status = ComponentStatus.FAILED
            self.all_components["ai_intelligence"].error = str(e)
            logger.error(f"❌ AI Intelligence System: {e}")
    
    async def _check_security_tools(self):
        """Check security tools availability"""
        for tool_name, tool_check in self.security_tools.items():
            try:
                logger.info(f"🔍 Checking {tool_check.name}...")
                
                # Try to run version command
                if tool_check.check_command:
                    result = await self._run_command(tool_check.check_command)
                    
                    # For some tools, we accept non-zero exit codes if they produce output
                    tool_available = result["success"] or (
                        result["output"] and 
                        len(result["output"].strip()) > 0 and
                        not "command not found" in result["error"].lower() and
                        not "no such file" in result["error"].lower()
                    )
                    
                    if tool_available:
                        tool_check.status = ComponentStatus.AVAILABLE
                        tool_check.version = result["output"][:100]  # First 100 chars
                        logger.info(f"✅ {tool_check.name}: Available (v{tool_check.version[:20]})")
                    else:
                        tool_check.status = ComponentStatus.FAILED
                        tool_check.error = result["error"] or "Tool not responding properly"
                        logger.warning(f"⚠️ {tool_check.name}: Not found - will use built-in fallback")
                
                tool_check.last_checked = datetime.now()
                
            except Exception as e:
                tool_check.status = ComponentStatus.FAILED
                tool_check.error = str(e)
                logger.warning(f"⚠️ {tool_check.name}: Check failed - {e}")
    
    async def _setup_missing_tools(self):
        """Attempt to install missing critical tools"""
        # Check if Go is available for installing tools
        go_available = await self._check_go_installation()
        
        for tool_name, tool_check in self.security_tools.items():
            if tool_check.status == ComponentStatus.FAILED and tool_check.install_command and go_available:
                try:
                    logger.info(f"🔧 Installing {tool_check.name}...")
                    tool_check.status = ComponentStatus.INSTALLING
                    
                    result = await self._run_command(tool_check.install_command, timeout=300)  # 5 min timeout
                    
                    if result["success"]:
                        # Re-check after installation
                        recheck_result = await self._run_command(tool_check.check_command)
                        
                        # Use same flexible checking logic
                        tool_available = recheck_result["success"] or (
                            recheck_result["output"] and 
                            len(recheck_result["output"].strip()) > 0 and
                            not "command not found" in recheck_result["error"].lower() and
                            not "no such file" in recheck_result["error"].lower()
                        )
                        
                        if tool_available:
                            tool_check.status = ComponentStatus.AVAILABLE
                            tool_check.version = recheck_result["output"][:100]
                            logger.info(f"✅ {tool_check.name}: Successfully installed")
                        else:
                            tool_check.status = ComponentStatus.FAILED
                            tool_check.error = "Installation completed but tool not working"
                            logger.warning(f"⚠️ {tool_check.name}: Installation issue")
                    else:
                        tool_check.status = ComponentStatus.FAILED
                        tool_check.error = f"Installation failed: {result['error']}"
                        logger.warning(f"⚠️ {tool_check.name}: Installation failed - {result['error']}")
                        
                except Exception as e:
                    tool_check.status = ComponentStatus.FAILED
                    tool_check.error = f"Installation error: {str(e)}"
                    logger.warning(f"⚠️ {tool_check.name}: Installation error - {e}")
    
    async def _final_validation(self):
        """Final system validation"""
        critical_failures = []
        
        for component_name, component in self.all_components.items():
            if component.required and component.status == ComponentStatus.FAILED:
                critical_failures.append(f"{component.name}: {component.error}")
        
        if critical_failures:
            self.health.status = SystemStatus.FAILED
            self.health.message = f"Critical components failed: {'; '.join(critical_failures)}"
            raise Exception(self.health.message)
        
        # Check if we have enough working tools
        working_tools = sum(1 for tool in self.security_tools.values() if tool.status == ComponentStatus.AVAILABLE)
        total_tools = len(self.security_tools)
        
        if working_tools == 0:
            self.health.status = SystemStatus.DEGRADED
            self.health.message = "No external security tools available - using built-in methods"
            logger.warning("⚠️ System in degraded mode: Using built-in security tools only")
        elif working_tools < total_tools:
            self.health.status = SystemStatus.DEGRADED
            self.health.message = f"Some tools unavailable ({working_tools}/{total_tools}) - mixed mode active"
            logger.info(f"⚡ System ready with {working_tools}/{total_tools} external tools")
        else:
            self.health.status = SystemStatus.READY
            self.health.message = "All systems operational - professional grade ready"
            logger.info("🎯 All security tools available - maximum capability mode")
    
    async def _check_go_installation(self) -> bool:
        """Check if Go is installed for tool installation"""
        try:
            result = await self._run_command("go version")
            return result["success"]
        except:
            return False
    
    async def _run_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """Run shell command with timeout"""
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            return {
                "success": process.returncode == 0,
                "output": stdout.decode().strip(),
                "error": stderr.decode().strip(),
                "return_code": process.returncode
            }
        except asyncio.TimeoutError:
            return {
                "success": False,
                "output": "",
                "error": f"Command timeout after {timeout}s",
                "return_code": -1
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e),
                "return_code": -1
            }
    
    async def _update_progress(self, message: str, percentage: int):
        """Update initialization progress"""
        self.health.message = message
        self.health.progress_percentage = percentage
        logger.info(f"🔄 [{percentage}%] {message}")
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current system health status for API"""
        return {
            "status": self.health.status.value,
            "message": self.health.message,
            "progress_percentage": self.health.progress_percentage,
            "startup_time": self.health.startup_time.isoformat() if self.health.startup_time else None,
            "ready_time": self.health.ready_time.isoformat() if self.health.ready_time else None,
            "components": {
                name: {
                    "name": component.name,
                    "status": component.status.value,
                    "version": component.version,
                    "error": component.error,
                    "required": component.required,
                    "last_checked": component.last_checked.isoformat() if component.last_checked else None
                }
                for name, component in self.all_components.items()
            },
            "summary": {
                "total_components": len(self.all_components),
                "available": len([c for c in self.all_components.values() if c.status == ComponentStatus.AVAILABLE]),
                "failed": len([c for c in self.all_components.values() if c.status == ComponentStatus.FAILED]),
                "installing": len([c for c in self.all_components.values() if c.status == ComponentStatus.INSTALLING])
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Quick health check for monitoring"""
        return self.get_health_status()


# Global system initializer instance
system_initializer = SystemInitializer()
