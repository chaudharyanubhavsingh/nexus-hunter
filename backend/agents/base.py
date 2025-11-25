"""
Base Agent class for Nexus Hunter autonomous agents
Enhanced with professional cybersecurity prompt engineering
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Callable
from uuid import UUID
from datetime import datetime

from loguru import logger

from core.websocket_manager import WebSocketManager
from core.redis_client import RedisClient


class AgentResult:
    """Standard result class for agent operations"""
    
    def __init__(self, success: bool = True, data: Dict[str, Any] = None, error: str = None, message: str = None):
        self.success = success
        self.data = data or {}
        self.error = error
        self.message = message
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "message": self.message,
            "timestamp": self.timestamp
        }


class BaseAgent(ABC):
    """Base class for all autonomous agents with cybersecurity expertise"""
    
    def __init__(self, name: str, agent_type: str = None):
        self.name = name
        self.agent_type = agent_type or name.lower().replace("agent", "")
        self.is_running = False
        self._progress_callback: Optional[Callable] = None
        self._cancel_event = asyncio.Event()
        self._current_phase = "idle"
        self._expert_context = {}
        self.logger = logger  # Add logger attribute for agents that expect it
    
    def set_progress_callback(self, callback: Callable) -> None:
        """Set callback for progress updates"""
        self._progress_callback = callback
    
    async def update_progress(self, step: str, data: Dict[str, Any] = None) -> None:
        """Update progress and broadcast to WebSocket clients"""
        if self._progress_callback:
            await self._progress_callback(step, data or {})
        
        # Also broadcast via WebSocket
        await self._broadcast_progress(step, data or {})
    
    async def _broadcast_progress(self, step: str, data: Dict[str, Any]) -> None:
        """Broadcast progress update via WebSocket"""
        try:
            message = {
                "agent": self.name,
                "step": step,
                "data": data,
                "timestamp": None,  # Will be set by frontend
            }
            
            # Cache the update in Redis for persistence
            cache_key = f"agent_progress:{self.name}"
            await RedisClient.set(cache_key, message, expire=3600)
            
        except Exception as e:
            logger.error(f"Failed to broadcast progress: {e}")
    
    def cancel(self) -> None:
        """Cancel the agent execution"""
        self._cancel_event.set()
        logger.info(f"🛑 {self.name} agent cancellation requested")
    
    def is_cancelled(self) -> bool:
        """Check if agent execution was cancelled"""
        return self._cancel_event.is_set()
    
    async def get_expert_guidance(self, phase: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get professional cybersecurity guidance for current phase"""
        try:
            # Import here to avoid circular imports
            from agents.prompt_engineering.cybersecurity_llm import get_expert_guidance
            
            # Merge contexts
            full_context = {**self._expert_context, **(context or {})}
            full_context["agent_name"] = self.name
            full_context["agent_type"] = self.agent_type
            full_context["current_phase"] = phase
            
            self._current_phase = phase
            
            # Get expert guidance
            guidance = await get_expert_guidance(self.agent_type, phase, full_context)
            
            # Log the guidance
            logger.info(f"🧠 {self.name} received expert guidance for {phase} phase")
            
            # Broadcast guidance to UI
            await self.update_progress(f"expert_guidance_{phase}", {
                "guidance_available": True,
                "expert_confidence": guidance.get("confidence", 80),
                "methodology": guidance.get("methodology", "Professional cybersecurity approach"),
                "phase": phase
            })
            
            return guidance
            
        except Exception as e:
            logger.warning(f"⚠️ Failed to get expert guidance: {e}")
            return {
                "guidance": f"Proceeding with standard {self.agent_type} methodology for {phase}",
                "confidence": 70,
                "source": "fallback"
            }
    
    def set_expert_context(self, context: Dict[str, Any]) -> None:
        """Set expert context for intelligent decision making"""
        self._expert_context.update(context)
        logger.debug(f"🎯 Updated expert context for {self.name}")
    
    async def expert_update_progress(self, phase: str, data: Dict[str, Any] = None, 
                                   guidance_needed: bool = False) -> None:
        """Enhanced progress update with optional expert guidance"""
        progress_data = data or {}
        
        # Get expert guidance if needed
        if guidance_needed:
            guidance = await self.get_expert_guidance(phase, progress_data)
            progress_data["expert_guidance"] = guidance.get("guidance", "")
            progress_data["expert_confidence"] = guidance.get("confidence", 80)
        
        # Add cybersecurity context
        progress_data["cybersecurity_phase"] = phase
        progress_data["agent_expertise"] = self.agent_type
        progress_data["professional_standards"] = True
        
        await self.update_progress(phase, progress_data)
    
    @abstractmethod
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the agent's main functionality"""
        pass
    
    async def run(self, **kwargs) -> Dict[str, Any]:
        """Run the agent with error handling and lifecycle management"""
        if self.is_running:
            raise RuntimeError(f"{self.name} agent is already running")
        
        self.is_running = True
        self._cancel_event.clear()
        
        try:
            logger.info(f"🚀 Starting {self.name} agent")
            await self.update_progress("starting", {"status": "Agent initialization"})
            
            result = await self.execute(**kwargs)
            
            if not self.is_cancelled():
                await self.update_progress("completed", {"status": "Agent completed successfully"})
                logger.info(f"✅ {self.name} agent completed successfully")
            else:
                await self.update_progress("cancelled", {"status": "Agent execution cancelled"})
                logger.info(f"🛑 {self.name} agent execution cancelled")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ {self.name} agent failed: {e}")
            await self.update_progress("failed", {"status": f"Agent failed: {str(e)}"})
            raise
        
        finally:
            self.is_running = False
    
    async def save_result(self, key: str, data: Any, expire: int = 3600) -> None:
        """Save agent result to Redis"""
        try:
            cache_key = f"agent_result:{self.name}:{key}"
            await RedisClient.set(cache_key, data, expire=expire)
        except Exception as e:
            logger.error(f"Failed to save agent result: {e}")
    
    async def load_result(self, key: str) -> Optional[Any]:
        """Load agent result from Redis"""
        try:
            cache_key = f"agent_result:{self.name}:{key}"
            return await RedisClient.get(cache_key)
        except Exception as e:
            logger.error(f"Failed to load agent result: {e}")
            return None
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        return datetime.now().isoformat()


class AgentOrchestrator:
    """Orchestrates multiple agents for complex scanning operations"""
    
    def __init__(self):
        self.agents: Dict[str, BaseAgent] = {}
        self.execution_queue: asyncio.Queue = asyncio.Queue()
        self.results: Dict[str, Any] = {}
    
    def register_agent(self, agent: BaseAgent) -> None:
        """Register an agent with the orchestrator"""
        self.agents[agent.name] = agent
        logger.info(f"📋 Registered agent: {agent.name}")
    
    async def execute_sequential(self, agent_names: List[str], **kwargs) -> Dict[str, Any]:
        """Execute agents sequentially"""
        results = {}
        
        for agent_name in agent_names:
            if agent_name not in self.agents:
                raise ValueError(f"Agent {agent_name} not registered")
            
            agent = self.agents[agent_name]
            try:
                result = await agent.run(**kwargs)
                results[agent_name] = result
                
                # Pass results to next agent
                kwargs.update({"previous_results": results})
                
            except Exception as e:
                logger.error(f"Agent {agent_name} failed: {e}")
                results[agent_name] = {"error": str(e)}
                # Continue with other agents
        
        return results
    
    async def execute_parallel(self, agent_names: List[str], **kwargs) -> Dict[str, Any]:
        """Execute agents in parallel"""
        if not agent_names:
            return {}
        
        tasks = []
        for agent_name in agent_names:
            if agent_name not in self.agents:
                raise ValueError(f"Agent {agent_name} not registered")
            
            agent = self.agents[agent_name]
            task = asyncio.create_task(agent.run(**kwargs))
            tasks.append((agent_name, task))
        
        results = {}
        for agent_name, task in tasks:
            try:
                result = await task
                results[agent_name] = result
            except Exception as e:
                logger.error(f"Agent {agent_name} failed: {e}")
                results[agent_name] = {"error": str(e)}
        
        return results
    
    def cancel_all(self) -> None:
        """Cancel all running agents"""
        for agent in self.agents.values():
            agent.cancel()
        logger.info("🛑 Cancelled all agents") 