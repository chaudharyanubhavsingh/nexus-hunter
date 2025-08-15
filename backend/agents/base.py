"""
Base Agent class for Nexus Hunter autonomous agents
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Callable
from uuid import UUID

from loguru import logger

from core.websocket_manager import WebSocketManager
from core.redis_client import RedisClient


class BaseAgent(ABC):
    """Base class for all autonomous agents"""
    
    def __init__(self, name: str):
        self.name = name
        self.is_running = False
        self._progress_callback: Optional[Callable] = None
        self._cancel_event = asyncio.Event()
    
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