"""
Workflow Engine - Configurable Security Scanning Workflows
Advanced workflow orchestration with AI-powered decision making
"""

import asyncio
import json
import yaml
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

from loguru import logger
from agents.base import BaseAgent
from agents.agentic_ai.controller import AgentType, AgentTask, TaskPriority, AgentStatus


class WorkflowType(str, Enum):
    """Workflow types"""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    FULL_SECURITY_AUDIT = "full_security_audit"
    COMPLIANCE_CHECK = "compliance_check"
    PENETRATION_TEST = "penetration_test"
    BUG_BOUNTY = "bug_bounty"
    ENTERPRISE_SECURITY = "enterprise_security"
    CONTINUOUS_MONITORING = "continuous_monitoring"


class TriggerType(str, Enum):
    """Workflow trigger types"""
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    EVENT_DRIVEN = "event_driven"
    API_TRIGGERED = "api_triggered"
    CONTINUOUS = "continuous"


@dataclass
class WorkflowStep:
    """Individual workflow step definition"""
    id: str
    name: str
    agent_type: AgentType
    description: str
    config: Dict[str, Any]
    dependencies: List[str]
    timeout: int
    retry_count: int
    condition: Optional[str] = None  # Python expression for conditional execution
    parallel_group: Optional[str] = None  # For parallel execution
    priority: TaskPriority = TaskPriority.MEDIUM


@dataclass
class WorkflowDefinition:
    """Complete workflow definition"""
    id: str
    name: str
    description: str
    type: WorkflowType
    version: str
    author: str
    created_at: datetime
    steps: List[WorkflowStep]
    global_config: Dict[str, Any]
    triggers: List[Dict[str, Any]]
    notifications: Dict[str, Any]
    metadata: Dict[str, Any]


@dataclass
class WorkflowExecution:
    """Workflow execution instance"""
    id: str
    workflow_id: str
    status: AgentStatus
    started_at: datetime
    completed_at: Optional[datetime]
    trigger_type: TriggerType
    input_data: Dict[str, Any]
    results: Dict[str, Any]
    step_results: Dict[str, Any]
    error_message: Optional[str]
    progress: int


class WorkflowEngine(BaseAgent):
    """
    Advanced Workflow Engine for orchestrating security scanning workflows
    Supports conditional logic, parallel execution, and AI-powered decisions
    """
    
    def __init__(self):
        super().__init__("WorkflowEngine")
        self.workflows: Dict[str, WorkflowDefinition] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.workflow_templates_path = Path("./workflows/templates")
        self.user_workflows_path = Path("./workflows/user")
        
        # Create directories
        self.workflow_templates_path.mkdir(parents=True, exist_ok=True)
        self.user_workflows_path.mkdir(parents=True, exist_ok=True)
        
        # Load built-in workflows
        self._initialize_builtin_workflows()
        
        # Load user workflows
        self._load_user_workflows()
    
    def _initialize_builtin_workflows(self):
        """Initialize built-in workflow templates"""
        
        # Import and register agentic report generation workflow
        try:
            from agents.workflows.agentic_report_workflow import agentic_report_workflow
            
            workflow_def = agentic_report_workflow.get_workflow_definition()
            self.register_workflow(workflow_def)
            
            logger.info("✅ Registered agentic report generation workflow")
            
        except Exception as e:
            logger.error(f"Failed to register agentic report workflow: {e}")
        
        # Register other built-in workflows here
        logger.info(f"📋 Initialized {len(self.workflows)} built-in workflows")
        
        # Bug Bounty Workflow
        bug_bounty_workflow = WorkflowDefinition(
            id="bug_bounty_standard",
            name="Bug Bounty Standard Scan",
            description="Comprehensive bug bounty hunting workflow",
            type=WorkflowType.BUG_BOUNTY,
            version="1.0",
            author="Nexus Hunter",
            created_at=datetime.utcnow(),
            steps=[
                WorkflowStep(
                    id="subdomain_discovery",
                    name="Subdomain Discovery",
                    agent_type=AgentType.SUBDOMAIN_DISCOVERY,
                    description="Discover subdomains using multiple sources",
                    config={"aggressive": True, "sources": "all"},
                    dependencies=[],
                    timeout=600,
                    retry_count=2,
                    priority=TaskPriority.HIGH
                ),
                WorkflowStep(
                    id="port_scanning",
                    name="Port Scanning",
                    agent_type=AgentType.PORT_SCANNING,
                    description="Scan for open ports and services",
                    config={"profile": "common", "timeout": 10},
                    dependencies=["subdomain_discovery"],
                    timeout=900,
                    retry_count=1,
                    priority=TaskPriority.HIGH
                ),
                WorkflowStep(
                    id="web_technology",
                    name="Technology Detection",
                    agent_type=AgentType.WEB_TECHNOLOGY,
                    description="Detect web technologies and frameworks",
                    config={"deep_analysis": True},
                    dependencies=["port_scanning"],
                    timeout=300,
                    retry_count=1,
                    priority=TaskPriority.MEDIUM
                ),
                WorkflowStep(
                    id="vulnerability_scan",
                    name="Vulnerability Scanning",
                    agent_type=AgentType.NUCLEI_SCANNING,
                    description="Comprehensive vulnerability scanning",
                    config={"templates": ["critical", "high"], "rate_limit": 50},
                    dependencies=["web_technology"],
                    timeout=1200,
                    retry_count=1,
                    priority=TaskPriority.HIGH
                ),
                WorkflowStep(
                    id="custom_exploit",
                    name="Custom Vulnerability Testing",
                    agent_type=AgentType.VULNERABILITY,
                    description="Custom vulnerability testing and exploitation",
                    config={"safe_mode": True, "max_depth": 3},
                    dependencies=["vulnerability_scan"],
                    timeout=1800,
                    retry_count=1,
                    condition="len(step_results['vulnerability_scan']['vulnerabilities']) > 0",
                    priority=TaskPriority.MEDIUM
                )
            ],
            global_config={
                "target_scope": ["in_scope_only"],
                "output_formats": ["json", "html"],
                "concurrent_agents": 3,
                "rate_limiting": True
            },
            triggers=[
                {"type": "manual", "enabled": True},
                {"type": "scheduled", "cron": "0 2 * * *", "enabled": False}
            ],
            notifications={
                "on_completion": True,
                "on_critical_findings": True,
                "channels": ["slack", "email"]
            },
            metadata={
                "tags": ["bug_bounty", "web_security", "comprehensive"],
                "estimated_duration": 3600,
                "resource_requirements": "medium"
            }
        )
        
        # Enterprise Security Audit Workflow
        enterprise_workflow = WorkflowDefinition(
            id="enterprise_security_audit",
            name="Enterprise Security Audit",
            description="Comprehensive enterprise security assessment",
            type=WorkflowType.ENTERPRISE_SECURITY,
            version="1.0",
            author="Nexus Hunter",
            created_at=datetime.utcnow(),
            steps=[
                WorkflowStep(
                    id="asset_discovery",
                    name="Asset Discovery",
                    agent_type=AgentType.SUBDOMAIN_DISCOVERY,
                    description="Comprehensive asset discovery",
                    config={"passive_sources": True, "active_sources": True},
                    dependencies=[],
                    timeout=1200,
                    retry_count=2,
                    priority=TaskPriority.HIGH
                ),
                WorkflowStep(
                    id="dns_analysis",
                    name="DNS Intelligence",
                    agent_type=AgentType.DNS_INTELLIGENCE,
                    description="DNS security analysis",
                    config={"check_dnssec": True, "analyze_records": True},
                    dependencies=["asset_discovery"],
                    timeout=600,
                    retry_count=1,
                    priority=TaskPriority.HIGH,
                    parallel_group="recon"
                ),
                WorkflowStep(
                    id="port_analysis",
                    name="Port Analysis",
                    agent_type=AgentType.PORT_SCANNING,
                    description="Comprehensive port analysis",
                    config={"profile": "enterprise", "service_detection": True},
                    dependencies=["asset_discovery"],
                    timeout=1800,
                    retry_count=1,
                    priority=TaskPriority.HIGH,
                    parallel_group="recon"
                ),
                WorkflowStep(
                    id="ssl_analysis",
                    name="SSL/TLS Analysis",
                    agent_type=AgentType.SSL_INTELLIGENCE,
                    description="SSL/TLS security analysis",
                    config={"check_vulnerabilities": True, "analyze_ciphers": True},
                    dependencies=["port_analysis"],
                    timeout=600,
                    retry_count=1,
                    priority=TaskPriority.MEDIUM
                ),
                WorkflowStep(
                    id="vulnerability_assessment",
                    name="Vulnerability Assessment",
                    agent_type=AgentType.NUCLEI_SCANNING,
                    description="Enterprise vulnerability assessment",
                    config={"templates": ["all"], "compliance_checks": True},
                    dependencies=["ssl_analysis", "dns_analysis"],
                    timeout=3600,
                    retry_count=1,
                    priority=TaskPriority.CRITICAL
                ),
                WorkflowStep(
                    id="secret_scanning",
                    name="Secret Scanning",
                    agent_type=AgentType.SECRET_SCANNING,
                    description="Comprehensive secret exposure analysis",
                    config={"deep_scan": True, "check_repositories": True},
                    dependencies=["vulnerability_assessment"],
                    timeout=1800,
                    retry_count=1,
                    priority=TaskPriority.HIGH
                ),
                WorkflowStep(
                    id="github_intelligence",
                    name="Code Repository Analysis",
                    agent_type=AgentType.GITHUB_INTELLIGENCE,
                    description="GitHub repository security analysis",
                    config={"analyze_commits": True, "check_secrets": True},
                    dependencies=["secret_scanning"],
                    timeout=1200,
                    retry_count=1,
                    priority=TaskPriority.MEDIUM
                )
            ],
            global_config={
                "comprehensive_mode": True,
                "compliance_frameworks": ["SOC2", "ISO27001", "PCI-DSS"],
                "concurrent_agents": 5,
                "detailed_reporting": True
            },
            triggers=[
                {"type": "manual", "enabled": True},
                {"type": "scheduled", "cron": "0 1 1 * *", "enabled": True}  # Monthly
            ],
            notifications={
                "on_completion": True,
                "on_critical_findings": True,
                "executive_summary": True,
                "channels": ["email", "slack", "webhook"]
            },
            metadata={
                "tags": ["enterprise", "compliance", "comprehensive"],
                "estimated_duration": 7200,
                "resource_requirements": "high"
            }
        )
        
        # Quick Reconnaissance Workflow
        recon_workflow = WorkflowDefinition(
            id="quick_recon",
            name="Quick Reconnaissance",
            description="Fast reconnaissance for quick assessments",
            type=WorkflowType.RECONNAISSANCE,
            version="1.0",
            author="Nexus Hunter",
            created_at=datetime.utcnow(),
            steps=[
                WorkflowStep(
                    id="basic_discovery",
                    name="Basic Discovery",
                    agent_type=AgentType.SUBDOMAIN_DISCOVERY,
                    description="Basic subdomain discovery",
                    config={"quick_mode": True, "sources": "essential"},
                    dependencies=[],
                    timeout=300,
                    retry_count=1,
                    priority=TaskPriority.HIGH
                ),
                WorkflowStep(
                    id="port_probe",
                    name="Port Probing",
                    agent_type=AgentType.PORT_SCANNING,
                    description="Quick port probe",
                    config={"profile": "quick", "top_ports": 100},
                    dependencies=["basic_discovery"],
                    timeout=300,
                    retry_count=1,
                    priority=TaskPriority.HIGH,
                    parallel_group="quick_scan"
                ),
                WorkflowStep(
                    id="web_probe",
                    name="Web Service Probing",
                    agent_type=AgentType.WEB_TECHNOLOGY,
                    description="Web service detection",
                    config={"basic_fingerprinting": True},
                    dependencies=["basic_discovery"],
                    timeout=300,
                    retry_count=1,
                    priority=TaskPriority.MEDIUM,
                    parallel_group="quick_scan"
                )
            ],
            global_config={
                "speed_optimized": True,
                "concurrent_agents": 3,
                "minimal_output": True
            },
            triggers=[
                {"type": "manual", "enabled": True},
                {"type": "api_triggered", "enabled": True}
            ],
            notifications={
                "on_completion": True,
                "channels": ["webhook"]
            },
            metadata={
                "tags": ["reconnaissance", "quick", "lightweight"],
                "estimated_duration": 600,
                "resource_requirements": "low"
            }
        )
        
        # Store workflows
        self.workflows[bug_bounty_workflow.id] = bug_bounty_workflow
        self.workflows[enterprise_workflow.id] = enterprise_workflow
        self.workflows[recon_workflow.id] = recon_workflow
        
        # Save templates to disk
        self._save_workflow_template(bug_bounty_workflow)
        self._save_workflow_template(enterprise_workflow)
        self._save_workflow_template(recon_workflow)
        
        logger.info(f"✅ Initialized {len(self.workflows)} built-in workflows")
    
    def _save_workflow_template(self, workflow: WorkflowDefinition):
        """Save workflow template to disk"""
        try:
            template_file = self.workflow_templates_path / f"{workflow.id}.yaml"
            
            # Convert to serializable format
            workflow_dict = asdict(workflow)
            
            # Handle datetime serialization
            workflow_dict["created_at"] = workflow.created_at.isoformat()
            
            with open(template_file, 'w') as f:
                yaml.dump(workflow_dict, f, default_flow_style=False, indent=2)
            
        except Exception as e:
            logger.warning(f"Failed to save workflow template {workflow.id}: {e}")
    
    def _load_user_workflows(self):
        """Load user-defined workflows"""
        try:
            for workflow_file in self.user_workflows_path.glob("*.yaml"):
                workflow = self._load_workflow_from_file(workflow_file)
                if workflow:
                    self.workflows[workflow.id] = workflow
                    
            logger.info(f"📁 Loaded {len(self.workflows)} total workflows")
            
        except Exception as e:
            logger.warning(f"Failed to load user workflows: {e}")
    
    def _load_workflow_from_file(self, file_path: Path) -> Optional[WorkflowDefinition]:
        """Load workflow from YAML file"""
        try:
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)
            
            # Convert steps
            steps = []
            for step_data in data.get("steps", []):
                step = WorkflowStep(
                    id=step_data["id"],
                    name=step_data["name"],
                    agent_type=AgentType(step_data["agent_type"]),
                    description=step_data["description"],
                    config=step_data.get("config", {}),
                    dependencies=step_data.get("dependencies", []),
                    timeout=step_data.get("timeout", 300),
                    retry_count=step_data.get("retry_count", 1),
                    condition=step_data.get("condition"),
                    parallel_group=step_data.get("parallel_group"),
                    priority=TaskPriority(step_data.get("priority", "medium"))
                )
                steps.append(step)
            
            # Create workflow
            workflow = WorkflowDefinition(
                id=data["id"],
                name=data["name"],
                description=data["description"],
                type=WorkflowType(data["type"]),
                version=data["version"],
                author=data["author"],
                created_at=datetime.fromisoformat(data["created_at"]),
                steps=steps,
                global_config=data.get("global_config", {}),
                triggers=data.get("triggers", []),
                notifications=data.get("notifications", {}),
                metadata=data.get("metadata", {})
            )
            
            return workflow
            
        except Exception as e:
            logger.warning(f"Failed to load workflow from {file_path}: {e}")
            return None
    
    async def execute(self, scan_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Execute a workflow"""
        workflow_id = scan_data.get("workflow_id")
        if not workflow_id:
            raise ValueError("No workflow_id specified")
        
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        logger.info(f"🔄 Starting workflow execution: {workflow.name}")
        
        # Create execution instance
        execution = WorkflowExecution(
            id=f"{workflow_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            workflow_id=workflow_id,
            status=AgentStatus.RUNNING,
            started_at=datetime.utcnow(),
            completed_at=None,
            trigger_type=TriggerType.MANUAL,
            input_data=scan_data,
            results={},
            step_results={},
            error_message=None,
            progress=0
        )
        
        self.executions[execution.id] = execution
        
        try:
            # Execute workflow steps
            results = await self._execute_workflow_steps(workflow, execution)
            
            execution.status = AgentStatus.COMPLETED
            execution.completed_at = datetime.utcnow()
            execution.results = results
            execution.progress = 100
            
            logger.info(f"✅ Workflow {workflow.name} completed successfully")
            return results
            
        except Exception as e:
            execution.status = AgentStatus.FAILED
            execution.error_message = str(e)
            execution.completed_at = datetime.utcnow()
            
            logger.error(f"❌ Workflow {workflow.name} failed: {e}")
            raise
    
    async def _execute_workflow_steps(self, workflow: WorkflowDefinition, execution: WorkflowExecution) -> Dict[str, Any]:
        """Execute workflow steps with dependency management"""
        steps = workflow.steps
        completed_steps: Set[str] = set()
        step_results: Dict[str, Any] = {}
        
        # Group steps by parallel groups
        parallel_groups = {}
        sequential_steps = []
        
        for step in steps:
            if step.parallel_group:
                if step.parallel_group not in parallel_groups:
                    parallel_groups[step.parallel_group] = []
                parallel_groups[step.parallel_group].append(step)
            else:
                sequential_steps.append(step)
        
        # Execute steps
        total_steps = len(steps)
        step_count = 0
        
        # Execute sequential steps and parallel groups
        all_steps = sequential_steps + list(parallel_groups.keys())
        
        for item in all_steps:
            if self.is_cancelled():
                break
            
            if isinstance(item, WorkflowStep):
                # Sequential step
                if self._can_execute_step(item, completed_steps):
                    if self._evaluate_step_condition(item, step_results):
                        result = await self._execute_step(item, execution.input_data, step_results)
                        step_results[item.id] = result
                        completed_steps.add(item.id)
                        step_count += 1
                        
                        # Update progress
                        execution.progress = (step_count / total_steps) * 100
                        execution.step_results = step_results
                        
                        await self.update_progress(f"step_{item.id}", {
                            "step": item.name,
                            "status": "completed",
                            "progress": f"{step_count}/{total_steps}"
                        })
            
            elif isinstance(item, str):
                # Parallel group
                group_steps = parallel_groups[item]
                
                # Check if all dependencies are met for the group
                can_execute_group = all(
                    self._can_execute_step(step, completed_steps) 
                    for step in group_steps
                )
                
                if can_execute_group:
                    # Execute parallel group
                    group_tasks = []
                    for step in group_steps:
                        if self._evaluate_step_condition(step, step_results):
                            task = self._execute_step(step, execution.input_data, step_results)
                            group_tasks.append((step.id, task))
                    
                    # Wait for parallel execution
                    group_results = await asyncio.gather(*[task for _, task in group_tasks], return_exceptions=True)
                    
                    # Process results
                    for i, (step_id, result) in enumerate([(step_id, result) for (step_id, _), result in zip(group_tasks, group_results)]):
                        if not isinstance(result, Exception):
                            step_results[step_id] = result
                            completed_steps.add(step_id)
                            step_count += 1
                        else:
                            logger.error(f"Step {step_id} failed: {result}")
                    
                    # Update progress
                    execution.progress = (step_count / total_steps) * 100
                    execution.step_results = step_results
        
        # Compile final results
        final_results = {
            "workflow_id": workflow.id,
            "workflow_name": workflow.name,
            "execution_id": execution.id,
            "steps_executed": list(completed_steps),
            "step_results": step_results,
            "summary": self._generate_workflow_summary(step_results),
            "metadata": {
                "total_steps": total_steps,
                "completed_steps": len(completed_steps),
                "execution_time": (datetime.utcnow() - execution.started_at).total_seconds(),
                "workflow_type": workflow.type.value
            }
        }
        
        return final_results
    
    def _can_execute_step(self, step: WorkflowStep, completed_steps: Set[str]) -> bool:
        """Check if step can be executed based on dependencies"""
        return all(dep in completed_steps for dep in step.dependencies)
    
    def _evaluate_step_condition(self, step: WorkflowStep, step_results: Dict[str, Any]) -> bool:
        """Evaluate step execution condition"""
        if not step.condition:
            return True
        
        try:
            # Create safe evaluation context
            context = {
                "step_results": step_results,
                "len": len,
                "any": any,
                "all": all
            }
            
            return eval(step.condition, {"__builtins__": {}}, context)
        except Exception as e:
            logger.warning(f"Failed to evaluate step condition '{step.condition}': {e}")
            return True  # Default to execute if condition evaluation fails
    
    async def _execute_step(self, step: WorkflowStep, input_data: Dict[str, Any], step_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single workflow step"""
        logger.info(f"🔄 Executing step: {step.name}")
        
        try:
            # Get agent instance
            agent = await self._get_agent_instance(step.agent_type)
            
            # Prepare step input data
            step_input = {
                **input_data,
                **step.config,
                "step_results": step_results,
                "workflow_context": True
            }
            
            # Execute with timeout
            result = await asyncio.wait_for(
                agent.execute(step_input),
                timeout=step.timeout
            )
            
            logger.info(f"✅ Step {step.name} completed successfully")
            return result
            
        except asyncio.TimeoutError:
            logger.error(f"⏰ Step {step.name} timed out after {step.timeout}s")
            raise
        except Exception as e:
            logger.error(f"❌ Step {step.name} failed: {e}")
            
            # Retry if configured
            if step.retry_count > 0:
                logger.info(f"🔄 Retrying step {step.name} ({step.retry_count} retries left)")
                # Implement retry logic here
            
            raise
    
    async def _get_agent_instance(self, agent_type: AgentType) -> BaseAgent:
        """Get agent instance for the specified type"""
        # Import and instantiate agents
        if agent_type == AgentType.SUBDOMAIN_DISCOVERY:
            from agents.reconnaissance_agents.subfinder_agent import SubfinderAgent
            return SubfinderAgent()
        elif agent_type == AgentType.PORT_SCANNING:
            from agents.reconnaissance_agents.naabu_agent import NaabuAgent
            return NaabuAgent()
        elif agent_type == AgentType.WEB_TECHNOLOGY:
            from agents.reconnaissance_agents.httpx_agent import HttpxAgent
            return HttpxAgent()
        elif agent_type == AgentType.NUCLEI_SCANNING:
            from agents.vulnerability_agents.nuclei_agent import NucleiAgent
            return NucleiAgent()
        elif agent_type == AgentType.SECRET_SCANNING:
            from agents.vulnerability_agents.secret_agent import SecretAgent
            return SecretAgent()
        elif agent_type == AgentType.GITHUB_INTELLIGENCE:
            from agents.reconnaissance_agents.github_agent import GitHubAgent
            return GitHubAgent()
        else:
            # Fallback to existing agents
            from agents.recon_agent import ReconAgent
            return ReconAgent()
    
    def _generate_workflow_summary(self, step_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate workflow execution summary"""
        summary = {
            "total_findings": 0,
            "vulnerabilities_found": 0,
            "secrets_discovered": 0,
            "subdomains_discovered": 0,
            "open_ports": 0,
            "technologies_identified": 0,
            "risk_score": 0
        }
        
        # Aggregate results from all steps
        for step_id, result in step_results.items():
            if isinstance(result, dict):
                # Count vulnerabilities
                vulns = result.get("vulnerabilities", [])
                summary["vulnerabilities_found"] += len(vulns)
                
                # Count secrets
                secrets = result.get("secrets", [])
                summary["secrets_discovered"] += len(secrets)
                
                # Count subdomains
                subdomains = result.get("subdomains", [])
                summary["subdomains_discovered"] += len(subdomains)
                
                # Count open ports
                ports = result.get("ports", {})
                summary["open_ports"] += sum(len(port_list) for port_list in ports.values())
                
                # Count technologies
                technologies = result.get("technologies", {})
                summary["technologies_identified"] += len(technologies)
        
        # Calculate total findings
        summary["total_findings"] = (
            summary["vulnerabilities_found"] + 
            summary["secrets_discovered"]
        )
        
        # Calculate risk score
        summary["risk_score"] = min(
            summary["vulnerabilities_found"] * 5 + 
            summary["secrets_discovered"] * 10 +
            summary["open_ports"] * 0.5,
            100
        )
        
        return summary
    
    def get_available_workflows(self) -> List[Dict[str, Any]]:
        """Get list of available workflows"""
        return [
            {
                "id": workflow.id,
                "name": workflow.name,
                "description": workflow.description,
                "type": workflow.type.value,
                "estimated_duration": workflow.metadata.get("estimated_duration", 0),
                "resource_requirements": workflow.metadata.get("resource_requirements", "medium"),
                "tags": workflow.metadata.get("tags", [])
            }
            for workflow in self.workflows.values()
        ]
    
    def get_workflow_definition(self, workflow_id: str) -> Optional[WorkflowDefinition]:
        """Get workflow definition"""
        return self.workflows.get(workflow_id)
    
    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get workflow execution status"""
        execution = self.executions.get(execution_id)
        if not execution:
            return None
        
        return {
            "id": execution.id,
            "workflow_id": execution.workflow_id,
            "status": execution.status.value,
            "progress": execution.progress,
            "started_at": execution.started_at.isoformat(),
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
            "step_results": list(execution.step_results.keys()),
            "error_message": execution.error_message
        }
    
    async def create_custom_workflow(self, workflow_data: Dict[str, Any]) -> WorkflowDefinition:
        """Create custom user workflow"""
        try:
            # Validate and create workflow
            workflow = self._parse_workflow_data(workflow_data)
            
            # Save to user workflows
            self.workflows[workflow.id] = workflow
            
            # Save to disk
            user_workflow_file = self.user_workflows_path / f"{workflow.id}.yaml"
            with open(user_workflow_file, 'w') as f:
                yaml.dump(asdict(workflow), f, default_flow_style=False, indent=2)
            
            logger.info(f"✅ Created custom workflow: {workflow.name}")
            return workflow
            
        except Exception as e:
            logger.error(f"❌ Failed to create custom workflow: {e}")
            raise
    
    def _parse_workflow_data(self, data: Dict[str, Any]) -> WorkflowDefinition:
        """Parse workflow data into WorkflowDefinition"""
        # Implementation for parsing workflow data
        # This would validate and convert the input data
        pass
    
    async def execute_workflow(
        self, 
        workflow_name: str, 
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a specific workflow by name"""
        try:
            if workflow_name not in self.workflows:
                return {
                    "success": False,
                    "error": f"Workflow '{workflow_name}' not found"
                }
            
            workflow_def = self.workflows[workflow_name]
            
            # Handle agentic report generation workflow specially
            if workflow_name == "agentic_report_generation":
                return await self._execute_agentic_report_workflow(context)
            
            # Default workflow execution
            return await self._execute_standard_workflow(workflow_def, context)
            
        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _execute_agentic_report_workflow(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the agentic report generation workflow"""
        try:
            from agents.workflows.agentic_report_workflow import agentic_report_workflow
            
            logger.info("🚀 Executing agentic report generation workflow")
            
            # Execute workflow steps in sequence with AI coordination
            results = {}
            
            # Step 1: AI Analysis and Planning
            analysis_result = await agentic_report_workflow.execute_step(
                "ai_analysis_planning", context
            )
            if not analysis_result.get("success"):
                return analysis_result
            
            results.update(analysis_result)
            context.update(analysis_result)
            
            # Step 2: Parallel Report Generation
            report_types = context.get("report_types", ["executive", "technical", "disclosure"])
            parallel_tasks = []
            
            if "technical" in report_types:
                parallel_tasks.append(
                    agentic_report_workflow.execute_step("vulnerability_analysis", context)
                )
                parallel_tasks.append(
                    agentic_report_workflow.execute_step("technical_details", context)
                )
            
            if "executive" in report_types:
                parallel_tasks.append(
                    agentic_report_workflow.execute_step("executive_summary", context)
                )
            
            if "disclosure" in report_types:
                parallel_tasks.append(
                    agentic_report_workflow.execute_step("disclosure_generation", context)
                )
            
            # Execute parallel tasks
            import asyncio
            parallel_results = await asyncio.gather(*parallel_tasks, return_exceptions=True)
            
            # Process parallel results
            for result in parallel_results:
                if isinstance(result, Exception):
                    logger.error(f"Parallel task failed: {result}")
                    continue
                if result.get("success"):
                    results.update(result)
                    context.update(result)
            
            # Step 3: Format Generation
            format_result = await agentic_report_workflow.execute_step(
                "format_generation", context
            )
            if format_result.get("success"):
                results.update(format_result)
                context.update(format_result)
            
            # Step 4: AI Quality Assurance
            qa_result = await agentic_report_workflow.execute_step(
                "ai_quality_assurance", context
            )
            if qa_result.get("success"):
                results.update(qa_result)
            
            logger.info("✅ Agentic report generation workflow completed")
            
            return {
                "success": True,
                "workflow_type": "agentic_reporting",
                "ReportAgent": results,
                "metadata": context.get("metadata", {}),
                "ai_orchestrated": True
            }
            
        except Exception as e:
            logger.error(f"❌ Agentic workflow execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "workflow_type": "agentic_reporting"
            }
    
    async def _execute_standard_workflow(
        self, 
        workflow_def: WorkflowDefinition, 
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a standard workflow definition"""
        # Implementation for standard workflow execution
        # This would handle the general case for other workflows
        return {
            "success": True,
            "message": "Standard workflow execution not implemented yet"
        }
