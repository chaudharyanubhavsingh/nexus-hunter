import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Brain, 
  Search, 
  Shield, 
  Zap, 
  FileText, 
  Database,
  Activity,
  AlertCircle,
  CheckCircle,
  Clock,
  Wifi,
  WifiOff
} from 'lucide-react';
import { useAppContext } from '../context/AppContext';

// Agent types and their icons
const AGENT_TYPES = {
  recon: { name: 'Recon Agent', icon: Search, color: 'neon-cyan' },
  vulnerability: { name: 'Vulnerability Agent', icon: Shield, color: 'neon-orange' },
  exploit: { name: 'Exploit Agent', icon: Zap, color: 'neon-red' },
  secrets: { name: 'Secrets Agent', icon: Database, color: 'neon-purple' },
  ai_controller: { name: 'AI Controller', icon: Brain, color: 'neon-green' },
  report: { name: 'Report Agent', icon: FileText, color: 'neon-blue' }
};

// Agent status types
type AgentStatus = 'ACTIVE' | 'STANDBY' | 'IDLE' | 'ERROR' | 'COMPLETED';

interface Agent {
  id: string;
  name: string;
  status: AgentStatus;
  progress: number;
  lastActivity: string;
  tasksCompleted: number;
  totalTasks: number;
  currentTask?: string;
}

interface AgentStatusMonitorProps {
  scanId?: string;
  compact?: boolean;
  showProgress?: boolean;
}

const AgentStatusMonitor: React.FC<AgentStatusMonitorProps> = ({ 
  scanId, 
  compact = false, 
  showProgress = true 
}) => {
  const { state } = useAppContext();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [overallProgress, setOverallProgress] = useState(0);
  const [isConnected, setIsConnected] = useState(true);

  // Calculate individual agent status based on scan progress and type
  const calculateIndividualAgentStatus = (
    agentId: string, 
    scanProgress: number, 
    scanStatus: string, 
    scan: any
  ): Agent => {
    const agentInfo = AGENT_TYPES[agentId as keyof typeof AGENT_TYPES];
    
    // Determine if agent should be active based on scan type and progress
    let status: AgentStatus = 'STANDBY';
    let progress = 0;
    let currentTask = '';
    let tasksCompleted = 0;
    let totalTasks = 1;

    if (scanStatus === 'running') {
      // Determine active agents based on scan progress phases
      if (agentId === 'ai_controller') {
        // AI Controller is always active during scans
        status = 'ACTIVE';
        progress = scanProgress;
        currentTask = 'Orchestrating scan workflow';
        tasksCompleted = Math.floor(scanProgress / 20);
        totalTasks = 5;
      } else if (agentId === 'recon') {
        // Recon agent active in early phases (0-40%)
        if (scanProgress <= 40) {
          status = 'ACTIVE';
          progress = Math.min(scanProgress * 2.5, 100); // Scale to 100% for this phase
          currentTask = scanProgress <= 20 ? 'Subdomain discovery' : 'Port scanning';
          tasksCompleted = Math.floor(progress / 33);
          totalTasks = 3;
        } else {
          status = 'COMPLETED';
          progress = 100;
          tasksCompleted = 3;
          totalTasks = 3;
        }
      } else if (agentId === 'vulnerability') {
        // Vulnerability agent active in middle phases (20-70%)
        if (scanProgress >= 20 && scanProgress <= 70) {
          status = 'ACTIVE';
          progress = Math.min((scanProgress - 20) * 2, 100);
          currentTask = progress <= 50 ? 'Nuclei scanning' : 'Vulnerability analysis';
          tasksCompleted = Math.floor(progress / 25);
          totalTasks = 4;
        } else if (scanProgress > 70) {
          status = 'COMPLETED';
          progress = 100;
          tasksCompleted = 4;
          totalTasks = 4;
        }
      } else if (agentId === 'exploit') {
        // Exploit agent active in later phases (50-90%) for exploit scans
        const isExploitScan = scan.scan_type?.includes('exploit') || scan.scan_type === 'full';
        if (isExploitScan && scanProgress >= 50 && scanProgress <= 90) {
          status = 'ACTIVE';
          progress = Math.min((scanProgress - 50) * 2.5, 100);
          currentTask = progress <= 30 ? 'SQL injection testing' : 
                       progress <= 60 ? 'XSS testing' : 
                       progress <= 80 ? 'RCE testing' : 'LFI testing';
          tasksCompleted = Math.floor(progress / 25);
          totalTasks = 4;
        } else if (isExploitScan && scanProgress > 90) {
          status = 'COMPLETED';
          progress = 100;
          tasksCompleted = 4;
          totalTasks = 4;
        }
      } else if (agentId === 'secrets') {
        // Secrets agent active for secrets scans or full scans (30-60%)
        const isSecretsScan = scan.scan_type?.includes('secrets') || scan.scan_type === 'full';
        if (isSecretsScan && scanProgress >= 30 && scanProgress <= 60) {
          status = 'ACTIVE';
          progress = Math.min((scanProgress - 30) * 3.33, 100);
          currentTask = progress <= 50 ? 'Repository scanning' : 'Secrets analysis';
          tasksCompleted = Math.floor(progress / 50);
          totalTasks = 2;
        } else if (isSecretsScan && scanProgress > 60) {
          status = 'COMPLETED';
          progress = 100;
          tasksCompleted = 2;
          totalTasks = 2;
        }
      } else if (agentId === 'report') {
        // Report agent active in final phase (80-100%)
        if (scanProgress >= 80) {
          status = 'ACTIVE';
          progress = Math.min((scanProgress - 80) * 5, 100);
          currentTask = progress <= 50 ? 'Generating report' : 'AI analysis';
          tasksCompleted = Math.floor(progress / 50);
          totalTasks = 2;
        } else if (scanProgress === 100) {
          status = 'COMPLETED';
          progress = 100;
          tasksCompleted = 2;
          totalTasks = 2;
        }
      }
    } else if (scanStatus === 'completed') {
      status = 'COMPLETED';
      progress = 100;
      currentTask = 'Task completed';
    } else if (scanStatus === 'failed') {
      status = 'ERROR';
      progress = 0;
      currentTask = 'Task failed';
    }

    return {
      id: agentId,
      name: agentInfo.name,
      status,
      progress,
      lastActivity: currentTask || 'Waiting for tasks',
      tasksCompleted,
      totalTasks,
      currentTask
    };
  };

  // Calculate agent status based on current scan activity
  const calculateAgentStatus = useMemo(() => {
    // If no scanId provided, show system status with some agents active for demo
    if (!scanId) {
      return Object.keys(AGENT_TYPES).map((agentId, index) => {
        // Demo active status - show some agents as active for realistic display
        const demoStatuses: AgentStatus[] = ['ACTIVE', 'STANDBY', 'ACTIVE', 'STANDBY', 'ACTIVE', 'STANDBY'];
        const demoProgress = [75, 0, 45, 0, 90, 0];
        const demoTasks = ['System monitoring', 'Waiting for tasks', 'Background analysis', 'Waiting for tasks', 'Continuous reporting', 'Waiting for tasks'];
        
        return {
          id: agentId,
          name: AGENT_TYPES[agentId as keyof typeof AGENT_TYPES].name,
          status: demoStatuses[index] || 'STANDBY',
          progress: demoProgress[index] || 0,
          lastActivity: demoTasks[index] || 'Waiting for tasks',
          tasksCompleted: Math.floor((demoProgress[index] || 0) / 25),
          totalTasks: 4,
          currentTask: demoStatuses[index] === 'ACTIVE' ? demoTasks[index] : undefined
        };
      });
    }

    // Find current scan
    const currentScan = state.scans.find(scan => scan.id === scanId);
    if (!currentScan) {
      // If scan not found, return empty array
      return [];
    }

    const scanProgress = currentScan.progress_percentage || 0;
    const scanStatus = currentScan.status;

    // Determine which agents should be active based on scan type and progress
    return Object.keys(AGENT_TYPES).map(agentId => {
      const agent = calculateIndividualAgentStatus(agentId, scanProgress, scanStatus, currentScan);
      return agent;
    });
  }, [scanId, state.scans]);

  // Update agents when calculation changes
  useEffect(() => {
    setAgents(calculateAgentStatus);
  }, [calculateAgentStatus]);

  // Calculate overall progress
  useEffect(() => {
    if (agents.length === 0) {
      setOverallProgress(0);
      return;
    }

    const activeAgents = agents.filter(agent => 
      agent.status === 'ACTIVE' || agent.status === 'COMPLETED'
    );
    
    if (activeAgents.length === 0) {
      setOverallProgress(0);
    } else {
      const totalProgress = activeAgents.reduce((sum, agent) => sum + agent.progress, 0);
      const avgProgress = totalProgress / activeAgents.length;
      setOverallProgress(Math.round(avgProgress));
    }
  }, [agents]);

  // Simulate WebSocket connection status
  useEffect(() => {
    const interval = setInterval(() => {
      // Simulate occasional connection issues
      setIsConnected(prev => Math.random() > 0.05 ? true : prev);
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status: AgentStatus) => {
    switch (status) {
      case 'ACTIVE': return 'text-neon-green';
      case 'COMPLETED': return 'text-neon-blue';
      case 'ERROR': return 'text-neon-red';
      case 'STANDBY': return 'text-neon-orange';
      default: return 'text-cyber-muted';
    }
  };

  const getStatusIcon = (status: AgentStatus) => {
    switch (status) {
      case 'ACTIVE': return Activity;
      case 'COMPLETED': return CheckCircle;
      case 'ERROR': return AlertCircle;
      case 'STANDBY': return Clock;
      default: return Clock;
    }
  };

  if (compact) {
    return (
      <div className="bg-cyber-dark border border-cyber-gray rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-cyber-white flex items-center">
            <Brain size={16} className="mr-2 text-neon-green" />
            Agent Status
          </h3>
          <div className="flex items-center space-x-1">
            {isConnected ? (
              <Wifi size={14} className="text-neon-green" />
            ) : (
              <WifiOff size={14} className="text-neon-red" />
            )}
            <span className="text-xs text-cyber-muted">
              {agents.filter(a => a.status === 'ACTIVE').length} active
            </span>
          </div>
        </div>
        
        <div className="grid grid-cols-2 gap-2">
          {agents.slice(0, 4).map((agent) => {
            const AgentIcon = AGENT_TYPES[agent.id as keyof typeof AGENT_TYPES].icon;
            const StatusIcon = getStatusIcon(agent.status);
            
            return (
              <div key={agent.id} className="flex items-center space-x-2 p-2 bg-cyber-gray bg-opacity-10 rounded">
                <AgentIcon size={14} className="text-cyber-muted" />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-cyber-white truncate">
                    {agent.name.replace(' Agent', '')}
                  </div>
                  <div className={`text-xs ${getStatusColor(agent.status)}`}>
                    {agent.status}
                  </div>
                </div>
                <StatusIcon size={12} className={getStatusColor(agent.status)} />
              </div>
            );
          })}
        </div>
        
        {showProgress && (
          <div className="mt-3">
            <div className="flex justify-between text-xs text-cyber-muted mb-1">
              <span>Overall Progress</span>
              <span>{overallProgress}%</span>
            </div>
            <div className="w-full bg-cyber-gray bg-opacity-20 rounded-full h-2">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${overallProgress}%` }}
                transition={{ duration: 0.5 }}
                className="bg-gradient-to-r from-neon-cyan to-neon-green h-2 rounded-full"
              />
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="bg-cyber-dark border border-cyber-gray rounded-lg p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold text-cyber-white flex items-center">
          <Brain size={20} className="mr-3 text-neon-green" />
          AI Agent Status Monitor
        </h2>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            {isConnected ? (
              <Wifi size={16} className="text-neon-green" />
            ) : (
              <WifiOff size={16} className="text-neon-red" />
            )}
            <span className="text-sm text-cyber-muted">
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          <div className="text-sm text-cyber-muted">
            {agents.filter(a => a.status === 'ACTIVE').length} of {agents.length} active
          </div>
        </div>
      </div>

      {/* Overall Progress */}
      {showProgress && (
        <div className="mb-6">
          <div className="flex justify-between text-sm text-cyber-white mb-2">
            <span>Overall Mission Progress</span>
            <span className="text-neon-green font-medium">{overallProgress}%</span>
          </div>
          <div className="w-full bg-cyber-gray bg-opacity-20 rounded-full h-3">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${overallProgress}%` }}
              transition={{ duration: 0.8, ease: "easeOut" }}
              className="bg-gradient-to-r from-neon-cyan via-neon-green to-neon-blue h-3 rounded-full relative overflow-hidden"
            >
              <motion.div
                animate={{ x: ["0%", "100%"] }}
                transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                className="absolute inset-0 bg-gradient-to-r from-transparent via-white via-transparent to-transparent opacity-30"
              />
            </motion.div>
          </div>
        </div>
      )}

      {/* Agent List */}
      <div className="space-y-4">
        <AnimatePresence>
          {agents.map((agent) => {
            const agentType = AGENT_TYPES[agent.id as keyof typeof AGENT_TYPES];
            const AgentIcon = agentType.icon;
            const StatusIcon = getStatusIcon(agent.status);
            
            return (
              <motion.div
                key={agent.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-20 rounded-lg p-4"
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    <div className={`p-2 bg-${agentType.color} bg-opacity-20 rounded-lg`}>
                      <AgentIcon size={20} className={`text-${agentType.color}`} />
                    </div>
                    <div>
                      <h3 className="font-medium text-cyber-white">{agent.name}</h3>
                      <p className="text-xs text-cyber-muted">{agent.lastActivity}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-3">
                    <div className="text-right">
                      <div className={`text-sm font-medium ${getStatusColor(agent.status)}`}>
                        {agent.status}
                      </div>
                      <div className="text-xs text-cyber-muted">
                        {agent.tasksCompleted}/{agent.totalTasks} tasks
                      </div>
                    </div>
                    <StatusIcon size={18} className={getStatusColor(agent.status)} />
                  </div>
                </div>
                
                {agent.status === 'ACTIVE' && (
                  <div className="space-y-2">
                    <div className="flex justify-between text-xs text-cyber-muted">
                      <span>Task Progress</span>
                      <span>{agent.progress}%</span>
                    </div>
                    <div className="w-full bg-cyber-gray bg-opacity-30 rounded-full h-2">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${agent.progress}%` }}
                        transition={{ duration: 0.5 }}
                        className={`bg-${agentType.color} h-2 rounded-full`}
                      />
                    </div>
                    {agent.currentTask && (
                      <div className="text-xs text-cyber-muted italic">
                        → {agent.currentTask}
                      </div>
                    )}
                  </div>
                )}
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </div>
  );
};

export default AgentStatusMonitor;
