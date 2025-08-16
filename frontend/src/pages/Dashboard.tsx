import { useState } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { 
  Activity, 
  Target, 
  Shield, 
  AlertTriangle, 
  Zap,
  TrendingUp,
  Eye,
  Brain
} from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { useDashboardData } from '../hooks/useApi'
import AddTargetModal from '../components/AddTargetModal'
import CreateScanModal from '../components/CreateScanModal'

export default function Dashboard() {
  const { state } = useAppContext()
  const dashboardData = useDashboardData()
  const navigate = useNavigate()

  // Modal states
  const [isAddTargetModalOpen, setIsAddTargetModalOpen] = useState(false)
  const [isCreateScanModalOpen, setIsCreateScanModalOpen] = useState(false)

  // Remove manual refetch calls - rely on query cache and WebSocket updates
  // The excessive manual refetching was causing database noise

  const recentActivity = [
    {
      id: 1,
      type: 'scan_completed',
      message: 'Vulnerability scan completed for example.com',
      timestamp: '2 minutes ago',
      severity: 'high',
      icon: Shield
    },
    {
      id: 2,
      type: 'vuln_found', 
      message: 'SQL Injection vulnerability detected',
      timestamp: '5 minutes ago',
      severity: 'critical',
      icon: AlertTriangle
    },
    {
      id: 3,
      type: 'scan_started',
      message: 'Reconnaissance scan initiated for api.target.com',
      timestamp: '12 minutes ago',
      severity: 'info',
      icon: Eye
    },
    {
      id: 4,
      type: 'report_generated',
      message: 'Security assessment report generated',
      timestamp: '25 minutes ago',
      severity: 'success',
      icon: Brain
    }
  ]

  // Update stats with real data
  const currentStats = [
    {
      label: 'Active Scans',
      value: state.stats.activeScans.toString(),
      change: '+' + Math.max(0, state.stats.activeScans - 1),
      icon: Activity,
      color: 'text-neon-green',
      bgColor: 'bg-neon-green/10',
      borderColor: 'border-neon-green/30'
    },
    {
      label: 'Targets',
      value: state.stats.totalTargets.toString(),
      change: '+' + Math.max(0, state.targets.length - 5),
      icon: Target,
      color: 'text-primary',
      bgColor: 'bg-primary/10',
      borderColor: 'border-primary/30'
    },
    {
      label: 'Vulnerabilities',
      value: state.stats.totalVulnerabilities.toString(),
      change: '+' + Math.max(0, state.stats.totalVulnerabilities - 10),
      icon: Shield,
      color: 'text-danger',
      bgColor: 'bg-danger/10',
      borderColor: 'border-danger/30'
    },
    {
      label: 'Critical Issues',
      value: state.stats.criticalVulnerabilities.toString(),
      change: '+' + state.stats.criticalVulnerabilities,
      icon: AlertTriangle,
      color: 'text-warning',
      bgColor: 'bg-warning/10',
      borderColor: 'border-warning/30'
    }
  ]

  if (dashboardData.isLoading) {
    return (
      <div className="space-y-6 flex items-center justify-center min-h-screen">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
          className="w-8 h-8 border-2 border-neon-cyan border-t-transparent rounded-full"
        />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-cyber font-bold text-glow mb-2">
            COMMAND CENTER
          </h1>
          <p className="text-cyber-muted">
            Autonomous Security Intelligence Dashboard
          </p>
        </div>
        
        <motion.div
          className="flex items-center space-x-2 text-xs bg-primary/10 border border-primary/30 px-4 py-2 rounded-lg"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <Zap size={16} className="text-primary animate-pulse" />
          <span className="text-primary font-mono">NEXUS PROTOCOL ACTIVE</span>
        </motion.div>
      </motion.div>

      {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {currentStats.map((stat, index) => {
          const Icon = stat.icon
          
          return (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              whileHover={{ scale: 1.02, y: -2 }}
              className={`
                card-cyber p-6 rounded-lg
                ${stat.bgColor} border ${stat.borderColor}
                hover:shadow-neon transition-all duration-300
              `}
            >
              <div className="flex items-center justify-between mb-4">
                <Icon className={`${stat.color} w-8 h-8`} />
                <span className={`text-xs font-mono ${stat.color} bg-current/10 px-2 py-1 rounded`}>
                  {stat.change}
                </span>
              </div>
              
              <div className="space-y-1">
                <div className={`text-2xl font-cyber font-bold ${stat.color} text-glow`}>
                  {stat.value}
                </div>
                <div className="text-sm text-cyber-muted font-mono uppercase tracking-wider">
                  {stat.label}
                </div>
              </div>
            </motion.div>
          )
        })}
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Activity Feed */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="lg:col-span-2 card-cyber p-6 rounded-lg"
        >
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-cyber font-bold text-primary text-glow">
              REAL-TIME ACTIVITY
            </h2>
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-success rounded-full animate-pulse" />
              <span className="text-xs text-cyber-muted font-mono">LIVE</span>
            </div>
          </div>
          
          <div className="space-y-4 max-h-96 overflow-y-auto scrollbar-cyber">
            {recentActivity.map((activity, index) => {
              const Icon = activity.icon
              
              return (
                <motion.div
                  key={activity.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: index * 0.1 }}
                  className="flex items-start space-x-3 p-3 rounded border border-cyber-light/20 hover:border-primary/30 transition-colors"
                >
                  <div className={`
                    p-2 rounded-full
                    ${activity.severity === 'critical' ? 'bg-danger/20 text-danger' : ''}
                    ${activity.severity === 'high' ? 'bg-warning/20 text-warning' : ''}
                    ${activity.severity === 'info' ? 'bg-info/20 text-info' : ''}
                    ${activity.severity === 'success' ? 'bg-success/20 text-success' : ''}
                  `}>
                    <Icon size={16} />
                  </div>
                  
                  <div className="flex-1">
                    <p className="text-sm text-primary font-mono">
                      {activity.message}
                    </p>
                    <p className="text-xs text-cyber-muted mt-1">
                      {activity.timestamp}
                    </p>
                  </div>
                </motion.div>
              )
            })}
          </div>
        </motion.div>

        {/* System Status */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="space-y-6"
        >
          {/* Agent Status */}
          <div className="card-cyber p-6 rounded-lg">
            <h3 className="text-lg font-cyber font-bold text-primary text-glow mb-4">
              AGENT STATUS
            </h3>
            
            <div className="space-y-3">
              {[
                { name: 'Recon Agent', status: 'active', progress: 85 },
                { name: 'Exploit Agent', status: 'standby', progress: 0 },
                { name: 'Report Agent', status: 'active', progress: 45 }
              ].map((agent) => (
                <div key={agent.name} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-mono text-cyber-light">
                      {agent.name}
                    </span>
                    <span className={`
                      text-xs font-mono px-2 py-1 rounded
                      ${agent.status === 'active' 
                        ? 'text-success bg-success/20' 
                        : 'text-cyber-light bg-cyber-light/20'
                      }
                    `}>
                      {agent.status.toUpperCase()}
                    </span>
                  </div>
                  
                  {agent.progress > 0 && (
                    <div className="progress-cyber h-1">
                      <motion.div
                        className="progress-fill h-full"
                        initial={{ width: 0 }}
                        animate={{ width: `${agent.progress}%` }}
                        transition={{ duration: 1, delay: 0.5 }}
                      />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Quick Actions */}
          <div className="card-cyber p-6 rounded-lg">
            <h3 className="text-lg font-cyber font-bold text-primary text-glow mb-4">
              QUICK ACTIONS
            </h3>
            
            <div className="space-y-3">
              <button 
                onClick={() => setIsCreateScanModalOpen(true)}
                className="w-full btn-cyber text-left p-3 hover:bg-primary/10 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span>NEW SCAN</span>
                  <TrendingUp size={16} />
                </div>
              </button>
              
              <button 
                onClick={() => setIsAddTargetModalOpen(true)}
                className="w-full btn-cyber text-left p-3 hover:bg-primary/10 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span>ADD TARGET</span>
                  <Target size={16} />
                </div>
              </button>
              
              <button 
                onClick={() => navigate('/reports')}
                className="w-full btn-cyber text-left p-3 hover:bg-primary/10 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span>VIEW REPORTS</span>
                  <Eye size={16} />
                </div>
              </button>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Modals */}
      <AddTargetModal
        isOpen={isAddTargetModalOpen}
        onClose={() => setIsAddTargetModalOpen(false)}
      />
      
      <CreateScanModal
        isOpen={isCreateScanModalOpen}
        onClose={() => setIsCreateScanModalOpen(false)}
      />
    </div>
  )
} 