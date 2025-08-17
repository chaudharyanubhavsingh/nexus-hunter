import { useState, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { 
  Activity, 
  Target, 
  Shield, 
  AlertTriangle, 
  Zap,
  TrendingUp,
  Eye
} from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { useDashboardData } from '../hooks/useApi'
import AddTargetModal from '../components/AddTargetModal'
import CreateScanModal from '../components/CreateScanModal'
import webSocketService from '../services/websocket'

// Activity icon resolver to handle persisted entries
const resolveActivityIcon = (item: { icon?: any; iconKey?: string; type?: string; severity?: string }) => {
  if (item.icon) return item.icon
  const key = (item.iconKey || '').toLowerCase()
  switch (key) {
    case 'activity':
    case 'scan':
      return Activity
    case 'target':
      return Target
    case 'shield':
    case 'vulnerability':
      return Shield
    case 'alert':
    case 'warning':
      return AlertTriangle
    case 'zap':
      return Zap
    case 'eye':
      return Eye
    default:
      // fallback based on type
      switch ((item.type || '').toLowerCase()) {
        case 'scan_failed':
          return AlertTriangle
        case 'scan_completed':
        case 'vulnerability_found':
        case 'report_generated':
          return Shield
        case 'system_status':
          return Zap
        case 'scan_update':
        default:
          return Activity
      }
  }
}

// Persistent key across refresh; reset on backend boot change
const getActivityKey = (): string => `nexus_activity_feed_persistent`

export default function Dashboard() {
  const { state } = useAppContext()
  const dashboardData = useDashboardData()
  const navigate = useNavigate()

  // Modal states
  const [isAddTargetModalOpen, setIsAddTargetModalOpen] = useState(false)
  const [isCreateScanModalOpen, setIsCreateScanModalOpen] = useState(false)

  // Real-time activity feed
  type ActivityItem = {
    id: string
    type: 'scan_started' | 'scan_update' | 'scan_completed' | 'scan_failed' | 'vulnerability_found' | 'system_status' | 'report_generated'
    message: string
    timestamp: string
    severity: 'info' | 'success' | 'high' | 'critical'
    icon?: any
    iconKey?: string
    payload?: any
  }

  const [activityFeed, setActivityFeed] = useState<ActivityItem[]>(() => {
    try {
      const cached = localStorage.getItem(getActivityKey())
      if (cached) {
        const parsed = JSON.parse(cached)
        if (Array.isArray(parsed)) return parsed
      }
    } catch {}
    return []
  })
  const feedRef = useRef<HTMLDivElement | null>(null)

  // persist feed to localStorage on change
  useEffect(() => {
    try {
      localStorage.setItem(getActivityKey(), JSON.stringify(activityFeed))
    } catch {}
  }, [activityFeed])

  // reset activity on new websocket session (fresh LIVE session)
  useEffect(() => {
    const unsub = webSocketService.subscribe('connection_status', (payload: any) => {
      if (payload?.boot_id) {
        const lastBoot = localStorage.getItem('nexus_backend_boot_id')
        if (lastBoot !== payload.boot_id) {
          // Backend restarted → clear activity for a new session
          setActivityFeed([])
          try { localStorage.setItem(getActivityKey(), JSON.stringify([])) } catch {}
          try { localStorage.setItem('nexus_backend_boot_id', payload.boot_id) } catch {}
        }
      }
    })
    return () => { if (unsub) unsub() }
  }, [])

  // sync from localStorage when other tabs/components update it
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === getActivityKey() && e.newValue) {
        try {
          const parsed = JSON.parse(e.newValue)
          if (Array.isArray(parsed)) {
            setActivityFeed(parsed)
          }
        } catch {}
      }
    }
    const onActivity = () => {
      try {
        const raw = localStorage.getItem(getActivityKey())
        if (raw) {
          const parsed = JSON.parse(raw)
          if (Array.isArray(parsed)) setActivityFeed(parsed)
        }
      } catch {}
    }
    window.addEventListener('storage', onStorage)
    window.addEventListener('nexus-activity-updated' as any, onActivity)
    return () => {
      window.removeEventListener('storage', onStorage)
      window.removeEventListener('nexus-activity-updated' as any, onActivity)
    }
  }, [])

  // Subscribe to WebSocket events for live activity
  useEffect(() => {
    const unsubscribers: Array<() => void> = []

    const addItem = (item: ActivityItem) => {
      setActivityFeed((prev) => {
        const next = [item, ...prev]
        return next.slice(0, 300) // cap to 300 items
      })
    }

    const nowTs = () => new Date().toLocaleTimeString()

    if (!webSocketService.isConnected()) {
      webSocketService.connect()
    }

    // reflect target CRUD pushed by useApi via localStorage event listener already in place

    // scan_update (running/progress/cancelled)
    unsubscribers.push(
      webSocketService.subscribe('scan_update', (data: any) => {
        const status = data?.status
        const progress = typeof data?.progress === 'number' ? ` (${data.progress}%)` : ''
        const rawMsg = (data?.message || '').toString()

        // Map phases from message content
        let iconKey = 'activity'
        if (/subdomain/i.test(rawMsg)) iconKey = 'eye'
        else if (/port scan/i.test(rawMsg) || /port scanning/i.test(rawMsg)) iconKey = 'activity'
        else if (/vulnerability test/i.test(rawMsg)) iconKey = 'shield'
        else if (/analyzing/i.test(rawMsg)) iconKey = 'shield'
        else if (/report/i.test(rawMsg)) iconKey = 'zap'

        const message = status === 'cancelled'
          ? `Scan ${data?.scan_id} cancelled`
          : rawMsg
            ? `${rawMsg}${progress}`
            : `Scan ${data?.scan_id} ${status}${progress}`

        addItem({
          id: `${data?.scan_id}-${Date.now()}`,
          type: 'scan_update',
          message,
          timestamp: nowTs(),
          severity: status === 'cancelled' ? 'high' : 'info',
          iconKey,
          payload: data
        })
      })
    )

    // scan_completed (also derive vulnerabilities and report generation entries)
    unsubscribers.push(
      webSocketService.subscribe('scan_completed', (data: any) => {
        addItem({
          id: `${data?.scan_id}-${Date.now()}`,
          type: 'scan_completed',
          message: `Scan ${data?.scan_id} completed`,
          timestamp: nowTs(),
          severity: 'success',
          iconKey: 'shield',
          payload: data
        })

        // Derive summary from results
        try {
          const results = data?.results || {}
          const targetDomain = results?.target_domain
          const subdomains: string[] = Array.isArray(results?.subdomains) ? results.subdomains : []
          const openPorts: number[] = Array.isArray(results?.open_ports) ? results.open_ports : []
          const technologies: string[] = Array.isArray(results?.technologies) ? results.technologies : []
          const vulns: any[] = Array.isArray(results?.vulnerabilities) ? results.vulnerabilities : []

          if (targetDomain) {
            addItem({
              id: `${data?.scan_id}-summary-target-${Date.now()}`,
              type: 'scan_update',
              message: `Target scanned: ${targetDomain}`,
              timestamp: nowTs(),
              severity: 'info',
              iconKey: 'eye',
              payload: { scan_id: data?.scan_id, targetDomain }
            })
          }

          if (subdomains.length > 0) {
            const first = subdomains.slice(0, 5).join(', ')
            const more = subdomains.length > 5 ? `, +${subdomains.length - 5} more` : ''
            addItem({
              id: `${data?.scan_id}-summary-subdomains-${Date.now()}`,
              type: 'scan_update',
              message: `Subdomains (${subdomains.length}): ${first}${more}`,
              timestamp: nowTs(),
              severity: 'info',
              iconKey: 'eye',
              payload: { scan_id: data?.scan_id, subdomains }
            })
          }

          if (openPorts.length > 0) {
            const ports = openPorts.slice(0, 10).join(', ')
            const more = openPorts.length > 10 ? `, +${openPorts.length - 10} more` : ''
            addItem({
              id: `${data?.scan_id}-summary-ports-${Date.now()}`,
              type: 'scan_update',
              message: `Open ports (${openPorts.length}): ${ports}${more}`,
              timestamp: nowTs(),
              severity: 'info',
              iconKey: 'activity',
              payload: { scan_id: data?.scan_id, openPorts }
            })
          }

          if (technologies.length > 0) {
            const tech = technologies.slice(0, 10).join(', ')
            const more = technologies.length > 10 ? `, +${technologies.length - 10} more` : ''
            addItem({
              id: `${data?.scan_id}-summary-tech-${Date.now()}`,
              type: 'scan_update',
              message: `Technologies: ${tech}${more}`,
              timestamp: nowTs(),
              severity: 'info',
              iconKey: 'activity',
              payload: { scan_id: data?.scan_id, technologies }
            })
          }

          // Findings summary
          if (vulns.length > 0) {
            const counts = vulns.reduce((acc: any, v: any) => {
              const s = (v?.severity || 'info').toLowerCase()
              acc.total += 1
              if (s === 'critical') acc.critical += 1
              else if (s === 'high') acc.high += 1
              else if (s === 'medium') acc.medium += 1
              else acc.low += 1
              return acc
            }, { total: 0, critical: 0, high: 0, medium: 0, low: 0 })
            addItem({
              id: `${data?.scan_id}-summary-findings-${Date.now()}`,
              type: 'scan_update',
              message: `Findings: ${counts.total} (Critical: ${counts.critical}, High: ${counts.high}, Medium: ${counts.medium}, Low: ${counts.low})`,
              timestamp: nowTs(),
              severity: counts.critical > 0 || counts.high > 0 ? 'high' : 'info',
              iconKey: 'shield',
              payload: { scan_id: data?.scan_id, counts }
            })
          }
        } catch {}

        // Derive vulnerabilities (individual entries)
        try {
          const results = data?.results || {}
          const vulns = Array.isArray(results?.vulnerabilities) ? results.vulnerabilities : []
          if (vulns.length > 0) {
            vulns.slice(0, 50).forEach((v: any, idx: number) => {
              const sev = (v?.severity || 'info').toLowerCase()
              addItem({
                id: `${data?.scan_id}-vuln-${idx}-${Date.now()}`,
                type: 'vulnerability_found',
                message: `${v?.title || 'Vulnerability'} (Severity: ${v?.severity || 'info'})`,
                timestamp: nowTs(),
                severity: sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : sev === 'medium' ? 'high' : 'info',
                iconKey: 'shield',
                payload: { scan_id: data?.scan_id, vulnerability: v }
              })
            })
          }
        } catch {}

        // Report generation marker
        addItem({
          id: `${data?.scan_id}-report-${Date.now()}`,
          type: 'report_generated',
          message: `Reports generated for scan ${data?.scan_id}`,
          timestamp: nowTs(),
          severity: 'success',
          iconKey: 'shield',
          payload: { scan_id: data?.scan_id }
        })
      })
    )

    // scan_failed
    unsubscribers.push(
      webSocketService.subscribe('scan_failed', (data: any) => {
        addItem({
          id: `${data?.scan_id}-${Date.now()}`,
          type: 'scan_failed',
          message: `Scan ${data?.scan_id} failed`,
          timestamp: nowTs(),
          severity: 'critical',
          iconKey: 'alert',
          payload: data
        })
      })
    )

    // vulnerability_found
    unsubscribers.push(
      webSocketService.subscribe('vulnerability_found', (data: any) => {
        const title = data?.vulnerability?.title || 'Vulnerability found'
        const severity = (data?.vulnerability?.severity || 'info').toLowerCase()
        addItem({
          id: `${data?.scan_id}-${Date.now()}`,
          type: 'vulnerability_found',
          message: `${title} (Scan ${data?.scan_id})`,
          timestamp: nowTs(),
          severity: severity === 'critical' ? 'critical' : severity === 'high' ? 'high' : 'info',
          iconKey: 'shield',
          payload: data
        })
      })
    )

    // system_status (optional)
    unsubscribers.push(
      webSocketService.subscribe('system_status', (data: any) => {
        addItem({
          id: `system-${Date.now()}`,
          type: 'system_status',
          message: 'System status update received',
          timestamp: nowTs(),
          severity: 'info',
        iconKey: 'zap',
          payload: data
        })
      })
    )

    return () => {
      unsubscribers.forEach((u) => u && u())
    }
  }, [])

  // Auto-scroll to top on new item (visual polish for LIVE feel)
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = 0
    }
  }, [activityFeed])

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
          <Zap size={16} className={state.wsConnectionStatus === 'connected' ? 'text-primary animate-pulse' : 'text-cyber-muted'} />
          <span className={state.wsConnectionStatus === 'connected' ? 'text-primary font-mono' : 'text-cyber-muted font-mono'}>
            {state.wsConnectionStatus === 'connected' ? 'NEXUS PROTOCOL ACTIVE' : 'OFFLINE'}
          </span>
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
              <div className={`w-2 h-2 rounded-full ${state.wsConnectionStatus === 'connected' ? 'bg-success animate-pulse' : 'bg-cyber-light'}`} />
              <span className="text-xs text-cyber-muted font-mono">{state.wsConnectionStatus === 'connected' ? 'LIVE' : 'OFFLINE'}</span>
            </div>
          </div>
          
          <div ref={feedRef} className="space-y-4 max-h-96 overflow-y-auto scrollbar-cyber">
            {activityFeed.length === 0 && (
              <div className="text-xs text-cyber-muted font-mono">No activity yet. Start a scan to see live updates.</div>
            )}
            {activityFeed.map((activity, index) => {
              const Icon = resolveActivityIcon(activity)
              
              return (
                <motion.div
                  key={activity.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: index * 0.05 }}
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