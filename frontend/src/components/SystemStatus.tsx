import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { CheckCircle, AlertCircle, Loader, Settings, Activity, Zap } from 'lucide-react'

interface SystemStatusProps {
  className?: string
}

interface SystemHealth {
  status: 'initializing' | 'setting_up' | 'ready' | 'degraded' | 'failed'
  message: string
  progress_percentage: number
  components: Record<string, any>
  summary: {
    total_components: number
    available: number
    failed: number
    installing: number
  }
}

export default function SystemStatus({ className = '' }: SystemStatusProps) {
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const checkSystemStatus = async () => {
      try {
        const response = await fetch('/api/system/status')
        const health = await response.json()
        setSystemHealth(health)
      } catch (error) {
        console.error('Failed to fetch system status:', error)
        setSystemHealth({
          status: 'failed',
          message: 'Unable to check system status',
          progress_percentage: 0,
          components: {},
          summary: { total_components: 0, available: 0, failed: 1, installing: 0 }
        })
      } finally {
        setLoading(false)
      }
    }

    // Initial check
    checkSystemStatus()

    // Dynamic polling based on system status
    const getPollingInterval = () => {
      if (!systemHealth) return 3000 // Initial fast check
      
      switch (systemHealth.status) {
        case 'initializing':
          return 1000 // Very fast during initialization
        case 'setting_up':
          return 2000 // Fast during setup
        case 'ready':
          return 30000 // Slow when stable
        case 'degraded':
          return 10000 // Medium when degraded
        case 'failed':
          return 5000 // Fast when failed (for recovery)
        default:
          return 5000
      }
    }

    const interval = setInterval(checkSystemStatus, getPollingInterval())
    return () => clearInterval(interval)
  }, [systemHealth?.status])

  if (loading) {
    return (
      <div className={`flex items-center space-x-2 ${className}`}>
        <Loader className="w-4 h-4 animate-spin text-primary" />
        <span className="text-sm text-primary/70">Checking...</span>
      </div>
    )
  }

  if (!systemHealth) return null

  const getStatusIcon = () => {
    switch (systemHealth.status) {
      case 'ready':
        return <CheckCircle className="w-4 h-4 text-green-400" />
      case 'degraded':
        return <AlertCircle className="w-4 h-4 text-yellow-400" />
      case 'initializing':
      case 'setting_up':
        return <Loader className="w-4 h-4 animate-spin text-blue-400" />
      case 'failed':
        return <AlertCircle className="w-4 h-4 text-red-400" />
      default:
        return <Settings className="w-4 h-4 text-primary/50" />
    }
  }

  const getStatusText = () => {
    switch (systemHealth.status) {
      case 'ready':
        return 'Active'
      case 'degraded':
        return 'Limited'
      case 'initializing':
        return 'Starting...'
      case 'setting_up':
        return 'Setting up...'
      case 'failed':
        return 'Error'
      default:
        return 'Unknown'
    }
  }

  const getStatusDescription = () => {
    switch (systemHealth.status) {
      case 'ready':
        return 'All systems operational'
      case 'degraded': 
        return 'Some tools unavailable'
      case 'initializing':
        return 'Platform initializing'
      case 'setting_up':
        return 'Installing components'
      case 'failed':
        return 'System error occurred'
      default:
        return 'Status unknown'
    }
  }

  const getStatusColor = () => {
    switch (systemHealth.status) {
      case 'ready':
        return 'text-green-400'
      case 'degraded':
        return 'text-yellow-400'
      case 'initializing':
      case 'setting_up':
        return 'text-blue-400'
      case 'failed':
        return 'text-red-400'
      default:
        return 'text-primary/50'
    }
  }

  const isStarting = systemHealth.status === 'initializing' || systemHealth.status === 'setting_up'

  return (
    <div className={`flex items-center space-x-2 ${className}`}>
      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.3 }}
        className="flex items-center space-x-2"
      >
        {getStatusIcon()}
        <div className="flex flex-col">
          <span className={`text-sm font-semibold ${getStatusColor()}`}>
            {getStatusText()}
          </span>
          {isStarting && (
            <span className="text-xs text-primary/60">
              {getStatusDescription()}
            </span>
          )}
        </div>
      </motion.div>

      {isStarting && systemHealth.progress_percentage > 0 && (
        <motion.div
          initial={{ width: 0, opacity: 0 }}
          animate={{ width: 'auto', opacity: 1 }}
          className="flex items-center space-x-2"
        >
          <div className="w-20 bg-cyber-dark/50 rounded-full h-1.5 overflow-hidden">
            <motion.div
              className="h-full bg-gradient-to-r from-primary to-blue-400"
              initial={{ width: '0%' }}
              animate={{ width: `${systemHealth.progress_percentage}%` }}
              transition={{ duration: 0.5, ease: 'easeOut' }}
            />
          </div>
          <span className="text-xs text-primary/60">
            {systemHealth.progress_percentage}%
          </span>
        </motion.div>
      )}

      {/* Detailed status tooltip on hover */}
      <div className="group relative">
        <Activity className="w-3 h-3 text-primary/30 group-hover:text-primary/60 cursor-help" />
        
        <div className="absolute bottom-full right-0 mb-2 w-80 bg-cyber-dark/95 backdrop-blur-sm border border-primary/20 rounded-lg p-3 opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none z-50">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-semibold text-primary">System Status</h4>
              <span className={`text-xs px-2 py-1 rounded ${getStatusColor()} bg-current/10`}>
                {systemHealth.status.toUpperCase()}
              </span>
            </div>
            
            <p className="text-xs text-primary/70">{systemHealth.message}</p>
            
            <div className="grid grid-cols-3 gap-2 text-xs">
              <div className="text-center">
                <div className="text-green-400 font-medium">{systemHealth.summary.available}</div>
                <div className="text-primary/50">Available</div>
              </div>
              <div className="text-center">
                <div className="text-yellow-400 font-medium">{systemHealth.summary.installing}</div>
                <div className="text-primary/50">Installing</div>
              </div>
              <div className="text-center">
                <div className="text-red-400 font-medium">{systemHealth.summary.failed}</div>
                <div className="text-primary/50">Failed</div>
              </div>
            </div>

            {/* Show key components status */}
            {Object.keys(systemHealth.components).length > 0 && (
              <div className="mt-2 space-y-1">
                <h5 className="text-xs font-medium text-primary/80">Components:</h5>
                {Object.entries(systemHealth.components).slice(0, 4).map(([name, component]: [string, any]) => (
                  <div key={name} className="flex items-center justify-between text-xs">
                    <span className="text-primary/60 capitalize">{component.name || name}</span>
                    <div className="flex items-center space-x-1">
                      {component.status === 'available' && (
                        <CheckCircle className="w-3 h-3 text-green-400" />
                      )}
                      {component.status === 'failed' && (
                        <AlertCircle className="w-3 h-3 text-red-400" />
                      )}
                      {component.status === 'installing' && (
                        <Loader className="w-3 h-3 animate-spin text-blue-400" />
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
          
          {/* Tooltip arrow */}
          <div className="absolute top-full right-4 w-2 h-2 bg-cyber-dark/95 border-r border-b border-primary/20 transform rotate-45 -mt-1"></div>
        </div>
      </div>
    </div>
  )
}
