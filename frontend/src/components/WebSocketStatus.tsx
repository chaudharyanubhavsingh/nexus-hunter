import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Wifi, WifiOff, Zap } from 'lucide-react'
import { useAppContext } from '../context/AppContext'

export default function WebSocketStatus() {
  const { state } = useAppContext()
  const [lastPing, setLastPing] = useState<number | null>(null)

  useEffect(() => {
    // Update ping time when connected
    let interval: number

    if (state.wsConnectionStatus === 'connected') {
      setLastPing(Date.now())
      
      // Simulate periodic ping
      interval = setInterval(() => {
        setLastPing(Date.now())
      }, 5000)
    }

    return () => {
      if (interval) clearInterval(interval)
    }
  }, [state.wsConnectionStatus])

  const getStatusConfig = () => {
    switch (state.wsConnectionStatus) {
      case 'connecting':
        return {
          icon: Zap,
          color: 'text-warning',
          label: 'CONNECTING',
          bgColor: 'bg-warning/10',
          borderColor: 'border-warning/30'
        }
      case 'connected':
        return {
          icon: Wifi,
          color: 'text-success animate-pulse',
          label: 'LIVE',
          bgColor: 'bg-success/10',
          borderColor: 'border-success/30'
        }
      case 'error':
        return {
          icon: WifiOff,
          color: 'text-danger',
          label: 'ERROR',
          bgColor: 'bg-danger/10',
          borderColor: 'border-danger/30'
        }
      default:
        return {
          icon: WifiOff,
          color: 'text-cyber-muted',
          label: 'OFFLINE',
          bgColor: 'bg-cyber-light/10',
          borderColor: 'border-cyber-light/30'
        }
    }
  }

  const config = getStatusConfig()
  const Icon = config.icon

  return (
    <motion.div
      className={`
        flex items-center space-x-2 px-3 py-1 rounded-full border
        ${config.bgColor} ${config.borderColor}
        font-mono text-xs
      `}
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
    >
      <Icon size={12} className={config.color} />
      <span className={config.color}>
        {config.label}
      </span>
      {state.wsConnectionStatus === 'connected' && lastPing && (
        <span className="text-cyber-muted">
          {Math.round((Date.now() - lastPing) / 1000)}s
        </span>
      )}
    </motion.div>
  )
} 