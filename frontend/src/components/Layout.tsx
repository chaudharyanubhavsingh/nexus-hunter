import { useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity,
  Target,
  Scan,
  FileText,
  Settings,
  Menu,
  X,
  Zap,
  Shield,
  Brain,
  Eye,
} from 'lucide-react'

import WebSocketStatus from './WebSocketStatus'
import NotificationCenter from './NotificationCenter'
import SystemStatus from './SystemStatus'

interface LayoutProps {
  children: React.ReactNode
}

const navItems = [
  { path: '/', icon: Activity, label: 'Dashboard', description: 'Real-time overview' },
  { path: '/targets', icon: Target, label: 'Targets', description: 'Attack surface' },
  { path: '/scans', icon: Scan, label: 'Scans', description: 'AI-powered operations' },
  { path: '/reports', icon: FileText, label: 'Reports', description: 'Intelligence output' },
  { path: '/settings', icon: Settings, label: 'Settings', description: 'Configuration' },
]

export default function Layout({ children }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const location = useLocation()

  return (
    <div className="flex h-screen bg-cyber-black text-primary">
      {/* Sidebar */}
      <AnimatePresence>
        {sidebarOpen && (
          <motion.div
            initial={{ x: -300 }}
            animate={{ x: 0 }}
            exit={{ x: -300 }}
            transition={{ type: 'spring', damping: 20 }}
            className="fixed inset-y-0 left-0 z-50 w-64 lg:hidden"
          >
            <div className="flex h-full flex-col bg-cyber-dark/95 backdrop-blur-md border-r border-primary/30">
              <SidebarContent />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Desktop sidebar */}
      <div className="hidden lg:flex lg:flex-col lg:w-64 lg:bg-cyber-dark/80 lg:backdrop-blur-md lg:border-r lg:border-primary/30">
        <SidebarContent />
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="bg-cyber-dark/50 backdrop-blur-md border-b border-primary/30 px-4 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="lg:hidden btn-cyber p-2"
              >
                {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
              </button>
              
              <motion.h1 
                className="text-xl font-cyber font-bold text-glow"
                data-text="NEXUS HUNTER"
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
              >
                NEXUS HUNTER
              </motion.h1>
              
              <div className="hidden md:flex items-center space-x-2 text-xs text-cyber-muted">
                <span className="flex items-center space-x-1">
                  <Brain size={12} className="text-neon-purple" />
                  <span>AI-POWERED</span>
                </span>
                <span className="text-cyber-light/50">|</span>
                <span className="flex items-center space-x-1">
                  <Shield size={12} className="text-neon-green" />
                  <span>AUTONOMOUS</span>
                </span>
                <span className="text-cyber-light/50">|</span>
                <span className="flex items-center space-x-1">
                  <Eye size={12} className="text-neon-orange" />
                  <span>INTELLIGENCE</span>
                </span>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <NotificationCenter />
              <SystemStatus />
              <WebSocketStatus />
            </div>
          </div>
        </header>

        {/* Main content area */}
        <main className="flex-1 overflow-auto scrollbar-cyber bg-cyber-black/50">
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
            className="p-6"
          >
            {children}
          </motion.div>
        </main>
      </div>

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-cyber-black/80 backdrop-blur-sm z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  )
}

function SidebarContent() {
  const location = useLocation()

  return (
    <>
      {/* Logo */}
      <div className="p-6 border-b border-primary/30">
        <motion.div 
          className="flex items-center space-x-3"
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="w-8 h-8 bg-primary/20 border border-primary rounded flex items-center justify-center">
            <Zap size={16} className="text-primary" />
          </div>
          <div>
            <div className="font-cyber font-bold text-sm text-glow">NEXUS</div>
            <div className="text-xs text-cyber-muted">HUNTER</div>
          </div>
        </motion.div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-2">
        {navItems.map((item, index) => {
          const isActive = location.pathname === item.path
          const Icon = item.icon

          return (
            <motion.div
              key={item.path}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
            >
              <NavLink
                to={item.path}
                className={`
                  group flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200
                  ${isActive 
                    ? 'bg-primary/20 text-primary border border-primary/50 shadow-neon' 
                    : 'text-cyber-white hover:text-primary hover:bg-cyber-light/10'
                  }
                `}
              >
                <Icon 
                  size={18} 
                  className={`
                    ${isActive ? 'text-primary animate-pulse-neon' : 'group-hover:text-primary'}
                    transition-colors duration-200
                  `} 
                />
                <div className="flex-1">
                  <div className={`font-medium text-sm ${isActive ? 'text-primary' : ''}`}>
                    {item.label}
                  </div>
                  <div className="text-xs text-cyber-muted group-hover:text-cyber-light">
                    {item.description}
                  </div>
                </div>
                
                {isActive && (
                  <motion.div
                    layoutId="activeIndicator"
                    className="w-2 h-2 bg-primary rounded-full shadow-neon"
                    initial={false}
                    transition={{ type: 'spring', damping: 15 }}
                  />
                )}
              </NavLink>
            </motion.div>
          )
        })}
      </nav>

      {/* System status */}
      <div className="p-4 border-t border-primary/30">
        <motion.div 
          className="text-xs text-cyber-light space-y-2"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.8 }}
        >
          <div className="flex justify-between">
            <span>System Status</span>
            <span className="text-success animate-pulse">ONLINE</span>
          </div>
          <div className="flex justify-between">
            <span>Security Level</span>
            <span className="text-warning">ENHANCED</span>
          </div>
          <div className="flex justify-between">
            <span>Version</span>
            <span className="text-primary">1.0.0</span>
          </div>
        </motion.div>
      </div>
    </>
  )
} 