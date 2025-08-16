import { Routes, Route } from 'react-router-dom'
import { motion } from 'framer-motion'

import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Targets from './pages/Targets'
import Scans from './pages/Scans'
import ScanDetails from './pages/ScanDetails'
import ScheduledScans from './pages/ScheduledScans'
import Reports from './pages/Reports'
import Settings from './pages/Settings'

function App() {
  return (
    <div className="min-h-screen bg-cyber-gradient">
      {/* Background effects */}
      <div className="fixed inset-0 cyber-grid opacity-20 pointer-events-none" />
      <div className="fixed inset-0 scan-lines opacity-10 pointer-events-none" />
      
      {/* Matrix rain effect */}
      <div className="fixed inset-0 pointer-events-none opacity-5">
        {Array.from({ length: 20 }).map((_, i) => (
          <motion.div
            key={i}
            className="absolute text-matrix-green text-xs font-mono"
            style={{
              left: `${i * 5}%`,
              animationDelay: `${i * 0.5}s`,
            }}
            animate={{
              y: ['0vh', '110vh'],
            }}
            transition={{
              duration: 15,
              repeat: Infinity,
              ease: 'linear',
              delay: i * 0.5,
            }}
          >
            {Array.from({ length: 30 }).map((_, j) => (
              <div key={j} className="block">
                {String.fromCharCode(0x30A0 + Math.random() * 96)}
              </div>
            ))}
          </motion.div>
        ))}
      </div>
      
      <Layout>
                    <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/targets" element={<Targets />} />
              <Route path="/scans" element={<Scans />} />
              <Route path="/scans/:scanId" element={<ScanDetails />} />
              <Route path="/scheduled-scans" element={<ScheduledScans />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
      </Layout>
    </div>
  )
}

export default App 