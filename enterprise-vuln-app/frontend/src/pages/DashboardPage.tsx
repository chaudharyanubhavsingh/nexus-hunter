/**
 * Dashboard Page Component
 * Main enterprise dashboard with metrics and overview
 */

import React, { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import {
  UserIcon,
  ShoppingBagIcon,
  CurrencyDollarIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon
} from '@heroicons/react/24/outline'

import { useAuth } from '@services/AuthContext'

interface DashboardStats {
  totalUsers: number
  totalProducts: number
  totalOrders: number
  totalRevenue: number
  vulnerabilities: number
  securityScore: number
}

const DashboardPage: React.FC = () => {
  const { user } = useAuth()
  const [stats, setStats] = useState<DashboardStats>({
    totalUsers: 0,
    totalProducts: 0,
    totalOrders: 0,
    totalRevenue: 0,
    vulnerabilities: 0,
    securityScore: 0
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Simulate loading dashboard data
    const loadDashboardData = async () => {
      try {
        // VULNERABLE: Simulate API call with fake data
        await new Promise(resolve => setTimeout(resolve, 1000))
        
        // VULNERABLE: Hardcoded sensitive data for demo
        setStats({
          totalUsers: 12847,
          totalProducts: 1532,
          totalOrders: 4829,
          totalRevenue: 2849573.42,
          vulnerabilities: 47, // Show vulnerability count
          securityScore: 23 // Low security score
        })
        
        // VULNERABLE: Log sensitive business metrics
        console.log('Dashboard loaded for user:', user?.username)
        console.log('Business metrics:', {
          revenue: 2849573.42,
          profit_margin: 0.34,
          customer_acquisition_cost: 127.50
        })
        
      } catch (error) {
        console.error('Failed to load dashboard data:', error)
      } finally {
        setLoading(false)
      }
    }

    loadDashboardData()
  }, [user])

  const statCards = [
    {
      title: 'Total Users',
      value: stats.totalUsers.toLocaleString(),
      icon: UserIcon,
      color: 'blue',
      trend: '+12.5%'
    },
    {
      title: 'Products',
      value: stats.totalProducts.toLocaleString(),
      icon: ShoppingBagIcon,
      color: 'green',
      trend: '+8.2%'
    },
    {
      title: 'Orders',
      value: stats.totalOrders.toLocaleString(),
      icon: ChartBarIcon,
      color: 'purple',
      trend: '+23.1%'
    },
    {
      title: 'Revenue',
      value: `$${stats.totalRevenue.toLocaleString()}`,
      icon: CurrencyDollarIcon,
      color: 'yellow',
      trend: '+18.9%'
    },
    {
      title: 'Vulnerabilities',
      value: stats.vulnerabilities.toLocaleString(),
      icon: ExclamationTriangleIcon,
      color: 'red',
      trend: '+5 new',
      isVulnerable: true
    },
    {
      title: 'Security Score',
      value: `${stats.securityScore}/100`,
      icon: ShieldExclamationIcon,
      color: 'red',
      trend: '-12 pts',
      isVulnerable: true
    }
  ]

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="loading-spinner"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <h1 className="text-3xl font-bold text-white">
          Welcome back, {user?.firstName || user?.username}! 👋
        </h1>
        <p className="text-gray-400 mt-2">
          Here's what's happening in your VulnCorp Enterprise today.
        </p>
      </motion.div>

      {/* VULNERABLE: Security Alert Banner */}
      <motion.div
        className="bg-red-900 border border-red-600 rounded-lg p-4"
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: 0.2 }}
      >
        <div className="flex items-center">
          <ExclamationTriangleIcon className="h-6 w-6 text-red-400 mr-3" />
          <div>
            <h3 className="text-red-200 font-semibold">Security Alert</h3>
            <p className="text-red-300 text-sm">
              {stats.vulnerabilities} active vulnerabilities detected. 
              Security score: {stats.securityScore}/100 (Critical)
            </p>
          </div>
        </div>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {statCards.map((stat, index) => (
          <motion.div
            key={stat.title}
            className={`enterprise-card ${stat.isVulnerable ? 'border-red-600' : ''}`}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 * index }}
            whileHover={{ scale: 1.02 }}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-sm font-medium ${
                  stat.isVulnerable ? 'text-red-300' : 'text-gray-400'
                }`}>
                  {stat.title}
                </p>
                <p className={`text-2xl font-bold ${
                  stat.isVulnerable ? 'text-red-200' : 'text-white'
                } mt-1`}>
                  {stat.value}
                </p>
                <p className={`text-sm mt-2 ${
                  stat.trend.startsWith('+') && !stat.isVulnerable
                    ? 'text-green-400'
                    : stat.isVulnerable
                    ? 'text-red-400'
                    : 'text-red-400'
                }`}>
                  {stat.trend}
                </p>
              </div>
              <stat.icon className={`h-8 w-8 ${
                stat.isVulnerable ? 'text-red-400' : 'text-blue-400'
              }`} />
            </div>
          </motion.div>
        ))}
      </div>

      {/* Recent Activity */}
      <motion.div
        className="enterprise-card"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
      >
        <h3 className="text-lg font-semibold text-white mb-4">Recent Activity</h3>
        <div className="space-y-3">
          {/* VULNERABLE: Display sensitive operational data */}
          <div className="flex items-center justify-between p-3 bg-gray-700 rounded">
            <div>
              <p className="text-white font-medium">SQL Injection Attack Detected</p>
              <p className="text-gray-400 text-sm">Target: /api/vulnerable/sql/login</p>
            </div>
            <span className="text-red-400 text-sm">2 min ago</span>
          </div>
          
          <div className="flex items-center justify-between p-3 bg-gray-700 rounded">
            <div>
              <p className="text-white font-medium">XSS Payload Submitted</p>
              <p className="text-gray-400 text-sm">User: testuser, Endpoint: /api/vulnerable/xss/search</p>
            </div>
            <span className="text-red-400 text-sm">5 min ago</span>
          </div>
          
          <div className="flex items-center justify-between p-3 bg-gray-700 rounded">
            <div>
              <p className="text-white font-medium">Admin Login from New Location</p>
              <p className="text-gray-400 text-sm">IP: 192.168.1.100, Location: Unknown</p>
            </div>
            <span className="text-yellow-400 text-sm">15 min ago</span>
          </div>
          
          <div className="flex items-center justify-between p-3 bg-gray-700 rounded">
            <div>
              <p className="text-white font-medium">File Upload Successful</p>
              <p className="text-gray-400 text-sm">File: shell.php, Size: 2.3 KB</p>
            </div>
            <span className="text-red-400 text-sm">32 min ago</span>
          </div>
        </div>
      </motion.div>

      {/* VULNERABLE: System Information Panel */}
      <motion.div
        className="grid grid-cols-1 lg:grid-cols-2 gap-6"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
      >
        <div className="enterprise-card">
          <h3 className="text-lg font-semibold text-white mb-4">System Information</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-400">Server:</span>
              <span className="text-white">{window.location.hostname}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Environment:</span>
              <span className="text-white">{process.env.NODE_ENV || 'development'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Version:</span>
              <span className="text-white">v1.0.0</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Database:</span>
              <span className="text-white">MySQL 8.0 (vulncorp_enterprise)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Session ID:</span>
              <span className="text-white font-mono text-xs">
                {localStorage.getItem('auth-token')?.slice(-12) || 'N/A'}
              </span>
            </div>
          </div>
        </div>

        <div className="enterprise-card border-red-600">
          <h3 className="text-lg font-semibold text-red-200 mb-4">Vulnerability Status</h3>
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">SQL Injection:</span>
              <span className="status-badge bg-red-900 text-red-200">12 Critical</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">XSS:</span>
              <span className="status-badge bg-red-900 text-red-200">8 High</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Command Injection:</span>
              <span className="status-badge bg-red-900 text-red-200">5 Critical</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">File Upload:</span>
              <span className="status-badge bg-red-900 text-red-200">3 High</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Authentication:</span>
              <span className="status-badge bg-yellow-900 text-yellow-200">7 Medium</span>
            </div>
          </div>
          <div className="mt-4 pt-4 border-t border-red-600">
            <p className="text-red-300 text-xs">
              ⚠️ This application contains intentional vulnerabilities for security testing
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  )
}

export default DashboardPage

