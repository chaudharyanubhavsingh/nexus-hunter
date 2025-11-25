/**
 * VulnCorp Enterprise Dashboard - Main Business Dashboard
 * ======================================================
 * 
 * Comprehensive enterprise dashboard showing all business metrics,
 * security status, and vulnerability management overview
 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

interface SystemHealth {
  status: string;
  vulnerabilities: {
    total: number;
    enabled: number;
    categories: number;
  };
  modules: {
    [key: string]: string;
  };
}

const EnterpriseDashboard: React.FC = () => {
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [realtimeData, setRealtimeData] = useState({
    activeUsers: 1247,
    todayOrders: 89,
    revenue: 45678.90,
    systemLoad: 67,
    threats: 23,
    incidents: 5
  });

  useEffect(() => {
    loadSystemHealth();
    
    // Simulate real-time data updates
    const interval = setInterval(() => {
      setRealtimeData(prev => ({
        ...prev,
        activeUsers: prev.activeUsers + Math.floor(Math.random() * 10) - 5,
        todayOrders: prev.todayOrders + Math.floor(Math.random() * 3),
        revenue: prev.revenue + Math.random() * 100,
        systemLoad: Math.max(20, Math.min(90, prev.systemLoad + Math.floor(Math.random() * 6) - 3)),
        threats: prev.threats + Math.floor(Math.random() * 2),
        incidents: Math.max(0, prev.incidents + Math.floor(Math.random() * 2) - 1)
      }));
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const loadSystemHealth = async () => {
    try {
      const response = await fetch('/api/health');
      const data = await response.json();
      setSystemHealth(data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to load system health:', error);
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2 flex items-center gap-3">
            <span className="text-blue-600">🏢</span>VulnCorp Enterprise Dashboard
          </h1>
          <p className="text-lg text-gray-600">
            Welcome to the comprehensive enterprise management platform
          </p>
        </div>

        {/* Real-time Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-6 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow-lg p-6 border-l-4 border-blue-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 uppercase tracking-wide">Active Users</p>
                <p className="text-3xl font-bold text-gray-900">{realtimeData.activeUsers.toLocaleString()}</p>
              </div>
              <div className="p-3 bg-blue-100 rounded-full">
                <span className="text-2xl">👥</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6 border-l-4 border-green-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 uppercase tracking-wide">Orders Today</p>
                <p className="text-3xl font-bold text-gray-900">{realtimeData.todayOrders}</p>
              </div>
              <div className="p-3 bg-green-100 rounded-full">
                <span className="text-2xl">📦</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6 border-l-4 border-yellow-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 uppercase tracking-wide">Revenue Today</p>
                <p className="text-3xl font-bold text-gray-900">${realtimeData.revenue.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</p>
              </div>
              <div className="p-3 bg-yellow-100 rounded-full">
                <span className="text-2xl">💰</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6 border-l-4 border-purple-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 uppercase tracking-wide">System Load</p>
                <p className="text-3xl font-bold text-gray-900">{realtimeData.systemLoad}%</p>
              </div>
              <div className="p-3 bg-purple-100 rounded-full">
                <span className="text-2xl">⚙️</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6 border-l-4 border-red-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 uppercase tracking-wide">Security Threats</p>
                <p className="text-3xl font-bold text-gray-900">{realtimeData.threats}</p>
              </div>
              <div className="p-3 bg-red-100 rounded-full">
                <span className="text-2xl">🚨</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6 border-l-4 border-orange-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 uppercase tracking-wide">Incidents</p>
                <p className="text-3xl font-bold text-gray-900">{realtimeData.incidents}</p>
              </div>
              <div className="p-3 bg-orange-100 rounded-full">
                <span className="text-2xl">⚠️</span>
              </div>
            </div>
          </div>
        </div>

        {/* Security Status */}
        <div className="bg-white rounded-lg shadow-lg p-6 mb-8">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
              🛡️ Security Status
            </h2>
            <Link 
              to="/vulnerability-manager" 
              className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
            >
              Manage Vulnerabilities
            </Link>
          </div>
          
          {systemHealth && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <h3 className="text-lg font-semibold text-red-800 mb-2">⚠️ Critical Alert</h3>
                <p className="text-red-600 mb-3">
                  {systemHealth.vulnerabilities.enabled} of {systemHealth.vulnerabilities.total} vulnerabilities are currently ENABLED for testing
                </p>
                <div className="text-sm text-red-500">
                  Security Score: <span className="font-bold">23/100</span> (Critical Risk)
                </div>
              </div>
              
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                <h3 className="text-lg font-semibold text-yellow-800 mb-2">🔍 Active Categories</h3>
                <p className="text-yellow-600 mb-3">
                  {systemHealth.vulnerabilities.categories} vulnerability categories active
                </p>
                <div className="text-sm text-yellow-600">
                  Ready for Nexus Hunter testing
                </div>
              </div>
              
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h3 className="text-lg font-semibold text-blue-800 mb-2">📊 System Status</h3>
                <p className="text-blue-600 mb-3">
                  All enterprise modules operational
                </p>
                <div className="text-sm text-blue-600">
                  Environment: {systemHealth.status}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Enterprise Modules */}
        <div className="bg-white rounded-lg shadow-lg p-6 mb-8">
          <h2 className="text-2xl font-bold text-gray-900 mb-6 flex items-center gap-2">
            🏢 Enterprise Modules
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Link to="/hr" className="dashboard-card">
              <div className="card-header">
                <h3 className="card-title flex items-center gap-2">
                  👥 HR Management
                </h3>
                <span className="text-xl">📋</span>
              </div>
              <p className="text-slate-300">Employee management, payroll, benefits</p>
              <div className="card-stats">1,247 employees • 23 vulnerabilities</div>
            </Link>

            <Link to="/finance" className="dashboard-card">
              <div className="card-header">
                <h3 className="card-title flex items-center gap-2">
                  💰 Finance
                </h3>
                <span className="text-xl">📊</span>
              </div>
              <p className="text-slate-300">Accounting, budgets, financial reporting</p>
              <div className="card-stats">$2.3M revenue • 18 vulnerabilities</div>
            </Link>

            <Link to="/crm" className="dashboard-card">
              <div className="card-header">
                <h3 className="card-title flex items-center gap-2">
                  🤝 CRM
                </h3>
                <span className="text-xl">📈</span>
              </div>
              <p className="text-slate-300">Customer relationships, sales pipeline</p>
              <div className="card-stats">5,432 customers • 15 vulnerabilities</div>
            </Link>

            <Link to="/inventory" className="dashboard-card">
              <div className="card-header">
                <h3 className="card-title flex items-center gap-2">
                  📦 Inventory
                </h3>
                <span className="text-xl">📝</span>
              </div>
              <p className="text-slate-300">Stock management, supply chain</p>
              <div className="card-stats">2,156 products • 12 vulnerabilities</div>
            </Link>

            <Link to="/documents" className="dashboard-card">
              <div className="card-header">
                <h3 className="card-title flex items-center gap-2">
                  📄 Documents
                </h3>
                <span className="text-xl">🗂</span>
              </div>
              <p className="text-slate-300">File management, document storage</p>
              <div className="card-stats">8,934 files • 19 vulnerabilities</div>
            </Link>

            <Link to="/api-gateway" className="dashboard-card">
              <div className="card-header">
                <h3 className="card-title flex items-center gap-2">
                  🌐 API Gateway
                </h3>
                <span className="text-xl">🔗</span>
              </div>
              <p className="text-slate-300">API management, microservices</p>
              <div className="card-stats">47 endpoints • 25 vulnerabilities</div>
            </Link>

            <Link to="/admin" className="dashboard-card">
              <div className="card-header">
                <h3 className="card-title flex items-center gap-2">
                  🔐 Admin Panel
                </h3>
                <span className="text-xl">⚙️</span>
              </div>
              <p className="text-slate-300">System administration, user management</p>
              <div className="card-stats">Admin access • 31 vulnerabilities</div>
            </Link>

            <Link to="/vulnerability-lab" className="dashboard-card">
              <div className="card-header">
                <h3 className="card-title flex items-center gap-2">
                  🧪 Security Lab
                </h3>
                <span className="text-xl">🔍</span>
              </div>
              <p className="text-slate-300">Vulnerability testing interface</p>
              <div className="card-stats">Interactive testing • All vulnerabilities</div>
            </Link>
          </div>
        </div>

        {/* Recent Security Events */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h2 className="text-2xl font-bold text-gray-900 mb-6 flex items-center gap-2">
            📈 Recent Security Events
          </h2>
          
          <div className="space-y-4">
            <div className="flex items-center p-4 bg-red-50 border border-red-200 rounded-lg">
              <div className="p-2 bg-red-100 rounded-full mr-4">
                <span className="text-xl">🛛</span>
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-red-800">SQL Injection Attempt Detected</h3>
                  <span className="text-sm text-red-600">2 minutes ago</span>
                </div>
                <p className="text-red-600">Malicious payload detected in /api/vulnerable/sql/login endpoint</p>
              </div>
            </div>

            <div className="flex items-center p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
              <div className="p-2 bg-yellow-100 rounded-full mr-4">
                <span className="text-xl">😂</span>
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-yellow-800">XSS Payload Submitted</h3>
                  <span className="text-sm text-yellow-600">5 minutes ago</span>
                </div>
                <p className="text-yellow-600">Cross-site scripting attempt in comment submission form</p>
              </div>
            </div>

            <div className="flex items-center p-4 bg-blue-50 border border-blue-200 rounded-lg">
              <div className="p-2 bg-blue-100 rounded-full mr-4">
                <span className="text-xl">🔍</span>
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-blue-800">Security Scan Completed</h3>
                  <span className="text-sm text-blue-600">15 minutes ago</span>
                </div>
                <p className="text-blue-600">Nexus Hunter completed comprehensive vulnerability assessment</p>
              </div>
            </div>

            <div className="flex items-center p-4 bg-green-50 border border-green-200 rounded-lg">
              <div className="p-2 bg-green-100 rounded-full mr-4">
                <span className="text-xl">🔑</span>
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-green-800">Admin Login Successful</h3>
                  <span className="text-sm text-green-600">1 hour ago</span>
                </div>
                <p className="text-green-600">Administrator successfully logged in from 192.168.1.100</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EnterpriseDashboard;
