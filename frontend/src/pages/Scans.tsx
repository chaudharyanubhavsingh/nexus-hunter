import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Play, Pause, Square, Search, Filter, Clock, CheckCircle, AlertTriangle } from 'lucide-react';
import { useAppContext } from '../context/AppContext';
import { useScans, useCancelScan } from '../hooks/useApi';
import CreateScanModal from '../components/CreateScanModal';

const Scans: React.FC = () => {
  const { state } = useAppContext();
  const scansQuery = useScans();
  const cancelScanMutation = useCancelScan();
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);

  // Ensure data is loaded and refreshed
  React.useEffect(() => {
    if (scansQuery.refetch) {
      scansQuery.refetch();
    }
  }, []);

  const handleCancelScan = async (scanId: string, scanName: string) => {
    if (window.confirm(`Are you sure you want to cancel "${scanName}"?`)) {
      try {
        await cancelScanMutation.mutateAsync(scanId);
      } catch (error) {
        // Error handling is done in the mutation
      }
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'neon-cyan';
      case 'completed': return 'neon-green';
      case 'failed': return 'neon-orange';
      case 'queued': return 'cyber-gray';
      default: return 'cyber-gray';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running': return Play;
      case 'completed': return CheckCircle;
      case 'failed': return AlertTriangle;
      case 'queued': return Clock;
      default: return Clock;
    }
  };

  if (scansQuery.isLoading) {
    return (
      <div className="min-h-screen bg-cyber-black text-cyber-white p-6 flex items-center justify-center">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
          className="w-8 h-8 border-2 border-neon-green border-t-transparent rounded-full"
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-cyber-black text-cyber-white p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold text-glow mb-2">
              SECURITY OPERATIONS
            </h1>
            <p className="text-cyber-muted">
              Monitor and manage autonomous security scans
            </p>
          </div>
          <div className="flex gap-4">
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => setIsCreateModalOpen(true)}
              className="bg-neon-green bg-opacity-20 border border-neon-green text-neon-green px-6 py-3 rounded-lg flex items-center gap-2 hover:bg-opacity-30 transition-all"
            >
              <Play size={20} />
              NEW SCAN
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="bg-cyber-gray bg-opacity-20 border border-cyber-gray text-cyber-gray px-6 py-3 rounded-lg flex items-center gap-2 hover:bg-opacity-30 transition-all"
            >
              <Filter size={20} />
              FILTER
            </motion.button>
          </div>
        </div>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        {[
          { label: 'Active Scans', value: state.stats.activeScans.toString(), icon: Play, color: 'neon-cyan' },
          { label: 'Completed Today', value: state.scans.filter(s => s.status === 'completed').length.toString(), icon: CheckCircle, color: 'neon-green' },
          { label: 'Total Findings', value: state.stats.totalVulnerabilities.toString(), icon: Search, color: 'neon-pink' },
          { label: 'Critical Issues', value: state.stats.criticalVulnerabilities.toString(), icon: AlertTriangle, color: 'neon-orange' }
        ].map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg p-6 hover:border-opacity-50 transition-all"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-cyber-muted text-sm">{stat.label}</p>
                <p className={`text-2xl font-bold text-${stat.color}`}>
                  {stat.value}
                </p>
              </div>
              <stat.icon className={`text-${stat.color}`} size={24} />
            </div>
          </motion.div>
        ))}
      </div>

      {/* Scans Table */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.4 }}
        className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg overflow-hidden"
      >
        <div className="p-6 border-b border-cyber-gray border-opacity-30">
          <h2 className="text-xl font-bold text-neon-cyan">SCAN OPERATIONS</h2>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-cyber-gray bg-opacity-5">
              <tr>
                <th className="text-left p-4 text-cyber-muted">Scan Name</th>
                <th className="text-left p-4 text-cyber-muted">Target</th>
                <th className="text-left p-4 text-cyber-muted">Type</th>
                <th className="text-left p-4 text-cyber-muted">Status</th>
                <th className="text-left p-4 text-cyber-muted">Progress</th>
                <th className="text-left p-4 text-cyber-muted">Findings</th>
                <th className="text-left p-4 text-cyber-muted">Duration</th>
                <th className="text-left p-4 text-cyber-muted">Actions</th>
              </tr>
            </thead>
            <tbody>
              {state.scans.map((scan, index) => {
                const StatusIcon = getStatusIcon(scan.status);
                return (
                  <motion.tr
                    key={scan.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.5 + index * 0.1 }}
                    className="border-b border-cyber-gray border-opacity-20 hover:bg-cyber-gray hover:bg-opacity-5"
                  >
                    <td className="p-4">
                      <div className="font-medium text-cyber-white">{scan.name}</div>
                      <div className="text-xs text-cyber-muted font-mono">{scan.id}</div>
                    </td>
                                          <td className="p-4">
                        <div className="text-neon-cyan font-mono">
                          {state.targets.find(t => t.id === scan.target_id)?.domain || scan.target_id}
                        </div>
                      </td>
                    <td className="p-4">
                      <span className="px-2 py-1 bg-neon-pink bg-opacity-20 text-neon-pink rounded text-xs font-bold">
                        {scan.type.toUpperCase()}
                      </span>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <StatusIcon className={`text-${getStatusColor(scan.status)}`} size={16} />
                        <span className={`text-${getStatusColor(scan.status)} text-sm font-medium`}>
                          {scan.status.toUpperCase()}
                        </span>
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="w-full bg-cyber-gray bg-opacity-30 rounded-full h-2">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${scan.progress}%` }}
                          transition={{ duration: 0.5, delay: 0.7 + index * 0.1 }}
                          className={`h-2 rounded-full bg-${getStatusColor(scan.status)}`}
                        />
                      </div>
                      <div className="text-xs text-cyber-muted mt-1">{scan.progress}%</div>
                    </td>
                    <td className="p-4">
                      <div className="flex flex-col">
                        <span className="text-cyber-white font-medium">
                          {scan.results?.vulnerabilities?.length || 0}
                        </span>
                        {scan.results?.vulnerabilities?.some((v: any) => v.severity === 'critical') && (
                          <span className="text-neon-orange text-xs">
                            {scan.results.vulnerabilities.filter((v: any) => v.severity === 'critical').length} critical
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="text-cyber-muted text-sm">
                        {scan.completed_at ? (
                          <>
                            {Math.round((new Date(scan.completed_at).getTime() - new Date(scan.created_at).getTime()) / 60000)}m
                          </>
                        ) : (
                          <>
                            {Math.round((Date.now() - new Date(scan.created_at).getTime()) / 60000)}m
                          </>
                        )}
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="flex gap-2">
                        {scan.status === 'running' || scan.status === 'pending' ? (
                          <button 
                            onClick={() => handleCancelScan(scan.id, scan.name)}
                            disabled={cancelScanMutation.isLoading}
                            className="text-neon-orange hover:text-cyber-white transition-colors disabled:opacity-50"
                            title="Cancel Scan"
                          >
                            <Square size={16} />
                          </button>
                        ) : (
                          <button 
                            onClick={() => window.location.href = `/scans/${scan.id}`}
                            className="text-neon-green hover:text-cyber-white transition-colors"
                            title="View Details"
                          >
                            <Search size={16} />
                          </button>
                        )}
                      </div>
                    </td>
                  </motion.tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </motion.div>

      {/* Create Scan Modal */}
      <CreateScanModal 
        isOpen={isCreateModalOpen} 
        onClose={() => setIsCreateModalOpen(false)} 
      />
    </div>
  );
};

export default Scans; 