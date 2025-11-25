import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Play, Search, Square, Clock, AlertTriangle, Filter, CheckCircle, XCircle, Brain, Zap } from 'lucide-react';
import { useAppContext } from '../context/AppContext';
import { useScans, useCreateScan, useCancelScan, useDeleteScan } from '../hooks/useApi';
import CreateScanModal from '../components/CreateScanModal';
import { Scan } from '../services/api';
import { useNavigate } from 'react-router-dom';

const Scans: React.FC = () => {
  const { state } = useAppContext();
  const scansQuery = useScans();
  const createScanMutation = useCreateScan();
  const cancelScanMutation = useCancelScan();
  const deleteScanMutation = useDeleteScan();
  
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const navigate = useNavigate();

  // Remove redundant refetch on mount - rely on query cache and WebSocket updates
  // The excessive refetching was causing database noise

  // Optimized polling for active scans only
  useEffect(() => {
    const hasActiveScans = state.scans.some(scan => 
      scan.status === 'running' || scan.status === 'pending'
    );

    if (hasActiveScans) {
      // Use longer interval and only for active scans
      const interval = setInterval(() => {
        scansQuery.refetch();
      }, 60000); // Increased to 60 seconds

      return () => clearInterval(interval);
    }
  }, [state.scans, scansQuery]);

  const handleCancelScan = async (scanId: string, scanName: string) => {
    if (window.confirm(`Are you sure you want to cancel "${scanName}"?`)) {
      try {
        await cancelScanMutation.mutateAsync(scanId);
      } catch (error) {
        // Error handling is done in the mutation
      }
    }
  };

  const handleDeleteScan = async (scanId: string, scanName: string) => {
    if (window.confirm(`Are you sure you want to delete "${scanName}"? This action cannot be undone.`)) {
      try {
        await deleteScanMutation.mutateAsync(scanId);
      } catch (error) {
        // Error handling is done in the mutation
      }
    }
  };

  const handleRetryScan = async (scan: Scan) => {
    try {
      const mapBack: Record<Scan['scan_type'], 'recon' | 'vulnerability' | 'full'> = {
        reconnaissance: 'recon',
        vulnerability: 'vulnerability',
        full: 'full',
      };
      const retryData = {
        name: `${scan.name} (Retry)`,
        target_id: scan.target_id,
        type: mapBack[scan.scan_type],
        config: scan.config || {},
      } as const;
      await createScanMutation.mutateAsync(retryData);
    } catch (error) {
      // Error handling is done in the mutation
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'bg-neon-cyan bg-opacity-20 text-neon-cyan';
      case 'completed': return 'bg-neon-green bg-opacity-20 text-neon-green';
      case 'failed': return 'bg-neon-orange bg-opacity-20 text-neon-orange';
      case 'cancelled': return 'bg-neon-red bg-opacity-20 text-neon-red';
      case 'pending': return 'bg-cyber-gray bg-opacity-20 text-cyber-gray';
      default: return 'bg-cyber-gray bg-opacity-20 text-cyber-gray';
    }
  };

  const getStatusTextColor = (status: string) => {
    switch (status) {
      case 'running': return 'text-neon-cyan';
      case 'completed': return 'text-neon-green';
      case 'failed': return 'text-neon-orange';
      case 'cancelled': return 'text-neon-red';
      case 'pending': return 'text-cyber-gray';
      default: return 'text-cyber-gray';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running': return Play;
      case 'completed': return CheckCircle;
      case 'failed': return AlertTriangle;
      case 'cancelled': return XCircle;
      case 'pending': return Clock;
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
            <div className="flex items-center space-x-3 mb-2">
              <h1 className="text-4xl font-bold text-glow">
                SECURITY OPERATIONS
              </h1>
              <div className="flex items-center space-x-2 bg-gradient-to-r from-purple-600/20 to-blue-600/20 border border-purple-500/30 px-3 py-1 rounded-lg">
                <Brain className="w-5 h-5 text-purple-400" />
                <span className="text-purple-300 text-sm font-medium">AI-POWERED</span>
              </div>
            </div>
            <p className="text-cyber-muted">
              Monitor and manage AI-powered autonomous security scans with intelligent decision making
            </p>
          </div>
          <div className="flex gap-4">
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => setIsCreateModalOpen(true)}
              className="bg-gradient-to-r from-purple-600/20 to-blue-600/20 border border-purple-500 text-purple-300 px-6 py-3 rounded-lg flex items-center gap-2 hover:from-purple-600/30 hover:to-blue-600/30 transition-all"
            >
              <Brain size={20} />
              AI SCAN
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
          { label: 'Total Completed', value: state.scans.filter(s => s.status === 'completed').length.toString(), icon: CheckCircle, color: 'neon-green' },
          { label: 'Total Findings', value: state.scans.filter(s => s.status === 'completed' && s.results).reduce((sum, s) => {
            const results = typeof s.results === 'string' ? JSON.parse(s.results) : s.results;
            
            // Handle both flat vulnerabilities array (legacy) and agent-specific results (new)
            let vulnCount = 0;
            if (Array.isArray(results?.vulnerabilities)) {
              vulnCount = results.vulnerabilities.length;
            } else if (results) {
              // Check agent-specific results
              Object.keys(results).forEach(agentName => {
                const agentResults = results[agentName];
                if (agentResults && Array.isArray(agentResults.vulnerabilities)) {
                  vulnCount += agentResults.vulnerabilities.length;
                }
              });
            }
            
            return sum + vulnCount;
          }, 0).toString(), icon: Search, color: 'neon-pink' },
          { label: 'Critical Issues', value: state.scans.filter(s => s.status === 'completed' && s.results).reduce((sum, s) => {
            const results = typeof s.results === 'string' ? JSON.parse(s.results) : s.results;
            
            // Handle both flat vulnerabilities array (legacy) and agent-specific results (new)
            let criticalCount = 0;
            if (Array.isArray(results?.vulnerabilities)) {
              criticalCount = results.vulnerabilities.filter((v: any) => v.severity === 'critical').length;
            } else if (results) {
              // Check agent-specific results
              Object.keys(results).forEach(agentName => {
                const agentResults = results[agentName];
                if (agentResults && Array.isArray(agentResults.vulnerabilities)) {
                  criticalCount += agentResults.vulnerabilities.filter((v: any) => v.severity === 'critical').length;
                }
              });
            }
            
            return sum + criticalCount;
          }, 0).toString(), icon: AlertTriangle, color: 'neon-orange' }
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
                <th className="text-left p-4 text-cyber-muted">Findings</th>
                <th className="text-left p-4 text-cyber-muted">Duration</th>
                <th className="text-left p-4 text-cyber-muted">Actions</th>
              </tr>
            </thead>
            <tbody>
              {state.scans.map((scan, index) => {
                const StatusIcon = getStatusIcon(scan.status);
                
                // Fixed duration calculation with proper ISO timestamp parsing
                const calculateDuration = () => {
                  try {
                    // For completed scans: use completed_at - started_at
                    if (scan.status === 'completed' && scan.completed_at && scan.started_at) {
                      // Handle ISO timestamps properly (remove Z suffix if present)
                      const startTimeStr = typeof scan.started_at === 'string' 
                        ? scan.started_at.replace('Z', '') 
                        : scan.started_at;
                      const endTimeStr = typeof scan.completed_at === 'string'
                        ? scan.completed_at.replace('Z', '')
                        : scan.completed_at;
                        
                      const startTime = new Date(startTimeStr).getTime();
                      const endTime = new Date(endTimeStr).getTime();
                      
                      // Debug logging for troubleshooting
                      if (scan.id === '214a8f0f-eb44-466c-aa66-d902c39dd0f4') {
                        console.log('Duration Debug for specific scan:', {
                          startTimeStr, endTimeStr, startTime, endTime, 
                          duration: (endTime - startTime) / 1000
                        });
                      }
                      
                      const duration = Math.round((endTime - startTime) / 1000);
                      return Math.max(0, duration); // Ensure non-negative
                    }
                    
                    // For running/pending scans: use now - started_at  
                    if ((scan.status === 'running' || scan.status === 'pending') && scan.started_at) {
                      const startTimeStr = typeof scan.started_at === 'string' 
                        ? scan.started_at.replace('Z', '') 
                        : scan.started_at;
                      const startTime = new Date(startTimeStr).getTime();
                      const duration = Math.round((Date.now() - startTime) / 1000);
                      return Math.max(0, Math.min(duration, 86400)); // Cap at 24 hours
                    }
                    
                    // Fallback for scans without proper started_at
                    if ((scan.status === 'running' || scan.status === 'pending') && scan.created_at) {
                      const createdTime = new Date(scan.created_at).getTime();
                      const duration = Math.round((Date.now() - createdTime) / 1000);
                      // Only use if reasonable (less than 2 hours)
                      return duration < 7200 ? Math.max(0, duration) : 0;
                    }
                    
                    // For completed scans without proper timestamps, try created_at to updated_at
                    if (scan.status === 'completed' && scan.created_at && scan.updated_at) {
                      const startTime = new Date(scan.created_at).getTime();
                      const endTime = new Date(scan.updated_at).getTime();
                      const duration = Math.round((endTime - startTime) / 1000);
                      return duration > 0 && duration < 86400 ? duration : 0; // Reasonable range
                    }
                    
                    return 0; // Default fallback
                  } catch (error) {
                    console.warn('Duration calculation error for scan:', scan.id, error);
                    return 0; // Return 0 instead of -1 to show "0s"
                  }
                };
                
                const duration = calculateDuration();
                
                const formatDuration = (seconds: number) => {
                  if (seconds === 0) return '0s';
                  if (seconds < 60) return `${seconds}s`;
                  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
                  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
                  return `${Math.round(seconds / 86400)}d`;
                };

                return (
                  <motion.tr
                    key={scan.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.5 + index * 0.1 }}
                    className="border-b border-cyber-gray border-opacity-20 hover:bg-cyber-gray hover:bg-opacity-5"
                  >
                    {/* 1. Scan Name */}
                    <td className="p-4">
                      <div className="font-medium text-cyber-white">{scan.name}</div>
                      <div className="text-xs text-cyber-muted font-mono">{scan.id}</div>
                    </td>
                    
                    {/* 2. Target */}
                    <td className="p-4">
                      <div className="text-neon-cyan font-mono">
                        {state.targets.find(t => t.id === scan.target_id)?.domain || 'Unknown'}
                      </div>
                    </td>
                    
                    {/* 3. Type */}
                    <td className="p-4">
                      <span className="text-xs font-bold text-neon-green">
                        {scan.scan_type.toUpperCase()}
                      </span>
                    </td>
                    
                    {/* 4. Status (with Progress when running) */}
                    <td className="p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <StatusIcon size={16} className={getStatusTextColor(scan.status)} />
                        <span className={`px-2 py-1 rounded text-xs font-bold ${getStatusColor(scan.status)}`}>
                          {scan.status.toUpperCase()}
                        </span>
                      </div>
                      
                      {/* Progress bar only for running/pending scans */}
                      {(scan.status === 'running' || scan.status === 'pending') && (
                        <div className="w-full">
                          <div className="flex justify-between text-xs text-cyber-muted mb-1">
                            <span>Progress</span>
                            <span>{Math.min(scan.progress_percentage || 0, 99)}%</span>
                          </div>
                          <div className="w-full bg-cyber-gray bg-opacity-20 rounded-full h-2">
                            <motion.div
                              className="bg-gradient-to-r from-neon-cyan to-neon-green h-2 rounded-full"
                              initial={{ width: 0 }}
                              animate={{ width: `${Math.min(scan.progress_percentage || 0, 99)}%` }}
                              transition={{ duration: 0.3 }}
                            />
                          </div>
                        </div>
                      )}
                    </td>
                    
                    {/* 5. Findings */}
                    <td className="p-4">
                      <div className="flex flex-col">
                        {(() => {
                          // Handle both object and string results for individual scans
                          const results = scan.results ? (typeof scan.results === 'string' ? JSON.parse(scan.results) : scan.results) : null;
                          const vulns = results?.vulnerabilities || [];
                          const totalFindings = Array.isArray(vulns) ? vulns.length : 0;
                          const criticalCount = Array.isArray(vulns) ? vulns.filter((v: any) => v.severity === 'critical').length : 0;
                          
                          return (
                            <>
                              <span className="text-cyber-white font-medium">
                                {totalFindings}
                              </span>
                              {criticalCount > 0 && (
                                <span className="text-neon-orange text-xs">
                                  {criticalCount} critical
                                </span>
                              )}
                            </>
                          );
                        })()}
                      </div>
                    </td>
                    
                    {/* 6. Duration */}
                    <td className="p-4">
                      <div className="text-cyber-muted text-sm">
                        {scan.status === 'completed' ? (
                          <span className="text-cyber-white">{formatDuration(duration)}</span>
                        ) : scan.status === 'running' || scan.status === 'pending' ? (
                          <span className="text-neon-cyan">{formatDuration(duration)}</span>
                        ) : scan.status === 'failed' ? (
                          <span className="text-neon-red">--</span>
                        ) : scan.status === 'cancelled' ? (
                          <span className="text-neon-orange">--</span>
                        ) : (
                          <span className="text-cyber-muted">--</span>
                        )}
                      </div>
                    </td>
                    
                    {/* 7. Actions */}
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
                        ) : scan.status === 'completed' ? (
                          <button 
                            onClick={() => navigate(`/scans/${scan.id}`)}
                            className="text-neon-green hover:text-cyber-white transition-colors"
                            title="View Details"
                          >
                            <Search size={16} />
                          </button>
                        ) : scan.status === 'failed' ? (
                          <>
                            <button 
                              onClick={() => handleRetryScan(scan)}
                              className="text-neon-cyan hover:text-cyber-white transition-colors"
                              title="Retry Scan"
                            >
                              <Play size={16} />
                            </button>
                            <button 
                              onClick={() => handleDeleteScan(scan.id, scan.name)}
                              className="text-neon-red hover:text-cyber-white transition-colors"
                              title="Delete Scan"
                            >
                              <AlertTriangle size={16} />
                            </button>
                          </>
                        ) : scan.status === 'cancelled' ? (
                          <>
                            <button 
                              onClick={() => handleRetryScan(scan)}
                              className="text-neon-cyan hover:text-cyber-white transition-colors"
                              title="Retry Scan"
                            >
                              <Play size={16} />
                            </button>
                            <button 
                              onClick={() => handleDeleteScan(scan.id, scan.name)}
                              className="text-neon-red hover:text-cyber-white transition-colors"
                              title="Delete Scan"
                            >
                              <AlertTriangle size={16} />
                            </button>
                          </>
                        ) : (
                          <button 
                            disabled={true}
                            className="text-cyber-muted opacity-50"
                            title="No actions available"
                          >
                            <AlertTriangle size={16} />
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