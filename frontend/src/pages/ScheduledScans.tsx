import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Calendar, Play, Trash2, RefreshCw } from 'lucide-react';

interface ScheduledScan {
  id: string;
  target_id: string;
  target_name: string;
  scan_type: string;
  schedule_type: string;
  schedule_time: string;
  next_run: string;
  config: any;
}

const ScheduledScans: React.FC = () => {
  const [scheduledScans, setScheduledScans] = useState<ScheduledScan[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadScheduledScans = async () => {
    try {
      setIsLoading(true);
      const response = await fetch('/api/scans/schedules');
      if (!response.ok) {
        throw new Error('Failed to load scheduled scans');
      }
      const data = await response.json();
      setScheduledScans(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setIsLoading(false);
    }
  };

  const deleteScheduledScan = async (scheduleId: string) => {
    try {
      const response = await fetch(`/api/scans/schedules/${scheduleId}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        throw new Error('Failed to delete scheduled scan');
      }
      await loadScheduledScans(); // Reload the list
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete scan');
    }
  };

  const executeNow = async (scheduleId: string) => {
    try {
      const response = await fetch(`/api/scans/schedules/${scheduleId}/execute`, {
        method: 'POST',
      });
      if (!response.ok) {
        throw new Error('Failed to execute scan');
      }
      // Optionally reload or show success message
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to execute scan');
    }
  };

  useEffect(() => {
    loadScheduledScans();
    
    // Refresh every 30 seconds
    const interval = setInterval(loadScheduledScans, 30000);
    return () => clearInterval(interval);
  }, []);

  const formatScheduleType = (type: string) => {
    switch (type) {
      case 'once': return '📅 One Time';
      case 'daily': return '🔄 Daily';
      case 'weekly': return '📆 Weekly';
      case 'monthly': return '📋 Monthly';
      default: return type;
    }
  };

  const formatNextRun = (nextRun: string) => {
    const date = new Date(nextRun);
    const now = new Date();
    const diffMs = date.getTime() - now.getTime();
    const diffHours = Math.round(diffMs / (1000 * 60 * 60));

    if (diffHours < 0) {
      return '⚠️ Overdue';
    } else if (diffHours < 1) {
      const diffMinutes = Math.round(diffMs / (1000 * 60));
      return `🔜 In ${diffMinutes}m`;
    } else if (diffHours < 24) {
      return `🕐 In ${diffHours}h`;
    } else {
      const diffDays = Math.round(diffHours / 24);
      return `📅 In ${diffDays}d`;
    }
  };

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
              SCHEDULED SCANS
            </h1>
            <p className="text-cyber-muted">
              Manage and monitor your automated scan schedules
            </p>
          </div>
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={loadScheduledScans}
            className="bg-neon-cyan bg-opacity-20 border border-neon-cyan text-neon-cyan px-6 py-3 rounded-lg flex items-center gap-2 hover:bg-opacity-30 transition-all"
          >
            <RefreshCw size={20} />
            REFRESH
          </motion.button>
        </div>
      </motion.div>

      {/* Loading State */}
      {isLoading && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex items-center justify-center py-20"
        >
          <div className="text-center">
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-neon-cyan"></div>
            <p className="text-cyber-muted mt-4">Loading scheduled scans...</p>
          </div>
        </motion.div>
      )}

      {/* Error State */}
      {error && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="bg-neon-red bg-opacity-20 border border-neon-red text-neon-red p-4 rounded-lg mb-6"
        >
          {error}
        </motion.div>
      )}

      {/* Scheduled Scans List */}
      {!isLoading && !error && (
        <>
          {scheduledScans.length === 0 ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex items-center justify-center py-20"
            >
              <div className="text-center">
                <Calendar className="mx-auto h-16 w-16 text-cyber-muted mb-4" />
                <h3 className="text-xl font-medium text-cyber-white mb-2">No Scheduled Scans</h3>
                <p className="text-cyber-muted max-w-md">
                  You don't have any scheduled scans yet. Create a new scan and select "Schedule for Later" to add one.
                </p>
              </div>
            </motion.div>
          ) : (
            <div className="space-y-4">
              {scheduledScans.map((scan, index) => (
                <motion.div
                  key={scan.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.1 }}
                  className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg p-6 hover:border-opacity-50 transition-all"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="p-2 bg-neon-cyan bg-opacity-20 rounded-lg">
                          <Calendar className="text-neon-cyan" size={20} />
                        </div>
                        <div>
                          <h3 className="text-lg font-bold text-cyber-white">
                            {scan.scan_type.toUpperCase()} Scan
                          </h3>
                          <p className="text-cyber-muted text-sm">
                            Target: {scan.target_name || scan.target_id}
                          </p>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                          <span className="text-cyber-muted">Schedule:</span>
                          <p className="text-cyber-white font-medium">
                            {formatScheduleType(scan.schedule_type)}
                          </p>
                        </div>
                        <div>
                          <span className="text-cyber-muted">Time:</span>
                          <p className="text-cyber-white font-medium">
                            {scan.schedule_time}
                          </p>
                        </div>
                        <div>
                          <span className="text-cyber-muted">Next Run:</span>
                          <p className="text-cyber-white font-medium">
                            {formatNextRun(scan.next_run)}
                          </p>
                        </div>
                        <div>
                          <span className="text-cyber-muted">Full Date:</span>
                          <p className="text-cyber-white font-medium">
                            {new Date(scan.next_run).toLocaleString()}
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="flex gap-2 ml-4">
                      <motion.button
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        onClick={() => executeNow(scan.id)}
                        className="bg-neon-green bg-opacity-20 border border-neon-green text-neon-green py-2 px-3 rounded text-sm hover:bg-opacity-30 transition-all"
                        title="Execute Now"
                      >
                        <Play size={16} />
                      </motion.button>
                      <motion.button
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        onClick={() => {
                          if (window.confirm('Are you sure you want to delete this scheduled scan?')) {
                            deleteScheduledScan(scan.id);
                          }
                        }}
                        className="bg-neon-red bg-opacity-20 border border-neon-red text-neon-red py-2 px-3 rounded text-sm hover:bg-opacity-30 transition-all"
                        title="Delete Schedule"
                      >
                        <Trash2 size={16} />
                      </motion.button>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default ScheduledScans; 