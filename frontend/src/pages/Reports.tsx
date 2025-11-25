import React, { useEffect } from 'react';
import { motion } from 'framer-motion';
import { Download, FileText, Mail, Trash2, Filter } from 'lucide-react';
import { useAppContext } from '../context/AppContext';
import { useReports, useDownloadReport, useScans } from '../hooks/useApi';

const Reports: React.FC = () => {
  const { state } = useAppContext();
  const reportsQuery = useReports();
  const downloadReportMutation = useDownloadReport();

  // Ensure scans data is available for generating reports
  const scansQuery = useScans();

  // Loading and error states
  const isLoading = reportsQuery.isLoading || scansQuery.isLoading;
  const hasError = Boolean(reportsQuery.error || scansQuery.error);

  // Simple retry mechanism for user-initiated retries only
  const handleRetry = () => {
    reportsQuery.refetch();
    scansQuery.refetch();
  };

  // Remove automatic retry logic - rely on WebSocket for real-time updates
  // The excessive auto-retry was causing database noise

  // Debug logging for data state (simplified)
  useEffect(() => {
    console.log('Reports Status:', {
      isLoading,
      hasError,
      scansCount: state.scans.length,
      reportsStatus: reportsQuery.status,
      scansStatus: scansQuery.status
    });
  }, [isLoading, hasError, state.scans.length, reportsQuery.status, scansQuery.status]);

  const handleDownloadReport = async (scanId: string, reportType: string) => {
    try {
      console.log('Downloading PDF report:', { scanId, reportType });
      // Always download as PDF - this is the intended workflow
      await downloadReportMutation.mutateAsync({ scanId, reportType, format: 'pdf' });
    } catch (error) {
      console.error('Error downloading report:', error);
      // Error handling is done in the mutation
    }
  };

  const handleViewReport = async (scanId: string, reportType: string) => {
    try {
      // Open the report in a new tab using correct backend endpoints
      const url = `http://localhost:8000/api/reports/${scanId}/${reportType}?format=html`;
      window.open(url, '_blank');
    } catch (error) {
      console.error('Error viewing report:', error);
    }
  };

  const handleDeleteReport = async (scanId: string, reportType: string) => {
    try {
      if (window.confirm(`Delete ${reportType} report for this scan?`)) {
        const res = await fetch(`/api/reports/${scanId}`, { method: 'DELETE' })
        if (!res.ok) {
          const err = await res.text()
          throw new Error(err || 'Failed to delete report')
        }
        // Refresh data from backend so deleted report does not reappear
        reportsQuery.refetch()
        scansQuery.refetch()
        console.log(`Deleted report: ${reportType} for scan ${scanId}`)
      }
    } catch (error) {
      console.error('Error deleting report:', error)
    }
  }

  // Generate reports only from completed scans that found vulnerabilities
  const reports = state.scans
    .filter(scan => {
      // Only include completed scans that found vulnerabilities
      const isCompleted = scan.status === 'completed';
      const hasFindings = scan.results?.vulnerabilities?.length > 0 || 
                         (scan.results && Object.keys(scan.results).length > 0 && 
                          JSON.stringify(scan.results).includes('vulnerability'));
      return isCompleted && hasFindings;
    })
    .flatMap(scan => {
      const target = state.targets.find(t => t.id === scan.target_id);
      
      // Calculate vulnerability count from agent-specific results
      let vulnerabilityCount = 0;
      let criticalCount = 0;
      
      if (scan.results) {
        // Check for flat vulnerabilities array (legacy format)
        if (Array.isArray(scan.results.vulnerabilities)) {
          vulnerabilityCount = scan.results.vulnerabilities.length;
          criticalCount = scan.results.vulnerabilities.filter((v: any) => v.severity === 'critical').length;
        } else {
          // Check agent-specific results (new format)
          Object.keys(scan.results).forEach(agentName => {
            const agentResults = scan.results[agentName];
            if (agentResults && Array.isArray(agentResults.vulnerabilities)) {
              vulnerabilityCount += agentResults.vulnerabilities.length;
              criticalCount += agentResults.vulnerabilities.filter((v: any) => v.severity === 'critical').length;
            }
          });
        }
      }
      
      return [
        {
          id: `${scan.id}_executive`,
          name: `Executive Report - ${scan.name}`,
          target: target?.domain || scan.target_id,
          type: 'executive' as const,
          createdDate: scan.completed_at || scan.updated_at,
          scanId: scan.id,
          findings: vulnerabilityCount,
          criticalFindings: criticalCount
        },
        {
          id: `${scan.id}_technical`,
          name: `Technical Report - ${scan.name}`,
          target: target?.domain || scan.target_id,
          type: 'technical' as const,
          createdDate: scan.completed_at || scan.updated_at,
          scanId: scan.id,
          findings: vulnerabilityCount,
          criticalFindings: criticalCount
        },
        {
          id: `${scan.id}_disclosure`,
          name: `Disclosure Document - ${scan.name}`,
          target: target?.domain || scan.target_id,
          type: 'disclosure' as const,
          createdDate: scan.completed_at || scan.updated_at,
          scanId: scan.id,
          findings: vulnerabilityCount,
          criticalFindings: criticalCount
        }
      ];
    });

  const getReportIcon = (type: string) => {
    switch (type) {
      case 'executive': return FileText;
      case 'technical': return FileText;
      case 'disclosure': return Mail;
      default: return FileText;
    }
  };

  const getReportColor = (type: string) => {
    switch (type) {
      case 'executive': return 'neon-cyan';
      case 'technical': return 'neon-green';
      case 'disclosure': return 'neon-pink';
      default: return 'cyber-gray';
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
              INTELLIGENCE REPORTS
            </h1>
            <p className="text-cyber-muted">
              Generated security assessments and disclosure documents
            </p>
          </div>
          <div className="flex gap-4">
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

      {/* Loading State */}
      {isLoading && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex items-center justify-center py-20"
        >
          <div className="text-center">
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-neon-cyan"></div>
            <p className="text-cyber-muted mt-4">Loading reports...</p>
          </div>
        </motion.div>
      )}

      {/* Error State */}
      {hasError && !isLoading && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex items-center justify-center py-20"
        >
          <div className="text-center">
            <p className="text-neon-red mb-4">Failed to load reports</p>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={handleRetry}
              className="bg-neon-red bg-opacity-20 border border-neon-red text-neon-red px-6 py-3 rounded-lg hover:bg-opacity-30 transition-all"
            >
              Retry
            </motion.button>
          </div>
        </motion.div>
      )}

      {/* Content - only show when not loading and no error */}
      {!isLoading && !hasError && (
        <>
          {/* Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            {[
              { label: 'Total Reports', value: reports.length.toString(), icon: FileText, color: 'neon-cyan' },
              { label: 'Executive Summaries', value: reports.filter(r => r.type === 'executive').length.toString(), icon: FileText, color: 'neon-green' },
              { label: 'Technical Reports', value: reports.filter(r => r.type === 'technical').length.toString(), icon: FileText, color: 'neon-pink' },
              { label: 'Disclosure Drafts', value: reports.filter(r => r.type === 'disclosure').length.toString(), icon: Mail, color: 'neon-orange' }
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

          {/* Reports Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {reports.length === 0 ? (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="col-span-full flex items-center justify-center py-20"
              >
                <div className="text-center">
                  <FileText className="mx-auto h-16 w-16 text-cyber-muted mb-4" />
                  <h3 className="text-xl font-medium text-cyber-white mb-2">No Reports Available</h3>
                  <p className="text-cyber-muted max-w-md">
                    {state.scans.length === 0 
                      ? "No completed scans found. Create and run scans to generate security reports."
                      : "No reports found for completed scans with vulnerabilities. Reports are only generated for scans that find security issues."
                    }
                  </p>
                </div>
              </motion.div>
            ) : (
              reports.map((report, index) => {
                const ReportIcon = getReportIcon(report.type);
                const reportColor = getReportColor(report.type);
                
                return (
                  <motion.div
                    key={report.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.4 + index * 0.1 }}
                    className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg p-6 hover:border-opacity-50 transition-all group"
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 bg-${reportColor} bg-opacity-20 rounded-lg`}>
                          <ReportIcon className={`text-${reportColor}`} size={24} />
                        </div>
                        <div>
                          <span className={`px-2 py-1 bg-${reportColor} bg-opacity-20 text-${reportColor} rounded text-xs font-bold`}>
                            {report.type.toUpperCase()}
                          </span>
                        </div>
                      </div>
                      <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button 
                          onClick={() => handleDeleteReport(report.scanId, report.type)}
                          className="text-neon-red hover:text-cyber-white transition-colors"
                          title="Delete Report"
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </div>

                    <h3 className="text-lg font-bold text-cyber-white mb-2">{report.name}</h3>
                    <p className="text-cyber-muted text-sm mb-4">Target: {report.target}</p>

                    <div className="space-y-2 mb-4">
                      <div className="flex justify-between text-sm">
                        <span className="text-cyber-muted">Total Findings:</span>
                        <span className="text-cyber-white font-medium">{report.findings}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-cyber-muted">Critical Issues:</span>
                        <span className={`font-medium ${report.criticalFindings > 0 ? 'text-neon-orange' : 'text-neon-green'}`}>
                          {report.criticalFindings}
                        </span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-cyber-muted">Generated:</span>
                        <span className="text-cyber-white font-medium">
                          {new Date(report.createdDate).toLocaleDateString()}
                        </span>
                      </div>
                    </div>

                    <div className="flex gap-2">
                      <motion.button
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        onClick={() => handleViewReport(report.scanId, report.type)}
                        className={`flex-1 bg-${reportColor} bg-opacity-20 border border-${reportColor} text-${reportColor} py-2 px-3 rounded text-sm font-medium hover:bg-opacity-30 transition-all`}
                      >
                        View Report
                      </motion.button>
                      <motion.button
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        onClick={() => handleDownloadReport(report.scanId, report.type)}
                        disabled={downloadReportMutation.isLoading}
                        className="bg-cyber-gray bg-opacity-20 border border-cyber-gray text-cyber-gray py-2 px-3 rounded text-sm hover:bg-opacity-30 transition-all disabled:opacity-50"
                        title="Download PDF"
                      >
                        <Download size={16} />
                      </motion.button>
                    </div>
                  </motion.div>
                );
              })
            )}
          </div>
        </>
      )}
    </div>
  );
};

export default Reports; 