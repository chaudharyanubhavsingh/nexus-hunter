import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Download, FileText, Mail, Eye, Calendar, Filter } from 'lucide-react';
import { useAppContext } from '../context/AppContext';
import { useReports, useDownloadReport } from '../hooks/useApi';

const Reports: React.FC = () => {
  const { state } = useAppContext();
  const reportsQuery = useReports();
  const downloadReportMutation = useDownloadReport();

  // Ensure data is loaded
  React.useEffect(() => {
    if (reportsQuery.refetch) {
      reportsQuery.refetch();
    }
  }, []);

  const handleDownloadReport = async (scanId: string, reportType: string, format: string = 'pdf') => {
    try {
      console.log('Downloading report:', { scanId, reportType, format });
      await downloadReportMutation.mutateAsync({ scanId, reportType, format });
    } catch (error) {
      console.error('Error downloading report:', error);
      // Error handling is done in the mutation
    }
  };

  const handleViewReport = async (scanId: string, reportType: string) => {
    try {
      // Open the report in a new tab
      const url = `http://localhost:8000/api/reports/${scanId}/${reportType === 'executive' ? 'executive-summary' : 'technical-report'}?format=html`;
      window.open(url, '_blank');
    } catch (error) {
      console.error('Error viewing report:', error);
    }
  };

  // Generate reports from completed scans
  const reports = state.scans
    .filter(scan => scan.status === 'completed')
    .flatMap(scan => {
      const target = state.targets.find(t => t.id === scan.target_id);
      const vulnerabilityCount = scan.results?.vulnerabilities?.length || 0;
      const criticalCount = scan.results?.vulnerabilities?.filter((v: any) => v.severity === 'critical').length || 0;
      
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
              className="bg-neon-green bg-opacity-20 border border-neon-green text-neon-green px-6 py-3 rounded-lg flex items-center gap-2 hover:bg-opacity-30 transition-all"
            >
              <FileText size={20} />
              GENERATE REPORT
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
        {reports.map((report, index) => {
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
                    onClick={() => handleViewReport(report.scanId, report.type)}
                    className="text-neon-cyan hover:text-cyber-white transition-colors"
                    title="View Report"
                  >
                    <Eye size={16} />
                  </button>
                  <button 
                    onClick={() => handleDownloadReport(report.scanId, report.type, 'pdf')}
                    disabled={downloadReportMutation.isLoading}
                    className="text-neon-green hover:text-cyber-white transition-colors disabled:opacity-50"
                    title="Download PDF"
                  >
                    <Download size={16} />
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
                  className={`flex-1 bg-${reportColor} bg-opacity-20 border border-${reportColor} text-${reportColor} py-2 px-3 rounded text-sm font-medium hover:bg-opacity-30 transition-all`}
                >
                  View Report
                </motion.button>
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  className="bg-cyber-gray bg-opacity-20 border border-cyber-gray text-cyber-gray py-2 px-3 rounded text-sm hover:bg-opacity-30 transition-all"
                >
                  <Download size={16} />
                </motion.button>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
};

export default Reports; 