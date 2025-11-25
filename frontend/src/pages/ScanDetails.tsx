import React, { useMemo } from 'react';
import { motion } from 'framer-motion';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Download, Eye, AlertTriangle, CheckCircle, Play, Clock } from 'lucide-react';
import { useAppContext } from '../context/AppContext';
import { useScanDetails, useDownloadReport } from '../hooks/useApi';
import AgentStatusMonitor from '../components/AgentStatusMonitor';

const formatDateTime = (iso?: string) => {
  try {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
  } catch {
    return iso || '—';
  }
};

const ScanDetails: React.FC = () => {
  const navigate = useNavigate();
  const { scanId = '' } = useParams();
  const { state } = useAppContext();
  const scanQuery = useScanDetails(scanId);
  const downloadReport = useDownloadReport();
  const handlePreview = (scanId: string, type: 'technical' | 'executive' = 'technical') => {
    const base = (import.meta as any).env?.VITE_API_URL || 'http://localhost:8000'
    const url = `${base}/api/reports/${scanId}/${type}-report?format=html`
    window.open(url, '_blank')
  }

  // Prefer live scan from context (updated via WebSocket), fallback to query
  const scan = useMemo(() => {
    const fromCtx = state.scans.find(s => s.id === scanId);
    return fromCtx || (scanQuery.data as any) || null;
  }, [scanId, state.scans, scanQuery.data]);

  const target = useMemo(() => {
    if (!scan) return null;
    return state.targets.find(t => t.id === scan.target_id) || null;
  }, [scan, state.targets]);

  const results = (scan && (scan as any).results) || {};
  
  // Calculate vulnerabilities from agent-specific results
  let vulnerabilities: any[] = [];
  if (Array.isArray(results?.vulnerabilities)) {
    // Legacy flat format
    vulnerabilities = results.vulnerabilities;
  } else if (results) {
    // New agent-specific format
    Object.keys(results).forEach(agentName => {
      const agentResults = results[agentName];
      if (agentResults && Array.isArray(agentResults.vulnerabilities)) {
        vulnerabilities = vulnerabilities.concat(agentResults.vulnerabilities);
      }
    });
  }

  const handleExport = async (type: 'technical' | 'executive' = 'technical') => {
    if (!scan) return;
    try {
      await downloadReport.mutateAsync({ scanId: scan.id, reportType: type, format: 'pdf' });
    } catch {}
  };

  // const handleShare = async () => {
  //   try {
  //     await navigator.clipboard.writeText(window.location.href);
  //   } catch {}
  // };

  if (scanQuery.isLoading && !scan) {
    return (
      <div className="min-h-screen bg-cyber-black text-cyber-white p-6 flex items-center justify-center">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
          className="w-8 h-8 border-2 border-neon-cyan border-t-transparent rounded-full"
        />
      </div>
    );
  }

  if (scanQuery.isError && !scan) {
    return (
      <div className="min-h-screen bg-cyber-black text-cyber-white p-6">
        <button onClick={() => navigate(-1)} className="text-neon-cyan hover:text-cyber-white transition-colors mb-4">
          <ArrowLeft size={24} />
        </button>
        <div className="text-neon-red">Failed to load scan details.</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-cyber-black text-cyber-white p-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="mb-8">
        <div className="flex items-center gap-4 mb-4">
          <button onClick={() => navigate(-1)} className="text-neon-cyan hover:text-cyber-white transition-colors">
            <ArrowLeft size={24} />
          </button>
          <div>
            <h1 className="text-4xl font-bold text-glow">SCAN DETAILS</h1>
            <p className="text-cyber-muted">Detailed analysis and findings</p>
          </div>
        </div>

        <div className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-bold text-neon-cyan mb-2">{scan?.name || 'Security Assessment'}</h2>
              <p className="text-cyber-muted">
                Target: {target?.domain || scan?.target_id || '—'} |
                {' '}Started: {formatDateTime((scan as any)?.started_at || scan?.created_at)} |
                {' '}Status: {(scan as any)?.status}
              </p>
            </div>
            <div className="flex gap-4">
              <motion.button whileHover={{ scale: 1.05 }} onClick={() => handleExport('technical')} className="bg-neon-green bg-opacity-20 border border-neon-green text-neon-green px-4 py-2 rounded-lg flex items-center gap-2">
                <Download size={18} />
                Export
              </motion.button>
              <motion.button whileHover={{ scale: 1.05 }} onClick={() => handlePreview(scan?.id as string, 'technical')} className="bg-neon-cyan bg-opacity-20 border border-neon-cyan text-neon-cyan px-4 py-2 rounded-lg flex items-center gap-2">
                <Eye size={18} />
                Preview
              </motion.button>
            </div>
          </div>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.2 }} className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg p-6">
            <h3 className="text-lg font-bold text-neon-cyan mb-4">VULNERABILITIES FOUND</h3>
            <div className="space-y-4">
              {vulnerabilities.length === 0 && (
                <div className="text-cyber-muted text-sm">No vulnerabilities found yet.</div>
              )}
              {vulnerabilities.map((vuln: any, index: number) => {
                const sev = (vuln?.severity || 'info').toLowerCase();
                const badgeClass = sev === 'critical' ? 'text-neon-red bg-neon-red/20' : sev === 'high' ? 'text-neon-orange bg-neon-orange/20' : sev === 'medium' ? 'text-neon-yellow bg-neon-yellow/20' : 'text-cyber-muted bg-cyber-muted/20';
                return (
                  <div key={index} className="border border-cyber-gray border-opacity-20 rounded p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <AlertTriangle className="text-neon-orange" size={20} />
                        <div>
                          <p className="font-medium text-cyber-white">{vuln?.title || 'Untitled finding'}</p>
                          <p className="text-sm text-cyber-muted">Severity: {vuln?.severity || 'Info'}</p>
                        </div>
                      </div>
                      <span className={`px-2 py-1 rounded text-xs ${badgeClass}`}>
                        {(vuln?.confirmed || vuln?.confidence === 100) ? 'Confirmed' : 'Potential'}
                      </span>
                    </div>
                    {vuln?.description && (
                      <p className="text-sm text-cyber-muted mt-2">{vuln.description}</p>
                    )}
                    {vuln?.url && (
                      <p className="text-xs text-cyber-muted mt-1">URL: {vuln.url}</p>
                    )}
                  </div>
                );
              })}
            </div>
          </motion.div>
        </div>

        <div className="space-y-6">
          {/* Dynamic Agent Status Monitor */}
          <motion.div 
            initial={{ opacity: 0, x: 20 }} 
            animate={{ opacity: 1, x: 0 }} 
            transition={{ delay: 0.3 }}
          >
            <AgentStatusMonitor 
              scanId={scan?.id} 
              compact={false}
              showProgress={true}
            />
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default ScanDetails; 