import React from 'react';
import { motion } from 'framer-motion';
import { ArrowLeft, Play, Download, Share, AlertTriangle, CheckCircle, Clock } from 'lucide-react';

const ScanDetails: React.FC = () => {
  return (
    <div className="min-h-screen bg-cyber-black text-cyber-white p-6">
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <div className="flex items-center gap-4 mb-4">
          <button className="text-neon-cyan hover:text-cyber-white transition-colors">
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
              <h2 className="text-xl font-bold text-neon-cyan mb-2">Full Security Assessment</h2>
              <p className="text-cyber-muted">Target: api.example.com | Started: 2024-08-15 11:30:00</p>
            </div>
            <div className="flex gap-4">
              <motion.button
                whileHover={{ scale: 1.05 }}
                className="bg-neon-green bg-opacity-20 border border-neon-green text-neon-green px-4 py-2 rounded-lg flex items-center gap-2"
              >
                <Download size={18} />
                Export
              </motion.button>
              <motion.button
                whileHover={{ scale: 1.05 }}
                className="bg-neon-cyan bg-opacity-20 border border-neon-cyan text-neon-cyan px-4 py-2 rounded-lg flex items-center gap-2"
              >
                <Share size={18} />
                Share
              </motion.button>
            </div>
          </div>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg p-6"
          >
            <h3 className="text-lg font-bold text-neon-cyan mb-4">VULNERABILITIES FOUND</h3>
            <div className="space-y-4">
              {[
                { severity: 'High', title: 'SQL Injection in Login Form', status: 'Confirmed' },
                { severity: 'Medium', title: 'Cross-Site Scripting (XSS)', status: 'Confirmed' },
                { severity: 'Low', title: 'Information Disclosure', status: 'Potential' }
              ].map((vuln, index) => (
                <div key={index} className="border border-cyber-gray border-opacity-20 rounded p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <AlertTriangle className="text-neon-orange" size={20} />
                      <div>
                        <p className="font-medium text-cyber-white">{vuln.title}</p>
                        <p className="text-sm text-cyber-muted">Severity: {vuln.severity}</p>
                      </div>
                    </div>
                    <span className="px-2 py-1 bg-neon-orange bg-opacity-20 text-neon-orange rounded text-xs">
                      {vuln.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </div>

        <div className="space-y-6">
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3 }}
            className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg p-6"
          >
            <h3 className="text-lg font-bold text-neon-cyan mb-4">SCAN PROGRESS</h3>
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <CheckCircle className="text-neon-green" size={20} />
                <span className="text-cyber-white">Reconnaissance</span>
              </div>
              <div className="flex items-center gap-3">
                <CheckCircle className="text-neon-green" size={20} />
                <span className="text-cyber-white">Port Scanning</span>
              </div>
              <div className="flex items-center gap-3">
                <Play className="text-neon-cyan" size={20} />
                <span className="text-cyber-white">Vulnerability Testing</span>
              </div>
              <div className="flex items-center gap-3">
                <Clock className="text-cyber-gray" size={20} />
                <span className="text-cyber-gray">Report Generation</span>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default ScanDetails; 