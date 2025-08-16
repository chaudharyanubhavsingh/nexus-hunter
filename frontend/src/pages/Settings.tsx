import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Settings as SettingsIcon, Shield, Bell, Database, Key, Save } from 'lucide-react';

const Settings: React.FC = () => {
  const [settings, setSettings] = useState({
    notifications: true,
    autoScan: false,
    concurrentScans: 3,
    scanTimeout: 3600,
    apiKey: '••••••••••••••••',
    retentionDays: 30
  });

  const [isLoading, setIsLoading] = useState(false);

  // Load current timeout from backend on component mount
  useEffect(() => {
    loadCurrentSettings();
  }, []);

  const loadCurrentSettings = async () => {
    try {
      const response = await fetch('/api/scans/system-status');
      if (response.ok) {
        const data = await response.json();
        setSettings(prev => ({
          ...prev,
          scanTimeout: data.stuck_scan_monitor.current_timeout,
          notifications: data.notification_system.enabled,
          autoScan: data.auto_scan_scheduler.enabled,
          concurrentScans: data.concurrent_scan_manager.max_concurrent_scans
        }));
      }
    } catch (error) {
      console.error('Failed to load current settings:', error);
    }
  };

  const updateSetting = (key: string, value: any) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  const saveSettings = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/scans/update-settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scan_timeout: settings.scanTimeout,
          notifications: settings.notifications,
          auto_scan: settings.autoScan,
          concurrent_scans: settings.concurrentScans
        })
      });

      if (response.ok) {
        const result = await response.json();
        console.log('Settings updated:', result);
        
        // Silent success: refresh current settings to reflect persisted state
        loadCurrentSettings();
      } else {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to save settings');
      }
    } catch (error) {
      console.error('Failed to save settings:', error);
    } finally {
      setIsLoading(false);
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
              SYSTEM CONFIGURATION
            </h1>
            <p className="text-cyber-muted">
              Configure platform settings and security parameters
            </p>
          </div>
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={saveSettings}
            disabled={isLoading}
            className={`px-6 py-3 rounded-lg flex items-center gap-2 transition-all ${
              isLoading 
                ? 'bg-cyber-gray bg-opacity-20 border border-cyber-gray text-cyber-gray cursor-not-allowed'
                : 'bg-neon-green bg-opacity-20 border border-neon-green text-neon-green hover:bg-opacity-30'
            }`}
          >
            <Save size={20} />
            {isLoading ? 'SAVING...' : 'SAVE CHANGES'}
          </motion.button>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* General Settings */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg p-6"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-neon-cyan bg-opacity-20 rounded-lg">
              <SettingsIcon className="text-neon-cyan" size={24} />
            </div>
            <h2 className="text-xl font-bold text-neon-cyan">GENERAL SETTINGS</h2>
          </div>

          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-cyber-white font-medium">Enable Notifications</h3>
                <p className="text-cyber-muted text-sm">Receive alerts for scan completion and vulnerabilities</p>
              </div>
              <button
                onClick={() => updateSetting('notifications', !settings.notifications)}
                className={`w-12 h-6 rounded-full transition-all ${
                  settings.notifications ? 'bg-neon-green' : 'bg-cyber-gray bg-opacity-50'
                }`}
              >
                <div className={`w-5 h-5 bg-white rounded-full transition-transform ${
                  settings.notifications ? 'translate-x-6' : 'translate-x-0.5'
                }`} />
              </button>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-cyber-white font-medium">Auto-Scan Schedule</h3>
                <p className="text-cyber-muted text-sm">Automatically scan targets on a schedule</p>
              </div>
              <button
                onClick={() => updateSetting('autoScan', !settings.autoScan)}
                className={`w-12 h-6 rounded-full transition-all ${
                  settings.autoScan ? 'bg-neon-green' : 'bg-cyber-gray bg-opacity-50'
                }`}
              >
                <div className={`w-5 h-5 bg-white rounded-full transition-transform ${
                  settings.autoScan ? 'translate-x-6' : 'translate-x-0.5'
                }`} />
              </button>
            </div>

            <div>
              <h3 className="text-cyber-white font-medium mb-2">Concurrent Scans</h3>
              <input
                type="number"
                value={settings.concurrentScans}
                onChange={(e) => updateSetting('concurrentScans', parseInt(e.target.value))}
                className="w-full bg-cyber-gray bg-opacity-20 border border-cyber-gray border-opacity-30 rounded-lg px-4 py-2 text-cyber-white focus:border-neon-cyan focus:outline-none"
                min="1"
                max="10"
              />
              <p className="text-cyber-muted text-sm mt-1">Maximum number of simultaneous scans</p>
            </div>

            <div>
              <h3 className="text-cyber-white font-medium mb-2">Scan Timeout (seconds)</h3>
              <input
                type="number"
                value={settings.scanTimeout}
                onChange={(e) => updateSetting('scanTimeout', parseInt(e.target.value))}
                className="w-full bg-cyber-gray bg-opacity-20 border border-cyber-gray border-opacity-30 rounded-lg px-4 py-2 text-cyber-white focus:border-neon-cyan focus:outline-none"
                min="300"
                max="7200"
              />
              <p className="text-cyber-muted text-sm mt-1">
                Maximum time allowed for each scan. Updates are applied immediately to running monitor.
              </p>
            </div>
          </div>
        </motion.div>

        {/* Security Settings */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg p-6"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-neon-orange bg-opacity-20 rounded-lg">
              <Shield className="text-neon-orange" size={24} />
            </div>
            <h2 className="text-xl font-bold text-neon-orange">SECURITY SETTINGS</h2>
          </div>

          <div className="space-y-6">
            <div>
              <h3 className="text-cyber-white font-medium mb-2">API Key</h3>
              <div className="flex gap-2">
                <input
                  type="password"
                  value={settings.apiKey}
                  onChange={(e) => updateSetting('apiKey', e.target.value)}
                  className="flex-1 bg-cyber-gray bg-opacity-20 border border-cyber-gray border-opacity-30 rounded-lg px-4 py-2 text-cyber-white focus:border-neon-cyan focus:outline-none"
                  placeholder="Enter API key"
                />
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  className="bg-neon-cyan bg-opacity-20 border border-neon-cyan text-neon-cyan px-4 py-2 rounded-lg"
                >
                  <Key size={18} />
                </motion.button>
              </div>
              <p className="text-cyber-muted text-sm mt-1">OpenAI API key for AI-powered analysis</p>
            </div>

            <div>
              <h3 className="text-cyber-white font-medium mb-2">Data Retention (days)</h3>
              <input
                type="number"
                value={settings.retentionDays}
                onChange={(e) => updateSetting('retentionDays', parseInt(e.target.value))}
                className="w-full bg-cyber-gray bg-opacity-20 border border-cyber-gray border-opacity-30 rounded-lg px-4 py-2 text-cyber-white focus:border-neon-cyan focus:outline-none"
                min="7"
                max="365"
              />
              <p className="text-cyber-muted text-sm mt-1">How long to keep scan data and reports</p>
            </div>

            <div className="border-t border-cyber-gray border-opacity-20 pt-6">
              <h3 className="text-cyber-white font-medium mb-4">Security Guidelines</h3>
              <div className="space-y-3 text-sm">
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 bg-neon-green rounded-full mt-2" />
                  <p className="text-cyber-muted">Only scan targets you own or have explicit permission to test</p>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 bg-neon-green rounded-full mt-2" />
                                      <p className="text-cyber-muted">Follow responsible disclosure practices for found vulnerabilities</p>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 bg-neon-green rounded-full mt-2" />
                                      <p className="text-cyber-muted">Keep your API keys secure and rotate them regularly</p>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 bg-neon-orange rounded-full mt-2" />
                                      <p className="text-cyber-muted">This tool is for ethical security testing only</p>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Database Settings */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg p-6"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-neon-pink bg-opacity-20 rounded-lg">
              <Database className="text-neon-pink" size={24} />
            </div>
            <h2 className="text-xl font-bold text-neon-pink">DATABASE STATUS</h2>
          </div>

          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-cyber-muted">Connection Status:</span>
              <span className="text-neon-green font-medium">Connected</span>
            </div>
            <div className="flex justify-between items-center">
                              <span className="text-cyber-muted">Total Records:</span>
              <span className="text-cyber-white font-medium">2,847</span>
            </div>
            <div className="flex justify-between items-center">
                              <span className="text-cyber-muted">Database Size:</span>
              <span className="text-cyber-white font-medium">1.2 GB</span>
            </div>
            <div className="flex justify-between items-center">
                              <span className="text-cyber-muted">Last Backup:</span>
              <span className="text-cyber-white font-medium">2 hours ago</span>
            </div>
          </div>

          <div className="flex gap-2 mt-6">
            <motion.button
              whileHover={{ scale: 1.05 }}
              className="flex-1 bg-neon-pink bg-opacity-20 border border-neon-pink text-neon-pink py-2 px-4 rounded-lg text-sm hover:bg-opacity-30 transition-all"
            >
              Backup Now
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.05 }}
              className="flex-1 bg-neon-orange bg-opacity-20 border border-neon-orange text-neon-orange py-2 px-4 rounded-lg text-sm hover:bg-opacity-30 transition-all"
            >
              Optimize
            </motion.button>
          </div>
        </motion.div>

        {/* System Information */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-30 rounded-lg p-6"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-neon-green bg-opacity-20 rounded-lg">
              <Bell className="text-neon-green" size={24} />
            </div>
            <h2 className="text-xl font-bold text-neon-green">SYSTEM INFO</h2>
          </div>

          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-cyber-muted">Version:</span>
              <span className="text-cyber-white font-medium">v1.0.0</span>
            </div>
            <div className="flex justify-between items-center">
                              <span className="text-cyber-muted">Uptime:</span>
              <span className="text-cyber-white font-medium">2d 14h 32m</span>
            </div>
            <div className="flex justify-between items-center">
                              <span className="text-cyber-muted">CPU Usage:</span>
              <span className="text-neon-green font-medium">23%</span>
            </div>
            <div className="flex justify-between items-center">
                              <span className="text-cyber-muted">Memory Usage:</span>
              <span className="text-neon-cyan font-medium">4.2 GB / 16 GB</span>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default Settings; 