import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Play, Target, Settings, Zap, Shield, Clock } from 'lucide-react';
import { useCreateScan, useTargets } from '../hooks/useApi';
import { useAppContext } from '../context/AppContext';
import UniversalForm, { FormField } from './UniversalForm';
import { ValidationSchema } from '../utils/validation';

interface CreateScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  preselectedTargetId?: string;
}

const CreateScanModal: React.FC<CreateScanModalProps> = ({ 
  isOpen, 
  onClose, 
  preselectedTargetId 
}) => {
  const { state } = useAppContext();
  const createScanMutation = useCreateScan();
  const targetsQuery = useTargets(); // Fetch targets
  const [activeTab, setActiveTab] = useState<'basic' | 'advanced' | 'schedule'>('basic');

  // Get active targets for selection
  const activeTargets = useMemo(() => {
    return state.targets.filter(t => t.is_active);
  }, [state.targets]);

  // Debug logging
  useEffect(() => {
    console.log('CreateScanModal Debug:', {
      isOpen,
      targetsCount: state.targets.length,
      activeTargetsCount: activeTargets.length,
      isLoadingTargets: targetsQuery.isLoading,
      targetsError: targetsQuery.error,
      preselectedTargetId
    });
  }, [isOpen, state.targets, activeTargets, targetsQuery.isLoading, targetsQuery.error, preselectedTargetId]);

  // Only refetch targets if modal is opened and no targets exist at all
  // Reduced aggressive refetching to prevent database noise
  useEffect(() => {
    if (isOpen && state.targets.length === 0 && !targetsQuery.isLoading) {
      console.log('CreateScanModal: Fetching targets (none exist)...');
      targetsQuery.refetch();
    }
  }, [isOpen, state.targets.length, targetsQuery.isLoading, targetsQuery]);

  // Comprehensive form fields - make dynamic
  const formFields: FormField[] = useMemo(() => [
    {
      name: 'name',
      label: 'Scan Name',
      type: 'text',
      placeholder: 'e.g., Full Security Assessment',
      description: 'A descriptive name for this scan',
      required: true,
    },
    {
      name: 'target_id',
      label: 'Target',
      type: 'select',
      placeholder: 'Select a target...',
      description: 'Choose the target to scan',
      required: true,
      options: activeTargets.length > 0 ? activeTargets.map(target => ({
        value: target.id,
        label: `${target.name} (${target.domain})`,
      })) : [{ value: '', label: 'No active targets available', disabled: true }],
    },
    {
      name: 'type',
      label: 'Scan Type',
      type: 'radio',
      description: 'Choose the type of security scan to perform',
      required: true,
      options: [
        { 
          value: 'recon', 
          label: '🔍 Reconnaissance - Basic discovery and enumeration (15-30 min)'
        },
        { 
          value: 'vulnerability', 
          label: '🛡️ Vulnerability Scan - Comprehensive security testing (30-60 min)'
        },
        { 
          value: 'full', 
          label: '🚀 Full Assessment - Complete security audit (1-2 hours)'
        },
      ],
    },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea',
      placeholder: 'Optional description of this scan...',
      description: 'Additional context about this scan',
      rows: 3,
    },
    {
      name: 'priority',
      label: 'Priority Level',
      type: 'select',
      placeholder: 'Select priority...',
      description: 'Execution priority for this scan',
      options: [
        { value: 'low', label: '🟢 Low Priority' },
        { value: 'medium', label: '🟡 Medium Priority' },
        { value: 'high', label: '🟠 High Priority' },
        { value: 'critical', label: '🔴 Critical Priority' },
      ],
    },
    {
      name: 'max_concurrent_requests',
      label: 'Concurrent Requests',
      type: 'range',
      description: 'Maximum concurrent requests (affects scan speed vs. server load)',
      min: 1,
      max: 50,
    },
    {
      name: 'timeout_seconds',
      label: 'Request Timeout (seconds)',
      type: 'number',
      placeholder: '30',
      description: 'Timeout for individual requests',
      min: 5,
      max: 300,
    },
    {
      name: 'rate_limit',
      label: 'Global Rate Limit (req/sec)',
      type: 'number',
      placeholder: '5',
      description: 'Global throttling to avoid overloading the target',
      min: 1,
      max: 100,
    },
    {
      name: 'custom_headers',
      label: 'Custom Headers',
      type: 'json',
      placeholder: '{\n  "User-Agent": "Nexus-Hunter/1.0",\n  "Authorization": "Bearer token"\n}',
      description: 'Custom HTTP headers for requests (JSON format)',
      rows: 4,
    },
    {
      name: 'auth_config',
      label: 'Authentication Config',
      type: 'json',
      placeholder: '{\n  "type": "bearer|basic|cookie",\n  "token": "...",\n  "username": "...",\n  "password": "..."\n}',
      description: 'Authentication details if needed',
      rows: 4,
    },
    {
      name: 'exclude_paths',
      label: 'Exclude Paths',
      type: 'tags',
      placeholder: 'Add paths to exclude (press Enter to add)',
      description: 'Paths or patterns to exclude from scanning',
      maxTags: 20,
    },
    {
      name: 'include_subdomains',
      label: 'Include Subdomains',
      type: 'checkbox',
      description: 'Automatically discover and scan subdomains',
    },
    {
      name: 'deep_scan',
      label: 'Deep Scan Mode',
      type: 'checkbox',
      description: 'Enable extensive testing (increases scan time)',
    },
    {
      name: 'save_responses',
      label: 'Save HTTP Responses',
      type: 'checkbox',
      description: 'Save full HTTP responses for analysis',
    },
    {
      name: 'schedule_type',
      label: 'Execution Type',
      type: 'select',
      placeholder: 'Run immediately',
      description: 'When to execute this scan',
      options: [
        { value: 'immediate', label: '⚡ Run Immediately' },
        { value: 'scheduled', label: '📅 Schedule for Later' },
      ],
    },
    {
      name: 'schedule_frequency',
      label: 'Schedule Frequency',
      type: 'select',
      placeholder: 'One time only',
      description: 'How often to repeat this scan',
      condition: (formData: any) => formData.schedule_type === 'scheduled',
      options: [
        { value: 'once', label: '📅 One Time Only' },
        { value: 'daily', label: '🔄 Daily' },
        { value: 'weekly', label: '📆 Weekly' },
        { value: 'monthly', label: '📋 Monthly' },
      ],
    },
    {
      name: 'scheduled_time',
      label: 'Scheduled Time',
      type: 'datetime-local',
      description: 'When to run the scan (for one-time) or start time (for recurring)',
      condition: (formData: any) => formData.schedule_type === 'scheduled',
    },
    {
      name: 'recurrence_pattern',
      label: 'Recurrence Pattern',
      type: 'select',
      placeholder: 'Select frequency...',
      description: 'How often to repeat the scan',
      options: [
        { value: 'daily', label: 'Daily' },
        { value: 'weekly', label: 'Weekly' },
        { value: 'monthly', label: 'Monthly' },
      ],
    },
    {
      name: 'notify_on_completion',
      label: 'Notify on Completion',
      type: 'checkbox',
      description: 'Send notification when scan completes',
    },
    {
      name: 'notification_email',
      label: 'Notification Email',
      type: 'email',
      placeholder: 'security@company.com',
      description: 'Email address for notifications',
    },
  ], [activeTargets]);

  // Auto-apply saved advanced target settings into scan config defaults
  useEffect(() => {
    try {
      const selectedTarget = state.targets.find(t => t.id === (preselectedTargetId || undefined)) || null;
      const domain = selectedTarget?.domain;
      if (!domain) return;
      const saved = localStorage.getItem(`target_settings:${domain}`);
      if (!saved) return;
      const adv = JSON.parse(saved);
      // Merge into initial defaults in a controlled way
      (initialData as any).priority = adv?.priority || (initialData as any).priority;
      (initialData as any).max_concurrent_requests = adv?.rate_limit || (initialData as any).max_concurrent_requests;
      (initialData as any).include_subdomains = true;
    } catch {}
  }, [state.targets, preselectedTargetId]);

  // Validation schema
  const validationSchema: ValidationSchema = {
    name: {
      required: true,
      minLength: 3,
      maxLength: 100,
    },
    target_id: {
      required: true,
    },
    type: {
      required: true,
    },
    timeout_seconds: {
      min: 5,
      max: 300,
    },
    max_concurrent_requests: {
      min: 1,
      max: 50,
    },
    custom_headers: {
      custom: (value: string) => {
        if (value) {
          try {
            JSON.parse(value);
          } catch {
            return 'Please enter valid JSON';
          }
        }
        return null;
      },
    },
    notification_email: {
      pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    },
  };

  const handleSubmit = async (formData: Record<string, any>) => {
    try {
      // Parse custom headers if provided
      let customHeaders = null;
      if (formData.custom_headers) {
        try {
          customHeaders = JSON.parse(formData.custom_headers);
        } catch {
          // Already validated
        }
      }
      let authConfig = null;
      if (formData.auth_config) {
        try { authConfig = JSON.parse(formData.auth_config); } catch { authConfig = null; }
      }

      // Prepare scan data with extensive config
      const scanData = {
        name: formData.name,
        target_id: formData.target_id,
        type: formData.type,
        config: {
          description: formData.description || undefined,
          priority: formData.priority,
          max_concurrent_requests: formData.max_concurrent_requests || 10,
          timeout_seconds: formData.timeout_seconds || 30,
          rate_limit: formData.rate_limit || undefined,
          custom_headers: customHeaders,
          auth: authConfig,
          exclude_paths: formData.exclude_paths || [],
          include_subdomains: formData.include_subdomains || false,
          deep_scan: formData.deep_scan || false,
          save_responses: formData.save_responses || false,
          schedule_type: formData.schedule_type || 'immediate',
          scheduled_time: formData.scheduled_time,
          recurrence_pattern: formData.recurrence_pattern,
          notify_on_completion: formData.notify_on_completion || false,
          notification_email: formData.notification_email,
        },
      };

      await createScanMutation.mutateAsync(scanData);
      onClose();
    } catch (error) {
      // Error handling is done in the mutation
    }
  };

  const getFieldsForTab = (tab: string): FormField[] => {
    switch (tab) {
      case 'basic':
        return formFields.filter(f => 
          ['name', 'target_id', 'type', 'description', 'priority'].includes(f.name)
        );
      case 'advanced':
        return formFields.filter(f => 
          ['max_concurrent_requests', 'timeout_seconds', 'custom_headers', 'exclude_paths', 
           'include_subdomains', 'deep_scan', 'save_responses'].includes(f.name)
        );
      case 'schedule':
        return formFields.filter(f => 
          ['schedule_type', 'scheduled_time', 'recurrence_pattern', 'notify_on_completion', 
           'notification_email'].includes(f.name)
        );
      default:
        return formFields;
    }
  };

  const initialData = useMemo(() => ({
    target_id: preselectedTargetId || (activeTargets.length > 0 ? activeTargets[0].id : ''),
    name: preselectedTargetId ? `Scan for ${activeTargets.find(t => t.id === preselectedTargetId)?.name || 'Target'}` : '',
    type: 'recon',
    priority: 'medium',
    max_concurrent_requests: 10,
    timeout_seconds: 30,
    include_subdomains: true,
    schedule_type: 'immediate',
    notify_on_completion: true,
  }), [preselectedTargetId, activeTargets]);

  // Show loading state while targets are being fetched
  const isLoadingData = targetsQuery.isLoading && state.targets.length === 0;

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black bg-opacity-50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={onClose}
          >
            {/* Modal */}
            <motion.div
              initial={{ opacity: 0, scale: 0.9, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9, y: 20 }}
              className="bg-cyber-dark border border-cyber-gray rounded-lg w-full max-w-4xl max-h-[90vh] overflow-hidden"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header */}
              <div className="flex items-center justify-between p-6 border-b border-cyber-gray border-opacity-30">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-neon-green bg-opacity-20 rounded-lg">
                    <Play className="text-neon-green" size={20} />
                  </div>
                  <h2 className="text-lg font-bold text-neon-green">CREATE NEW SCAN</h2>
                </div>
                <button
                  onClick={onClose}
                  className="text-cyber-muted hover:text-cyber-white transition-colors"
                >
                  <X size={20} />
                </button>
              </div>

              {/* Tabs */}
              <div className="px-6 pt-4">
                <div className="flex space-x-1 bg-cyber-gray bg-opacity-20 rounded-lg p-1">
                  {[
                    { id: 'basic', label: 'Basic Setup', icon: Target },
                    { id: 'advanced', label: 'Advanced Options', icon: Settings },
                    { id: 'schedule', label: 'Schedule & Notifications', icon: Clock },
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id as any)}
                      className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
                        activeTab === tab.id
                          ? 'bg-neon-green text-cyber-black'
                          : 'text-cyber-muted hover:text-cyber-white'
                      }`}
                    >
                      <tab.icon size={16} />
                      {tab.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Form Content */}
              <div className="p-6 overflow-y-auto max-h-[calc(90vh-200px)]">
                {isLoadingData ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="flex items-center gap-3">
                      <div className="w-6 h-6 border-2 border-neon-cyan border-t-transparent rounded-full animate-spin"></div>
                      <span className="text-cyber-muted">Loading targets...</span>
                    </div>
                  </div>
                ) : activeTargets.length === 0 ? (
                  <div className="text-center py-8">
                    <div className="p-3 bg-neon-orange bg-opacity-20 rounded-full w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                      <Target className="text-neon-orange" size={32} />
                    </div>
                    <h3 className="text-lg font-bold text-neon-orange mb-2">No Active Targets</h3>
                    <p className="text-cyber-muted mb-4">
                      You need to create and activate at least one target before you can start a scan.
                    </p>
                    <button
                      onClick={onClose}
                      className="bg-neon-orange bg-opacity-20 border border-neon-orange text-neon-orange px-4 py-2 rounded-lg hover:bg-opacity-30 transition-colors"
                    >
                      Add Targets First
                    </button>
                  </div>
                ) : (
                  <>
                    <UniversalForm
                      fields={getFieldsForTab(activeTab)}
                      initialData={initialData}
                      validationSchema={validationSchema}
                      onSubmit={handleSubmit}
                      submitLabel={createScanMutation.isLoading ? 'Creating Scan...' : 'Create Scan'}
                      isLoading={createScanMutation.isLoading}
                      showProgress={true}
                      layout="vertical"
                      className="space-y-6"
                    />

                    {/* Quick Info Panel */}
                    {activeTab === 'basic' && (
                      <div className="mt-8 p-4 bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-20 rounded-lg">
                        <h4 className="text-sm font-medium text-neon-green mb-3 flex items-center">
                          <Settings size={16} className="mr-2" />
                          Quick Reference
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                          <div className="text-center p-3 bg-neon-cyan bg-opacity-10 rounded">
                            <Target size={24} className="mx-auto mb-2 text-neon-cyan" />
                            <div className="font-medium text-neon-cyan">Reconnaissance</div>
                            <div className="text-cyber-muted">15-30 min • Basic discovery</div>
                          </div>
                          <div className="text-center p-3 bg-neon-orange bg-opacity-10 rounded">
                            <Shield size={24} className="mx-auto mb-2 text-neon-orange" />
                            <div className="font-medium text-neon-orange">Vulnerability Scan</div>
                            <div className="text-cyber-muted">30-60 min • Security testing</div>
                          </div>
                          <div className="text-center p-3 bg-neon-red bg-opacity-10 rounded">
                            <Zap size={24} className="mx-auto mb-2 text-neon-red" />
                            <div className="font-medium text-neon-red">Full Assessment</div>
                            <div className="text-cyber-muted">1-2 hours • Complete audit</div>
                          </div>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            </motion.div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

export default CreateScanModal; 