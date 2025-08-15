import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Play, Target, Settings, Zap } from 'lucide-react';
import { useCreateScan } from '../hooks/useApi';
import { useAppContext } from '../context/AppContext';

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
  const [formData, setFormData] = useState({
    name: '',
    target_id: preselectedTargetId || '',
    type: 'recon' as 'recon' | 'vulnerability' | 'full',
  });
  const [errors, setErrors] = useState<Record<string, string>>({});

  const createScanMutation = useCreateScan();

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Scan name is required';
    }

    if (!formData.target_id) {
      newErrors.target_id = 'Please select a target';
    }

    if (!formData.type) {
      newErrors.type = 'Please select a scan type';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    try {
      await createScanMutation.mutateAsync(formData);
      onClose();
      resetForm();
    } catch (error) {
      // Error handling is done in the mutation
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      target_id: preselectedTargetId || '',
      type: 'recon',
    });
    setErrors({});
  };

  const handleClose = () => {
    resetForm();
    onClose();
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const getScanTypeConfig = (type: string) => {
    switch (type) {
      case 'recon':
        return {
          icon: Target,
          color: 'neon-cyan',
          description: 'Subdomain discovery, port scanning, and service enumeration',
          duration: '15-30 minutes',
          level: 'Basic'
        };
      case 'vulnerability':
        return {
          icon: Settings,
          color: 'neon-orange',
          description: 'Vulnerability scanning with safe payloads (SQLi, XSS, etc.)',
          duration: '30-60 minutes',
          level: 'Moderate'
        };
      case 'full':
        return {
          icon: Zap,
          color: 'neon-red',
          description: 'Complete recon + vulnerability assessment + report generation',
          duration: '1-2 hours',
          level: 'Comprehensive'
        };
      default:
        return {
          icon: Target,
          color: 'cyber-gray',
          description: '',
          duration: '',
          level: ''
        };
    }
  };

  const selectedTarget = state.targets.find(t => t.id === formData.target_id);

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
            onClick={handleClose}
          >
            {/* Modal */}
            <motion.div
              initial={{ opacity: 0, scale: 0.9, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9, y: 20 }}
              className="bg-cyber-dark border border-cyber-gray rounded-lg w-full max-w-lg"
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
                  onClick={handleClose}
                  className="text-cyber-muted hover:text-cyber-white transition-colors"
                >
                  <X size={20} />
                </button>
              </div>

              {/* Form */}
              <form onSubmit={handleSubmit} className="p-6 space-y-6">
                {/* Scan Name */}
                <div>
                  <label htmlFor="name" className="block text-sm font-medium text-cyber-white mb-2">
                    Scan Name
                  </label>
                  <input
                    type="text"
                    id="name"
                    name="name"
                    value={formData.name}
                    onChange={handleInputChange}
                    className={`w-full px-4 py-3 bg-cyber-gray bg-opacity-20 border rounded-lg text-cyber-white placeholder-cyber-muted focus:outline-none focus:border-neon-green transition-colors ${
                      errors.name ? 'border-neon-red' : 'border-cyber-gray border-opacity-30'
                    }`}
                    placeholder="e.g., Full Security Assessment"
                  />
                  {errors.name && (
                    <p className="mt-1 text-sm text-neon-red">{errors.name}</p>
                  )}
                </div>

                {/* Target Selection */}
                <div>
                  <label htmlFor="target_id" className="block text-sm font-medium text-cyber-white mb-2">
                    Target
                  </label>
                  <select
                    id="target_id"
                    name="target_id"
                    value={formData.target_id}
                    onChange={handleInputChange}
                    className={`w-full px-4 py-3 bg-cyber-gray bg-opacity-20 border rounded-lg text-cyber-white focus:outline-none focus:border-neon-green transition-colors appearance-none ${
                      errors.target_id ? 'border-neon-red' : 'border-cyber-gray border-opacity-30'
                    }`}
                  >
                    <option value="">Select a target...</option>
                    {state.targets.filter(t => t.is_active).map((target) => (
                      <option key={target.id} value={target.id}>
                        {target.name} ({target.domain})
                      </option>
                    ))}
                  </select>
                  {errors.target_id && (
                    <p className="mt-1 text-sm text-neon-red">{errors.target_id}</p>
                  )}
                  {selectedTarget && (
                    <div className="mt-2 p-3 bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-20 rounded-lg">
                      <p className="text-sm text-cyber-white">
                        <span className="font-medium">Domain:</span> {selectedTarget.domain}
                      </p>
                      <p className="text-sm text-cyber-muted">
                        <span className="font-medium">Scope:</span> {selectedTarget.scope}
                      </p>
                    </div>
                  )}
                </div>

                {/* Scan Type */}
                <div>
                  <label className="block text-sm font-medium text-cyber-white mb-3">
                    Scan Type
                  </label>
                  <div className="space-y-3">
                    {(['recon', 'vulnerability', 'full'] as const).map((type) => {
                      const config = getScanTypeConfig(type);
                      const Icon = config.icon;
                      const isSelected = formData.type === type;

                      return (
                        <label
                          key={type}
                          className={`block p-4 border rounded-lg cursor-pointer transition-all ${
                            isSelected
                              ? `border-${config.color} bg-${config.color} bg-opacity-10`
                              : 'border-cyber-gray border-opacity-30 hover:border-opacity-50'
                          }`}
                        >
                          <div className="flex items-start gap-3">
                            <input
                              type="radio"
                              name="type"
                              value={type}
                              checked={isSelected}
                              onChange={handleInputChange}
                              className="sr-only"
                            />
                            <div className={`p-2 rounded-lg ${
                              isSelected 
                                ? `bg-${config.color} bg-opacity-20` 
                                : 'bg-cyber-gray bg-opacity-20'
                            }`}>
                              <Icon 
                                className={isSelected ? `text-${config.color}` : 'text-cyber-muted'} 
                                size={18} 
                              />
                            </div>
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                <span className={`font-medium ${
                                  isSelected ? `text-${config.color}` : 'text-cyber-white'
                                }`}>
                                  {type.charAt(0).toUpperCase() + type.slice(1)} Scan
                                </span>
                                <span className={`px-2 py-1 rounded text-xs font-bold ${
                                  config.level === 'Basic' ? 'bg-neon-cyan bg-opacity-20 text-neon-cyan' :
                                  config.level === 'Moderate' ? 'bg-neon-orange bg-opacity-20 text-neon-orange' :
                                  'bg-neon-red bg-opacity-20 text-neon-red'
                                }`}>
                                  {config.level}
                                </span>
                              </div>
                              <p className="text-sm text-cyber-muted mb-1">
                                {config.description}
                              </p>
                              <p className="text-xs text-cyber-muted">
                                Duration: {config.duration}
                              </p>
                            </div>
                          </div>
                        </label>
                      );
                    })}
                  </div>
                  {errors.type && (
                    <p className="mt-1 text-sm text-neon-red">{errors.type}</p>
                  )}
                </div>

                {/* Actions */}
                <div className="flex gap-3 pt-4">
                  <button
                    type="button"
                    onClick={handleClose}
                    className="flex-1 px-4 py-3 bg-cyber-gray bg-opacity-20 border border-cyber-gray text-cyber-muted rounded-lg hover:bg-opacity-30 hover:text-cyber-white transition-all"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={createScanMutation.isLoading}
                    className="flex-1 px-4 py-3 bg-neon-green bg-opacity-20 border border-neon-green text-neon-green rounded-lg hover:bg-opacity-30 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {createScanMutation.isLoading ? 'Starting...' : 'Start Scan'}
                  </button>
                </div>
              </form>
            </motion.div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

export default CreateScanModal; 