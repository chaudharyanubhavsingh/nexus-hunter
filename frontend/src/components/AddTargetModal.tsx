import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Target, Globe, Shield } from 'lucide-react';
import { useCreateTarget } from '../hooks/useApi';
import toast from 'react-hot-toast';

interface AddTargetModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const AddTargetModal: React.FC<AddTargetModalProps> = ({ isOpen, onClose }) => {
  const [formData, setFormData] = useState({
    name: '',
    domain: '',
    scope: 'full',
  });
  const [errors, setErrors] = useState<Record<string, string>>({});

  const createTargetMutation = useCreateTarget();

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Target name is required';
    }

    if (!formData.domain.trim()) {
      newErrors.domain = 'Domain is required';
    } else {
      // Basic domain validation
      const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
      if (!domainRegex.test(formData.domain)) {
        newErrors.domain = 'Please enter a valid domain name';
      }
    }

    if (!formData.scope) {
      newErrors.scope = 'Scope is required';
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
      await createTargetMutation.mutateAsync(formData);
      onClose();
      resetForm();
    } catch (error) {
      // Error handling is done in the mutation
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      domain: '',
      scope: 'full',
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
              className="bg-cyber-dark border border-cyber-gray rounded-lg w-full max-w-md"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header */}
              <div className="flex items-center justify-between p-6 border-b border-cyber-gray border-opacity-30">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-neon-cyan bg-opacity-20 rounded-lg">
                    <Target className="text-neon-cyan" size={20} />
                  </div>
                  <h2 className="text-lg font-bold text-neon-cyan">ADD NEW TARGET</h2>
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
                {/* Target Name */}
                <div>
                  <label htmlFor="name" className="block text-sm font-medium text-cyber-white mb-2">
                    Target Name
                  </label>
                  <input
                    type="text"
                    id="name"
                    name="name"
                    value={formData.name}
                    onChange={handleInputChange}
                    className={`w-full px-4 py-3 bg-cyber-gray bg-opacity-20 border rounded-lg text-cyber-white placeholder-cyber-muted focus:outline-none focus:border-neon-cyan transition-colors ${
                      errors.name ? 'border-neon-red' : 'border-cyber-gray border-opacity-30'
                    }`}
                    placeholder="e.g., Production API"
                  />
                  {errors.name && (
                    <p className="mt-1 text-sm text-neon-red">{errors.name}</p>
                  )}
                </div>

                {/* Domain */}
                <div>
                  <label htmlFor="domain" className="block text-sm font-medium text-cyber-white mb-2">
                    Domain
                  </label>
                  <div className="relative">
                    <Globe className="absolute left-3 top-1/2 transform -translate-y-1/2 text-cyber-muted" size={18} />
                    <input
                      type="text"
                      id="domain"
                      name="domain"
                      value={formData.domain}
                      onChange={handleInputChange}
                      className={`w-full pl-10 pr-4 py-3 bg-cyber-gray bg-opacity-20 border rounded-lg text-cyber-white placeholder-cyber-muted focus:outline-none focus:border-neon-cyan transition-colors ${
                        errors.domain ? 'border-neon-red' : 'border-cyber-gray border-opacity-30'
                      }`}
                      placeholder="e.g., api.example.com"
                    />
                  </div>
                  {errors.domain && (
                    <p className="mt-1 text-sm text-neon-red">{errors.domain}</p>
                  )}
                </div>

                {/* Scope */}
                <div>
                  <label htmlFor="scope" className="block text-sm font-medium text-cyber-white mb-2">
                    Scan Scope
                  </label>
                  <div className="relative">
                    <Shield className="absolute left-3 top-1/2 transform -translate-y-1/2 text-cyber-muted" size={18} />
                    <select
                      id="scope"
                      name="scope"
                      value={formData.scope}
                      onChange={handleInputChange}
                      className={`w-full pl-10 pr-4 py-3 bg-cyber-gray bg-opacity-20 border rounded-lg text-cyber-white focus:outline-none focus:border-neon-cyan transition-colors appearance-none ${
                        errors.scope ? 'border-neon-red' : 'border-cyber-gray border-opacity-30'
                      }`}
                    >
                      <option value="full">Full Domain & Subdomains</option>
                      <option value="subdomain">Subdomains Only</option>
                      <option value="domain">Domain Only</option>
                      <option value="custom">Custom Scope</option>
                    </select>
                  </div>
                  {errors.scope && (
                    <p className="mt-1 text-sm text-neon-red">{errors.scope}</p>
                  )}
                </div>

                {/* Guidelines */}
                <div className="bg-cyber-gray bg-opacity-10 border border-cyber-gray border-opacity-20 rounded-lg p-4">
                  <h4 className="text-sm font-medium text-neon-orange mb-2">Security Guidelines</h4>
                  <ul className="text-xs text-cyber-muted space-y-1">
                    <li>• Only scan targets you own or have explicit permission to test</li>
                    <li>• Ensure compliance with applicable laws and regulations</li>
                    <li>• Follow responsible disclosure practices for any findings</li>
                  </ul>
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
                    disabled={createTargetMutation.isLoading}
                    className="flex-1 px-4 py-3 bg-neon-cyan bg-opacity-20 border border-neon-cyan text-neon-cyan rounded-lg hover:bg-opacity-30 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {createTargetMutation.isLoading ? 'Adding...' : 'Add Target'}
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

export default AddTargetModal; 