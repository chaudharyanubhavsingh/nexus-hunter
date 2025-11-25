import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Target, X } from 'lucide-react';
import { useCreateTarget } from '../hooks/useApi';
import UniversalForm, { FormField } from './UniversalForm';
import { ValidationSchema, validationPatterns } from '../utils/validation';
import { useAppContext } from '../context/AppContext';
import toast from 'react-hot-toast';

interface AddTargetModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const AddTargetModal: React.FC<AddTargetModalProps> = ({ isOpen, onClose }) => {
  const createTargetMutation = useCreateTarget();
  const { state } = useAppContext();

  // Define form fields with comprehensive input handling
  const formFields: FormField[] = [
    {
      name: 'name',
      label: 'Target Name',
      type: 'text',
      placeholder: 'e.g., Production API',
      description: 'A descriptive name for this target',
      required: true,
    },
    {
      name: 'domain',
      label: 'Domain',
      type: 'domain',
      placeholder: 'e.g., api.example.com',
      description: 'Primary domain to scan (automatically sanitized)',
      required: true,
    },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea',
      placeholder: 'Brief description of this target...',
      description: 'Optional description for team reference',
      rows: 3,
    },
    {
      name: 'scope_type',
      label: 'Scan Scope',
      type: 'select',
      placeholder: 'Select scan scope...',
      description: 'Choose what to include in the scan',
      required: true,
      options: [
        { value: 'full', label: 'Full Domain & Subdomains' },
        { value: 'subdomain', label: 'Subdomains Only' },
        { value: 'domain', label: 'Domain Only' },
        { value: 'custom', label: 'Custom Scope' },
      ],
    },
    {
      name: 'custom_scope',
      label: 'Custom Scope Rules',
      type: 'tags',
      placeholder: 'Add scope rules (press Enter or comma to add)',
      description: 'Specific URLs, domains, or patterns to include',
      maxTags: 10,
    },
    {
      name: 'out_of_scope',
      label: 'Out of Scope',
      type: 'tags',
      placeholder: 'Add exclusions (press Enter or comma to add)',
      description: 'URLs, domains, or patterns to exclude from scanning',
      maxTags: 10,
    },
    {
      name: 'priority',
      label: 'Priority Level',
      type: 'select',
      placeholder: 'Select priority...',
      description: 'Scanning priority for this target',
      options: [
        { value: 'low', label: '🟢 Low Priority' },
        { value: 'medium', label: '🟡 Medium Priority' },
        { value: 'high', label: '🟠 High Priority' },
        { value: 'critical', label: '🔴 Critical Priority' },
      ],
    },
    {
      name: 'max_depth',
      label: 'Max Scan Depth',
      type: 'range',
      description: 'Maximum depth for recursive scanning',
      min: 1,
      max: 10,
      step: 1,
    },
    {
      name: 'contact_email',
      label: 'Security Contact',
      type: 'email',
      placeholder: 'security@example.com',
      description: 'Contact email for responsible disclosure',
    },
    {
      name: 'rate_limit',
      label: 'Rate Limit (requests/sec)',
      type: 'number',
      placeholder: '5',
      description: 'Maximum requests per second to avoid overloading',
      min: 1,
      max: 100,
    },
    {
      name: 'authentication_required',
      label: 'Requires Authentication',
      type: 'checkbox',
      description: 'Check if this target requires authentication',
    },
    {
      name: 'api_config',
      label: 'API Configuration',
      type: 'json',
      placeholder: '{\n  "auth_type": "bearer",\n  "headers": {}\n}',
      description: 'JSON configuration for API authentication',
      rows: 4,
    },
    {
      name: 'notes',
      label: 'Additional Notes',
      type: 'textarea',
      placeholder: 'Any special instructions or notes...',
      description: 'Internal notes for the security team',
      rows: 2,
    },
  ];

  // Comprehensive validation schema
  const validationSchema: ValidationSchema = {
    name: {
      required: true,
      minLength: 2,
      maxLength: 100,
    },
    domain: {
      required: true,
      pattern: validationPatterns.domain,
    },
    description: {
      maxLength: 500,
    },
    scope_type: {
      required: true,
    },
    contact_email: {
      pattern: validationPatterns.email,
    },
    rate_limit: {
      min: 1,
      max: 100,
    },
    max_depth: {
      min: 1,
      max: 10,
    },
    api_config: {
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
  };

  const normalizeDomain = (raw: string): string => {
    if (!raw) return raw;
    let d = raw.trim().toLowerCase();
    d = d.replace('http://', '').replace('https://', '');
    if (d.endsWith('/')) d = d.slice(0, -1);
    return d;
  };

  const handleSubmit = async (formData: Record<string, any>) => {
    try {
      // Normalize domain
      const normalizedDomain = normalizeDomain(formData.domain);

      // Prevent duplicates (match backend behavior)
      const exists = state.targets.some(t => t.domain.toLowerCase() === normalizedDomain);
      if (exists) {
        toast.error('Target domain already exists');
        return;
      }

      // Convert scope selection to backend format
      let scopeArray: string[] = [];
      
      if (formData.scope_type === 'custom' && formData.custom_scope?.length > 0) {
        scopeArray = formData.custom_scope;
      } else if (formData.scope_type === 'full') {
        scopeArray = [`*.${normalizedDomain}`, normalizedDomain];
      } else if (formData.scope_type === 'subdomain') {
        scopeArray = [`*.${normalizedDomain}`];
      } else if (formData.scope_type === 'domain') {
        scopeArray = [normalizedDomain];
      }

      // Parse API config JSON if provided
      let apiConfig = null;
      if (formData.api_config) {
        try {
          apiConfig = JSON.parse(formData.api_config);
        } catch (e) {
          // JSON parsing already validated in validation schema
        }
      }

      // Prepare COMPREHENSIVE data for backend - all fields now properly sent
      const targetData = {
        // Basic fields
        name: formData.name,
        domain: normalizedDomain,
        description: formData.description || undefined,
        scope: scopeArray.length > 0 ? scopeArray : undefined,
        out_of_scope: formData.out_of_scope?.length > 0 ? formData.out_of_scope : undefined,
        
        // Advanced fields - now properly sent to backend instead of localStorage
        priority: formData.priority || "medium",
        max_depth: formData.max_depth ?? 5,
        contact_email: formData.contact_email || undefined,
        rate_limit: formData.rate_limit ?? 5,
        authentication_required: !!formData.authentication_required,
        api_config: apiConfig,
        notes: formData.notes || undefined,
      };

      await createTargetMutation.mutateAsync(targetData);

      // Still save some basic settings locally for UI convenience (optional)
      try {
        const uiPreferences = {
          priority: formData.priority || "medium",
          scope_type: formData.scope_type || "full",
        };
        localStorage.setItem(`target_ui_prefs:${normalizedDomain}`, JSON.stringify(uiPreferences));
      } catch {}

      onClose();
    } catch (error) {
      // Error handling is done in the mutation
    }
  };

  const handleClose = () => {
    onClose();
  };

  const [activeTab, setActiveTab] = useState<'basic' | 'advanced' | 'auth'>('basic');

  const getFieldsForTab = (tab: string): FormField[] => {
    switch (tab) {
      case 'basic':
        return formFields.filter(f => 
          ['name', 'domain', 'description', 'scope_type', 'custom_scope', 'out_of_scope'].includes(f.name)
        );
      case 'advanced':
        return formFields.filter(f => 
          ['priority', 'max_depth', 'contact_email', 'rate_limit', 'notes'].includes(f.name)
        );
      case 'auth':
        return formFields.filter(f => 
          ['authentication_required', 'api_config'].includes(f.name)
        );
      default:
        return formFields;
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
              className="bg-cyber-dark border border-cyber-gray rounded-lg w-full max-w-4xl max-h-[90vh] overflow-hidden"
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

              {/* Tabs */}
              <div className="px-6 pt-4">
                <div className="flex space-x-1 bg-cyber-gray bg-opacity-20 rounded-lg p-1">
                  {[
                    { id: 'basic', label: 'Basic Info' },
                    { id: 'advanced', label: 'Advanced' },
                    { id: 'auth', label: 'Authentication' },
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id as any)}
                      className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
                        activeTab === tab.id
                          ? 'bg-neon-cyan text-cyber-black'
                          : 'text-cyber-muted hover:text-cyber-white'
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Form Content */}
              <div className="p-6 overflow-y-auto max-h-[calc(90vh-200px)]">
                <UniversalForm
                  fields={getFieldsForTab(activeTab)}
                  validationSchema={validationSchema}
                  onSubmit={handleSubmit}
                  submitLabel={createTargetMutation.isLoading ? 'Creating...' : 'Create Target'}
                  isLoading={createTargetMutation.isLoading}
                  showProgress={true}
                  layout="vertical"
                  className="space-y-6"
                />
              </div>
            </motion.div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

export default AddTargetModal; 