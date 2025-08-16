/**
 * Universal Form Components
 * Comprehensive input handling inspired by Excalidraw's versatile interface
 */

import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Eye, EyeOff, AlertCircle, CheckCircle, Info, Upload, X,
  Calendar, Clock, Hash, Globe, Mail, Lock, User, Search, Filter,
  Code, Image, File, Link, Phone, DollarSign
} from 'lucide-react';
import {
  ValidationSchema,
  validateForm,
  inputFormatters,
  sanitizeInput
} from '../utils/validation';

export type InputType = 
  | 'text' | 'email' | 'password' | 'number' | 'tel' | 'url' | 'search'
  | 'textarea' | 'select' | 'multiselect' | 'checkbox' | 'radio' | 'switch'
  | 'file' | 'image' | 'date' | 'datetime-local' | 'time' | 'range'
  | 'color' | 'json' | 'code' | 'tags' | 'ip' | 'port' | 'domain'
  | 'currency' | 'percentage' | 'rating' | 'autocomplete' | 'phone';

export interface FormField {
  name: string;
  label: string;
  type: InputType;
  placeholder?: string;
  description?: string;
  required?: boolean;
  disabled?: boolean;
  options?: Array<{ value: string; label: string; disabled?: boolean }>;
  multiple?: boolean;
  accept?: string; // For file inputs
  min?: number | string;
  max?: number | string;
  step?: number;
  rows?: number; // For textarea
  formatter?: (value: string) => string;
  icon?: React.ComponentType<{ size?: number; className?: string }>;
  prefix?: string;
  suffix?: string;
  autocomplete?: string[];
  maxTags?: number;
  allowCustom?: boolean; // For tags/autocomplete
  validation?: any; // Custom validation rules
}

export interface UniversalFormProps {
  fields: FormField[];
  initialData?: Record<string, any>;
  validationSchema?: ValidationSchema;
  onSubmit: (data: Record<string, any>) => Promise<void> | void;
  onReset?: () => void;
  onChange?: (data: Record<string, any>) => void;
  submitLabel?: string;
  resetLabel?: string;
  isLoading?: boolean;
  disabled?: boolean;
  className?: string;
  layout?: 'vertical' | 'horizontal' | 'grid';
  columns?: number;
  showProgress?: boolean;
  autoSave?: boolean;
  autoSaveDelay?: number;
}

const getFieldIcon = (type: InputType, fieldIcon?: React.ComponentType<any>) => {
  if (fieldIcon) return fieldIcon;
  
  const iconMap: Record<InputType, React.ComponentType<any>> = {
    text: User,
    email: Mail,
    password: Lock,
    number: Hash,
    tel: Phone,
    url: Link,
    search: Search,
    textarea: User,
    select: Filter,
    multiselect: Filter,
    checkbox: CheckCircle,
    radio: CheckCircle,
    switch: CheckCircle,
    file: File,
    image: Image,
    date: Calendar,
    'datetime-local': Calendar,
    time: Clock,
    range: Filter,
    color: Filter,
    json: Code,
    code: Code,
    tags: Filter,
    ip: Globe,
    port: Hash,
    domain: Globe,
    currency: DollarSign,
    percentage: Hash,
    rating: CheckCircle,
    autocomplete: Search,
    phone: Phone
  };
  
  return iconMap[type] || User;
};

const UniversalInput: React.FC<{
  field: FormField;
  value: any;
  error?: string;
  onChange: (value: any) => void;
  onBlur?: () => void;
}> = ({ field, value, error, onChange, onBlur }) => {
  const [showPassword, setShowPassword] = useState(false);
  const [tags, setTags] = useState<string[]>(Array.isArray(value) ? value : []);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const Icon = getFieldIcon(field.type, field.icon);

  const baseClasses = `
    w-full px-4 py-3 bg-cyber-gray bg-opacity-20 border rounded-lg 
    text-cyber-white placeholder-cyber-muted focus:outline-none 
    focus:border-neon-cyan transition-colors disabled:opacity-50
    ${error ? 'border-neon-red' : 'border-cyber-gray border-opacity-30'}
  `;

  const handleChange = (newValue: any) => {
    let processedValue = newValue;

    // Apply formatters
    if (field.formatter && typeof newValue === 'string') {
      processedValue = field.formatter(newValue);
    } else if (field.type === 'phone') {
      processedValue = inputFormatters.phone(newValue);
    } else if (field.type === 'currency') {
      processedValue = inputFormatters.currency(newValue);
    } else if (field.type === 'domain') {
      processedValue = sanitizeInput.domain(newValue);
    } else if (field.type === 'email') {
      processedValue = sanitizeInput.email(newValue);
    }

    onChange(processedValue);
  };

  const renderInput = () => {
    switch (field.type) {
      case 'textarea':
        return (
          <textarea
            name={field.name}
            value={value || ''}
            onChange={(e) => handleChange(e.target.value)}
            onBlur={onBlur}
            placeholder={field.placeholder}
            disabled={field.disabled}
            rows={field.rows || 4}
            className={`${baseClasses} resize-none`}
          />
        );

      case 'select':
        return (
          <select
            name={field.name}
            value={value || ''}
            onChange={(e) => handleChange(e.target.value)}
            onBlur={onBlur}
            disabled={field.disabled}
            className={baseClasses}
          >
            <option value="">{field.placeholder || 'Select...'}</option>
            {field.options?.map(option => (
              <option 
                key={option.value} 
                value={option.value}
                disabled={option.disabled}
              >
                {option.label}
              </option>
            ))}
          </select>
        );

      case 'checkbox':
        return (
          <label className="flex items-center space-x-3 cursor-pointer">
            <input
              type="checkbox"
              name={field.name}
              checked={!!value}
              onChange={(e) => handleChange(e.target.checked)}
              onBlur={onBlur}
              disabled={field.disabled}
              className="w-5 h-5 text-neon-cyan bg-cyber-gray border-cyber-gray rounded focus:ring-neon-cyan focus:ring-2"
            />
            <span className="text-cyber-white">{field.label}</span>
          </label>
        );

      case 'radio':
        return (
          <div className="space-y-2">
            {field.options?.map(option => (
              <label key={option.value} className="flex items-center space-x-3 cursor-pointer">
                <input
                  type="radio"
                  name={field.name}
                  value={option.value}
                  checked={value === option.value}
                  onChange={(e) => handleChange(e.target.value)}
                  onBlur={onBlur}
                  disabled={field.disabled || option.disabled}
                  className="w-5 h-5 text-neon-cyan bg-cyber-gray border-cyber-gray focus:ring-neon-cyan focus:ring-2"
                />
                <span className="text-cyber-white">{option.label}</span>
              </label>
            ))}
          </div>
        );

      case 'file':
      case 'image':
        return (
          <div className="space-y-2">
            <input
              ref={fileInputRef}
              type="file"
              name={field.name}
              onChange={(e) => handleChange(e.target.files)}
              onBlur={onBlur}
              disabled={field.disabled}
              accept={field.accept}
              multiple={field.multiple}
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className={`${baseClasses} flex items-center justify-center space-x-2 hover:bg-cyber-gray hover:bg-opacity-30`}
              disabled={field.disabled}
            >
              <Upload size={20} />
              <span>{field.placeholder || 'Choose file...'}</span>
            </button>
            {value && (
              <div className="text-sm text-cyber-muted">
                {Array.from(value).map((file: any, index: number) => (
                  <div key={index} className="flex items-center justify-between bg-cyber-gray bg-opacity-20 rounded px-3 py-2 mt-1">
                    <span>{file.name}</span>
                    <button
                      type="button"
                      onClick={() => {
                        const newFiles = Array.from(value).filter((_, i) => i !== index);
                        handleChange(newFiles.length ? newFiles : null);
                      }}
                      className="text-neon-red hover:text-cyber-white"
                    >
                      <X size={16} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        );

      case 'tags':
        return (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-2 mb-2">
              {tags.map((tag, index) => (
                <span
                  key={index}
                  className="inline-flex items-center px-3 py-1 rounded-full text-sm bg-neon-cyan bg-opacity-20 text-neon-cyan"
                >
                  {tag}
                  <button
                    type="button"
                    onClick={() => {
                      const newTags = tags.filter((_, i) => i !== index);
                      setTags(newTags);
                      onChange(newTags);
                    }}
                    className="ml-2 text-neon-cyan hover:text-cyber-white"
                  >
                    <X size={14} />
                  </button>
                </span>
              ))}
            </div>
            <input
              type="text"
              placeholder={field.placeholder || 'Add tags...'}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ',') {
                  e.preventDefault();
                  const newTag = e.currentTarget.value.trim();
                  if (newTag && !tags.includes(newTag) && (!field.maxTags || tags.length < field.maxTags)) {
                    const newTags = [...tags, newTag];
                    setTags(newTags);
                    onChange(newTags);
                    e.currentTarget.value = '';
                  }
                }
              }}
              className={baseClasses}
              disabled={field.disabled}
            />
          </div>
        );

      case 'json':
      case 'code':
        return (
          <div className="relative">
            <textarea
              name={field.name}
              value={value || ''}
              onChange={(e) => handleChange(e.target.value)}
              onBlur={onBlur}
              placeholder={field.placeholder}
              disabled={field.disabled}
              rows={field.rows || 6}
              className={`${baseClasses} font-mono text-sm resize-none`}
            />
            <div className="absolute top-2 right-2">
              <Code size={16} className="text-cyber-muted" />
            </div>
          </div>
        );

      case 'range':
        return (
          <div className="space-y-2">
            <input
              type="range"
              name={field.name}
              value={value || field.min || 0}
              onChange={(e) => handleChange(parseFloat(e.target.value))}
              onBlur={onBlur}
              min={field.min}
              max={field.max}
              step={field.step}
              disabled={field.disabled}
              className="w-full h-2 bg-cyber-gray rounded-lg appearance-none cursor-pointer slider"
            />
            <div className="flex justify-between text-sm text-cyber-muted">
              <span>{field.min}</span>
              <span className="text-neon-cyan">{value || field.min || 0}</span>
              <span>{field.max}</span>
            </div>
          </div>
        );

      case 'password':
        return (
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              name={field.name}
              value={value || ''}
              onChange={(e) => handleChange(e.target.value)}
              onBlur={onBlur}
              placeholder={field.placeholder}
              disabled={field.disabled}
              className={`${baseClasses} pr-12`}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-cyber-muted hover:text-cyber-white"
            >
              {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
            </button>
          </div>
        );

      default:
        // Standard input types
        return (
          <div className="relative">
            {field.prefix && (
              <span className="absolute left-3 top-1/2 transform -translate-y-1/2 text-cyber-muted">
                {field.prefix}
              </span>
            )}
            {Icon && !field.prefix && (
              <Icon size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-cyber-muted" />
            )}
            <input
              type={field.type === 'domain' ? 'text' : field.type}
              name={field.name}
              value={value || ''}
              onChange={(e) => handleChange(e.target.value)}
              onBlur={onBlur}
              placeholder={field.placeholder}
              disabled={field.disabled}
              min={field.min}
              max={field.max}
              step={field.step}
              className={`${baseClasses} ${(Icon && !field.prefix) || field.prefix ? 'pl-10' : ''} ${field.suffix ? 'pr-10' : ''}`}
            />
            {field.suffix && (
              <span className="absolute right-3 top-1/2 transform -translate-y-1/2 text-cyber-muted">
                {field.suffix}
              </span>
            )}
          </div>
        );
    }
  };

  return (
    <div className="space-y-2">
      {field.type !== 'checkbox' && (
        <label className="block text-sm font-medium text-cyber-white">
          {field.label}
          {field.required && <span className="text-neon-red ml-1">*</span>}
        </label>
      )}
      
      {renderInput()}
      
      {field.description && (
        <p className="text-xs text-cyber-muted flex items-center">
          <Info size={12} className="mr-1" />
          {field.description}
        </p>
      )}
      
      <AnimatePresence>
        {error && (
          <motion.p
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="text-sm text-neon-red flex items-center"
          >
            <AlertCircle size={14} className="mr-1" />
            {error}
          </motion.p>
        )}
      </AnimatePresence>
    </div>
  );
};

export const UniversalForm: React.FC<UniversalFormProps> = ({
  fields,
  initialData = {},
  validationSchema,
  onSubmit,
  onReset,
  onChange,
  submitLabel = 'Submit',
  resetLabel = 'Reset',
  isLoading = false,
  disabled = false,
  className = '',
  layout = 'vertical',
  columns = 1,
  showProgress = false,
  autoSave = false,
  autoSaveDelay = 1000
}) => {
  const [formData, setFormData] = useState<Record<string, any>>(initialData);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [touchedFields, setTouchedFields] = useState<Set<string>>(new Set());
  const autoSaveTimeoutRef = useRef<number>();

  const progress = fields.length > 0 ? 
    (fields.filter(field => {
      const value = formData[field.name];
      // Count as filled if: has a value, is false (for checkboxes), or is 0 (for numbers)
      return value !== '' && value !== null && value !== undefined;
    }).length / fields.length) * 100 : 0;

  useEffect(() => {
    if (onChange) {
      onChange(formData);
    }

    if (autoSave && Object.keys(formData).length > 0) {
      if (autoSaveTimeoutRef.current) {
        clearTimeout(autoSaveTimeoutRef.current);
      }
      autoSaveTimeoutRef.current = setTimeout(() => {
        onSubmit(formData);
      }, autoSaveDelay);
    }

    return () => {
      if (autoSaveTimeoutRef.current) {
        clearTimeout(autoSaveTimeoutRef.current);
      }
    };
  }, [formData, onChange, autoSave, autoSaveDelay, onSubmit]);

  const handleFieldChange = (fieldName: string, value: any) => {
    setFormData(prev => ({ ...prev, [fieldName]: value }));
    
    // Clear error when user starts typing
    if (errors[fieldName]) {
      setErrors(prev => ({ ...prev, [fieldName]: '' }));
    }
  };

  const handleFieldBlur = (fieldName: string) => {
    setTouchedFields(prev => new Set(prev).add(fieldName));
    
    // Validate field on blur if validation schema provided
    if (validationSchema && validationSchema[fieldName]) {
      const result = validateForm({ [fieldName]: formData[fieldName] }, { [fieldName]: validationSchema[fieldName] });
      if (result.errors[fieldName]) {
        setErrors(prev => ({ ...prev, [fieldName]: result.errors[fieldName] }));
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (disabled || isLoading) return;

    // Validate all fields
    if (validationSchema) {
      const result = validateForm(formData, validationSchema);
      if (!result.isValid) {
        setErrors(result.errors);
        // Mark all fields as touched to show errors
        setTouchedFields(new Set(fields.map(f => f.name)));
        return;
      }
      setErrors({});
    }

    try {
      await onSubmit(formData);
    } catch (error) {
      console.error('Form submission error:', error);
    }
  };

  const handleReset = () => {
    setFormData(initialData);
    setErrors({});
    setTouchedFields(new Set());
    if (onReset) onReset();
  };

  const getLayoutClasses = () => {
    switch (layout) {
      case 'horizontal':
        return 'flex flex-wrap gap-4';
      case 'grid':
        return `grid grid-cols-1 md:grid-cols-${columns} gap-4`;
      default:
        return 'space-y-6';
    }
  };

  return (
    <div className={`w-full ${className}`}>
      {showProgress && (
        <div className="mb-6">
          <div className="flex justify-between text-sm text-cyber-muted mb-2">
            <span>Progress</span>
            <span>{Math.round(progress)}%</span>
          </div>
          <div className="w-full bg-cyber-gray bg-opacity-20 rounded-full h-2">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${progress}%` }}
              transition={{ duration: 0.3 }}
              className="bg-gradient-to-r from-neon-cyan to-neon-green h-2 rounded-full"
            />
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className={getLayoutClasses()}>
          {fields.map(field => (
            <UniversalInput
              key={field.name}
              field={field}
              value={formData[field.name]}
              error={touchedFields.has(field.name) ? errors[field.name] : undefined}
              onChange={(value) => handleFieldChange(field.name, value)}
              onBlur={() => handleFieldBlur(field.name)}
            />
          ))}
        </div>

        <div className="flex gap-4 pt-4">
          <button
            type="submit"
            disabled={disabled || isLoading}
            className={`
              flex-1 flex items-center justify-center px-6 py-3 rounded-lg font-medium transition-all
              ${disabled || isLoading 
                ? 'bg-cyber-gray bg-opacity-50 text-cyber-muted cursor-not-allowed'
                : 'bg-gradient-to-r from-neon-cyan to-neon-green text-cyber-black hover:shadow-neon'
              }
            `}
          >
            {isLoading ? (
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                className="w-5 h-5 border-2 border-current border-t-transparent rounded-full mr-2"
              />
            ) : (
              <CheckCircle size={20} className="mr-2" />
            )}
            {isLoading ? 'Processing...' : submitLabel}
          </button>

          {onReset && (
            <button
              type="button"
              onClick={handleReset}
              disabled={disabled || isLoading}
              className="px-6 py-3 rounded-lg font-medium border border-cyber-gray border-opacity-30 text-cyber-white hover:bg-cyber-gray hover:bg-opacity-20 transition-all disabled:opacity-50"
            >
              {resetLabel}
            </button>
          )}
        </div>
      </form>
    </div>
  );
};

export default UniversalForm; 