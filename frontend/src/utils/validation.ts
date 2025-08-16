/**
 * Universal Input Validation Utilities
 * Inspired by Excalidraw's robust input handling
 */

export interface ValidationRule {
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  pattern?: RegExp;
  custom?: (value: any) => string | null;
}

export interface ValidationSchema {
  [key: string]: ValidationRule;
}

export interface ValidationResult {
  isValid: boolean;
  errors: Record<string, string>;
  sanitizedData: Record<string, any>;
}

/**
 * Sanitize different types of input
 */
export const sanitizeInput = {
  text: (value: string): string => {
    return value.trim().replace(/[<>\"'&]/g, (match) => {
      const entityMap: Record<string, string> = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
        '&': '&amp;'
      };
      return entityMap[match];
    });
  },

  domain: (value: string): string => {
    return value.toLowerCase()
      .trim()
      .replace(/^https?:\/\//, '') // Remove protocol
      .replace(/\/.*$/, '') // Remove path
      .replace(/[^a-z0-9.-]/g, ''); // Only allow valid domain chars
  },

  url: (value: string): string => {
    try {
      const url = new URL(value.trim());
      return url.toString();
    } catch {
      return value.trim();
    }
  },

  email: (value: string): string => {
    return value.toLowerCase().trim();
  },

  number: (value: string | number): number => {
    const num = typeof value === 'string' ? parseFloat(value) : value;
    return isNaN(num) ? 0 : num;
  },

  port: (value: string | number): number => {
    const port = typeof value === 'string' ? parseInt(value, 10) : value;
    return isNaN(port) ? 0 : Math.max(1, Math.min(65535, port));
  },

  ipAddress: (value: string): string => {
    return value.trim().replace(/[^0-9.:]/g, '');
  },

  json: (value: string): any => {
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  },

  array: (value: string | string[]): string[] => {
    if (Array.isArray(value)) return value;
    return value.split(',').map(item => item.trim()).filter(Boolean);
  },

  slug: (value: string): string => {
    return value
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-');
  }
};

/**
 * Validation patterns
 */
export const validationPatterns = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  domain: /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
  url: /^https?:\/\/([\w\-]+(\.[\w\-]+)*)(:[0-9]+)?(\/.*)?$/,
  ipv4: /^(\d{1,3}\.){3}\d{1,3}$/,
  ipv6: /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/,
  port: /^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$/,
  alphanumeric: /^[a-zA-Z0-9]+$/,
  slug: /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
  hexColor: /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  base64: /^[A-Za-z0-9+/]*={0,2}$/,
  json: /^[\],:{}\s]*$/
};

/**
 * Common validation rules
 */
export const commonValidations = {
  required: (value: any): string | null => {
    if (value === null || value === undefined || value === '') {
      return 'This field is required';
    }
    return null;
  },

  minLength: (min: number) => (value: string): string | null => {
    if (value && value.length < min) {
      return `Must be at least ${min} characters`;
    }
    return null;
  },

  maxLength: (max: number) => (value: string): string | null => {
    if (value && value.length > max) {
      return `Must be no more than ${max} characters`;
    }
    return null;
  },

  min: (min: number) => (value: number): string | null => {
    if (value < min) {
      return `Must be at least ${min}`;
    }
    return null;
  },

  max: (max: number) => (value: number): string | null => {
    if (value > max) {
      return `Must be no more than ${max}`;
    }
    return null;
  },

  pattern: (pattern: RegExp, message: string) => (value: string): string | null => {
    if (value && !pattern.test(value)) {
      return message;
    }
    return null;
  },

  email: (value: string): string | null => {
    if (value && !validationPatterns.email.test(value)) {
      return 'Please enter a valid email address';
    }
    return null;
  },

  domain: (value: string): string | null => {
    if (value && !validationPatterns.domain.test(value)) {
      return 'Please enter a valid domain name';
    }
    return null;
  },

  url: (value: string): string | null => {
    if (value && !validationPatterns.url.test(value)) {
      return 'Please enter a valid URL';
    }
    return null;
  },

  port: (value: string | number): string | null => {
    const port = typeof value === 'string' ? parseInt(value, 10) : value;
    if (isNaN(port) || port < 1 || port > 65535) {
      return 'Port must be between 1 and 65535';
    }
    return null;
  },

  ipAddress: (value: string): string | null => {
    if (value && !validationPatterns.ipv4.test(value) && !validationPatterns.ipv6.test(value)) {
      return 'Please enter a valid IP address';
    }
    return null;
  },

  json: (value: string): string | null => {
    if (value) {
      try {
        JSON.parse(value);
      } catch {
        return 'Please enter valid JSON';
      }
    }
    return null;
  }
};

/**
 * Universal form validator
 */
export class FormValidator {
  private schema: ValidationSchema;
  private data: Record<string, any>;

  constructor(schema: ValidationSchema, data: Record<string, any>) {
    this.schema = schema;
    this.data = data;
  }

  validate(): ValidationResult {
    const errors: Record<string, string> = {};
    const sanitizedData: Record<string, any> = {};

    for (const [field, rules] of Object.entries(this.schema)) {
      const value = this.data[field];
      
      // Sanitize the input first
      sanitizedData[field] = this.sanitizeField(field, value);

      // Validate the field
      const error = this.validateField(field, sanitizedData[field], rules);
      if (error) {
        errors[field] = error;
      }
    }

    return {
      isValid: Object.keys(errors).length === 0,
      errors,
      sanitizedData
    };
  }

  private sanitizeField(field: string, value: any): any {
    if (value === null || value === undefined) return value;

    // Determine sanitization method based on field name patterns
    if (field.includes('email')) return sanitizeInput.email(value);
    if (field.includes('domain')) return sanitizeInput.domain(value);
    if (field.includes('url') || field.includes('link')) return sanitizeInput.url(value);
    if (field.includes('port')) return sanitizeInput.port(value);
    if (field.includes('ip')) return sanitizeInput.ipAddress(value);
    if (field.includes('json') || field.includes('config')) return value; // Don't auto-sanitize JSON
    if (field.includes('slug') || field.includes('identifier')) return sanitizeInput.slug(value);
    if (Array.isArray(value) || field.includes('scope') || field.includes('tags')) {
      return sanitizeInput.array(value);
    }
    
    // Default to text sanitization
    return typeof value === 'string' ? sanitizeInput.text(value) : value;
  }

  private validateField(field: string, value: any, rules: ValidationRule): string | null {
    // Required validation
    if (rules.required && commonValidations.required(value)) {
      return commonValidations.required(value);
    }

    // Skip other validations if field is empty and not required
    if (!value && !rules.required) return null;

    // String validations
    if (typeof value === 'string') {
      if (rules.minLength && commonValidations.minLength(rules.minLength)(value)) {
        return commonValidations.minLength(rules.minLength)(value);
      }
      if (rules.maxLength && commonValidations.maxLength(rules.maxLength)(value)) {
        return commonValidations.maxLength(rules.maxLength)(value);
      }
      if (rules.pattern && !rules.pattern.test(value)) {
        return `Invalid format for ${field}`;
      }
    }

    // Number validations
    if (typeof value === 'number') {
      if (rules.min !== undefined && commonValidations.min(rules.min)(value)) {
        return commonValidations.min(rules.min)(value);
      }
      if (rules.max !== undefined && commonValidations.max(rules.max)(value)) {
        return commonValidations.max(rules.max)(value);
      }
    }

    // Custom validation
    if (rules.custom) {
      return rules.custom(value);
    }

    return null;
  }
}

/**
 * Quick validation helpers for common use cases
 */
export const validateField = (value: any, rules: ValidationRule): string | null => {
  const validator = new FormValidator({ field: rules }, { field: value });
  const result = validator.validate();
  return result.errors.field || null;
};

export const validateForm = (data: Record<string, any>, schema: ValidationSchema): ValidationResult => {
  const validator = new FormValidator(schema, data);
  return validator.validate();
};

/**
 * Real-time input formatters
 */
export const inputFormatters = {
  phone: (value: string): string => {
    const numbers = value.replace(/\D/g, '');
    const match = numbers.match(/^(\d{3})(\d{3})(\d{4})$/);
    return match ? `(${match[1]}) ${match[2]}-${match[3]}` : value;
  },

  creditCard: (value: string): string => {
    const numbers = value.replace(/\D/g, '');
    return numbers.replace(/(\d{4})(?=\d)/g, '$1 ');
  },

  currency: (value: string): string => {
    const numbers = value.replace(/[^\d.]/g, '');
    return numbers ? `$${parseFloat(numbers).toFixed(2)}` : '';
  },

  uppercase: (value: string): string => value.toUpperCase(),
  lowercase: (value: string): string => value.toLowerCase(),
  capitalize: (value: string): string => {
    return value.replace(/\w\S*/g, (txt) => 
      txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase()
    );
  }
}; 