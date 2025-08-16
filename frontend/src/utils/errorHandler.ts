/**
 * Utility functions for safe error handling in API responses
 */

export interface ApiError {
  response?: {
    status?: number;
    data?: {
      detail?: any;
      message?: string;
    };
  };
  message?: string;
}

/**
 * Safely extracts a user-friendly error message from API errors
 * Ensures the result is always a string, never an object
 */
export const getErrorMessage = (error: ApiError, fallbackMessage: string = 'An error occurred'): string => {
  // Check for validation errors (422 status)
  if (error.response?.status === 422 && error.response?.data?.detail) {
    const details = error.response.data.detail;
    
    if (Array.isArray(details)) {
      // Handle Pydantic validation errors
      const messages = details
        .map((err: any) => {
          if (typeof err === 'string') return err;
          if (err?.msg) return err.msg;
          if (err?.message) return err.message;
          return 'Validation error';
        })
        .filter(Boolean)
        .join(', ');
      
      return `Validation failed: ${messages}`;
    } else if (typeof details === 'string') {
      return `Validation failed: ${details}`;
    } else {
      // Fallback for non-string details
      return `Validation failed: ${JSON.stringify(details)}`;
    }
  }

  // Check for standard error responses
  if (error.response?.data?.detail) {
    const detail = error.response.data.detail;
    if (typeof detail === 'string') {
      return detail;
    } else {
      // Convert object to string safely
      return JSON.stringify(detail);
    }
  }

  // Check for error message
  if (error.response?.data?.message) {
    return error.response.data.message;
  }

  // Check for generic error message
  if (error.message) {
    return error.message;
  }

  // Final fallback
  return fallbackMessage;
};

/**
 * Extracts HTTP status code from API error
 */
export const getErrorStatus = (error: ApiError): number | undefined => {
  return error.response?.status;
};

/**
 * Checks if error is a validation error (422)
 */
export const isValidationError = (error: ApiError): boolean => {
  return error.response?.status === 422;
};

/**
 * Checks if error is a not found error (404)
 */
export const isNotFoundError = (error: ApiError): boolean => {
  return error.response?.status === 404;
};

/**
 * Checks if error is an authentication error (401)
 */
export const isAuthError = (error: ApiError): boolean => {
  return error.response?.status === 401;
};

/**
 * Checks if error is a forbidden error (403)
 */
export const isForbiddenError = (error: ApiError): boolean => {
  return error.response?.status === 403;
};

/**
 * Checks if error is a server error (5xx)
 */
export const isServerError = (error: ApiError): boolean => {
  const status = error.response?.status;
  return status ? status >= 500 && status < 600 : false;
};

/**
 * Gets a user-friendly message based on error type
 */
export const getUserFriendlyMessage = (error: ApiError, operation: string): string => {
  const status = getErrorStatus(error);
  
  switch (status) {
    case 400:
      return `Invalid request: ${getErrorMessage(error, 'Please check your input')}`;
    case 401:
      return 'You need to log in to perform this action';
    case 403:
      return 'You do not have permission to perform this action';
    case 404:
      return 'The requested resource was not found';
    case 422:
      return getErrorMessage(error, 'Please check your input');
    case 429:
      return 'Too many requests. Please try again later';
    case 500:
      return 'Server error. Please try again later';
    case 502:
    case 503:
    case 504:
      return 'Service temporarily unavailable. Please try again later';
    default:
      return getErrorMessage(error, `Failed to ${operation}`);
  }
}; 