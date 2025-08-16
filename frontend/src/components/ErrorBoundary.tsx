import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface ErrorBoundaryState {
  hasError: boolean;
  error?: Error;
  errorInfo?: React.ErrorInfo;
}

interface ErrorBoundaryProps {
  children: React.ReactNode;
  fallback?: React.ComponentType<{ error?: Error; resetError: () => void }>;
}

class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Error Boundary caught an error:', error, errorInfo);
    this.setState({
      error,
      errorInfo,
    });
  }

  resetError = () => {
    this.setState({ hasError: false, error: undefined, errorInfo: undefined });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        const FallbackComponent = this.props.fallback;
        return <FallbackComponent error={this.state.error} resetError={this.resetError} />;
      }

      return (
        <div className="min-h-screen bg-cyber-black flex items-center justify-center p-4">
          <div className="bg-cyber-dark border border-neon-red rounded-lg p-8 max-w-md w-full text-center">
            <div className="p-3 bg-neon-red bg-opacity-20 rounded-full w-16 h-16 mx-auto mb-4 flex items-center justify-center">
              <AlertTriangle className="text-neon-red" size={32} />
            </div>
            
            <h2 className="text-xl font-bold text-neon-red mb-2">Something went wrong</h2>
            <p className="text-cyber-muted mb-6">
              An unexpected error occurred. This is likely a temporary issue.
            </p>
            
            {(import.meta as any).env?.DEV && this.state.error && (
              <div className="bg-cyber-gray bg-opacity-20 rounded p-4 mb-6 text-left">
                <p className="text-xs text-neon-orange font-mono break-all">
                  {this.state.error.toString()}
                </p>
              </div>
            )}
            
            <div className="space-y-3">
              <button
                onClick={this.resetError}
                className="w-full flex items-center justify-center gap-2 bg-neon-cyan bg-opacity-20 border border-neon-cyan text-neon-cyan px-4 py-3 rounded-lg hover:bg-opacity-30 transition-colors"
              >
                <RefreshCw size={16} />
                Try Again
              </button>
              
              <button
                onClick={() => window.location.reload()}
                className="w-full bg-cyber-gray bg-opacity-20 border border-cyber-gray text-cyber-white px-4 py-3 rounded-lg hover:bg-opacity-30 transition-colors"
              >
                Reload Page
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary; 