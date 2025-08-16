import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { Target, Scan, Vulnerability } from '../services/api';
import webSocketService from '../services/websocket';
import { useQueryClient } from 'react-query';

// State interface
interface AppState {
  targets: Target[];
  scans: Scan[];
  vulnerabilities: Vulnerability[];
  activeScans: Set<string>;
  isLoading: boolean;
  error: string | null;
  wsConnectionStatus: 'connecting' | 'connected' | 'disconnected' | 'error';
  stats: {
    totalTargets: number;
    activeScans: number;
    totalVulnerabilities: number;
    criticalVulnerabilities: number;
  };
}

// Action types
type AppAction =
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'SET_TARGETS'; payload: Target[] }
  | { type: 'ADD_TARGET'; payload: Target }
  | { type: 'UPDATE_TARGET'; payload: Target }
  | { type: 'REMOVE_TARGET'; payload: string }
  | { type: 'SET_SCANS'; payload: Scan[] }
  | { type: 'ADD_SCAN'; payload: Scan }
  | { type: 'UPDATE_SCAN'; payload: Scan }
  | { type: 'REMOVE_SCAN'; payload: string }
  | { type: 'SET_VULNERABILITIES'; payload: Vulnerability[] }
  | { type: 'ADD_VULNERABILITY'; payload: Vulnerability }
  | { type: 'SET_WS_STATUS'; payload: 'connecting' | 'connected' | 'disconnected' | 'error' }
  | { type: 'UPDATE_STATS' }
  | { type: 'UPDATE_SCAN_BY_ID'; payload: { scan_id: string; updates: Partial<Scan> } };

// Initial state
const initialState: AppState = {
  targets: [],
  scans: [],
  vulnerabilities: [],
  activeScans: new Set(),
  isLoading: false,
  error: null,
  wsConnectionStatus: 'disconnected',
  stats: {
    totalTargets: 0,
    activeScans: 0,
    totalVulnerabilities: 0,
    criticalVulnerabilities: 0,
  },
};

// Reducer
const appReducer = (state: AppState, action: AppAction): AppState => {
  switch (action.type) {
    case 'SET_LOADING':
      return { ...state, isLoading: action.payload };

    case 'SET_ERROR':
      return { ...state, error: action.payload };

    case 'SET_TARGETS':
      return { ...state, targets: action.payload };

    case 'ADD_TARGET':
      return { ...state, targets: [...state.targets, action.payload] };

    case 'UPDATE_TARGET':
      return {
        ...state,
        targets: state.targets.map(target =>
          target.id === action.payload.id ? action.payload : target
        ),
      };

    case 'REMOVE_TARGET':
      return {
        ...state,
        targets: state.targets.filter(target => target.id !== action.payload),
      };

    case 'SET_SCANS':
      const activeScans = new Set(
        action.payload
          .filter(scan => scan.status === 'running' || scan.status === 'pending')
          .map(scan => scan.id)
      );
      return { ...state, scans: action.payload, activeScans };

    case 'ADD_SCAN':
      const newActiveScans = new Set(state.activeScans);
      if (action.payload.status === 'running' || action.payload.status === 'pending') {
        newActiveScans.add(action.payload.id);
      }
      return {
        ...state,
        scans: [...state.scans, action.payload],
        activeScans: newActiveScans,
      };

    case 'UPDATE_SCAN':
      const updatedActiveScans = new Set(state.activeScans);
      if (action.payload.status === 'running' || action.payload.status === 'pending') {
        updatedActiveScans.add(action.payload.id);
      } else {
        updatedActiveScans.delete(action.payload.id);
      }
      return {
        ...state,
        scans: state.scans.map(scan =>
          scan.id === action.payload.id ? action.payload : scan
        ),
        activeScans: updatedActiveScans,
      };

    case 'REMOVE_SCAN':
      const filteredActiveScans = new Set(state.activeScans);
      filteredActiveScans.delete(action.payload);
      return {
        ...state,
        scans: state.scans.filter(scan => scan.id !== action.payload),
        activeScans: filteredActiveScans,
      };

    case 'SET_VULNERABILITIES':
      return { ...state, vulnerabilities: action.payload };

    case 'ADD_VULNERABILITY':
      return {
        ...state,
        vulnerabilities: [...state.vulnerabilities, action.payload],
      };

    case 'SET_WS_STATUS':
      return { ...state, wsConnectionStatus: action.payload };

    case 'UPDATE_STATS':
      const completedScans = state.scans.filter(s => s.status === 'completed' && s.results)
      const totalVulns = completedScans.reduce((sum, s) => {
        const results = typeof (s as any).results === 'string' ? JSON.parse((s as any).results) : (s as any).results
        const vulns = Array.isArray(results?.vulnerabilities) ? results.vulnerabilities : []
        return sum + (vulns.length > 0 ? vulns.length : 0)
      }, 0)
      const criticalVulns = completedScans.reduce((sum, s) => {
        const results = typeof (s as any).results === 'string' ? JSON.parse((s as any).results) : (s as any).results
        const vulns = Array.isArray(results?.vulnerabilities) ? results.vulnerabilities : []
        const criticalCount = vulns.length > 0 ? vulns.filter((v: any) => v.severity === 'critical').length : 0
        return sum + criticalCount
      }, 0)
      const stats = {
        totalTargets: state.targets.filter(t => t.is_active).length,
        activeScans: state.activeScans.size,
        totalVulnerabilities: totalVulns,
        criticalVulnerabilities: criticalVulns,
      };
      return { ...state, stats };

    case 'UPDATE_SCAN_BY_ID':
      return {
        ...state,
        scans: state.scans.map(scan =>
          scan.id === action.payload.scan_id ? { ...scan, ...action.payload.updates } : scan
        ),
      };

    default:
      return state;
  }
};

// Context
interface AppContextType {
  state: AppState;
  dispatch: React.Dispatch<AppAction>;
  wsConnectionStatus: 'connecting' | 'connected' | 'disconnected' | 'error';
  actions: {
    setLoading: (loading: boolean) => void;
    addTarget: (target: Target) => void;
    updateTarget: (target: Target) => void;
    removeTarget: (id: string) => void;
    addScan: (scan: Scan) => void;
    updateScan: (scan: Scan) => void;
    removeScan: (id: string) => void;
    addVulnerability: (vulnerability: Vulnerability) => void;
    updateStats: () => void;
  };
}

const AppContext = createContext<AppContextType | undefined>(undefined);

// Provider component
interface AppProviderProps {
  children: React.ReactNode;
}

export const AppProvider: React.FC<AppProviderProps> = ({ children }) => {
  const [state, dispatch] = useReducer(appReducer, initialState);
  const queryClient = useQueryClient();

  // WebSocket integration
  useEffect(() => {
    // Auto-connect WebSocket when AppContext initializes
    console.log('AppContext: Initializing WebSocket connection');
    webSocketService.connect();

    // Subscribe to WebSocket events
    const unsubscribeStatusChange = webSocketService.subscribe('connection_status', (statusPayload) => {
      const nextStatus = (statusPayload && typeof statusPayload.status === 'string')
        ? statusPayload.status
        : 'disconnected'
      dispatch({ type: 'SET_WS_STATUS', payload: nextStatus });
    });

    const unsubscribeScanUpdate = webSocketService.subscribe('scan_update', (message) => {
      if (message && message.scan_id) {
        dispatch({
          type: 'UPDATE_SCAN_BY_ID',
          payload: {
            scan_id: message.scan_id,
            updates: {
              status: message.status,
              progress_percentage: typeof message.progress === 'number' ? message.progress : 0,
              ...(message.results && { results: message.results })
            }
          }
        });
      }
    });

    const unsubscribeScanCompleted = webSocketService.subscribe('scan_completed', (message) => {
      if (message && message.scan_id) {
        dispatch({
          type: 'UPDATE_SCAN_BY_ID',
          payload: {
            scan_id: message.scan_id,
            updates: {
              status: 'completed',
              progress_percentage: 100,
              ...(message.results && { results: message.results }),
              ...(message.completed_at && { completed_at: message.completed_at })
            }
          }
        });
        // Invalidate scans to ensure any derived data (e.g., server-side duration) is refreshed
        queryClient.invalidateQueries('scans');
        queryClient.invalidateQueries(['scanDetails', message.scan_id]);
      }
    });

    const unsubscribeScanFailed = webSocketService.subscribe('scan_failed', (message) => {
      if (message && message.scan_id) {
        dispatch({
          type: 'UPDATE_SCAN_BY_ID',
          payload: {
            scan_id: message.scan_id,
            updates: {
              status: 'failed',
              progress_percentage: 0
            }
          }
        });
        // Make sure list reflects failure state quickly
        queryClient.invalidateQueries('scans');
        queryClient.invalidateQueries(['scanDetails', message.scan_id]);
      }
    });

    // When a vulnerability is found, refresh vulnerabilities list
    const unsubscribeVulnFound = webSocketService.subscribe('vulnerability_found', (_message) => {
      queryClient.invalidateQueries('vulnerabilities');
    });

    // Cleanup subscriptions on unmount
    return () => {
      unsubscribeStatusChange();
      unsubscribeScanUpdate();
      unsubscribeScanCompleted();
      unsubscribeScanFailed();
      unsubscribeVulnFound();
      // Note: We don't disconnect WebSocket here as it should persist across route changes
    };
  }, [queryClient]);

  // Update stats whenever relevant state changes
  useEffect(() => {
    dispatch({ type: 'UPDATE_STATS' });
  }, [state.targets, state.scans, state.vulnerabilities]);

  // Action helpers
  const actions = {
    setLoading: (loading: boolean) => dispatch({ type: 'SET_LOADING', payload: loading }),
    setError: (error: string | null) => dispatch({ type: 'SET_ERROR', payload: error }),
    addTarget: (target: Target) => dispatch({ type: 'ADD_TARGET', payload: target }),
    updateTarget: (target: Target) => dispatch({ type: 'UPDATE_TARGET', payload: target }),
    removeTarget: (id: string) => dispatch({ type: 'REMOVE_TARGET', payload: id }),
    addScan: (scan: Scan) => dispatch({ type: 'ADD_SCAN', payload: scan }),
    updateScan: (scan: Scan) => dispatch({ type: 'UPDATE_SCAN', payload: scan }),
    removeScan: (id: string) => dispatch({ type: 'REMOVE_SCAN', payload: id }),
    addVulnerability: (vulnerability: Vulnerability) => dispatch({ type: 'ADD_VULNERABILITY', payload: vulnerability }),
    updateStats: () => dispatch({ type: 'UPDATE_STATS' }),
  };

  return (
    <AppContext.Provider value={{ 
      state, 
      dispatch, 
      wsConnectionStatus: state.wsConnectionStatus,
      actions 
    }}>
      {children}
    </AppContext.Provider>
  );
};

// Hook to use the context
export const useAppContext = () => {
  const context = useContext(AppContext);
  if (context === undefined) {
    throw new Error('useAppContext must be used within an AppProvider');
  }
  return context;
};

export default AppContext; 