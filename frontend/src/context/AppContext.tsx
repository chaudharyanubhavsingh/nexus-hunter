import React, { createContext, useContext, useReducer, useEffect, ReactNode } from 'react';
import { Target, Scan, Vulnerability } from '../services/api';
import { webSocketService } from '../services/websocket';
import toast from 'react-hot-toast';

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
  | { type: 'UPDATE_STATS' };

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
      const stats = {
        totalTargets: state.targets.filter(t => t.is_active).length,
        activeScans: state.activeScans.size,
        totalVulnerabilities: state.vulnerabilities.length,
        criticalVulnerabilities: state.vulnerabilities.filter(v => v.severity === 'critical').length,
      };
      return { ...state, stats };

    default:
      return state;
  }
};

// Context
interface AppContextType {
  state: AppState;
  dispatch: React.Dispatch<AppAction>;
  actions: {
    setLoading: (loading: boolean) => void;
    setError: (error: string | null) => void;
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
  children: ReactNode;
}

export const AppProvider: React.FC<AppProviderProps> = ({ children }) => {
  const [state, dispatch] = useReducer(appReducer, initialState);

  // WebSocket integration
  useEffect(() => {
    // Subscribe to WebSocket events
    const unsubscribeStatus = webSocketService.subscribe('connection_status', (data) => {
      dispatch({ type: 'SET_WS_STATUS', payload: data.status });
    });

    const unsubscribeScanUpdate = webSocketService.subscribe('scan_update', (data) => {
      // Update scan with new progress/status
      const updatedScan: Partial<Scan> = {
        id: data.scan_id,
        status: data.status,
        progress: data.progress,
      };
      
      // Find the existing scan and update it
      const existingScan = state.scans.find(s => s.id === data.scan_id);
      if (existingScan) {
        dispatch({
          type: 'UPDATE_SCAN',
          payload: { ...existingScan, ...updatedScan } as Scan
        });
      }
    });

    const unsubscribeVulnFound = webSocketService.subscribe('vulnerability_found', (data) => {
      toast.error(`New ${data.vulnerability.severity} vulnerability found: ${data.vulnerability.title}`);
      // Note: We would need the full vulnerability object to add it to state
    });

    const unsubscribeScanCompleted = webSocketService.subscribe('scan_completed', (data) => {
      toast.success(`Scan completed: ${data.scan_name || data.scan_id}`);
      // Update scan status to completed
      const existingScan = state.scans.find(s => s.id === data.scan_id);
      if (existingScan) {
        dispatch({
          type: 'UPDATE_SCAN',
          payload: { ...existingScan, status: 'completed', progress: 100 } as Scan
        });
      }
    });

    // Set initial WebSocket status
    dispatch({ 
      type: 'SET_WS_STATUS', 
      payload: webSocketService.getConnectionStatus() 
    });

    // Cleanup
    return () => {
      unsubscribeStatus();
      unsubscribeScanUpdate();
      unsubscribeVulnFound();
      unsubscribeScanCompleted();
    };
  }, [state.scans]);

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
    <AppContext.Provider value={{ state, dispatch, actions }}>
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