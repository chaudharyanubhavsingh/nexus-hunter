import { useQuery, useMutation, useQueryClient } from 'react-query';
import { useAppContext } from '../context/AppContext';
import apiService, { CreateTargetRequest, CreateScanRequest } from '../services/api';
import toast from 'react-hot-toast';
import { getUserFriendlyMessage } from '../utils/errorHandler';

// Query keys
export const QUERY_KEYS = {
  TARGETS: 'targets',
  SCANS: 'scans',
  VULNERABILITIES: 'vulnerabilities',
  SCAN_DETAILS: 'scanDetails',
  REPORTS: 'reports',
};

// Debounce utility to prevent multiple simultaneous refetches
const debounceMap = new Map<string, number>();

const debouncedRefetch = (key: string, refetchFn: () => void, delay: number = 500) => {
  if (debounceMap.has(key)) {
    clearTimeout(debounceMap.get(key)!);
  }
  
  const timeout = setTimeout(() => {
    refetchFn();
    debounceMap.delete(key);
  }, delay);
  
  debounceMap.set(key, timeout);
};

// Activity persistence helpers (align with Dashboard)
const getActivityKey = (): string => 'nexus_activity_feed_persistent';

const pushActivity = (entry: any) => {
  try {
    const key = getActivityKey();
    const raw = localStorage.getItem(key);
    const list = raw ? JSON.parse(raw) : [];
    const next = [
      {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: new Date().toLocaleTimeString(),
        ...entry,
      },
      ...Array.isArray(list) ? list : []
    ].slice(0, 300);
    localStorage.setItem(key, JSON.stringify(next));
    try {
      window.dispatchEvent(new CustomEvent('nexus-activity-updated', { detail: { key } }));
    } catch {}
  } catch {}
};

// Targets hooks
export const useTargets = () => {
  const { dispatch } = useAppContext();
  
  return useQuery(
    QUERY_KEYS.TARGETS,
    apiService.getTargets,
    {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes  
      refetchOnWindowFocus: false, // Disable aggressive refetching
      refetchOnMount: false, // Don't refetch on every mount
      refetchOnReconnect: true, // Keep this for WebSocket reconnects
      onSuccess: (data) => {
        dispatch({ type: 'SET_TARGETS', payload: data });
      },
      onError: (error) => {
        toast.error('Failed to fetch targets');
        console.error('Error fetching targets:', error);
      },
    }
  );
};

export const useCreateTarget = () => {
  const queryClient = useQueryClient();
  const { actions } = useAppContext();

  return useMutation(
    (data: CreateTargetRequest) => apiService.createTarget(data),
    {
      onSuccess: (newTarget) => {
        actions.addTarget(newTarget);
        queryClient.invalidateQueries(QUERY_KEYS.TARGETS);
        pushActivity({
          type: 'target_created',
          message: `Target "${newTarget.name}" created`,
          severity: 'success',
          iconKey: 'target',
          payload: newTarget,
        });
        toast.success(`Target "${newTarget.name}" created successfully`);
      },
      onError: (error: any) => {
        console.error('Error creating target:', error);
        const message = getUserFriendlyMessage(error, 'create target');
        toast.error(message);
      },
    }
  );
};

export const useUpdateTarget = () => {
  const queryClient = useQueryClient();
  const { actions } = useAppContext();

  return useMutation(
    ({ id, data }: { id: string; data: Partial<CreateTargetRequest> }) =>
      apiService.updateTarget(id, data),
    {
      onSuccess: (updatedTarget) => {
        actions.updateTarget(updatedTarget);
        queryClient.invalidateQueries(QUERY_KEYS.TARGETS);
        pushActivity({
          type: 'target_updated',
          message: `Target "${updatedTarget.name}" updated`,
          severity: 'info',
          iconKey: 'target',
          payload: updatedTarget,
        });
        toast.success(`Target "${updatedTarget.name}" updated successfully`);
      },
      onError: (error: any) => {
        console.error('Error updating target:', error);
        const message = getUserFriendlyMessage(error, 'update target');
        toast.error(message);
      },
    }
  );
};

export const useDeleteTarget = () => {
  const queryClient = useQueryClient();
  const { actions, state } = useAppContext();

  return useMutation(
    (idWithFlag: string) => {
      const [id, flag] = idWithFlag.split('::');
      const permanent = flag === 'permanent';
      return apiService.deleteTarget(id, permanent);
    },
    {
      onSuccess: (_data, variables) => {
        const idWithFlag = String(variables);
        const [id, flag] = idWithFlag.split('::');
        const isPermanent = flag === 'permanent';
        const target = state.targets.find(t => t.id === id);
        const nameOrId = target?.name || id;
        if (isPermanent) {
          actions.removeTarget(id);
        }
        queryClient.invalidateQueries(QUERY_KEYS.TARGETS);
        pushActivity({
          type: isPermanent ? 'target_deleted' : 'target_deactivated',
          message: isPermanent ? `Target "${nameOrId}" deleted permanently` : `Target "${nameOrId}" deactivated`,
          severity: isPermanent ? 'high' : 'info',
          iconKey: 'target',
          payload: { id, name: target?.name },
        });
        toast.success(isPermanent ? 'Target deleted permanently' : 'Target deactivated');
      },
      onError: (error: any) => {
        console.error('Error deleting target:', error);
        const message = getUserFriendlyMessage(error, 'delete target');
        toast.error(message);
      },
    }
  );
};

// Scans hooks
export const useScans = () => {
  const { dispatch } = useAppContext();
  
  return useQuery(
    QUERY_KEYS.SCANS,
    apiService.getScans,
    {
      staleTime: 10000, // 10 seconds - shorter for real-time updates
      cacheTime: 5 * 60 * 1000, // 5 minutes
      retry: 2,
      retryDelay: (attemptIndex) => Math.min(2000 * 2 ** attemptIndex, 20000),
      refetchOnMount: true, // Re-enable mount refetch for initial data loading
      refetchOnWindowFocus: true, // Re-enable for immediate updates when switching tabs
      refetchOnReconnect: true, // Keep for WebSocket reconnects
      refetchInterval: 30000, // Re-enable auto-refresh every 30 seconds for real-time updates
      onSuccess: (data) => {
        dispatch({ type: 'SET_SCANS', payload: data });
      },
      onError: (error) => {
        console.error('Error fetching scans:', error);
      },
    }
  );
};

export const useScanDetails = (scanId: string) => {
  return useQuery(
    [QUERY_KEYS.SCAN_DETAILS, scanId],
    () => apiService.getScan(scanId),
    {
      enabled: !!scanId,
      onError: (error) => {
        toast.error('Failed to fetch scan details');
        console.error('Error fetching scan details:', error);
      },
    }
  );
};

export const useCreateScan = () => {
  const queryClient = useQueryClient();
  const { actions } = useAppContext();

  return useMutation(
    (data: CreateScanRequest) => apiService.createScan(data),
    {
      onSuccess: (newScan) => {
        actions.addScan(newScan);
        queryClient.invalidateQueries(QUERY_KEYS.SCANS);
        pushActivity({
          type: 'scan_created',
          message: `Scan "${newScan.name}" started`,
          severity: 'info',
          iconKey: 'activity',
          payload: newScan,
        });
        toast.success(`Scan "${newScan.name}" started successfully`);
      },
      onError: (error: any) => {
        console.error('Error creating scan:', error);
        const message = getUserFriendlyMessage(error, 'start scan');
        toast.error(message);
      },
    }
  );
};

export const useCancelScan = () => {
  const queryClient = useQueryClient();

  return useMutation(
    (scanId: string) => apiService.cancelScan(scanId),
    {
      onSuccess: (_data, scanId) => {
        queryClient.invalidateQueries(QUERY_KEYS.SCANS);
        pushActivity({
          type: 'scan_cancelled',
          message: `Scan ${scanId} cancelled`,
          severity: 'high',
          iconKey: 'activity',
          payload: { scanId },
        });
        toast.success('Scan cancelled successfully');
      },
      onError: (error: any) => {
        console.error('Error cancelling scan:', error);
        const message = getUserFriendlyMessage(error, 'cancel scan');
        toast.error(message);
      },
    }
  );
};

export const useDeleteScan = () => {
  const queryClient = useQueryClient();
  const { actions } = useAppContext();

  return useMutation(
    (scanId: string) => apiService.deleteScan(scanId),
    {
      onSuccess: (_, scanId) => {
        actions.removeScan(scanId);
        queryClient.invalidateQueries(QUERY_KEYS.SCANS);
        pushActivity({
          type: 'scan_deleted',
          message: `Scan ${scanId} deleted`,
          severity: 'high',
          iconKey: 'activity',
          payload: { scanId },
        });
        toast.success('Scan deleted successfully');
      },
      onError: (error: any) => {
        console.error('Error deleting scan:', error);
        const message = getUserFriendlyMessage(error, 'delete scan');
        toast.error(message);
      },
    }
  );
};

// Vulnerabilities hooks
export const useVulnerabilities = (scanId?: string) => {
  const { dispatch } = useAppContext();
  
  return useQuery(
    [QUERY_KEYS.VULNERABILITIES, scanId],
    () => apiService.getVulnerabilities(),
    {
      staleTime: 2 * 60 * 1000, // 2 minutes
      cacheTime: 5 * 60 * 1000, // 5 minutes
      refetchOnWindowFocus: false, // Disable aggressive refetching
      refetchOnMount: false, // Don't refetch on every mount
      refetchOnReconnect: true, // Keep for WebSocket reconnects
      onSuccess: (data) => {
        dispatch({ type: 'SET_VULNERABILITIES', payload: data });
      },
      onError: (error) => {
        console.error('Error fetching vulnerabilities:', error);
      },
    }
  );
};

// Reports hooks
export const useReports = (scanId?: string) => {
  return useQuery(
    [QUERY_KEYS.REPORTS, scanId],
    () => apiService.getReports(scanId),
    {
      staleTime: 2 * 60 * 1000, // 2 minutes  
      cacheTime: 5 * 60 * 1000, // 5 minutes
      retry: 2, // Reduce retry attempts
      retryDelay: (attemptIndex) => Math.min(2000 * 2 ** attemptIndex, 20000),
      refetchOnWindowFocus: false, // Disable aggressive refetching
      refetchOnMount: false, // Don't refetch on every mount
      refetchOnReconnect: true, // Keep for WebSocket reconnects
      onError: (error) => {
        console.error('Error fetching reports:', error);
      },
    }
  );
};

export const useDownloadReport = () => {
  return useMutation(
    ({ scanId, reportType, format }: { scanId: string; reportType: string; format: string }) =>
      apiService.downloadReport(scanId, reportType, format),
    {
      onSuccess: (blob, { reportType, format, scanId }) => {
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${reportType}-report.${format}`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        
        pushActivity({
          type: 'report_downloaded',
          message: `Downloaded ${reportType} report for scan ${scanId}`,
          severity: 'success',
          iconKey: 'file',
          payload: { scanId, reportType, format },
        });
        toast.success('Report downloaded successfully');
      },
      onError: (error: any) => {
        console.error('Error downloading report:', error);
        const message = getUserFriendlyMessage(error, 'download report');
        toast.error(message);
      },
    }
  );
};

// Optimized combined hook for dashboard data with debounced refetch
export const useDashboardData = () => {
  const targets = useTargets();
  const scans = useScans();
  const vulnerabilities = useVulnerabilities();

  // Debounced refetch functions to prevent simultaneous calls
  const refetchAll = () => {
    debouncedRefetch('dashboard-targets', () => targets.refetch());
    debouncedRefetch('dashboard-scans', () => scans.refetch());
    debouncedRefetch('dashboard-vulnerabilities', () => vulnerabilities.refetch());
  };

  return {
    targets,
    scans,
    vulnerabilities,
    refetchAll, // Provide optimized refetch function
    isLoading: targets.isLoading || scans.isLoading || vulnerabilities.isLoading,
    isError: targets.isError || scans.isError || vulnerabilities.isError,
  };
}; 