import { useQuery, useMutation, useQueryClient } from 'react-query';
import { useAppContext } from '../context/AppContext';
import apiService, { Target, Scan, Vulnerability, CreateTargetRequest, CreateScanRequest } from '../services/api';
import toast from 'react-hot-toast';

// Query keys
export const QUERY_KEYS = {
  TARGETS: 'targets',
  SCANS: 'scans',
  VULNERABILITIES: 'vulnerabilities',
  SCAN_DETAILS: 'scanDetails',
  REPORTS: 'reports',
};

// Targets hooks
export const useTargets = () => {
  const { state, dispatch } = useAppContext();
  
  return useQuery(
    QUERY_KEYS.TARGETS,
    apiService.getTargets,
    {
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
        toast.success(`Target "${newTarget.name}" created successfully`);
      },
      onError: (error: any) => {
        const message = error.response?.data?.detail || 'Failed to create target';
        toast.error(message);
        console.error('Error creating target:', error);
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
        toast.success(`Target "${updatedTarget.name}" updated successfully`);
      },
      onError: (error: any) => {
        const message = error.response?.data?.detail || 'Failed to update target';
        toast.error(message);
        console.error('Error updating target:', error);
      },
    }
  );
};

export const useDeleteTarget = () => {
  const queryClient = useQueryClient();
  const { actions } = useAppContext();

  return useMutation(
    (id: string) => apiService.deleteTarget(id),
    {
      onSuccess: (_, deletedId) => {
        actions.removeTarget(deletedId);
        queryClient.invalidateQueries(QUERY_KEYS.TARGETS);
        toast.success('Target deleted successfully');
      },
      onError: (error: any) => {
        const message = error.response?.data?.detail || 'Failed to delete target';
        toast.error(message);
        console.error('Error deleting target:', error);
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
      onSuccess: (data) => {
        dispatch({ type: 'SET_SCANS', payload: data });
      },
      onError: (error) => {
        toast.error('Failed to fetch scans');
        console.error('Error fetching scans:', error);
      },
      refetchInterval: 5000, // Refetch every 5 seconds for real-time updates
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
        toast.success(`Scan "${newScan.name}" started successfully`);
      },
      onError: (error: any) => {
        const message = error.response?.data?.detail || 'Failed to start scan';
        toast.error(message);
        console.error('Error creating scan:', error);
      },
    }
  );
};

export const useCancelScan = () => {
  const queryClient = useQueryClient();
  const { actions } = useAppContext();

  return useMutation(
    (scanId: string) => apiService.cancelScan(scanId),
    {
      onSuccess: (_, scanId) => {
        // Update scan status to cancelled
        queryClient.invalidateQueries(QUERY_KEYS.SCANS);
        toast.success('Scan cancelled successfully');
      },
      onError: (error: any) => {
        const message = error.response?.data?.detail || 'Failed to cancel scan';
        toast.error(message);
        console.error('Error cancelling scan:', error);
      },
    }
  );
};

// Vulnerabilities hooks
export const useVulnerabilities = (scanId?: string) => {
  const { dispatch } = useAppContext();
  
  return useQuery(
    [QUERY_KEYS.VULNERABILITIES, scanId],
    () => apiService.getVulnerabilities(scanId),
    {
      onSuccess: (data) => {
        dispatch({ type: 'SET_VULNERABILITIES', payload: data });
      },
      onError: (error) => {
        toast.error('Failed to fetch vulnerabilities');
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
      onError: (error) => {
        toast.error('Failed to fetch reports');
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
      onSuccess: (blob, { reportType, format }) => {
        // Create download link
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${reportType}-report.${format}`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        
        toast.success('Report downloaded successfully');
      },
      onError: (error: any) => {
        const message = error.response?.data?.detail || 'Failed to download report';
        toast.error(message);
        console.error('Error downloading report:', error);
      },
    }
  );
};

// Combined hook for dashboard data
export const useDashboardData = () => {
  const targets = useTargets();
  const scans = useScans();
  const vulnerabilities = useVulnerabilities();

  return {
    targets,
    scans,
    vulnerabilities,
    isLoading: targets.isLoading || scans.isLoading || vulnerabilities.isLoading,
    isError: targets.isError || scans.isError || vulnerabilities.isError,
  };
}; 