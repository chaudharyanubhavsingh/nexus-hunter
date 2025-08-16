import axios from 'axios';

const API_BASE_URL = (import.meta as any).env?.VITE_API_URL || 'http://localhost:8000';

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for auth
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error);
    return Promise.reject(error);
  }
);

// Types
export interface Target {
  id: string;
  name: string;
  domain: string;
  description?: string;
  scope?: string[];
  out_of_scope?: string[];
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  name: string;
  target_id: string;
  scan_type: 'reconnaissance' | 'vulnerability' | 'full'; // Match backend ScanType enum
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress_percentage: number; // Match backend field name
  config: any;
  results: any;
  created_at: string;
  updated_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface Vulnerability {
  id: string;
  scan_id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cvss_score?: number;
  cve_id?: string;
  url?: string;
  poc?: string;
  evidence?: string;
  category: string;
  confidence: number;
  false_positive: boolean;
  created_at: string;
}

export interface CreateTargetRequest {
  name: string;
  domain: string;
  description?: string;
  scope?: string[];
  out_of_scope?: string[];
}

export interface CreateScanRequest {
  name: string;
  target_id: string;
  type: 'recon' | 'vulnerability' | 'full';
  config?: any;
}

// API Service Class
class ApiService {
  // Targets
  async getTargets(): Promise<Target[]> {
    const response = await api.get('/api/targets/', { params: { active_only: false } });
    return response.data.targets || [];
  }

  async getTarget(id: string): Promise<Target> {
    const response = await api.get(`/api/targets/${id}`);
    return response.data;
  }

  async createTarget(data: CreateTargetRequest): Promise<Target> {
    const response = await api.post('/api/targets/', data);
    return response.data;
  }

  async updateTarget(id: string, data: Partial<CreateTargetRequest>): Promise<Target> {
    const response = await api.put(`/api/targets/${id}`, data);
    return response.data;
  }

  async deleteTarget(id: string, permanent: boolean = false): Promise<void> {
    await api.delete(`/api/targets/${id}`, { params: { permanent } });
  }

  // Scans
  async getScans(): Promise<Scan[]> {
    const response = await api.get('/api/scans/');
    return response.data.scans || [];
  }

  async getScan(id: string): Promise<Scan> {
    const response = await api.get(`/api/scans/${id}`);
    return response.data;
  }

  async createScan(data: CreateScanRequest): Promise<Scan> {
    // Map frontend scan types to backend ScanType enum values
    const scanTypeMapping = {
      'recon': 'reconnaissance',
      'vulnerability': 'vulnerability', 
      'full': 'full'
    };

    // Transform frontend format to backend format
    const backendData = {
      name: data.name,
      target_id: data.target_id,
      scan_type: scanTypeMapping[data.type as keyof typeof scanTypeMapping], // Map scan type
      config: data.config
    };
    
    const response = await api.post('/api/scans/', backendData);
    return response.data;
  }

  async cancelScan(scanId: string): Promise<void> {
    const response = await api.post(`/api/scans/${scanId}/cancel`);
    return response.data;
  }

  async deleteScan(scanId: string): Promise<void> {
    const response = await api.delete(`/api/scans/${scanId}`);
    return response.data;
  }

  async getScanProgress(id: string): Promise<{ progress: number; status: string; current_phase: string }> {
    const response = await api.get(`/api/scans/${id}/progress`);
    return response.data;
  }

  async getScanResults(id: string): Promise<any> {
    const response = await api.get(`/api/scans/${id}/results`);
    return response.data;
  }

  // Vulnerabilities
  async getVulnerabilities(): Promise<Vulnerability[]> {
    const response = await api.get('/api/vulnerabilities/');
    return response.data || [];
  }

  // Reports
  async getReports(scanId?: string): Promise<any[]> {
    if (scanId) {
      const response = await api.get(`/api/reports/${scanId}`);
      return response.data;
    } else {
      const response = await api.get('/api/reports/');
      return response.data.reports || [];
    }
  }

  async getExecutiveSummary(scanId: string, format: 'markdown' | 'html' = 'markdown'): Promise<string> {
    const response = await api.get(`/api/reports/${scanId}/executive-summary`, {
      params: { format },
      responseType: 'text'
    });
    return response.data;
  }

  async getTechnicalReport(scanId: string, format: 'markdown' | 'html' = 'markdown'): Promise<string> {
    const response = await api.get(`/api/reports/${scanId}/technical-report`, {
      params: { format },
      responseType: 'text'
    });
    return response.data;
  }

  async getDisclosureEmail(scanId: string): Promise<string> {
    const response = await api.get(`/api/reports/${scanId}/disclosure-email`, {
      responseType: 'text'
    });
    return response.data;
  }

  async downloadReport(scanId: string, reportType: string, format: string = 'pdf'): Promise<Blob> {
    const response = await api.get(`/api/reports/${scanId}/download/${reportType}`, {
      responseType: 'blob',
      params: { format }
    });
    return response.data;
  }

  // Health check
  async healthCheck(): Promise<{ status: string; version: string }> {
    const response = await api.get('/health');
    return response.data;
  }
}

export const apiService = new ApiService();
export default apiService; 