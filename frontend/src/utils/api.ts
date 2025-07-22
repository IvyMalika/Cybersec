import axios, { AxiosInstance, AxiosError } from 'axios';
import { ApiError, OSINTRequest } from '../types/api';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

class ApiClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      timeout: 7200000,
      headers: {
        'Content-Type': 'application/json',
      },
      withCredentials: true,
    });

    this.setupInterceptors();
  }

  private setupInterceptors() {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('access_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const originalRequest = error.config;

        if (error.response?.status === 401 && !originalRequest?._retry) {
          originalRequest._retry = true;

          try {
            const refreshToken = localStorage.getItem('refresh_token');
            if (refreshToken) {
              const response = await this.client.post('/api/auth/refresh', {
                refresh_token: refreshToken,
              });
              
              const { access_token } = response.data;
              localStorage.setItem('access_token', access_token);
              
              return this.client(originalRequest);
            }
          } catch (refreshError) {
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            window.location.href = '/login';
          }
        }

        return Promise.reject(error);
      }
    );
  }

  // Auth endpoints
  async register(data: { username: string; email: string; password: string }) {
    const response = await this.client.post('/api/auth/register', data);
    return response.data;
  }

  async login(data: { username: string; password: string; mfa_code?: string }) {
    const response = await this.client.post('/api/auth/login', data);
    return response.data;
  }

  async setupMFA(enable: boolean) {
    const response = await this.client.post('/api/auth/mfa/setup', { enable });
    return response.data;
  }

  async verifyMFA(code: string) {
    const response = await this.client.post('/api/auth/mfa/verify', { code });
    return response.data;
  }

  // Tool endpoints
  async runNmapScan(data: { target: string; scan_type: string }) {
    const response = await this.client.post('/api/tools/nmap/scan', data);
    return response.data;
  }

  async runVulnerabilityScan(data: { target: string; scan_type: string }) {
    const response = await this.client.post('/api/tools/vulnerability/scan', data);
    return response.data;
  }

  async analyzeMalware(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await this.client.post('/api/tools/malware/analyze', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  }

  async monitorNetwork(data: { interface: string; timeout: number }) {
    const response = await this.client.post('/api/tools/network/monitor', data);
    return response.data;
  }

  async gatherOSINT(data: OSINTRequest) {
    const response = await this.client.post('/api/tools/osint/gather', data);
    return response.data;
  }

  async crackPassword(data: { hash: string; hash_type: string; wordlist_id: number }) {
    const response = await this.client.post('/api/tools/password/crack', data);
    return response.data;
  }

  async getThreatIntel(data: { indicator: string; type: string }) {
    const response = await this.client.post('/api/tools/threat/intel', data);
    return response.data;
  }

  // Job endpoints
  async getJobs(params?: { page?: number; limit?: number }) {
    const response = await this.client.get('/api/jobs', { params });
    return response.data;
  }

  async getJob(jobId: number) {
    const response = await this.client.get(`/api/jobs/${jobId}`);
    return response.data;
  }

  async getJobReport(jobId: number) {
    const response = await this.client.get(`/api/jobs/${jobId}/report`, {
      responseType: 'blob',
    });
    return response.data;
  }

  // Admin endpoints
  async getTargets() {
    const response = await this.client.get('/api/targets');
    return response.data;
  }

  async approveTarget(targetId: number) {
    const response = await this.client.post(`/api/admin/targets/${targetId}/approve`);
    return response.data;
  }

  async getUsers() {
    const response = await this.client.get('/api/admin/users');
    return response.data;
  }

  async updateUser(userId: number, data: { role: string; is_active: boolean }) {
    const response = await this.client.put(`/api/admin/users/${userId}`, data);
    return response.data;
  }

  async getAdminJobs() {
    const response = await this.client.get('/api/admin/jobs');
    return response.data;
  }

  async getAdminJobDetails(jobId: number) {
    const response = await this.client.get(`/api/admin/jobs/${jobId}`);
    return response.data;
  }

  async cancelJob(jobId: number) {
    const response = await this.client.post(`/api/admin/jobs/${jobId}/cancel`);
    return response.data;
  }

  async getAuditLogs() {
    const response = await this.client.get('/api/admin/audit/logs');
    return response.data;
  }

  // Health check
  async getHealthStatus() {
    const response = await this.client.get('/api/health');
    return response.data;
  }

  // Generic request method
  async request<T = any>(config: any): Promise<T> {
    const response = await this.client(config);
    return response.data;
  }
}

export const apiClient = new ApiClient();

export const handleApiError = (error: any): ApiError => {
  if (error.response?.data?.error) {
    return {
      error: error.response.data.error,
      description: error.response.data.description,
    };
  }
  
  return {
    error: error.message || 'An unexpected error occurred',
  };
};

export default apiClient;