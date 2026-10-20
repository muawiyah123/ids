/**
 * src/services/api.ts
 *
 * Typed API client — all API calls go through here.
 * Handles 401 automatically by clearing auth state.
 */
import axios, { AxiosInstance, AxiosError } from 'axios';
import type {
  TokenResponse, User, Detection, Alert, Agent, AgentRegisterResponse,
  DashboardSummary, TimelinePoint, Page, ModelStatus, AuditLog,
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL}/api/v1`
  : '/api/v1';

const WS_BASE = import.meta.env.VITE_WS_URL
  ? import.meta.env.VITE_WS_URL
  : `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.hostname}:8000`;

let _accessToken: string | null = null;
let _refreshToken: string | null = null;
let _onUnauthorized: (() => void) | null = null;
let _refreshPromise: Promise<string> | null = null;

export function setTokens(access: string, refresh: string) {
  _accessToken = access;
  _refreshToken = refresh;
}

export function clearTokens() {
  _accessToken = null;
  _refreshToken = null;
}

export function getAccessToken(): string | null {
  return _accessToken;
}

export function setUnauthorizedHandler(handler: () => void) {
  _onUnauthorized = handler;
}

export function getWebSocketUrl(tokenOverride?: string): string {
  const token = tokenOverride || _accessToken || '';
  return `${WS_BASE}/api/v1/ws/events?token=${encodeURIComponent(token)}`;
}

// Create axios instance
const api: AxiosInstance = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// Request interceptor — inject auth header
api.interceptors.request.use((config) => {
  if (_accessToken) {
    config.headers.Authorization = `Bearer ${_accessToken}`;
  }
  return config;
});

// Response interceptor — handle 401
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config;
    if (
      error.response?.status === 401 && original && _refreshToken &&
      !original.url?.includes('/auth/refresh') && !original.url?.includes('/auth/login') &&
      !(original as typeof original & { _retry?: boolean })._retry
    ) {
      (original as typeof original & { _retry?: boolean })._retry = true;
      try {
        if (!_refreshPromise) {
          const refreshToken = _refreshToken;
          _refreshPromise = api.post('/auth/refresh', { refresh_token: refreshToken })
            .then((response) => {
              setTokens(response.data.access_token, response.data.refresh_token);
              return response.data.access_token as string;
            })
            .finally(() => { _refreshPromise = null; });
        }
        const accessToken = await _refreshPromise;
        original.headers.Authorization = `Bearer ${accessToken}`;
        return api(original);
      } catch {
        clearTokens();
        _onUnauthorized?.();
      }
    } else if (error.response?.status === 401) {
      clearTokens();
      _onUnauthorized?.();
    }
    return Promise.reject(error);
  }
);

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
export const authApi = {
  login: async (email: string, password: string): Promise<TokenResponse> => {
    const res = await api.post('/auth/login', { email, password });
    return res.data;
  },
  register: async (email: string, password: string, full_name: string): Promise<User> => {
    const res = await api.post('/auth/register', { email, password, full_name });
    return res.data;
  },
  refresh: async (refreshToken: string): Promise<TokenResponse> => {
    const res = await api.post('/auth/refresh', { refresh_token: refreshToken });
    return res.data;
  },
  logout: async (): Promise<void> => {
    await api.post('/auth/logout');
  },
  me: async (): Promise<User> => {
    const res = await api.get('/auth/me');
    return res.data;
  },
  changePassword: async (current_password: string, new_password: string): Promise<void> => {
    await api.post('/auth/change-password', { current_password, new_password });
  },
};

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
export const dashboardApi = {
  getSummary: async (): Promise<DashboardSummary> => {
    const res = await api.get('/dashboard/summary');
    return res.data;
  },
  getTimeline: async (hours = 24, bucketMinutes = 60): Promise<TimelinePoint[]> => {
    const res = await api.get('/dashboard/timeline', { params: { hours, bucket_minutes: bucketMinutes } });
    return res.data;
  },
};

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------
export const detectionsApi = {
  list: async (params?: Record<string, unknown>): Promise<Page<Detection>> => {
    const res = await api.get('/detections', { params });
    return res.data;
  },
  get: async (id: string): Promise<Detection> => {
    const res = await api.get(`/detections/${id}`);
    return res.data;
  },
  getFeatures: async (id: string): Promise<{ detection_id: string; features: Record<string, number> }> => {
    const res = await api.get(`/detections/${id}/features`);
    return res.data;
  },
};

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
export const alertsApi = {
  list: async (params?: Record<string, unknown>): Promise<Page<Alert>> => {
    const res = await api.get('/alerts', { params });
    return res.data;
  },
  get: async (id: string): Promise<Alert> => {
    const res = await api.get(`/alerts/${id}`);
    return res.data;
  },
  getEvents: async (id: string): Promise<unknown[]> => {
    const res = await api.get(`/alerts/${id}/events`);
    return res.data;
  },
  acknowledge: async (id: string, comment?: string): Promise<Alert> => {
    const res = await api.post(`/alerts/${id}/acknowledge`, { comment });
    return res.data;
  },
  investigate: async (id: string, comment?: string): Promise<Alert> => {
    const res = await api.post(`/alerts/${id}/investigate`, { comment });
    return res.data;
  },
  resolve: async (id: string, comment?: string): Promise<Alert> => {
    const res = await api.post(`/alerts/${id}/resolve`, { comment });
    return res.data;
  },
  markFalsePositive: async (id: string, comment?: string): Promise<Alert> => {
    const res = await api.post(`/alerts/${id}/false-positive`, { comment });
    return res.data;
  },
  update: async (id: string, data: { notes?: string; assigned_to_id?: string }): Promise<Alert> => {
    const res = await api.patch(`/alerts/${id}`, data);
    return res.data;
  },
};

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------
export const agentsApi = {
  list: async (): Promise<Agent[]> => {
    const res = await api.get('/agents');
    return res.data;
  },
  get: async (id: string): Promise<Agent> => {
    const res = await api.get(`/agents/${id}`);
    return res.data;
  },
  register: async (data: { name: string; hostname?: string; description?: string; environment?: string }): Promise<AgentRegisterResponse> => {
    const res = await api.post('/agents/register', data);
    return res.data;
  },
  disable: async (id: string): Promise<void> => {
    await api.delete(`/agents/${id}`);
  },
};

// ---------------------------------------------------------------------------
// Analytics
// ---------------------------------------------------------------------------
export const analyticsApi = {
  attackDistribution: async (hours = 24): Promise<{ class: string; count: number }[]> => {
    const res = await api.get('/analytics/attack-distribution', { params: { hours } });
    return res.data;
  },
  severityDistribution: async (hours = 24): Promise<{ severity: string; count: number }[]> => {
    const res = await api.get('/analytics/severity-distribution', { params: { hours } });
    return res.data;
  },
  topSources: async (hours = 24, limit = 10): Promise<{ ip: string; count: number }[]> => {
    const res = await api.get('/analytics/top-sources', { params: { hours, limit } });
    return res.data;
  },
  topDestinations: async (hours = 24, limit = 10): Promise<{ ip: string; count: number }[]> => {
    const res = await api.get('/analytics/top-destinations', { params: { hours, limit } });
    return res.data;
  },
  trends: async (hours = 168): Promise<{ date: string; total: number; threats: number }[]> => {
    const res = await api.get('/analytics/trends', { params: { hours } });
    return res.data;
  },
};

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------
export const modelsApi = {
  getCurrent: async (): Promise<ModelStatus> => {
    const res = await api.get('/models/current');
    return res.data;
  },
  getFeatures: async (): Promise<{ feature_count: number; features: string[] }> => {
    const res = await api.get('/models/current/features');
    return res.data;
  },
  getImportance: async (): Promise<{ available: boolean; features?: { feature: string; importance: number; rank: number }[] }> => {
    const res = await api.get('/models/current/importance');
    return res.data;
  },
};

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------
export const auditApi = {
  list: async (params?: Record<string, unknown>): Promise<Page<AuditLog>> => {
    const res = await api.get('/audit', { params });
    return res.data;
  },
};

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------
export const healthApi = {
  check: async (): Promise<{ status: string; checks: Record<string, unknown> }> => {
    const res = await api.get('/ready');
    return res.data;
  },
};

export default api;
