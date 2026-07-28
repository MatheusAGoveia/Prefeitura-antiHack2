import { apiClient } from './client';
import { HealthResponse, ScopeCheckPayload, ScopeCheckResponse, SystemMemoria } from '@/types';

export async function checkHealth(): Promise<HealthResponse> {
  const response = await apiClient.get<HealthResponse>('/healthz');
  return response.data;
}

export async function checkReady(): Promise<HealthResponse> {
  const response = await apiClient.get<HealthResponse>('/ready');
  return response.data;
}

export async function checkScope(payload: ScopeCheckPayload): Promise<ScopeCheckResponse> {
  const response = await apiClient.post<ScopeCheckResponse>('/api/v1/security/check-scope', payload);
  return response.data;
}

export async function getSystemMemoria(): Promise<SystemMemoria> {
  const response = await apiClient.get<SystemMemoria>('/api/memoria');
  return response.data;
}
