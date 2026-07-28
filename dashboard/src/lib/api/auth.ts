import { apiClient } from './client';
import { AuthTokenRequest, AuthTokenResponse } from '@/types';

export async function fetchToken(payload?: AuthTokenRequest): Promise<AuthTokenResponse> {
  const defaultPayload: AuthTokenRequest = {
    user_id: 'admin-01',
    tenant: 'betim',
    roles: ['system_admin', 'analyst', 'engineer'],
  };
  const response = await apiClient.post<AuthTokenResponse>('/api/v1/auth/token', payload || defaultPayload);
  return response.data;
}

export function saveToken(token: string): void {
  if (typeof window !== 'undefined') {
    localStorage.setItem('govsec_token', token);
  }
}

export function getStoredToken(): string | null {
  if (typeof window !== 'undefined') {
    return localStorage.getItem('govsec_token');
  }
  return null;
}
