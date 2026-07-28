import { apiClient } from './client';
import { CreateTenantPayload, Tenant } from '@/types';

export async function getTenants(skip = 0, limit = 100): Promise<Tenant[]> {
  const response = await apiClient.get<Tenant[]>('/api/v1/tenants', {
    params: { skip, limit },
  });
  return response.data;
}

export async function createTenant(payload: CreateTenantPayload): Promise<Tenant> {
  const response = await apiClient.post<Tenant>('/api/v1/tenants', payload);
  return response.data;
}
