import { apiClient } from './client';
import { IngestLogPayload, IngestLogResponse } from '@/types';

export async function ingestLog(payload: IngestLogPayload): Promise<IngestLogResponse> {
  const response = await apiClient.post<IngestLogResponse>('/api/v1/logs', payload);
  return response.data;
}
