export interface Tenant {
  id: string;
  name: string;
  slug: string;
  status: 'active' | 'inactive' | 'suspended';
  created_at: string;
  updated_at: string;
}

export interface CreateTenantPayload {
  name: string;
  slug: string;
}

export interface IngestLogPayload {
  source: string;
  raw_data: Record<string, unknown>;
  tenant_id: string;
  timestamp?: string;
}

export interface IngestLogResponse {
  status: string;
  message: string;
}

export interface ScopeCheckPayload {
  target_ip: string;
}

export interface ScopeCheckResponse {
  target_ip: string;
  is_allowed: boolean;
  status: 'AUTHORIZED' | 'SCOPE_VIOLATION';
}

export interface AuthTokenRequest {
  user_id: string;
  tenant: string;
  roles: string[];
}

export interface AuthTokenResponse {
  access_token: string;
  token_type: string;
}

export interface HealthResponse {
  status: string;
  service?: string;
  database?: string;
  kafka?: string;
}

export interface SystemMemoria {
  estado_atual: {
    repositorio: string;
    branch: string;
    ultima_atualizacao: string;
  };
  progresso: {
    concluidos: number;
    pendentes: number;
    percentual: number;
  };
  historico_testes?: {
    resultado: string;
  };
}
