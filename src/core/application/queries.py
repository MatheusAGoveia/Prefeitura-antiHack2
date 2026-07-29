"""
Queries da Aplicação Core
GovSec Shield — Application Queries
"""

from uuid import UUID

from pydantic import BaseModel

from src.core.application.dto import LogResponseDTO, TenantResponseDTO
from src.core.domain.repositories import LogRepository, TenantRepository
from src.shared.observability import trace_span


class GetTenantByIdQuery(BaseModel):
    tenant_id: UUID


class ListTenantsQuery(BaseModel):
    skip: int = 0
    limit: int = 100
    search: str | None = None
    status: str | None = None
    tenant_filter: str | None = None


class ListLogsQuery(BaseModel):
    skip: int = 0
    limit: int = 100
    tenant_id: UUID | None = None
    source: str | None = None


class TenantQueryHandler:
    def __init__(self, tenant_repo: TenantRepository):
        self.tenant_repo = tenant_repo

    async def get_by_id(self, query: GetTenantByIdQuery) -> TenantResponseDTO | None:
        attributes = {
            "query.name": "GetTenantByIdQuery",
            "tenant.id": str(query.tenant_id),
            "user_id": "system",
        }
        with trace_span("Query.GetTenantByIdQuery", attributes=attributes):
            tenant = await self.tenant_repo.get_by_id(query.tenant_id)
            if not tenant:
                return None
            return TenantResponseDTO(
                id=tenant.id,
                name=tenant.name,
                slug=tenant.slug,
                status=tenant.status.value,
                created_at=tenant.created_at,
                updated_at=tenant.updated_at,
            )

    async def list(self, query: ListTenantsQuery) -> list[TenantResponseDTO]:
        attributes = {
            "query.name": "ListTenantsQuery",
            "tenant": query.tenant_filter or "global",
            "user_id": "system",
        }
        with trace_span("Query.ListTenantsQuery", attributes=attributes):
            tenants = await self.tenant_repo.list(
                skip=query.skip,
                limit=query.limit,
                search=query.search,
                status=query.status,
                tenant_filter=query.tenant_filter,
            )
            return [
                TenantResponseDTO(
                    id=t.id,
                    name=t.name,
                    slug=t.slug,
                    status=t.status.value,
                    created_at=t.created_at,
                    updated_at=t.updated_at,
                )
                for t in tenants
            ]


class LogQueryHandler:
    def __init__(self, log_repo: LogRepository):
        self.log_repo = log_repo

    async def list(self, query: ListLogsQuery) -> list[LogResponseDTO]:
        attributes = {
            "query.name": "ListLogsQuery",
            "tenant": str(query.tenant_id) if query.tenant_id else "global",
            "user_id": "system",
        }
        with trace_span("Query.ListLogsQuery", attributes=attributes):
            logs = await self.log_repo.list(
                skip=query.skip,
                limit=query.limit,
                tenant_id=query.tenant_id,
                source=query.source,
            )
            return [
                LogResponseDTO(
                    id=log.id,
                    source=log.source,
                    raw_data=log.raw_data,
                    tenant_id=log.tenant_id,
                    timestamp=log.timestamp,
                )
                for log in logs
            ]


