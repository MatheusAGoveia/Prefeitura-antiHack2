"""
Queries da Aplicação Core
GovSec Shield — Application Queries
"""

from uuid import UUID
from typing import List
from pydantic import BaseModel
from src.core.domain.repositories import TenantRepository
from src.core.application.dto import TenantResponseDTO

class GetTenantByIdQuery(BaseModel):
    tenant_id: UUID

class ListTenantsQuery(BaseModel):
    skip: int = 0
    limit: int = 100

class TenantQueryHandler:
    def __init__(self, tenant_repo: TenantRepository):
        self.tenant_repo = tenant_repo

    async def get_by_id(self, query: GetTenantByIdQuery) -> TenantResponseDTO | None:
        tenant = await self.tenant_repo.get_by_id(query.tenant_id)
        if not tenant:
            return None
        return TenantResponseDTO(
            id=tenant.id,
            name=tenant.name,
            slug=tenant.slug,
            status=tenant.status.value,
            created_at=tenant.created_at,
            updated_at=tenant.updated_at
        )

    async def list(self, query: ListTenantsQuery) -> List[TenantResponseDTO]:
        tenants = await self.tenant_repo.list(skip=query.skip, limit=query.limit)
        return [
            TenantResponseDTO(
                id=t.id,
                name=t.name,
                slug=t.slug,
                status=t.status.value,
                created_at=t.created_at,
                updated_at=t.updated_at
            )
            for t in tenants
        ]
