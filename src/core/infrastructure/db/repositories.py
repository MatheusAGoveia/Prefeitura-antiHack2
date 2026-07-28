"""
Implementação do Repositório PostgresTenantRepository
GovSec Shield — Infrastructure DB Repositories
"""

from typing import List, Optional
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from src.core.domain.entities import Tenant, TenantStatus
from src.core.domain.repositories import TenantRepository
from src.core.infrastructure.db.models import TenantModel

class PostgresTenantRepository(TenantRepository):
    def __init__(self, session: AsyncSession):
        self.session = session

    def _to_entity(self, model: TenantModel) -> Tenant:
        return Tenant(
            id=model.id,
            name=model.name,
            slug=model.slug,
            status=TenantStatus(model.status) if isinstance(model.status, str) else model.status,
            created_at=model.created_at,
            updated_at=model.updated_at
        )

    async def save(self, tenant: Tenant) -> Tenant:
        stmt = select(TenantModel).where(TenantModel.id == tenant.id)
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()

        if model is None:
            model = TenantModel(
                id=tenant.id,
                name=tenant.name,
                slug=tenant.slug,
                status=tenant.status,
                created_at=tenant.created_at,
                updated_at=tenant.updated_at
            )
            self.session.add(model)
        else:
            model.name = tenant.name
            model.slug = tenant.slug
            model.status = tenant.status
            model.updated_at = tenant.updated_at

        await self.session.flush()
        return self._to_entity(model)

    async def get_by_id(self, tenant_id: UUID) -> Optional[Tenant]:
        stmt = select(TenantModel).where(TenantModel.id == tenant_id)
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def get_by_slug(self, slug: str) -> Optional[Tenant]:
        stmt = select(TenantModel).where(TenantModel.slug == slug)
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def list(self, skip: int = 0, limit: int = 100) -> List[Tenant]:
        stmt = select(TenantModel).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        models = result.scalars().all()
        return [self._to_entity(m) for m in models]
