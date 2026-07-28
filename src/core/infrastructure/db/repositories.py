from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.domain.entities import AuditLog, Tenant, TenantStatus
from src.core.domain.repositories import LogRepository, TenantRepository
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
            updated_at=model.updated_at,
        )

    async def save(self, tenant: Tenant) -> Tenant:
        stmt = select(TenantModel).where(TenantModel.id == tenant.id)
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()

        status_enum = TenantStatus(tenant.status) if isinstance(tenant.status, str) else tenant.status

        if model is None:
            model = TenantModel(
                id=tenant.id,
                name=tenant.name,
                slug=tenant.slug,
                status=status_enum,
                created_at=tenant.created_at,
                updated_at=tenant.updated_at,
            )
            self.session.add(model)
        else:
            model.name = tenant.name
            model.slug = tenant.slug
            model.status = status_enum
            model.updated_at = tenant.updated_at

        await self.session.flush()
        return self._to_entity(model)

    async def get_by_id(self, tenant_id: UUID) -> Tenant | None:
        stmt = select(TenantModel).where(TenantModel.id == tenant_id)
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def get_by_slug(self, slug: str) -> Tenant | None:
        stmt = select(TenantModel).where(TenantModel.slug == slug)
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        search: str | None = None,
        status: str | None = None,
    ) -> list[Tenant]:
        stmt = select(TenantModel)
        if search:
            search_pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    TenantModel.name.ilike(search_pattern),
                    TenantModel.slug.ilike(search_pattern),
                )
            )
        if status:
            stmt = stmt.where(TenantModel.status == TenantStatus(status))

        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        models = result.scalars().all()
        return [self._to_entity(m) for m in models]

    async def delete(self, tenant_id: UUID) -> bool:
        stmt = select(TenantModel).where(TenantModel.id == tenant_id)
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        if not model:
            return False

        model.status = TenantStatus.INACTIVE
        model.updated_at = datetime.now(timezone.utc)
        await self.session.flush()
        return True



class InMemoryLogRepository(LogRepository):
    def __init__(self) -> None:
        self._logs: list[AuditLog] = []

    async def save(self, log: AuditLog) -> AuditLog:
        self._logs.insert(0, log)
        return log

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        tenant_id: UUID | None = None,
        source: str | None = None,
    ) -> list[AuditLog]:
        filtered = self._logs
        if tenant_id:
            filtered = [log for log in filtered if log.tenant_id == tenant_id]
        if source:
            filtered = [log for log in filtered if source.lower() in log.source.lower()]
        return filtered[skip : skip + limit]

