from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.domain.entities import AlertAcknowledgement, AuditLog, Tenant, TenantStatus
from src.core.domain.repositories import (
    AlertAcknowledgementRepository,
    LogRepository,
    TenantRepository,
)
from src.core.infrastructure.db.models import AlertAcknowledgementModel, AuditLogModel, TenantModel


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
        tenant_filter: str | None = None,
    ) -> list[Tenant]:
        stmt = select(TenantModel)
        if tenant_filter:
            # Filtro de tenant por UUID, slug ou nome (isolamento multi-tenant na query)
            stmt = stmt.where(
                or_(
                    TenantModel.slug == tenant_filter,
                    TenantModel.name == tenant_filter,
                    TenantModel.id == tenant_filter if len(tenant_filter) == 36 else False,
                )
            )
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


class PostgresLogRepository(LogRepository):
    """
    Repositório de Logs de Auditoria com Persistência em PostgreSQL.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    def _to_entity(self, model: AuditLogModel) -> AuditLog:
        return AuditLog(
            id=model.id,
            tenant_id=model.tenant_id,
            source=model.source,
            raw_data=model.raw_data,
            timestamp=model.timestamp,
        )

    async def save(self, log: AuditLog) -> AuditLog:
        model = AuditLogModel(
            id=log.id,
            tenant_id=log.tenant_id,
            source=log.source,
            raw_data=log.raw_data,
            timestamp=log.timestamp,
        )
        self.session.add(model)
        await self.session.flush()
        return self._to_entity(model)

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        tenant_id: UUID | None = None,
        source: str | None = None,
    ) -> list[AuditLog]:
        stmt = select(AuditLogModel)
        if tenant_id:
            stmt = stmt.where(AuditLogModel.tenant_id == tenant_id)
        if source:
            stmt = stmt.where(AuditLogModel.source.ilike(f"%{source}%"))

        stmt = stmt.order_by(AuditLogModel.timestamp.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        models = result.scalars().all()
        return [self._to_entity(m) for m in models]


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


class PostgresAlertAcknowledgementRepository(AlertAcknowledgementRepository):
    """
    Repositório de Acknowledgements de Alertas com Persistência em PostgreSQL.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    def _to_entity(self, model: AlertAcknowledgementModel) -> AlertAcknowledgement:
        return AlertAcknowledgement(
            id=model.id,
            alert_id=model.alert_id,
            fingerprint=model.fingerprint,
            reason=model.reason,
            acknowledged_by=model.acknowledged_by,
            tenant_id=model.tenant_id,
            timestamp=model.timestamp,
        )

    async def save(self, ack: AlertAcknowledgement) -> AlertAcknowledgement:
        model = AlertAcknowledgementModel(
            id=ack.id,
            alert_id=ack.alert_id,
            fingerprint=ack.fingerprint,
            reason=ack.reason,
            acknowledged_by=ack.acknowledged_by,
            tenant_id=ack.tenant_id,
            timestamp=ack.timestamp,
        )
        self.session.add(model)
        await self.session.flush()
        return self._to_entity(model)


    async def get_by_fingerprint(
        self, fingerprint: str, tenant_id: str
    ) -> AlertAcknowledgement | None:
        stmt = select(AlertAcknowledgementModel).where(
            AlertAcknowledgementModel.fingerprint == fingerprint,
            AlertAcknowledgementModel.tenant_id == tenant_id,
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def list(
        self, tenant_id: str | None = None, skip: int = 0, limit: int = 100
    ) -> list[AlertAcknowledgement]:
        stmt = select(AlertAcknowledgementModel)
        if tenant_id:
            stmt = stmt.where(AlertAcknowledgementModel.tenant_id == tenant_id)
        stmt = stmt.order_by(AlertAcknowledgementModel.timestamp.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        models = result.scalars().all()
        return [self._to_entity(m) for m in models]


class InMemoryAlertAcknowledgementRepository(AlertAcknowledgementRepository):
    """
    Repositório In-Memory para Acknowledgements de Alertas.
    """

    def __init__(self) -> None:
        self._acks: list[AlertAcknowledgement] = []

    async def save(self, ack: AlertAcknowledgement) -> AlertAcknowledgement:
        for existing in self._acks:
            if existing.fingerprint == ack.fingerprint and existing.tenant_id == ack.tenant_id:
                return existing
        self._acks.insert(0, ack)
        return ack

    async def get_by_fingerprint(
        self, fingerprint: str, tenant_id: str
    ) -> AlertAcknowledgement | None:
        for ack in self._acks:
            if ack.fingerprint == fingerprint and ack.tenant_id == tenant_id:
                return ack
        return None

    async def list(
        self, tenant_id: str | None = None, skip: int = 0, limit: int = 100
    ) -> list[AlertAcknowledgement]:
        filtered = self._acks
        if tenant_id:
            filtered = [ack for ack in filtered if ack.tenant_id == tenant_id]
        return filtered[skip : skip + limit]


class InMemoryTenantRepository(TenantRepository):
    """Repositório In-Memory para Tenants (Testes)."""

    def __init__(self) -> None:
        self._tenants: dict[UUID, Tenant] = {}

    async def save(self, tenant: Tenant) -> Tenant:
        self._tenants[tenant.id] = tenant
        return tenant

    async def get_by_id(self, tenant_id: UUID) -> Tenant | None:
        return self._tenants.get(tenant_id)

    async def get_by_slug(self, slug: str) -> Tenant | None:
        for tenant in self._tenants.values():
            if tenant.slug == slug:
                return tenant
        return None

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        search: str | None = None,
        status: str | None = None,
        tenant_filter: str | None = None,
    ) -> list[Tenant]:
        results = list(self._tenants.values())
        if tenant_filter:
            results = [
                t for t in results
                if str(t.id) == tenant_filter or t.slug == tenant_filter or t.name == tenant_filter
            ]
        if search:
            s = search.lower()
            results = [t for t in results if s in t.name.lower() or s in t.slug.lower()]
        if status:
            results = [t for t in results if str(t.status) == status or (hasattr(t.status, "value") and t.status.value == status)]
        return results[skip : skip + limit]

    async def delete(self, tenant_id: UUID) -> bool:
        tenant = self._tenants.get(tenant_id)
        if tenant:
            tenant.status = TenantStatus.INACTIVE if hasattr(TenantStatus, "INACTIVE") else "INACTIVE"
            return True
        return False





