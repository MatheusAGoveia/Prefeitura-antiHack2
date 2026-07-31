import hashlib
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import and_, desc, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.application.interfaces import CorrelationUnitOfWork, SecurityEventUnitOfWork
from src.core.domain.correlation import CorrelationRuleVersion
from src.core.domain.entities import AlertAcknowledgement, AuditLog, Tenant, TenantStatus
from src.core.domain.incidents import (
    Asset,
    Incident,
    IncidentEvidence,
    IncidentStatus,
    SecurityEvent,
    SecurityEventSeverity,
)
from src.core.domain.outbox import OutboxEvent
from src.core.domain.repositories import (
    AlertAcknowledgementRepository,
    AssetRepository,
    CorrelationRuleVersionRepository,
    IncidentEvidenceRepository,
    IncidentRepository,
    LogRepository,
    OutboxRepository,
    SecurityEventRepository,
    TenantRepository,
)
from src.core.infrastructure.db.models import (
    AlertAcknowledgementModel,
    AssetModel,
    AuditLogModel,
    CorrelationRuleVersionModel,
    IncidentEvidenceModel,
    IncidentModel,
    IncidentStatusHistoryModel,
    OutboxEventModel,
    SecurityEventModel,
    TenantModel,
)


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
        tenant_filter: UUID | None = None,
    ) -> list[Tenant]:
        stmt = select(TenantModel)
        if tenant_filter:
            stmt = stmt.where(TenantModel.id == tenant_filter)
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

    @staticmethod
    def _parse_uuid(val: UUID | str | None) -> UUID | None:
        if val is None:
            return None
        if isinstance(val, UUID):
            return val
        try:
            return UUID(str(val))
        except (ValueError, TypeError) as err:
            raise ValueError(f"tenant_id deve ser um UUID válido: '{val}'") from err

    async def get_by_fingerprint(
        self, fingerprint: str, tenant_id: UUID | str
    ) -> AlertAcknowledgement | None:
        t_uuid = self._parse_uuid(tenant_id)
        stmt = select(AlertAcknowledgementModel).where(
            AlertAcknowledgementModel.fingerprint == fingerprint,
            AlertAcknowledgementModel.tenant_id == t_uuid,
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def list(
        self, tenant_id: UUID | str | None = None, skip: int = 0, limit: int = 100
    ) -> list[AlertAcknowledgement]:
        t_uuid = self._parse_uuid(tenant_id)
        stmt = select(AlertAcknowledgementModel)
        if t_uuid:
            stmt = stmt.where(AlertAcknowledgementModel.tenant_id == t_uuid)
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

    @staticmethod
    def _parse_uuid(val: UUID | str | None) -> UUID | None:
        if val is None:
            return None
        if isinstance(val, UUID):
            return val
        try:
            return UUID(str(val))
        except (ValueError, TypeError) as err:
            raise ValueError(f"tenant_id deve ser um UUID válido: '{val}'") from err

    async def save(self, ack: AlertAcknowledgement) -> AlertAcknowledgement:
        for existing in self._acks:
            if existing.fingerprint == ack.fingerprint and existing.tenant_id == ack.tenant_id:
                return existing
        self._acks.insert(0, ack)
        return ack

    async def get_by_fingerprint(
        self, fingerprint: str, tenant_id: UUID | str
    ) -> AlertAcknowledgement | None:
        t_uuid = self._parse_uuid(tenant_id)
        for ack in self._acks:
            if ack.fingerprint == fingerprint and ack.tenant_id == t_uuid:
                return ack
        return None

    async def list(
        self, tenant_id: UUID | str | None = None, skip: int = 0, limit: int = 100
    ) -> list[AlertAcknowledgement]:
        t_uuid = self._parse_uuid(tenant_id)
        filtered = self._acks
        if t_uuid:
            filtered = [ack for ack in filtered if ack.tenant_id == t_uuid]
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
        tenant_filter: UUID | None = None,
    ) -> list[Tenant]:
        results = list(self._tenants.values())
        if tenant_filter:
            results = [t for t in results if t.id == tenant_filter]
        if search:
            s = search.lower()
            results = [t for t in results if s in t.name.lower() or s in t.slug.lower()]
        if status:
            results = [
                t
                for t in results
                if str(t.status) == status
                or (hasattr(t.status, "value") and t.status.value == status)
            ]
        return results[skip : skip + limit]

    async def delete(self, tenant_id: UUID) -> bool:
        tenant = self._tenants.get(tenant_id)
        if tenant:
            tenant.status = TenantStatus.INACTIVE
            return True
        return False


class PostgresAssetRepository(AssetRepository):
    """
    Repositório de Ativos com Persistência em PostgreSQL.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    def _to_entity(self, model: AssetModel) -> Asset:
        return Asset(
            asset_id=model.asset_id,
            tenant_id=model.tenant_id,
            name=model.name,
            asset_type=model.asset_type,
            service_name=model.service_name,
            environment=model.environment,
            criticality=model.criticality,
            is_active=model.is_active,
            created_at=model.created_at,
            updated_at=model.updated_at,
            hostname_or_ip=model.hostname_or_ip,
        )

    async def save(self, asset: Asset) -> Asset:
        stmt = select(AssetModel).where(
            AssetModel.asset_id == asset.asset_id,
            AssetModel.tenant_id == asset.tenant_id,
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()

        if model is None:
            model = AssetModel(
                asset_id=asset.asset_id,
                tenant_id=asset.tenant_id,
                name=asset.name,
                asset_type=asset.asset_type,
                service_name=asset.service_name,
                environment=asset.environment,
                criticality=asset.criticality,
                is_active=asset.is_active,
                hostname_or_ip=asset.hostname_or_ip,
                created_at=asset.created_at,
                updated_at=asset.updated_at,
            )
            self.session.add(model)
        else:
            model.name = asset.name
            model.asset_type = asset.asset_type
            model.service_name = asset.service_name
            model.environment = asset.environment
            model.criticality = asset.criticality
            model.is_active = asset.is_active
            model.hostname_or_ip = asset.hostname_or_ip
            model.updated_at = asset.updated_at

        await self.session.flush()
        return self._to_entity(model)

    async def get_by_id(self, asset_id: UUID, tenant_id: UUID) -> Asset | None:
        stmt = select(AssetModel).where(
            AssetModel.asset_id == asset_id,
            AssetModel.tenant_id == tenant_id,
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def resolve_active_asset(
        self, tenant_id: UUID, service_name: str, environment: str
    ) -> Asset | None:
        stmt = select(AssetModel).where(
            AssetModel.tenant_id == tenant_id,
            AssetModel.service_name == service_name,
            AssetModel.environment == environment,
            AssetModel.is_active.is_(True),
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def list(
        self, tenant_id: UUID, skip: int = 0, limit: int = 100
    ) -> list[Asset]:
        stmt = (
            select(AssetModel)
            .where(AssetModel.tenant_id == tenant_id)
            .order_by(AssetModel.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        models = result.scalars().all()
        return [self._to_entity(m) for m in models]


class PostgresSecurityEventRepository(SecurityEventRepository):
    """
    Repositório de Eventos de Segurança com Persistência em PostgreSQL e Idempotência Atômica.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    def _to_entity(self, model: SecurityEventModel) -> SecurityEvent:
        severity_enum = (
            SecurityEventSeverity(model.severity)
            if isinstance(model.severity, str)
            else model.severity
        )
        return SecurityEvent(
            event_id=model.event_id,
            tenant_id=model.tenant_id,
            source=model.source,
            event_type=model.event_type,
            severity=severity_enum,
            occurred_at=model.occurred_at,
            received_at=model.received_at,
            asset_id=model.asset_id,
            payload=model.payload,
            idempotency_key=model.idempotency_key,
            is_asset_resolved=model.is_asset_resolved,
            evidence_hash=model.evidence_hash,
        )

    async def save(self, event: SecurityEvent) -> tuple[SecurityEvent, bool]:
        existing = await self.get_by_idempotency_key(
            tenant_id=event.tenant_id,
            source=event.source,
            idempotency_key=event.idempotency_key,
        )
        if existing is not None:
            return existing, False

        severity_str = (
            event.severity.value if hasattr(event.severity, "value") else str(event.severity)
        )
        model = SecurityEventModel(
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            asset_id=event.asset_id,
            source=event.source,
            event_type=event.event_type,
            severity=severity_str,
            occurred_at=event.occurred_at,
            received_at=event.received_at,
            payload=event.payload,
            evidence_hash=event.evidence_hash,
            idempotency_key=event.idempotency_key,
            is_asset_resolved=event.is_asset_resolved,
        )

        try:
            async with self.session.begin_nested():
                self.session.add(model)
                await self.session.flush()
            return self._to_entity(model), True
        except IntegrityError:
            existing_after_conflict = await self.get_by_idempotency_key(
                tenant_id=event.tenant_id,
                source=event.source,
                idempotency_key=event.idempotency_key,
            )
            if existing_after_conflict is not None:
                return existing_after_conflict, False
            raise

    async def get_by_id(self, event_id: UUID, tenant_id: UUID) -> SecurityEvent | None:
        stmt = select(SecurityEventModel).where(
            SecurityEventModel.event_id == event_id,
            SecurityEventModel.tenant_id == tenant_id,
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def get_by_idempotency_key(
        self, tenant_id: UUID, source: str, idempotency_key: str
    ) -> SecurityEvent | None:
        stmt = select(SecurityEventModel).where(
            SecurityEventModel.tenant_id == tenant_id,
            SecurityEventModel.source == source,
            SecurityEventModel.idempotency_key == idempotency_key,
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def list(
        self,
        tenant_id: UUID,
        skip: int = 0,
        limit: int = 100,
        asset_id: UUID | None = None,
    ) -> list[SecurityEvent]:
        stmt = select(SecurityEventModel).where(SecurityEventModel.tenant_id == tenant_id)
        if asset_id is not None:
            stmt = stmt.where(SecurityEventModel.asset_id == asset_id)
        stmt = stmt.order_by(SecurityEventModel.occurred_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        models = result.scalars().all()
        return [self._to_entity(m) for m in models]


class PostgresCorrelationRuleVersionRepository(CorrelationRuleVersionRepository):
    """
    Repositório de Versões de Regras de Correlação com Persistência em PostgreSQL.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    def _to_entity(self, model: CorrelationRuleVersionModel) -> CorrelationRuleVersion:
        return CorrelationRuleVersion(
            rule_version_id=model.rule_version_id,
            rule_id=model.rule_id,
            rule_version=model.rule_version,
            name=model.name,
            category=model.category,
            is_active=model.is_active,
            created_at=model.created_at,
        )

    async def save(
        self, rule_version: CorrelationRuleVersion
    ) -> CorrelationRuleVersion:
        stmt = select(CorrelationRuleVersionModel).where(
            CorrelationRuleVersionModel.rule_id == rule_version.rule_id,
            CorrelationRuleVersionModel.rule_version == rule_version.rule_version,
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()

        if model is None:
            model = CorrelationRuleVersionModel(
                rule_version_id=rule_version.rule_version_id,
                rule_id=rule_version.rule_id,
                rule_version=rule_version.rule_version,
                name=rule_version.name,
                category=rule_version.category,
                is_active=rule_version.is_active,
                created_at=rule_version.created_at,
            )
            self.session.add(model)
        else:
            model.name = rule_version.name
            model.category = rule_version.category
            model.is_active = rule_version.is_active

        await self.session.flush()
        return self._to_entity(model)

    async def get_by_rule_and_version(
        self, rule_id: str, version: str
    ) -> CorrelationRuleVersion | None:
        stmt = select(CorrelationRuleVersionModel).where(
            CorrelationRuleVersionModel.rule_id == rule_id,
            CorrelationRuleVersionModel.rule_version == version,
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def list_active(
        self, skip: int = 0, limit: int = 100
    ) -> list[CorrelationRuleVersion]:
        stmt = (
            select(CorrelationRuleVersionModel)
            .where(CorrelationRuleVersionModel.is_active.is_(True))
            .order_by(
                CorrelationRuleVersionModel.rule_id,
                CorrelationRuleVersionModel.rule_version,
            )
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        models = result.scalars().all()
        return [self._to_entity(m) for m in models]


class InMemoryAssetRepository(AssetRepository):
    def __init__(self) -> None:
        self._assets: dict[UUID, Asset] = {}

    async def save(self, asset: Asset) -> Asset:
        self._assets[asset.asset_id] = asset
        return asset

    async def get_by_id(self, asset_id: UUID, tenant_id: UUID) -> Asset | None:
        asset = self._assets.get(asset_id)
        if asset and asset.tenant_id == tenant_id:
            return asset
        return None

    async def resolve_active_asset(
        self, tenant_id: UUID, service_name: str, environment: str
    ) -> Asset | None:
        for asset in self._assets.values():
            if (
                asset.tenant_id == tenant_id
                and asset.service_name == service_name
                and asset.environment == environment
                and asset.is_active
            ):
                return asset
        return None

    async def list(
        self, tenant_id: UUID, skip: int = 0, limit: int = 100
    ) -> list[Asset]:
        filtered = [a for a in self._assets.values() if a.tenant_id == tenant_id]
        return filtered[skip : skip + limit]


class InMemorySecurityEventRepository(SecurityEventRepository):
    def __init__(self) -> None:
        self._events: dict[UUID, SecurityEvent] = {}

    async def save(self, event: SecurityEvent) -> tuple[SecurityEvent, bool]:
        existing = await self.get_by_idempotency_key(
            tenant_id=event.tenant_id,
            source=event.source,
            idempotency_key=event.idempotency_key,
        )
        if existing is not None:
            return existing, False

        self._events[event.event_id] = event
        return event, True

    async def get_by_id(self, event_id: UUID, tenant_id: UUID) -> SecurityEvent | None:
        evt = self._events.get(event_id)
        if evt and evt.tenant_id == tenant_id:
            return evt
        return None

    async def get_by_idempotency_key(
        self, tenant_id: UUID, source: str, idempotency_key: str
    ) -> SecurityEvent | None:
        for evt in self._events.values():
            if (
                evt.tenant_id == tenant_id
                and evt.source == source
                and evt.idempotency_key == idempotency_key
            ):
                return evt
        return None

    async def list(
        self,
        tenant_id: UUID,
        skip: int = 0,
        limit: int = 100,
        asset_id: UUID | None = None,
    ) -> list[SecurityEvent]:
        filtered = [e for e in self._events.values() if e.tenant_id == tenant_id]
        if asset_id is not None:
            filtered = [e for e in filtered if e.asset_id == asset_id]
        return filtered[skip : skip + limit]


class InMemoryCorrelationRuleVersionRepository(CorrelationRuleVersionRepository):
    def __init__(self) -> None:
        self._rules: dict[UUID, CorrelationRuleVersion] = {}

    async def save(
        self, rule_version: CorrelationRuleVersion
    ) -> CorrelationRuleVersion:
        self._rules[rule_version.rule_version_id] = rule_version
        return rule_version

    async def get_by_rule_and_version(
        self, rule_id: str, version: str
    ) -> CorrelationRuleVersion | None:
        for rv in self._rules.values():
            if rv.rule_id == rule_id and rv.rule_version == version:
                return rv
        return None

    async def list_active(
        self, skip: int = 0, limit: int = 100
    ) -> list[CorrelationRuleVersion]:
        filtered = [rv for rv in self._rules.values() if rv.is_active]
        return filtered[skip : skip + limit]


class PostgresOutboxRepository(OutboxRepository):
    """
    Repositório de Mensagens do Transactional Outbox em PostgreSQL.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    def _to_entity(self, model: OutboxEventModel) -> OutboxEvent:
        return OutboxEvent(
            outbox_event_id=model.outbox_event_id,
            tenant_id=model.tenant_id,
            aggregate_type=model.aggregate_type,
            aggregate_id=model.aggregate_id,
            event_type=model.event_type,
            payload=model.payload,
            idempotency_key=model.idempotency_key,
            status=model.status,
            retry_count=model.retry_count,
            next_retry_at=model.next_retry_at,
            created_at=model.created_at,
            published_at=model.published_at,
            last_error=model.last_error,
        )

    async def save(self, outbox_event: OutboxEvent) -> OutboxEvent:
        model = OutboxEventModel(
            outbox_event_id=outbox_event.outbox_event_id,
            tenant_id=outbox_event.tenant_id,
            aggregate_type=outbox_event.aggregate_type,
            aggregate_id=outbox_event.aggregate_id,
            event_type=outbox_event.event_type,
            payload=outbox_event.payload,
            idempotency_key=outbox_event.idempotency_key,
            status=outbox_event.status,
            retry_count=outbox_event.retry_count,
            next_retry_at=outbox_event.next_retry_at,
            created_at=outbox_event.created_at,
            published_at=outbox_event.published_at,
            last_error=outbox_event.last_error,
        )
        self.session.add(model)
        await self.session.flush()
        return self._to_entity(model)

    async def fetch_pending_and_claim(
        self, limit: int = 100, lease_seconds: int = 30, lock_for_update: bool = True
    ) -> list[OutboxEvent]:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=lease_seconds)
        stmt = (
            select(OutboxEventModel)
            .where(
                or_(
                    OutboxEventModel.status == "pending",
                    and_(
                        OutboxEventModel.status == "failed",
                        OutboxEventModel.next_retry_at <= now,
                    ),
                    and_(
                        OutboxEventModel.status == "processing",
                        OutboxEventModel.claim_expires_at <= now,
                    ),
                )
            )
            .order_by(OutboxEventModel.created_at.asc())
            .limit(limit)
        )

        if lock_for_update and self.session.bind and self.session.bind.dialect.name == "postgresql":
            stmt = stmt.with_for_update(skip_locked=True)

        result = await self.session.execute(stmt)
        models = list(result.scalars().all())

        claimed_entities: list[OutboxEvent] = []
        for model in models:
            if model.status == "processing":
                model.retry_count += 1
            model.status = "processing"
            model.claimed_at = now
            model.claim_expires_at = expires_at
            claimed_entities.append(self._to_entity(model))

        await self.session.flush()
        return claimed_entities

    async def mark_published(self, outbox_event_id: UUID) -> None:
        stmt = select(OutboxEventModel).where(OutboxEventModel.outbox_event_id == outbox_event_id)
        res = await self.session.execute(stmt)
        model = res.scalar_one_or_none()
        if model:
            model.status = "published"
            model.published_at = datetime.now(timezone.utc)
            model.claim_expires_at = None
            await self.session.flush()

    async def mark_failed(
        self,
        outbox_event_id: UUID,
        error_message: str,
        max_retries: int = 5,
        backoff_seconds: int = 10,
    ) -> None:
        stmt = select(OutboxEventModel).where(OutboxEventModel.outbox_event_id == outbox_event_id)
        res = await self.session.execute(stmt)
        model = res.scalar_one_or_none()
        if model:
            model.retry_count += 1
            sanitized_err = error_message[:1024]
            model.last_error = sanitized_err
            model.claim_expires_at = None
            if model.retry_count >= max_retries:
                model.status = "failed"
                model.next_retry_at = None
            else:
                model.status = "failed"
                delay = backoff_seconds * (2 ** (model.retry_count - 1))
                model.next_retry_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
            await self.session.flush()


class InMemoryOutboxRepository(OutboxRepository):
    """
    Repositório InMemory de Mensagens do Transactional Outbox para Testes.
    """

    def __init__(self) -> None:
        self.events: dict[UUID, OutboxEvent] = {}

    async def save(self, outbox_event: OutboxEvent) -> OutboxEvent:
        self.events[outbox_event.outbox_event_id] = outbox_event
        return outbox_event

    async def fetch_pending_and_claim(
        self, limit: int = 100, lease_seconds: int = 30, lock_for_update: bool = True
    ) -> list[OutboxEvent]:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=lease_seconds)
        claimed: list[OutboxEvent] = []
        for evt in list(self.events.values()):
            if len(claimed) >= limit:
                break
            is_pending = evt.status == "pending"
            is_failed_eligible = (
                evt.status == "failed" and evt.next_retry_at and evt.next_retry_at <= now
            )
            is_lease_expired = (
                evt.status == "processing" and evt.claim_expires_at and evt.claim_expires_at <= now
            )

            if is_pending or is_failed_eligible or is_lease_expired:
                new_retries = evt.retry_count + 1 if is_lease_expired else evt.retry_count
                updated_evt = OutboxEvent(
                    outbox_event_id=evt.outbox_event_id,
                    tenant_id=evt.tenant_id,
                    aggregate_type=evt.aggregate_type,
                    aggregate_id=evt.aggregate_id,
                    event_type=evt.event_type,
                    payload=evt.payload,
                    idempotency_key=evt.idempotency_key,
                    status="processing",
                    retry_count=new_retries,
                    next_retry_at=evt.next_retry_at,
                    claimed_at=now,
                    claim_expires_at=expires_at,
                    created_at=evt.created_at,
                    published_at=evt.published_at,
                    last_error=evt.last_error,
                )
                self.events[evt.outbox_event_id] = updated_evt
                claimed.append(updated_evt)
        return claimed

    async def mark_published(self, outbox_event_id: UUID) -> None:
        if outbox_event_id in self.events:
            evt = self.events[outbox_event_id]
            updated = OutboxEvent(
                outbox_event_id=evt.outbox_event_id,
                tenant_id=evt.tenant_id,
                aggregate_type=evt.aggregate_type,
                aggregate_id=evt.aggregate_id,
                event_type=evt.event_type,
                payload=evt.payload,
                idempotency_key=evt.idempotency_key,
                status="published",
                retry_count=evt.retry_count,
                next_retry_at=evt.next_retry_at,
                claimed_at=evt.claimed_at,
                claim_expires_at=None,
                created_at=evt.created_at,
                published_at=datetime.now(timezone.utc),
                last_error=evt.last_error,
            )
            self.events[outbox_event_id] = updated

    async def mark_failed(
        self,
        outbox_event_id: UUID,
        error_message: str,
        max_retries: int = 5,
        backoff_seconds: int = 10,
    ) -> None:
        if outbox_event_id in self.events:
            evt = self.events[outbox_event_id]
            new_retries = evt.retry_count + 1
            sanitized_err = error_message[:1024]
            if new_retries >= max_retries:
                next_retry = None
            else:
                delay = backoff_seconds * (2 ** (new_retries - 1))
                next_retry = datetime.now(timezone.utc) + timedelta(seconds=delay)

            updated = OutboxEvent(
                outbox_event_id=evt.outbox_event_id,
                tenant_id=evt.tenant_id,
                aggregate_type=evt.aggregate_type,
                aggregate_id=evt.aggregate_id,
                event_type=evt.event_type,
                payload=evt.payload,
                idempotency_key=evt.idempotency_key,
                status="failed",
                retry_count=new_retries,
                next_retry_at=next_retry,
                claimed_at=evt.claimed_at,
                claim_expires_at=None,
                created_at=evt.created_at,
                published_at=evt.published_at,
                last_error=sanitized_err,
            )
            self.events[outbox_event_id] = updated


class InMemorySecurityEventUnitOfWork(SecurityEventUnitOfWork):
    """
    Unit of Work InMemory para testes da camada de aplicação e domínio.
    """

    def __init__(
        self,
        assets: AssetRepository | None = None,
        security_events: SecurityEventRepository | None = None,
        logs: LogRepository | None = None,
        outbox: OutboxRepository | None = None,
        tenants: TenantRepository | None = None,
    ) -> None:
        self._assets = assets or InMemoryAssetRepository()
        self._security_events = security_events or InMemorySecurityEventRepository()
        self._logs = logs or InMemoryLogRepository()
        self._outbox = outbox or InMemoryOutboxRepository()
        self._tenants = tenants or InMemoryTenantRepository()
        self.committed = False
        self.rolled_back = False

    @property
    def tenants(self) -> TenantRepository:
        return self._tenants

    @property
    def assets(self) -> AssetRepository:
        return self._assets

    @property
    def security_events(self) -> SecurityEventRepository:
        return self._security_events

    @property
    def logs(self) -> LogRepository:
        return self._logs

    @property
    def outbox(self) -> OutboxRepository:
        return self._outbox

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True


# ---------------------------------------------------------------------------
# M3.2 — Repositórios Postgres para Incidentes e Evidências
# ---------------------------------------------------------------------------

_ACTIVE_INCIDENT_STATUSES = (
    IncidentStatus.OPEN,
    IncidentStatus.ACKNOWLEDGED,
    IncidentStatus.INVESTIGATING,
    IncidentStatus.CONTAINED,
)


class PostgresIncidentRepository(IncidentRepository):
    """Repositório Postgres de Incidentes (M3.2). Isolamento estrito por tenant_id."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def _to_entity(self, model: IncidentModel) -> Incident:
        return Incident(
            incident_id=model.incident_id,
            tenant_id=model.tenant_id,
            title=model.title,
            description=model.description,
            severity=SecurityEventSeverity(model.severity),
            status=IncidentStatus(model.status),
            correlation_key=model.correlation_key,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )

    async def save(self, incident: Incident) -> Incident:
        stmt = select(IncidentModel).where(
            and_(
                IncidentModel.incident_id == incident.incident_id,
                IncidentModel.tenant_id == incident.tenant_id,
            )
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()

        key_hash = hashlib.sha256(
            incident.correlation_key.encode("utf-8")
        ).hexdigest()

        if model is None:
            model = IncidentModel(
                incident_id=incident.incident_id,
                tenant_id=incident.tenant_id,
                title=incident.title,
                description=incident.description,
                severity=incident.severity.value,
                status=incident.status.value,
                correlation_key=incident.correlation_key,
                correlation_key_hash=key_hash,
                created_at=incident.created_at,
                updated_at=incident.updated_at,
            )
            self.session.add(model)
            try:
                async with self.session.begin_nested():
                    await self.session.flush()
            except IntegrityError:
                # Concorrência: se outra transação criou o mesmo incidente ativo no mesmo instante
                existing = await self.find_open_by_correlation_key(
                    tenant_id=incident.tenant_id,
                    correlation_key_hash=key_hash,
                )
                if existing is not None:
                    return existing
                raise
        else:
            model.title = incident.title
            model.description = incident.description
            model.severity = incident.severity.value
            model.status = incident.status.value
            model.updated_at = incident.updated_at
            await self.session.flush()

        # Persistir histórico de auditoria pendente na mesma transação
        if incident.audit_history:
            for change in incident.audit_history:
                history_model = IncidentStatusHistoryModel(
                    history_id=uuid4(),
                    incident_id=incident.incident_id,
                    tenant_id=incident.tenant_id,
                    from_status=change.from_status.value,
                    to_status=change.to_status.value,
                    actor_id=change.actor_id,
                    reason=change.reason,
                    timestamp=change.timestamp,
                )
                self.session.add(history_model)
            await self.session.flush()

        return self._to_entity(model)

    async def get_by_id(self, incident_id: UUID, tenant_id: UUID) -> Incident | None:
        stmt = select(IncidentModel).where(
            and_(
                IncidentModel.incident_id == incident_id,
                IncidentModel.tenant_id == tenant_id,
            )
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def find_open_by_correlation_key(
        self, tenant_id: UUID, correlation_key_hash: str
    ) -> Incident | None:
        """Busca incidente ATIVO (status em 'open','acknowledged','investigating','contained')."""
        active_values = [s.value for s in _ACTIVE_INCIDENT_STATUSES]
        stmt = select(IncidentModel).where(
            and_(
                IncidentModel.tenant_id == tenant_id,
                IncidentModel.correlation_key_hash == correlation_key_hash,
                IncidentModel.status.in_(active_values),
            )
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def count(
        self,
        tenant_id: UUID,
        status: str | None = None,
    ) -> int:
        from sqlalchemy import func
        stmt = select(func.count()).select_from(IncidentModel).where(IncidentModel.tenant_id == tenant_id)
        if status:
            stmt = stmt.where(IncidentModel.status == status)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def list(
        self,
        tenant_id: UUID,
        skip: int = 0,
        limit: int = 50,
        status: str | None = None,
    ) -> list[Incident]:
        """Lista incidentes do tenant com ordenação estável created_at DESC, incident_id DESC."""
        stmt = select(IncidentModel).where(IncidentModel.tenant_id == tenant_id)
        if status:
            stmt = stmt.where(IncidentModel.status == status)
        stmt = stmt.order_by(
            desc(IncidentModel.created_at), desc(IncidentModel.incident_id)
        ).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return [self._to_entity(m) for m in result.scalars().all()]


class PostgresIncidentEvidenceRepository(IncidentEvidenceRepository):
    """Repositório Postgres de Evidências de Incidentes (M3.2). Idempotente via UQ e SAVEPOINT."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def _to_entity(self, model: IncidentEvidenceModel) -> IncidentEvidence:
        return IncidentEvidence(
            evidence_id=model.evidence_id,
            incident_id=model.incident_id,
            event_id=model.event_id,
            tenant_id=model.tenant_id,
            evidence_hash=model.evidence_hash,
            added_at=model.added_at,
            description=model.description,
            raw_payload_masked=model.raw_payload_masked,
        )

    async def save(self, evidence: IncidentEvidence) -> IncidentEvidence:
        """
        Persiste uma evidência. Se UNIQUE(incident_id, event_id) violar (replay),
        busca e retorna a evidência existente silenciosamente.
        Usa SAVEPOINT para idempotência atômica sem invalidar a transação pai.
        """
        already_exists = await self.exists(
            incident_id=evidence.incident_id,
            event_id=evidence.event_id,
            tenant_id=evidence.tenant_id,
        )
        if already_exists:
            stmt = select(IncidentEvidenceModel).where(
                and_(
                    IncidentEvidenceModel.incident_id == evidence.incident_id,
                    IncidentEvidenceModel.event_id == evidence.event_id,
                    IncidentEvidenceModel.tenant_id == evidence.tenant_id,
                )
            )
            result = await self.session.execute(stmt)
            return self._to_entity(result.scalar_one())

        model = IncidentEvidenceModel(
            evidence_id=evidence.evidence_id,
            incident_id=evidence.incident_id,
            tenant_id=evidence.tenant_id,
            event_id=evidence.event_id,
            evidence_hash=evidence.evidence_hash,
            description=evidence.description,
            raw_payload_masked=evidence.raw_payload_masked,
            added_at=evidence.added_at,
        )
        self.session.add(model)
        try:
            async with self.session.begin_nested():
                await self.session.flush()
        except IntegrityError:
            stmt = select(IncidentEvidenceModel).where(
                and_(
                    IncidentEvidenceModel.incident_id == evidence.incident_id,
                    IncidentEvidenceModel.event_id == evidence.event_id,
                    IncidentEvidenceModel.tenant_id == evidence.tenant_id,
                )
            )
            result = await self.session.execute(stmt)
            return self._to_entity(result.scalar_one())

        return self._to_entity(model)

    async def exists(
        self, incident_id: UUID, event_id: UUID, tenant_id: UUID
    ) -> bool:
        stmt = select(IncidentEvidenceModel.evidence_id).where(
            and_(
                IncidentEvidenceModel.incident_id == incident_id,
                IncidentEvidenceModel.event_id == event_id,
                IncidentEvidenceModel.tenant_id == tenant_id,
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def list_by_incident(
        self, incident_id: UUID, tenant_id: UUID
    ) -> list[IncidentEvidence]:
        stmt = select(IncidentEvidenceModel).where(
            and_(
                IncidentEvidenceModel.incident_id == incident_id,
                IncidentEvidenceModel.tenant_id == tenant_id,
            )
        ).order_by(IncidentEvidenceModel.added_at)
        result = await self.session.execute(stmt)
        return [self._to_entity(m) for m in result.scalars().all()]


# ---------------------------------------------------------------------------
# M3.2 — PostgresCorrelationUnitOfWork
# ---------------------------------------------------------------------------


class PostgresCorrelationUnitOfWork(CorrelationUnitOfWork):
    """
    Unit of Work Postgres para o motor de correlação (M3.2).
    Todos os repositórios compartilham a mesma AsyncSession (mesma transação).
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self._security_events = PostgresSecurityEventRepository(session)
        self._correlation_rules = PostgresCorrelationRuleVersionRepository(session)
        self._incidents = PostgresIncidentRepository(session)
        self._evidences = PostgresIncidentEvidenceRepository(session)
        self._logs = PostgresLogRepository(session)

    @property
    def security_events(self) -> PostgresSecurityEventRepository:
        return self._security_events

    @property
    def correlation_rules(self) -> PostgresCorrelationRuleVersionRepository:
        return self._correlation_rules

    @property
    def incidents(self) -> PostgresIncidentRepository:
        return self._incidents

    @property
    def evidences(self) -> PostgresIncidentEvidenceRepository:
        return self._evidences

    @property
    def logs(self) -> PostgresLogRepository:
        return self._logs

    async def __aenter__(self) -> "PostgresCorrelationUnitOfWork":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        if exc_type is not None:
            await self.rollback()
        await self.session.close()

    async def commit(self) -> None:
        await self.session.commit()

    async def rollback(self) -> None:
        await self.session.rollback()
