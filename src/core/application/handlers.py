"""
Command Handlers da Aplicação
GovSec Shield — Command Handlers
"""

import re
from datetime import datetime, timezone
from uuid import UUID

from src.core.application.commands import (
    AcknowledgeAlertCommand,
    CreateTenantCommand,
    DeleteTenantCommand,
    IngestLogCommand,
    IngestSecurityEventCommand,
    UpdateTenantCommand,
)
from src.core.application.dto import (
    AlertAcknowledgementResponseDTO,
    SecurityEventResponseDTO,
    TenantResponseDTO,
)
from src.core.application.interfaces import IEventPublisher
from src.core.domain.entities import AlertAcknowledgement, AuditLog, Tenant, TenantStatus
from src.core.domain.events import (
    AlertAcknowledgedEvent,
    LogIngestedEvent,
    SecurityEventReceivedEvent,
    TenantCreatedEvent,
)
from src.core.domain.exceptions import DomainError
from src.core.domain.incidents import SecurityEvent, SecurityEventSeverity
from src.core.domain.repositories import (
    AlertAcknowledgementRepository,
    AssetRepository,
    LogRepository,
    SecurityEventRepository,
    TenantRepository,
)


class CreateTenantHandler:
    def __init__(self, tenant_repo: TenantRepository, event_publisher: IEventPublisher):
        self.tenant_repo = tenant_repo
        self.event_publisher = event_publisher

    async def handle(self, command: CreateTenantCommand) -> TenantResponseDTO:
        name = command.payload["name"]
        slug = command.payload.get("slug")

        if not slug:
            slug = re.sub(r"[^\w]+", "-", name.lower()).strip("-")

        existing = await self.tenant_repo.get_by_slug(slug)
        if existing:
            raise ValueError(f"Já existe um Tenant registrado com o slug '{slug}'")

        tenant = Tenant(name=name, slug=slug, status=TenantStatus.ACTIVE)

        saved = await self.tenant_repo.save(tenant)

        event = TenantCreatedEvent(tenant_id=saved.id, name=saved.name, slug=saved.slug)
        await self.event_publisher.publish(event)

        return TenantResponseDTO(
            id=saved.id,
            name=saved.name,
            slug=saved.slug,
            status=saved.status.value,
            created_at=saved.created_at,
            updated_at=saved.updated_at,
        )


class UpdateTenantHandler:
    def __init__(self, tenant_repo: TenantRepository):
        self.tenant_repo = tenant_repo

    async def handle(self, command: UpdateTenantCommand) -> TenantResponseDTO:
        tenant_id = UUID(command.payload["tenant_id"])
        tenant = await self.tenant_repo.get_by_id(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant com ID '{tenant_id}' não foi encontrado.")

        name = command.payload.get("name")
        status_str = command.payload.get("status")

        if name:
            tenant.update_name(name)
        if status_str:
            tenant.status = TenantStatus(status_str)
            tenant.updated_at = datetime.now(timezone.utc)

        saved = await self.tenant_repo.save(tenant)
        return TenantResponseDTO(
            id=saved.id,
            name=saved.name,
            slug=saved.slug,
            status=saved.status.value,
            created_at=saved.created_at,
            updated_at=saved.updated_at,
        )


class DeleteTenantHandler:
    def __init__(self, tenant_repo: TenantRepository):
        self.tenant_repo = tenant_repo

    async def handle(self, command: DeleteTenantCommand) -> bool:
        tenant_id = UUID(command.payload["tenant_id"])
        tenant = await self.tenant_repo.get_by_id(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant com ID '{tenant_id}' não foi encontrado.")

        return await self.tenant_repo.delete(tenant_id)


class IngestLogHandler:
    def __init__(self, event_publisher: IEventPublisher, log_repo: LogRepository | None = None):
        self.event_publisher = event_publisher
        self.log_repo = log_repo

    async def handle(self, command: IngestLogCommand) -> None:
        source = command.payload["source"]
        raw_data = command.payload["raw_data"]
        tenant_id_str = command.payload["tenant_id"]
        try:
            tenant_id = UUID(str(tenant_id_str))
        except (ValueError, TypeError) as err:
            raise ValueError(f"tenant_id deve ser um UUID válido: '{tenant_id_str}'") from err

        timestamp_str = command.payload.get("timestamp")
        timestamp = (
            datetime.fromisoformat(timestamp_str) if timestamp_str else datetime.now(timezone.utc)
        )

        log_entity = AuditLog(
            tenant_id=tenant_id,
            source=source,
            raw_data=raw_data if isinstance(raw_data, str) else str(raw_data),
            timestamp=timestamp,
        )
        if self.log_repo:
            await self.log_repo.save(log_entity)

        event = LogIngestedEvent(
            tenant_id=tenant_id, source=source, raw_data=raw_data, timestamp=timestamp
        )

        await self.event_publisher.publish(event)


class AcknowledgeAlertHandler:
    def __init__(
        self,
        ack_repo: AlertAcknowledgementRepository,
        event_publisher: IEventPublisher,
    ):
        self.ack_repo = ack_repo
        self.event_publisher = event_publisher

    async def handle(self, command: AcknowledgeAlertCommand) -> AlertAcknowledgementResponseDTO:
        alert_id = command.payload["alert_id"]
        fingerprint = command.payload["fingerprint"]
        reason = command.payload["reason"]
        acknowledged_by = command.payload["acknowledged_by"]
        raw_tenant = command.payload.get("tenant_id")
        if isinstance(raw_tenant, UUID):
            tenant_id = raw_tenant
        elif raw_tenant:
            try:
                tenant_id = UUID(str(raw_tenant))
            except (ValueError, TypeError) as err:
                raise ValueError(f"tenant_id deve ser um UUID válido: '{raw_tenant}'") from err
        else:
            raise ValueError("tenant_id é obrigatório e deve ser um UUID válido.")

        existing = await self.ack_repo.get_by_fingerprint(fingerprint, tenant_id)
        if existing:
            return AlertAcknowledgementResponseDTO(
                id=existing.id,
                alert_id=existing.alert_id,
                fingerprint=existing.fingerprint,
                reason=existing.reason,
                acknowledged_by=existing.acknowledged_by,
                tenant_id=existing.tenant_id,
                timestamp=existing.timestamp,
            )

        ack_entity = AlertAcknowledgement(
            alert_id=alert_id,
            fingerprint=fingerprint,
            reason=reason,
            acknowledged_by=acknowledged_by,
            tenant_id=tenant_id,
        )

        saved = await self.ack_repo.save(ack_entity)

        event = AlertAcknowledgedEvent(
            alert_id=saved.alert_id,
            fingerprint=saved.fingerprint,
            reason=saved.reason,
            acknowledged_by=saved.acknowledged_by,
        )
        await self.event_publisher.publish(event)

        return AlertAcknowledgementResponseDTO(
            id=saved.id,
            alert_id=saved.alert_id,
            fingerprint=saved.fingerprint,
            reason=saved.reason,
            acknowledged_by=saved.acknowledged_by,
            tenant_id=saved.tenant_id,
            timestamp=saved.timestamp,
        )


class IngestSecurityEventHandler:
    """
    Handler CQRS para ingestão assíncrona, idempotente e auditável de SecurityEvent (M3.1).
    """

    def __init__(
        self,
        asset_repo: AssetRepository,
        security_event_repo: SecurityEventRepository,
        event_publisher: IEventPublisher,
        log_repo: LogRepository | None = None,
    ):
        self.asset_repo = asset_repo
        self.security_event_repo = security_event_repo
        self.event_publisher = event_publisher
        self.log_repo = log_repo

    async def handle(self, command: IngestSecurityEventCommand) -> SecurityEventResponseDTO:
        cmd_p = command.payload

        # 1. Validar tenant_id UUID
        raw_tenant = cmd_p["tenant_id"]
        if isinstance(raw_tenant, UUID):
            tenant_id = raw_tenant
        else:
            try:
                tenant_id = UUID(str(raw_tenant))
            except (ValueError, TypeError) as err:
                raise DomainError(f"tenant_id deve ser um UUID válido: '{raw_tenant}'") from err

        source = str(cmd_p["source"]).strip()
        event_type = str(cmd_p["event_type"]).strip()
        severity_val = cmd_p["severity"]
        severity_enum = (
            SecurityEventSeverity(severity_val)
            if isinstance(severity_val, str) and severity_val in SecurityEventSeverity.__members__
            else SecurityEventSeverity.HIGH
        )

        occurred_at_raw = cmd_p["occurred_at"]
        occurred_at = (
            datetime.fromisoformat(occurred_at_raw)
            if isinstance(occurred_at_raw, str)
            else occurred_at_raw
        )

        received_at_raw = cmd_p.get("received_at") or datetime.now(timezone.utc)
        received_at = (
            datetime.fromisoformat(received_at_raw)
            if isinstance(received_at_raw, str)
            else received_at_raw
        )

        idempotency_key = str(cmd_p["idempotency_key"]).strip()
        raw_payload = cmd_p.get("payload") or {}

        service_name = cmd_p.get("service_name")
        environment = cmd_p.get("environment")

        # 2. Resolução de Ativo por tenant_id, service_name e environment
        resolved_asset = None
        if service_name and environment:
            resolved_asset = await self.asset_repo.resolve_active_asset(
                tenant_id=tenant_id,
                service_name=service_name,
                environment=environment,
            )

        asset_id = resolved_asset.asset_id if resolved_asset else None
        is_asset_resolved = resolved_asset is not None

        # 3. Construção da Entidade de Domínio M3.0
        event_domain = SecurityEvent(
            tenant_id=tenant_id,
            source=source,
            event_type=event_type,
            severity=severity_enum,
            occurred_at=occurred_at,
            received_at=received_at,
            asset_id=asset_id,
            payload=raw_payload,
            idempotency_key=idempotency_key,
            is_asset_resolved=is_asset_resolved,
        )

        # 4. Caso o ativo não tenha sido resolvido, criar contrato UnresolvedAssetEvent (para rastreabilidade)
        if not is_asset_resolved:
            unresolved_event = event_domain.create_unresolved_asset_event()
            if self.log_repo and unresolved_event:
                audit_unresolved = AuditLog(
                    tenant_id=tenant_id,
                    source="SecurityEventIngestion",
                    raw_data=f"UnresolvedAssetEvent created for event_id={event_domain.event_id}, source={source}",
                )
                await self.log_repo.save(audit_unresolved)

        # 5. Persistência transacional no PostgreSQL
        saved_event, created = await self.security_event_repo.save(event_domain)

        # 6. Replay duplicado: retornar DTO suprimido sem republicar
        if not created:
            if self.log_repo:
                audit_suppressed = AuditLog(
                    tenant_id=tenant_id,
                    source="SecurityEventIngestion",
                    raw_data=f"Duplicate event suppressed. IdempotencyKey={idempotency_key}, Source={source}",
                )
                await self.log_repo.save(audit_suppressed)

            return SecurityEventResponseDTO(
                event_id=saved_event.event_id,
                tenant_id=saved_event.tenant_id,
                asset_id=saved_event.asset_id,
                source=saved_event.source,
                event_type=saved_event.event_type,
                severity=saved_event.severity.value
                if hasattr(saved_event.severity, "value")
                else str(saved_event.severity),
                occurred_at=saved_event.occurred_at,
                received_at=saved_event.received_at,
                idempotency_key=saved_event.idempotency_key,
                is_asset_resolved=saved_event.is_asset_resolved,
                evidence_hash=saved_event.evidence_hash,
                is_duplicate_suppressed=True,
            )

        # 7. Novo evento persistido com sucesso: auditar e publicar pós-commit
        if self.log_repo:
            audit_persisted = AuditLog(
                tenant_id=tenant_id,
                source="SecurityEventIngestion",
                raw_data=f"SecurityEvent persisted. EventID={saved_event.event_id}, IdempotencyKey={idempotency_key}",
            )
            await self.log_repo.save(audit_persisted)

        evt_received = SecurityEventReceivedEvent(
            tenant_id=saved_event.tenant_id,
            security_event_id=saved_event.event_id,
            source=saved_event.source,
            security_event_type=saved_event.event_type,
            severity=saved_event.severity.value
            if hasattr(saved_event.severity, "value")
            else str(saved_event.severity),
            is_asset_resolved=saved_event.is_asset_resolved,
            asset_id=saved_event.asset_id,
        )
        await self.event_publisher.publish(evt_received)

        return SecurityEventResponseDTO(
            event_id=saved_event.event_id,
            tenant_id=saved_event.tenant_id,
            asset_id=saved_event.asset_id,
            source=saved_event.source,
            event_type=saved_event.event_type,
            severity=saved_event.severity.value
            if hasattr(saved_event.severity, "value")
            else str(saved_event.severity),
            occurred_at=saved_event.occurred_at,
            received_at=saved_event.received_at,
            idempotency_key=saved_event.idempotency_key,
            is_asset_resolved=saved_event.is_asset_resolved,
            evidence_hash=saved_event.evidence_hash,
            is_duplicate_suppressed=False,
        )
