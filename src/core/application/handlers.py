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
from src.core.application.interfaces import IEventPublisher, SecurityEventUnitOfWork
from src.core.domain.entities import AlertAcknowledgement, AuditLog, Tenant, TenantStatus
from src.core.domain.events import (
    AlertAcknowledgedEvent,
    LogIngestedEvent,
    TenantCreatedEvent,
)
from src.core.domain.exceptions import DomainError
from src.core.domain.incidents import SecurityEvent, SecurityEventSeverity
from src.core.domain.outbox import OutboxEvent
from src.core.domain.repositories import (
    AlertAcknowledgementRepository,
    LogRepository,
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
    Handler CQRS para ingestão assíncrona, idempotente, auditável e transacional de SecurityEvent (M3.1).
    Fluxo Transacional com Transactional Outbox Pattern:
    1. Validar e normalizar entradas (tenant_id UUID, severidade sem fallback silencioso, occurred_at UTC obrigatório, payload dict).
    2. Utilizar obrigatoriamente a abstração tipada SecurityEventUnitOfWork.
    3. Resolver Asset por (tenant_id, service_name, environment).
    4. Construir SecurityEvent com validação estrita de domínio.
    5. Persistir SecurityEvent, AuditLogs e mensagem de Outbox na MESMA transação atomicamente.
    6. Executar commit na transação. O despacho para o broker é realizado assincronamente pelo OutboxDispatcher.
    """

    def __init__(self, uow: SecurityEventUnitOfWork) -> None:
        self.uow = uow

    async def handle(self, command: IngestSecurityEventCommand) -> SecurityEventResponseDTO:
        cmd_p = command.payload

        # 1. Validação estrita de tenant_id UUID
        raw_tenant = cmd_p.get("tenant_id")
        if isinstance(raw_tenant, UUID):
            tenant_id = raw_tenant
        elif raw_tenant:
            try:
                tenant_id = UUID(str(raw_tenant))
            except (ValueError, TypeError) as err:
                raise DomainError(f"tenant_id deve ser um UUID válido: '{raw_tenant}'") from err
        else:
            raise DomainError("tenant_id é obrigatório e deve ser um UUID válido.")

        # Validação estrita de strings não vazias
        source = str(cmd_p.get("source") or "").strip()
        if not source:
            raise DomainError("source é obrigatório e não pode ser vazio.")

        event_type = str(cmd_p.get("event_type") or "").strip()
        if not event_type:
            raise DomainError("event_type é obrigatório e não pode ser vazio.")

        idempotency_key = str(cmd_p.get("idempotency_key") or "").strip()
        if not idempotency_key:
            raise DomainError("idempotency_key é obrigatória e não pode ser vazia.")

        # Validação estrita de payload dict
        raw_payload = cmd_p.get("payload")
        if not isinstance(raw_payload, dict):
            raise DomainError(f"payload deve ser um dict, recebido: '{type(raw_payload).__name__}'")

        # Validação estrita de severidade sem fallback silencioso
        raw_severity = cmd_p.get("severity")
        if isinstance(raw_severity, SecurityEventSeverity):
            severity_enum = raw_severity
        elif isinstance(raw_severity, str):
            sev_upper = raw_severity.strip().upper()
            if sev_upper in SecurityEventSeverity.__members__:
                severity_enum = SecurityEventSeverity[sev_upper]
            else:
                raise DomainError(f"Severidade de segurança inválida: '{raw_severity}'")
        else:
            raise DomainError(f"Severidade de segurança inválida: '{raw_severity}'")

        # Conversão e validação estrita de occurred_at (OBRIGATÓRIO)
        occurred_at_raw = cmd_p.get("occurred_at")
        if occurred_at_raw is None:
            raise DomainError("occurred_at é obrigatório.")

        if isinstance(occurred_at_raw, str):
            try:
                occurred_at = datetime.fromisoformat(occurred_at_raw)
            except (ValueError, TypeError) as err:
                raise DomainError(f"occurred_at com formato ISO-8601 inválido: '{occurred_at_raw}'") from err
        elif isinstance(occurred_at_raw, datetime):
            occurred_at = occurred_at_raw
        else:
            raise DomainError(f"occurred_at inválido: '{occurred_at_raw}'")

        # Conversão de received_at (opcional, padrão agora em UTC)
        received_at_raw = cmd_p.get("received_at")
        if received_at_raw is None:
            received_at = datetime.now(timezone.utc)
        elif isinstance(received_at_raw, str):
            try:
                received_at = datetime.fromisoformat(received_at_raw)
            except (ValueError, TypeError) as err:
                raise DomainError(f"received_at com formato ISO-8601 inválido: '{received_at_raw}'") from err
        elif isinstance(received_at_raw, datetime):
            received_at = received_at_raw
        else:
            raise DomainError(f"received_at inválido: '{received_at_raw}'")

        service_name = cmd_p.get("service_name")
        environment = cmd_p.get("environment")

        async with self.uow:
            # 2. Resolução de Ativo por tenant_id, service_name e environment
            resolved_asset = None
            if service_name and environment:
                resolved_asset = await self.uow.assets.resolve_active_asset(
                    tenant_id=tenant_id,
                    service_name=service_name,
                    environment=environment,
                )

            asset_id = resolved_asset.asset_id if resolved_asset else None
            is_asset_resolved = resolved_asset is not None

            # 3. Construção da Entidade de Domínio M3.0 (valida UTC e sanitiza payload)
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

            # 4. Persistência transacional atômica (SecurityEvent, AuditLog e Outbox na mesma transação)
            saved_event, created = await self.uow.security_events.save(event_domain)

            if not created:
                # Replay duplicado: auditoria de supressão na mesma transação
                audit_suppressed = AuditLog(
                    tenant_id=tenant_id,
                    source="SecurityEventIngestion",
                    raw_data=f"Duplicate event suppressed. IdempotencyKey={idempotency_key}, Source={source}",
                )
                await self.uow.logs.save(audit_suppressed)
                await self.uow.commit()

                # Replay duplicado NÃO gera mensagem no outbox
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

            # Evento novo: auditoria de persistência
            audit_persisted = AuditLog(
                tenant_id=tenant_id,
                source="SecurityEventIngestion",
                raw_data=f"SecurityEvent persisted. EventID={saved_event.event_id}, IdempotencyKey={idempotency_key}",
            )
            await self.uow.logs.save(audit_persisted)

            # Auditoria de UnresolvedAssetEvent ÚNICA VEZ apenas para evento novo sem ativo
            if not is_asset_resolved:
                unresolved_event = saved_event.create_unresolved_asset_event()
                if unresolved_event:
                    audit_unresolved = AuditLog(
                        tenant_id=tenant_id,
                        source="SecurityEventIngestion",
                        raw_data=f"UnresolvedAssetEvent created for event_id={saved_event.event_id}, source={source}",
                    )
                    await self.uow.logs.save(audit_unresolved)

            # Gravação da mensagem de evento no Transactional Outbox na MESMA transação
            outbox_payload = {
                "tenant_id": str(saved_event.tenant_id),
                "security_event_id": str(saved_event.event_id),
                "source": saved_event.source,
                "security_event_type": saved_event.event_type,
                "severity": saved_event.severity.value
                if hasattr(saved_event.severity, "value")
                else str(saved_event.severity),
                "is_asset_resolved": saved_event.is_asset_resolved,
                "asset_id": str(saved_event.asset_id) if saved_event.asset_id else None,
            }
            outbox_entry = OutboxEvent(
                tenant_id=saved_event.tenant_id,
                aggregate_type="SecurityEvent",
                aggregate_id=saved_event.event_id,
                event_type="SecurityEventReceivedEvent",
                payload=outbox_payload,
                idempotency_key=f"outbox-{saved_event.tenant_id}-{saved_event.idempotency_key}",
            )
            await self.uow.outbox.save(outbox_entry)

            # Confirmar atomicamente a transação completa (Event + Audit + Outbox)
            await self.uow.commit()

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
