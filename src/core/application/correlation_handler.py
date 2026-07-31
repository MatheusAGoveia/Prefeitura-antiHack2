"""
Handler de Correlação Determinística de Eventos de Segurança.
GovSec Shield — Application Layer (M3.2)

Este módulo implementa o caso de uso puro de aplicação para correlação de eventos.
Acionado EXCLUSIVAMENTE pelo consumidor Kafka de correlação (CorrelationKafkaConsumer).
A requisição HTTP e o OutboxWorker NÃO executam nem modificam a correlação.

Fluxo CQRS:
  SecurityEventReceivedEvent (Kafka)
    → Carregar SecurityEvent do banco
    → Avaliar regras ativas de correlação (rule.is_eligible(event))
    → Gerar CorrelationKey determinística com bucket temporal (occurred_at)
    → Buscar incidente ativo por (tenant_id, correlation_key_hash)
    → Se não existe: criar Incident (status=open) + IncidentEvidence
    → Se existe: adicionar IncidentEvidence (idempotência: UNIQUE(incident_id, event_id))
    → Commit transacional da sessão DB (fora ou via UoW)

Garantias:
  - Elegibilidade estrita: regra inelegível NÃO cria incidente, evidência ou auditoria.
  - Idempotência: replay do mesmo evento não duplica incidente nem evidência.
  - Isolamento: cross-tenant impossível (tenant_id filtrado em todas as queries).
  - Domínio puro: sem imports de SQLAlchemy, FastAPI, Redis ou Kafka.
"""

import logging
from datetime import datetime, timezone
from uuid import UUID, uuid4

from src.core.application.interfaces.uow import CorrelationUnitOfWork
from src.core.domain.correlation import CorrelationKey, CorrelationRule
from src.core.domain.entities import AuditLog
from src.core.domain.exceptions import DomainError
from src.core.domain.incidents import (
    Incident,
    IncidentEvidence,
    IncidentStatus,
    SecurityEvent,
    sanitize_payload,
)

logger = logging.getLogger(__name__)


def _compute_time_bucket(occurred_at: datetime, window_seconds: int) -> str:
    """
    Calcula o início do bucket temporal (floor) a partir do timestamp do evento.

    Fórmula: bucket_start = floor(occurred_at_unix / window_seconds) * window_seconds

    Exemplo (janela de 3600s / 1h):
      occurred_at = 2026-07-30T14:37:22Z  →  bucket_start = 2026-07-30T14:00:00Z

    O bucket é incluído na chave de correlação para agrupar eventos dentro da mesma
    janela temporal, evitando que eventos de janelas distintas compartilhem um incidente.
    """
    ts_unix = occurred_at.timestamp()
    bucket_start_unix = (int(ts_unix) // window_seconds) * window_seconds
    bucket_dt = datetime.fromtimestamp(bucket_start_unix, tz=timezone.utc)
    return bucket_dt.isoformat()


def _build_correlation_key(
    rule: CorrelationRule,
    event: SecurityEvent,
    window_seconds: int,
) -> CorrelationKey:
    """
    Constrói o CorrelationKey determinístico com bucket temporal.

    - asset_key: str(asset_id) quando resolvido; "{source}:{event_type}" quando não resolvido.
    - time_window: ISO timestamp do início do bucket temporal (floor(occurred_at, window_seconds)).
    """
    asset_key = (
        str(event.asset_id)
        if event.asset_id is not None
        else f"{event.source}:{event.event_type}"
    )
    time_window = _compute_time_bucket(event.occurred_at, window_seconds)

    return CorrelationKey(
        tenant_id=event.tenant_id,
        rule_id=rule.rule_id,
        rule_version=rule.version,
        asset_key=asset_key,
        category=rule.category,
        time_window=time_window,
    )


class CorrelateSecurityEventHandler:
    """
    Handler de correlação determinística (Caso de Uso de Aplicação).
    Acionado pelo CorrelationKafkaConsumer.

    Aceita uma UoW de correlação já aberta (transação ativa).
    """

    def __init__(
        self,
        uow: CorrelationUnitOfWork,
        rules: list[CorrelationRule],
        window_seconds: int = 3600,
    ) -> None:
        """
        Args:
            uow: Unit of Work de correlação (sessão ativa).
            rules: Lista de regras de correlação a avaliar (apenas regras ativas).
            window_seconds: Duração da janela temporal em segundos (padrão: 3600 = 1h).
        """
        self._uow = uow
        self._rules = rules
        self._window_seconds = window_seconds

    async def handle(
        self,
        tenant_id: UUID,
        security_event_id: UUID,
    ) -> list[Incident]:
        """
        Processa a correlação de um SecurityEvent.

        Retorna a lista de incidentes criados ou atualizados.
        Se a regra for inelegível ou inativa, NENHUM incidente, evidência ou auditoria é criado.
        """
        if not isinstance(tenant_id, UUID):
            raise DomainError(f"tenant_id deve ser UUID, recebido: {type(tenant_id)}")
        if not isinstance(security_event_id, UUID):
            raise DomainError(f"security_event_id deve ser UUID, recebido: {type(security_event_id)}")

        # 1. Carregar o SecurityEvent do banco (filtro por tenant_id obrigatório)
        event = await self._uow.security_events.get_by_id(security_event_id, tenant_id)
        if event is None:
            logger.warning(
                "CorrelateSecurityEventHandler: SecurityEvent não encontrado. "
                "event_id=%s tenant_id=%s",
                security_event_id,
                tenant_id,
            )
            return []

        results: list[Incident] = []

        # 2. Avaliar cada regra
        for rule in self._rules:
            # OBRIGATÓRIO: Verificar elegibilidade da regra para o evento
            if hasattr(rule, "is_eligible") and not rule.is_eligible(event):
                logger.debug(
                    "CorrelateSecurityEventHandler: evento %s inelegível para regra %s",
                    security_event_id,
                    rule.rule_id,
                )
                continue

            corr_key = _build_correlation_key(rule, event, self._window_seconds)
            key_hash = corr_key.to_hash()
            canonical = corr_key.to_canonical_string()

            # 3. Buscar incidente ativo para esta chave (isolado por tenant_id)
            existing = await self._uow.incidents.find_open_by_correlation_key(
                tenant_id=tenant_id,
                correlation_key_hash=key_hash,
            )

            if existing is None:
                # 4a. Criar novo incidente
                now = datetime.now(timezone.utc)
                incident = Incident(
                    incident_id=uuid4(),
                    tenant_id=tenant_id,
                    title=f"[{rule.rule_id}] {rule.rule_name} — {event.event_type}",
                    description=(
                        f"Incidente gerado automaticamente pela regra '{rule.rule_name}' "
                        f"(v{rule.version}) para o evento '{event.event_type}' "
                        f"da fonte '{event.source}'."
                    ),
                    severity=event.severity,
                    status=IncidentStatus.OPEN,
                    correlation_key=canonical,
                    created_at=now,
                    updated_at=now,
                )
                saved_incident = await self._uow.incidents.save(incident)

                # Auditoria de criação
                await self._uow.logs.save(
                    AuditLog(
                        tenant_id=tenant_id,
                        source="CorrelationEngine",
                        raw_data=(
                            f"Incident created. incident_id={saved_incident.incident_id} "
                            f"rule_id={rule.rule_id} event_id={security_event_id} "
                            f"correlation_key_hash={key_hash}"
                        ),
                    )
                )
            else:
                saved_incident = existing

            # 4b. Vincular evidência (idempotente: UNIQUE(incident_id, event_id))
            evidence = IncidentEvidence(
                evidence_id=uuid4(),
                incident_id=saved_incident.incident_id,
                event_id=security_event_id,
                tenant_id=tenant_id,
                evidence_hash=event.evidence_hash,
                added_at=datetime.now(timezone.utc),
                description=(
                    f"Evento '{event.event_type}' (source={event.source}, "
                    f"severity={event.severity.value}) vinculado pela regra {rule.rule_id}."
                ),
                raw_payload_masked=sanitize_payload(event.payload),
            )
            await self._uow.evidences.save(evidence)

            results.append(saved_incident)

        return results
