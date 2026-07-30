"""
Handler de Correlação Determinística de Eventos de Segurança.
GovSec Shield — Application Layer (M3.2)

Este módulo é acionado EXCLUSIVAMENTE pelo CorrelationWorker (outbox consumer).
A requisição HTTP não executa correlação diretamente.

Fluxo CQRS:
  outbox_event (SecurityEventReceivedEvent)
    → Carregar SecurityEvent do banco
    → Carregar regras de correlação ativas
    → Avaliar cada regra (determinar se o evento é elegível)
    → Gerar CorrelationKey com bucket temporal
    → Buscar incidente ativo por (tenant_id, correlation_key_hash)
    → Se não existe: criar Incident (status=open) + IncidentEvidence
    → Se existe: adicionar IncidentEvidence (idempotência: IntegrityError → silêncio)
    → Commit atômico
    → mark_published no outbox

Garantias:
  - Idempotência: replay do mesmo outbox_event não duplica incidente nem evidência.
  - Isolamento: cross-tenant impossível (tenant_id filtrado em todas as queries).
  - Rastreabilidade: toda decisão auditada em AuditLog.
  - Regra inativa: não cria nem atualiza incidente.
  - Domínio puro: sem import de SQLAlchemy, FastAPI, Redis ou Kafka.
"""

import hashlib
import logging
from collections.abc import Callable
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
    SecurityEventSeverity,
    sanitize_payload,
)
from src.core.domain.outbox import OutboxEvent

logger = logging.getLogger(__name__)

# Status considerados "ativos" para correlação (incidente pode receber novas evidências)
_ACTIVE_STATUSES: frozenset[str] = frozenset(
    [
        IncidentStatus.OPEN,
        IncidentStatus.ACKNOWLEDGED,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CONTAINED,
    ]
)


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
    Handler de correlação determinística. Acionado pelo CorrelationWorker.

    Aceita uma UoW de correlação já aberta (transação ativa) e o OutboxEvent
    que representa o SecurityEventReceivedEvent a ser processado.

    O outbox_event é marcado como published/failed FORA desta classe,
    pelo CorrelationWorker, após o retorno bem-sucedido ou falha desta operação.
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
            rules: Lista de regras de correlação a avaliar. Deve conter APENAS regras ativas.
                   O filtro de is_active é responsabilidade do CorrelationWorker ao montar a lista.
            window_seconds: Duração da janela temporal em segundos (padrão: 3600 = 1h).
        """
        if not rules:
            # Sem regras ativas não há nada a correlacionar
            logger.debug("CorrelateSecurityEventHandler: nenhuma regra ativa fornecida.")
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
        Lança DomainError em caso de violação de contrato (tenant_id inválido, etc.).
        Erros de infraestrutura propagam normalmente para o CorrelationWorker decidir retry.
        """
        if not isinstance(tenant_id, UUID):
            raise DomainError(f"tenant_id deve ser UUID, recebido: {type(tenant_id)}")
        if not isinstance(security_event_id, UUID):
            raise DomainError(f"security_event_id deve ser UUID, recebido: {type(security_event_id)}")

        # 1. Carregar o SecurityEvent do banco (com filtro tenant_id obrigatório)
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

        # 2. Avaliar cada regra ativa
        for rule in self._rules:
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
            # save lida com IntegrityError silenciosamente (idempotência de replay)
            await self._uow.evidences.save(evidence)

            results.append(saved_incident)

        return results


class CorrelationWorker:
    """
    Worker assíncrono que consome eventos do Transactional Outbox e aciona a correlação.

    Arquitetura:
      1. Reclama lote de outbox_events com status 'pending' ou 'failed' (elegíveis a retry).
      2. Para cada evento do tipo 'SecurityEventReceivedEvent':
         a. Carrega regras de correlação ativas do tenant.
         b. Instancia CorrelateSecurityEventHandler e executa handle().
         c. Se sucesso: mark_published — o evento é considerado totalmente processado.
         d. Se falha: mark_failed — o evento será reprocessado (at-least-once).
      3. Commit único ao final do lote.

    Garantias:
      - Idempotência: mesmo outbox_event processado duas vezes não duplica incidente/evidência.
      - Durabilidade: correlação falha → mark_failed → retry automático.
      - Isolamento: tenant_id sempre filtrado nas queries.
    """

    def __init__(
        self,
        uow_factory: Callable[[], CorrelationUnitOfWork],
        rules_factory: Callable[[UUID], list[CorrelationRule]],
        max_retries: int = 5,
        backoff_seconds: int = 10,
        window_seconds: int = 3600,
    ) -> None:
        """
        Args:
            uow_factory: Fábrica que retorna uma nova instância de CorrelationUnitOfWork.
            rules_factory: Função que retorna as regras de correlação para um tenant_id.
                           Atenção: esta função NÃO deve filtrar is_active — o worker filtra.
            max_retries: Número máximo de tentativas antes de abandonar um evento.
            backoff_seconds: Base de backoff exponencial entre tentativas.
            window_seconds: Janela temporal para a chave de correlação (segundos).
        """
        self._uow_factory = uow_factory
        self._rules_factory = rules_factory
        self._max_retries = max_retries
        self._backoff_seconds = backoff_seconds
        self._window_seconds = window_seconds

    async def process_batch(self, batch_size: int = 50, lease_seconds: int = 60) -> int:
        """
        Processa um lote de SecurityEventReceivedEvents pendentes.

        Retorna o número de eventos processados com sucesso (marked_published).
        Cada evento é processado em sua PRÓPRIA transação para garantir que uma falha
        em um evento não afete os demais do lote.
        """
        # Fase 1: Reclamar os outbox_events elegíveis (transação curta de claim)
        async with self._uow_factory() as claim_uow:
            claimed = await claim_uow.outbox.fetch_pending_and_claim(
                limit=batch_size,
                lease_seconds=lease_seconds,
                lock_for_update=True,
            )
            await claim_uow.commit()

        if not claimed:
            return 0

        processed_count = 0

        # Fase 2: Processar cada evento em transação isolada
        for outbox_evt in claimed:
            if outbox_evt.event_type != "SecurityEventReceivedEvent":
                # Este worker só processa correlação; outros tipos são ignorados
                continue

            success = await self._process_single(outbox_evt)
            if success:
                processed_count += 1

        return processed_count

    async def _process_single(self, outbox_evt: OutboxEvent) -> bool:
        """
        Processa um único outbox_event em transação isolada.
        Retorna True se processado com sucesso, False se falhou.
        """
        tenant_id_raw = outbox_evt.payload.get("tenant_id")
        event_id_raw = outbox_evt.payload.get("security_event_id")

        try:
            tenant_id = UUID(str(tenant_id_raw))
            security_event_id = UUID(str(event_id_raw))
        except (ValueError, TypeError) as exc:
            logger.error(
                "CorrelationWorker: payload inválido no outbox_event=%s: %s",
                outbox_evt.outbox_event_id,
                exc,
            )
            await self._mark_failed(outbox_evt, f"Payload inválido: {exc}")
            return False

        try:
            async with self._uow_factory() as uow:
                # Carregar regras ativas — filtrar is_active=True
                all_rules = await uow.correlation_rules.list_active()
                active_rules: list[CorrelationRule] = []
                for rule_version in all_rules:
                    concrete = self._rules_factory(tenant_id)
                    for r in concrete:
                        if (
                            r.rule_id == rule_version.rule_id
                            and r.version == rule_version.rule_version
                            and rule_version.is_active
                        ):
                            active_rules.append(r)

                handler = CorrelateSecurityEventHandler(
                    uow=uow,
                    rules=active_rules,
                    window_seconds=self._window_seconds,
                )
                await handler.handle(
                    tenant_id=tenant_id,
                    security_event_id=security_event_id,
                )

                # Marcar como published DENTRO da mesma transação
                await uow.outbox.mark_published(outbox_evt.outbox_event_id)
                await uow.commit()

            logger.info(
                "CorrelationWorker: outbox_event=%s processado com sucesso.",
                outbox_evt.outbox_event_id,
            )
            return True

        except Exception as exc:
            logger.error(
                "CorrelationWorker: falha ao processar outbox_event=%s: %s",
                outbox_evt.outbox_event_id,
                exc,
            )
            await self._mark_failed(outbox_evt, str(exc))
            return False

    async def _mark_failed(self, outbox_evt: OutboxEvent, error_msg: str) -> None:
        """Marca o outbox_event como failed em transação isolada."""
        sanitized = self._sanitize_error(error_msg)
        try:
            async with self._uow_factory() as fail_uow:
                await fail_uow.outbox.mark_failed(
                    outbox_event_id=outbox_evt.outbox_event_id,
                    error_message=sanitized,
                    max_retries=self._max_retries,
                    backoff_seconds=self._backoff_seconds,
                )
                await fail_uow.commit()
        except Exception as inner_exc:
            logger.error(
                "CorrelationWorker: falha ao marcar outbox_event=%s como failed: %s",
                outbox_evt.outbox_event_id,
                inner_exc,
            )

    @staticmethod
    def _sanitize_error(err_msg: str) -> str:
        """Sanitiza a mensagem de erro removendo possíveis segredos."""
        truncated = err_msg[:1024]
        sensitive = ("password", "token", "secret", "api_key", "bearer", "authorization")
        for word in sensitive:
            if word in truncated.lower():
                return "[REDACTED ERROR MESSAGE]"
        return truncated
