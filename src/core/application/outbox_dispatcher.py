"""
Dispatcher de Eventos do Transactional Outbox.
GovSec Shield — Application Layer Outbox Dispatcher
"""

import logging
from collections.abc import Callable
from typing import Any
from uuid import UUID

from src.core.application.interfaces.event_publisher import IEventPublisher
from src.core.application.interfaces.uow import SecurityEventUnitOfWork
from src.core.domain.events import SecurityEventReceivedEvent

logger = logging.getLogger(__name__)


class OutboxDispatcher:
    """
    Componente da camada de aplicação responsável por processar e despachar mensagens
    do Transactional Outbox para o IEventPublisher (broker de mensageria).
    Garante entrega garantida (At-Least-Once) e recuperação resiliente em caso de falha de rede/broker.
    """

    def __init__(
        self,
        uow_factory: Callable[[], SecurityEventUnitOfWork],
        event_publisher: IEventPublisher,
        max_retries: int = 5,
        backoff_seconds: int = 10,
    ) -> None:
        self.uow_factory = uow_factory
        self.event_publisher = event_publisher
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds

    async def process_outbox_batch(self, batch_size: int = 100, lease_seconds: int = 30) -> int:
        """
        Busca e processa um lote de mensagens elegíveis no outbox.
        Retorna o número de mensagens processadas com sucesso.
        """
        async with self.uow_factory() as uow:
            claimed_events = await uow.outbox.fetch_pending_and_claim(
                limit=batch_size, lease_seconds=lease_seconds, lock_for_update=True
            )
            if not claimed_events:
                return 0

            processed_count = 0
            for outbox_evt in claimed_events:
                try:
                    domain_event = self._deserialize_event(outbox_evt.event_type, outbox_evt.payload)
                    await self.event_publisher.publish(domain_event)
                    await uow.outbox.mark_published(outbox_evt.outbox_event_id)
                    processed_count += 1
                except Exception as exc:
                    logger.error(
                        f"Falha ao despachar mensagem outbox {outbox_evt.outbox_event_id}: {exc}"
                    )
                    sanitized_err = self._sanitize_error_message(str(exc))
                    await uow.outbox.mark_failed(
                        outbox_event_id=outbox_evt.outbox_event_id,
                        error_message=sanitized_err,
                        max_retries=self.max_retries,
                        backoff_seconds=self.backoff_seconds,
                    )

            await uow.commit()
            return processed_count

    def _deserialize_event(self, event_type: str, payload: dict[str, Any]) -> SecurityEventReceivedEvent:
        if event_type == "SecurityEventReceivedEvent":
            raw_asset_id = payload.get("asset_id")
            asset_id = UUID(raw_asset_id) if raw_asset_id else None
            return SecurityEventReceivedEvent(
                tenant_id=UUID(payload["tenant_id"]),
                security_event_id=UUID(payload["security_event_id"]),
                source=str(payload["source"]),
                security_event_type=str(payload["security_event_type"]),
                severity=str(payload["severity"]),
                is_asset_resolved=bool(payload["is_asset_resolved"]),
                asset_id=asset_id,
            )
        raise ValueError(f"Tipo de evento outbox desconhecido: '{event_type}'")

    @staticmethod
    def _sanitize_error_message(err_msg: str) -> str:
        # Sanitizar se contiver dict-like e truncar para no máximo 1024 caracteres sem vazar secrets
        sanitized = err_msg[:1024]
        for secret_word in ("password", "token", "secret", "api_key", "bearer"):
            if secret_word in sanitized.lower():
                sanitized = "[REDACTED ERROR MESSAGE]"
                break
        return sanitized
