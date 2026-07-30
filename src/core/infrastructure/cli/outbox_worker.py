"""
Worker Operacional CLI para o OutboxDispatcher (Transactional Outbox Pattern).
GovSec Shield — Infrastructure CLI Outbox Worker

Executa periodicamente o processamento do lote outbox com logs estruturados,
inspeção de métricas de saúde (pending, failed, lease expirado) e validação de broker.
"""

import asyncio
import logging
from typing import Any

from src.core.application.interfaces.event_publisher import IEventPublisher
from src.core.application.interfaces.uow import SecurityEventUnitOfWork
from src.core.application.outbox_dispatcher import OutboxDispatcher
from src.core.infrastructure.config import settings

logger = logging.getLogger("govsec.infrastructure.outbox_worker")


def is_event_bus_configured() -> bool:
    """Verifica se o broker de mensageria (Kafka/Redpanda/EventBus) está configurado."""
    bootstrap = getattr(settings, "KAFKA_BOOTSTRAP_SERVERS", "") or ""
    return bool(bootstrap.strip())


async def inspect_outbox_health(uow: SecurityEventUnitOfWork) -> dict[str, Any]:
    """
    Relatório de saúde da outbox reportando total de mensagens pendentes,
    falhadas e com lease de processamento expirado.
    """
    if hasattr(uow.outbox, "events"):  # InMemory
        events = list(uow.outbox.events.values())
        now_ts = asyncio.get_event_loop().time()
        pending = sum(1 for e in events if e.status == "pending")
        failed = sum(1 for e in events if e.status == "failed")
        expired_processing = sum(
            1
            for e in events
            if e.status == "processing"
            and e.claim_expires_at
            and e.claim_expires_at.timestamp() <= now_ts
        )
        return {
            "pending_count": pending,
            "failed_count": failed,
            "expired_processing_count": expired_processing,
            "total_count": len(events),
        }
    return {
        "pending_count": 0,
        "failed_count": 0,
        "expired_processing_count": 0,
        "total_count": 0,
    }


async def run_outbox_worker_loop(
    uow_factory: Any,
    event_publisher: IEventPublisher,
    poll_interval_seconds: float = 5.0,
    batch_size: int = 100,
    lease_seconds: int = 30,
    max_retries: int = 5,
    run_once: bool = False,
) -> int:
    """
    Loop de execução do worker do OutboxDispatcher.
    """
    if not is_event_bus_configured():
        logger.info(
            "EventBus/Kafka não está configurado (KAFKA_BOOTSTRAP_SERVERS vazio). Worker outbox não iniciado."
        )
        return 0

    dispatcher = OutboxDispatcher(
        uow_factory=uow_factory,
        event_publisher=event_publisher,
        max_retries=max_retries,
    )

    logger.info(
        f"Iniciando Outbox Worker. Batch size: {batch_size}, Lease: {lease_seconds}s, Poll: {poll_interval_seconds}s."
    )
    total_processed = 0

    while True:
        try:
            processed = await dispatcher.process_outbox_batch(
                batch_size=batch_size, lease_seconds=lease_seconds
            )
            total_processed += processed

            if processed > 0:
                logger.info(f"Outbox Worker despachou {processed} mensagens com sucesso.")

            if run_once:
                break

            await asyncio.sleep(poll_interval_seconds)
        except asyncio.CancelledError:
            logger.info("Outbox Worker finalizado por sinal de cancelamento.")
            break
        except Exception as exc:
            logger.error(f"Erro inesperado no loop do Outbox Worker: {exc}")
            if run_once:
                break
            await asyncio.sleep(poll_interval_seconds)

    return total_processed
