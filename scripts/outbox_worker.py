"""
Ponto de Entrada para Execução do Outbox Worker.
GovSec Shield — Scripts Outbox Worker CLI Entrypoint
"""

import asyncio
import logging
import sys

from src.core.infrastructure.cli.outbox_worker import run_outbox_worker_loop
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.unit_of_work import AsyncSessionLocal, UnitOfWork
from src.core.infrastructure.messaging.kafka_event_bus import KafkaEventBus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("govsec.scripts.outbox_worker")


def uow_factory() -> UnitOfWork:
    """Factory de UnitOfWork inicializando com AsyncSessionLocal."""
    return UnitOfWork(AsyncSessionLocal())


async def main() -> None:
    logger.info("Iniciando script de worker do OutboxDispatcher...")

    if not settings.GOVSEC_USE_KAFKA:
        logger.warning(
            "Execução cancelada: GOVSEC_USE_KAFKA está desabilitado (False). "
            "O worker de produção exige o broker Kafka/Redpanda ativado."
        )
        sys.exit(0)

    publisher = KafkaEventBus(
        bootstrap_servers=settings.GOVSEC_KAFKA_BOOTSTRAP,
        use_kafka=settings.GOVSEC_USE_KAFKA,
    )
    await publisher.start()

    try:
        await run_outbox_worker_loop(
            uow_factory=uow_factory,
            event_publisher=publisher,
            poll_interval_seconds=5.0,
            run_once="--run-once" in sys.argv,
        )
    finally:
        await publisher.stop()


if __name__ == "__main__":
    asyncio.run(main())
