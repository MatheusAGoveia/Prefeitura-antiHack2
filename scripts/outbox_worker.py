"""
Ponto de Entrada para Execução do Outbox Worker.
GovSec Shield — Scripts Outbox Worker CLI Entrypoint
"""

import asyncio
import logging
import sys

from src.core.infrastructure.cli.outbox_worker import run_outbox_worker_loop
from src.core.infrastructure.db.repositories import InMemoryEventPublisher
from src.core.infrastructure.db.unit_of_work import UnitOfWork

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("govsec.scripts.outbox_worker")


async def main() -> None:
    logger.info("Iniciando script de worker do OutboxDispatcher...")
    publisher = InMemoryEventPublisher()
    await run_outbox_worker_loop(
        uow_factory=UnitOfWork,
        event_publisher=publisher,
        poll_interval_seconds=5.0,
        run_once="--run-once" in sys.argv,
    )


if __name__ == "__main__":
    asyncio.run(main())
