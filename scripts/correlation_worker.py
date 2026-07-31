"""
Script CLI Operacional — Worker do Motor de Correlação (M3.2).
GovSec Shield — Operational Scripts

Executa o consumidor Kafka de correlação em segundo plano com graceful shutdown.
Uso:
    poetry run python scripts/correlation_worker.py
"""

import asyncio
import contextlib
import logging
import signal
import sys

from src.core.infrastructure.config import settings
from src.core.infrastructure.messaging.correlation_consumer import CorrelationKafkaConsumer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("GovSecCorrelationWorker")


async def main() -> None:
    logger.info("Iniciando GovSec Shield Correlation Worker (M3.2)...")

    consumer = CorrelationKafkaConsumer(
        bootstrap_servers=settings.GOVSEC_KAFKA_BOOTSTRAP,
        group_id=settings.GOVSEC_KAFKA_CORRELATION_GROUP_ID,
    )

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def handle_signal(sig_name: str) -> None:
        logger.info("Sinal %s recebido. Encerrando o worker graciosamente...", sig_name)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, handle_signal, sig.name)

    async def run_worker() -> None:
        await consumer.start()
        run_task = asyncio.create_task(consumer.run())
        await stop_event.wait()
        await consumer.stop()
        run_task.cancel()

    try:
        await run_worker()
    except Exception as exc:
        logger.error("Erro fatal no worker de correlação: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        await consumer.stop()
        logger.info("Worker de correlação finalizado.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Worker interrompido pelo usuário.")
        sys.exit(0)
