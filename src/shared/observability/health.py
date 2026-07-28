"""
Health Checks (Liveness e Readiness Probe Engine)
GovSec Shield — Shared Observability
"""

from typing import Any

from fastapi import Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from src.core.infrastructure.db.unit_of_work import AsyncSessionLocal
from src.core.infrastructure.messaging.kafka_event_bus import KafkaEventBus


async def liveness_check_handler() -> Response:
    """
    Liveness Check (`/healthz`):
    Indica que o processo da API está ativo e operante.
    """
    return JSONResponse(
        content={
            "status": "ok",
            "service": "govsec-core",
        },
        status_code=status.HTTP_200_OK,
    )


async def perform_readiness_checks(
    event_bus: KafkaEventBus | None = None,
) -> tuple[bool, dict[str, str]]:
    """Executa a verificação ativa das dependências do sistema."""
    checks: dict[str, str] = {
        "database": "unknown",
        "kafka": "unknown",
    }
    all_healthy = True

    # 1. Teste de Banco de Dados PostgreSQL
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc!s}"
        all_healthy = False

    # 2. Teste de Broker Kafka / Redpanda
    try:
        bus = event_bus or KafkaEventBus()
        if bus.use_kafka and bus._producer:
            checks["kafka"] = "ok"
        else:
            checks["kafka"] = "fallback_in_memory"
    except Exception as exc:
        checks["kafka"] = f"error: {exc!s}"

    return all_healthy, checks


async def readiness_check_handler() -> Response:
    """
    Readiness Check (`/ready`):
    Endpoint HTTP do FastAPI para verificações ativas do PostgreSQL e Kafka.
    """
    all_healthy, checks = await perform_readiness_checks()
    payload: dict[str, Any] = {
        "status": "ready" if all_healthy else "degraded",
        "checks": checks,
    }
    status_code = status.HTTP_200_OK if all_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(content=payload, status_code=status_code)
