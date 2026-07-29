from typing import Any

import httpx
from fastapi import Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from src.core.infrastructure.config import settings
from src.core.infrastructure.db.unit_of_work import AsyncSessionLocal
from src.core.infrastructure.messaging.kafka_event_bus import KafkaEventBus
from src.shared.observability.metrics import (
    GOVSEC_EVENT_BUS_FALLBACK_ACTIVE,
    GOVSEC_OPA_AVAILABLE,
)


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
        "opa": "unknown",
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
            GOVSEC_EVENT_BUS_FALLBACK_ACTIVE.set(0)
        else:
            checks["kafka"] = "fallback_in_memory"
            GOVSEC_EVENT_BUS_FALLBACK_ACTIVE.set(1)
            # Em staging ou production, a indisponibilidade do broker desmarca readiness
            if settings.GOVSEC_ENV in ("staging", "production"):
                all_healthy = False
    except Exception as exc:
        checks["kafka"] = f"error: {exc!s}"
        GOVSEC_EVENT_BUS_FALLBACK_ACTIVE.set(1)
        if settings.GOVSEC_ENV in ("staging", "production"):
            all_healthy = False

    # 3. Teste de OPA Policy Engine
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(settings.GOVSEC_OPA_URL.rsplit("/", 1)[0] if "/" in settings.GOVSEC_OPA_URL else settings.GOVSEC_OPA_URL)
            if resp.status_code in (200, 404, 405):
                checks["opa"] = "ok"
                GOVSEC_OPA_AVAILABLE.set(1)
            else:
                checks["opa"] = f"unhealthy_status_{resp.status_code}"
                GOVSEC_OPA_AVAILABLE.set(0)
                if settings.GOVSEC_ENV in ("staging", "production"):
                    all_healthy = False
    except Exception as exc:
        checks["opa"] = f"unavailable: {exc!s}"
        GOVSEC_OPA_AVAILABLE.set(0)
        if settings.GOVSEC_ENV in ("staging", "production"):
            all_healthy = False

    return all_healthy, checks


async def readiness_check_handler() -> Response:
    """
    Readiness Check (`/ready`):
    Endpoint HTTP do FastAPI para verificações ativas do PostgreSQL, Kafka e OPA.
    """
    all_healthy, checks = await perform_readiness_checks()
    payload: dict[str, Any] = {
        "status": "ready" if all_healthy else "degraded",
        "checks": checks,
    }
    status_code = status.HTTP_200_OK if all_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(content=payload, status_code=status_code)

