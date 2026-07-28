"""
Métricas Prometheus e Middleware FastAPI
GovSec Shield — Shared Observability
"""

import time
from collections.abc import Callable
from typing import Any

from fastapi import Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, Counter, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware

# Contador Total de Requisições HTTP
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total de requisições HTTP processadas",
    ["method", "endpoint", "status_code", "tenant"],
    registry=REGISTRY,
)

# Histograma de Duração/Latência das Requisições HTTP (em segundos)
HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "Duração das requisições HTTP em segundos",
    ["method", "endpoint", "status_code"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=REGISTRY,
)

# Métricas de CQRS (Commands & Queries)
CQRS_COMMANDS_TOTAL = Counter(
    "cqrs_commands_total",
    "Total de comandos CQRS executados",
    ["command_name", "tenant", "status"],
    registry=REGISTRY,
)

CQRS_COMMAND_DURATION_SECONDS = Histogram(
    "cqrs_command_duration_seconds",
    "Duração da execução de comandos CQRS em segundos",
    ["command_name", "tenant"],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0),
    registry=REGISTRY,
)

# Métricas de Eventos de Domínio (Event-Driven Architecture)
DOMAIN_EVENTS_TOTAL = Counter(
    "domain_events_total",
    "Total de eventos de domínio processados pelos Event Handlers",
    ["event_type", "tenant", "status"],
    registry=REGISTRY,
)

DOMAIN_EVENT_HANDLER_DURATION_SECONDS = Histogram(
    "domain_event_handler_duration_seconds",
    "Duração do processamento de eventos de domínio pelos handlers em segundos",
    ["event_type", "tenant"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0),
    registry=REGISTRY,
)


class PrometheusMetricsMiddleware(BaseHTTPMiddleware):
    """
    Middleware FastAPI para contagem de requisições e medição de latência HTTP.
    """

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        start_time = time.perf_counter()
        method = request.method
        tenant = request.headers.get("X-Tenant-ID", "global")

        try:
            response: Response = await call_next(request)
            status_code = str(response.status_code)
        except Exception:
            status_code = "500"
            raise
        finally:
            duration = time.perf_counter() - start_time
            endpoint = request.scope.get("path", request.url.path)
            if hasattr(request, "route") and request.route and hasattr(request.route, "path"):
                endpoint = request.route.path

            if endpoint != "/metrics":
                HTTP_REQUESTS_TOTAL.labels(
                    method=method, endpoint=endpoint, status_code=status_code, tenant=tenant
                ).inc()
                HTTP_REQUEST_DURATION_SECONDS.labels(
                    method=method, endpoint=endpoint, status_code=status_code
                ).observe(duration)

        return response


async def metrics_endpoint_handler() -> Response:
    """Handler para o endpoint GET /metrics do Prometheus Exporter."""
    data: bytes = generate_latest(REGISTRY)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
