"""
Métricas Prometheus e Middleware FastAPI
GovSec Shield — Shared Observability
"""

import logging
import time
from collections.abc import Callable
from typing import Any

from fastapi import Depends, Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.infrastructure.config import settings
from src.core.infrastructure.db.unit_of_work import get_db_session

logger = logging.getLogger(__name__)

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

# ─── Métricas M2 — Monitoramento & Operação SRE ────────────────────────────────

GOVSEC_SERVICE_INFO = Gauge(
    "govsec_service_info",
    "Informações de versão e ambiente da API GovSec Shield",
    ["version", "environment", "service"],
    registry=REGISTRY,
)
GOVSEC_SERVICE_INFO.labels(
    version="1.0.0", environment=settings.GOVSEC_ENV, service="govsec-core-api"
).set(1)

# Conexões do Pool SQLAlchemy PostgreSQL
GOVSEC_DB_POOL_SIZE = Gauge(
    "govsec_db_pool_size",
    "Tamanho total configurado para o pool de conexões PostgreSQL",
    registry=REGISTRY,
)
GOVSEC_DB_POOL_CHECKED_OUT = Gauge(
    "govsec_db_pool_checked_out",
    "Número de conexões PostgreSQL atualmente em uso ativo",
    registry=REGISTRY,
)
GOVSEC_DB_POOL_OVERFLOW = Gauge(
    "govsec_db_pool_overflow",
    "Número de conexões adicionais de overflow abertas no pool",
    registry=REGISTRY,
)
GOVSEC_DB_POOL_AVAILABLE_CONNECTIONS = Gauge(
    "govsec_db_pool_available_connections",
    "Número de conexões imediatamente disponíveis no pool PostgreSQL",
    registry=REGISTRY,
)

# Ingestão de Logs & Eventos
GOVSEC_LOGS_INGESTED_TOTAL = Counter(
    "govsec_logs_ingested_total",
    "Total de logs de auditoria ingeridos operacionalmente",
    ["source", "tenant"],
    registry=REGISTRY,
)

# Estado de Componentes de Infraestrutura
GOVSEC_EVENT_BUS_FALLBACK_ACTIVE = Gauge(
    "govsec_event_bus_fallback_active",
    "Status do EventBus: 1 se em fallback in-memory, 0 se operando via Kafka",
    registry=REGISTRY,
)

GOVSEC_OPA_AVAILABLE = Gauge(
    "govsec_opa_available",
    "Status do OPA Engine: 1 se acessível e respondendo, 0 se indisponível",
    registry=REGISTRY,
)

# Pipeline de Alertas
GOVSEC_ALERT_DELIVERY_FAILURES_TOTAL = Counter(
    "govsec_alert_delivery_failures_total",
    "Total de falhas no envio de notificações ao Alertmanager",
    registry=REGISTRY,
)

GOVSEC_ALERTS_ACKNOWLEDGED_TOTAL = Counter(
    "govsec_alerts_acknowledged_total",
    "Total de alertas com acknowledgement humano auditado",
    ["tenant"],
    registry=REGISTRY,
)

# ─── Métricas M3.3 — Operações de Incidentes e Evidências ─────────────────────

GOVSEC_INCIDENTS_TOTAL = Counter(
    "govsec_incidents_total",
    "Total de incidentes criados no motor de correlação",
    ["severity", "status"],
    registry=REGISTRY,
)

GOVSEC_INCIDENT_STATUS_TRANSITIONS_TOTAL = Counter(
    "govsec_incident_status_transitions_total",
    "Total de transições de status de incidentes auditadas",
    ["from_status", "to_status"],
    registry=REGISTRY,
)

GOVSEC_INCIDENT_EVIDENCES_TOTAL = Counter(
    "govsec_incident_evidences_total",
    "Total de evidências de incidentes vinculadas",
    ["rule_id"],
    registry=REGISTRY,
)

GOVSEC_OPEN_INCIDENTS = Gauge(
    "govsec_open_incidents",
    "Quantidade de incidentes atualmente abertos por severidade",
    ["severity"],
    registry=REGISTRY,
)


def record_incident_created(severity: str, status: str) -> None:
    """Registra criação de incidente no contador histórico global de eventos criados (labels de baixa cardinalidade)."""
    sev_lower = severity.lower()
    st_lower = status.lower()
    GOVSEC_INCIDENTS_TOTAL.labels(severity=sev_lower, status=st_lower).inc()


def record_incident_status_transition(
    from_status: str, to_status: str, severity: str | None = None
) -> None:
    """Registra transição auditada de status de incidente no contador histórico de transições."""
    from_lower = from_status.lower()
    to_lower = to_status.lower()
    GOVSEC_INCIDENT_STATUS_TRANSITIONS_TOTAL.labels(
        from_status=from_lower, to_status=to_lower
    ).inc()


def record_incident_evidence_added(rule_id: str = "default") -> None:
    """Registra inclusão de evidência vinculada a incidente."""
    GOVSEC_INCIDENT_EVIDENCES_TOTAL.labels(rule_id=rule_id).inc()


def safe_record_incident_created(severity: str, status: str) -> None:
    """
    Adaptador de infraestrutura seguro: registra métrica Prometheus de incidente criado.
    Captura e loga falhas de observabilidade sem permitir que exceções da instrumentação
    afetem transações ou confirmações de offsets.
    """
    try:
        record_incident_created(severity=severity, status=status)
    except Exception as exc:
        # Justificativa Técnica: No limite da infraestrutura de observabilidade, uma falha na instrumentação
        # (ex: erro no client Prometheus ou travamento do registry) deve ser registrada como warning e
        # não pode interromper a transação do banco ou a confirmação de offset no Kafka.
        logger.warning(
            "Falha de instrumentação ao registrar métrica de incidente criado. severity=%s status=%s err=%s",
            severity,
            status,
            exc,
        )


def safe_record_incident_evidence_added(rule_id: str = "default") -> None:
    """
    Adaptador de infraestrutura seguro: registra métrica Prometheus de evidência adicionada.
    """
    try:
        record_incident_evidence_added(rule_id=rule_id)
    except Exception as exc:
        # Justificativa Técnica: Isolamento de falha de observabilidade pós-commit.
        logger.warning(
            "Falha de instrumentação ao registrar métrica de evidência adicionada. rule_id=%s err=%s",
            rule_id,
            exc,
        )


def safe_record_incident_status_transition(
    from_status: str, to_status: str, severity: str | None = None
) -> None:
    """
    Adaptador de infraestrutura seguro: registra métrica Prometheus de transição de status.
    """
    try:
        record_incident_status_transition(from_status=from_status, to_status=to_status, severity=severity)
    except Exception as exc:
        # Justificativa Técnica: Isolamento de falha de observabilidade pós-commit.
        logger.warning(
            "Falha de instrumentação ao registrar métrica de transição de status. from=%s to=%s err=%s",
            from_status,
            to_status,
            exc,
        )


async def sync_open_incidents_gauge_from_db(session: Any = None) -> None:
    """
    Reconstrói e sincroniza os valores do Gauge GOVSEC_OPEN_INCIDENTS a partir do estado real do banco de dados PostgreSQL.
    Garante resiliência a restarts e consistência entre réplicas.
    Severidades com 0 incidentes abertos são explicitamente zeradas no Gauge para não manter séries estagnadas.
    """
    from src.core.domain.incidents import SecurityEventSeverity
    from src.core.infrastructure.db.repositories import PostgresIncidentRepository

    if session is not None:
        repo = PostgresIncidentRepository(session)
        counts = await repo.count_open_by_severity()
    else:
        from src.core.infrastructure.db.unit_of_work import AsyncSessionLocal

        async with AsyncSessionLocal() as session_ctx:
            repo = PostgresIncidentRepository(session_ctx)
            counts = await repo.count_open_by_severity()

    for sev in SecurityEventSeverity:
        sev_key = sev.value.lower()
        cnt = counts.get(sev_key, 0)
        GOVSEC_OPEN_INCIDENTS.labels(severity=sev_key).set(cnt)


async def safe_sync_open_incidents_gauge_from_db(session: Any = None) -> None:
    """
    Adaptador de infraestrutura seguro para sincronização do Gauge GOVSEC_OPEN_INCIDENTS a partir do banco.
    Em caso de falha de conexão/consulta ao PostgreSQL, apenas registra um aviso no log sem publicar estado falso.
    """
    try:
        await sync_open_incidents_gauge_from_db(session)
    except Exception as exc:
        logger.warning(
            "Falha ao sincronizar gauge de incidentes a partir do banco de dados: %s",
            exc,
        )


def collect_db_pool_metrics() -> None:
    """Coleta dinâmica do estado do pool SQLAlchemy sem gerar alta cardinalidade."""
    try:
        from src.core.infrastructure.db.unit_of_work import engine

        pool = engine.pool
        size = pool.size()  # type: ignore[attr-defined]
        checkedout = pool.checkedout()  # type: ignore[attr-defined]
        overflow = pool.overflow()  # type: ignore[attr-defined]
        available = max(0, (size + overflow) - checkedout)

        GOVSEC_DB_POOL_SIZE.set(size)
        GOVSEC_DB_POOL_CHECKED_OUT.set(checkedout)
        GOVSEC_DB_POOL_OVERFLOW.set(overflow)
        GOVSEC_DB_POOL_AVAILABLE_CONNECTIONS.set(available)
    except Exception:
        # Fallback seguro caso o engine ainda não tenha inicializado
        GOVSEC_DB_POOL_SIZE.set(5)
        GOVSEC_DB_POOL_CHECKED_OUT.set(0)
        GOVSEC_DB_POOL_OVERFLOW.set(0)
        GOVSEC_DB_POOL_AVAILABLE_CONNECTIONS.set(5)


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


async def metrics_endpoint_handler(session: Any = Depends(get_db_session)) -> Response:
    """
    Handler para o endpoint GET /metrics do Prometheus Exporter.
    Executa a sincronização dinâmica do estado verdadeiro de incidentes abertos a partir do PostgreSQL.
    Caso o banco esteja indisponível, safe_sync_open_incidents_gauge_from_db registra warning
    sem publicar estados zerados falsos.
    """
    await safe_sync_open_incidents_gauge_from_db(session)

    collect_db_pool_metrics()
    data: bytes = generate_latest(REGISTRY)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)

