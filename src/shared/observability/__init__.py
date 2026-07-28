"""
GovSec Shield — Shared Observability Package
Exports Tracing, Metrics, Logging, Sanitizer, System Metrics e Health Check utilities.
"""

from src.shared.observability.health import liveness_check_handler, readiness_check_handler
from src.shared.observability.logging import (
    GovSecJSONFormatter,
    correlation_id_ctx,
    setup_structured_logging,
    tenant_ctx,
)
from src.shared.observability.metrics import (
    CQRS_COMMAND_DURATION_SECONDS,
    CQRS_COMMANDS_TOTAL,
    DOMAIN_EVENT_HANDLER_DURATION_SECONDS,
    DOMAIN_EVENTS_TOTAL,
    HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_TOTAL,
    PrometheusMetricsMiddleware,
    metrics_endpoint_handler,
)
from src.shared.observability.sanitizer import DataMasker, data_masker
from src.shared.observability.system_metrics import (
    SystemMetricsCollector,
    start_system_metrics_collector,
)
from src.shared.observability.tracing import (
    get_tracer,
    instrument_fastapi,
    setup_tracing,
    trace_span,
)

__all__ = [
    "setup_tracing",
    "get_tracer",
    "instrument_fastapi",
    "trace_span",
    "HTTP_REQUESTS_TOTAL",
    "HTTP_REQUEST_DURATION_SECONDS",
    "CQRS_COMMANDS_TOTAL",
    "CQRS_COMMAND_DURATION_SECONDS",
    "DOMAIN_EVENTS_TOTAL",
    "DOMAIN_EVENT_HANDLER_DURATION_SECONDS",
    "PrometheusMetricsMiddleware",
    "metrics_endpoint_handler",
    "GovSecJSONFormatter",
    "setup_structured_logging",
    "correlation_id_ctx",
    "tenant_ctx",
    "DataMasker",
    "data_masker",
    "SystemMetricsCollector",
    "start_system_metrics_collector",
    "liveness_check_handler",
    "readiness_check_handler",
]
