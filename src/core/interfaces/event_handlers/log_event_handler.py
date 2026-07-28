"""
Handler de Eventos de Domínio para Telemetria e Logs
GovSec Shield — Infrastructure Event Handlers
"""

import logging
import time
from typing import Any

from src.core.domain.events import LogIngestedEvent
from src.shared.observability.metrics import DOMAIN_EVENT_HANDLER_DURATION_SECONDS, DOMAIN_EVENTS_TOTAL
from src.shared.observability.tracing import trace_span

logger = logging.getLogger("govsec.event_handlers.log")


class LogEventHandler:
    """
    Processador de eventos de ingestão de telemetrias e logs brutos.

    Instrumentado com OpenTelemetry Spans e Prometheus Metrics para
    rastreamento de volume e latência de processamento de eventos.
    """

    async def handle_log_ingested(self, event: dict[str, Any] | LogIngestedEvent) -> None:
        tenant_id = event.tenant_id if isinstance(event, LogIngestedEvent) else event.get("tenant_id")
        source = event.source if isinstance(event, LogIngestedEvent) else event.get("source")
        raw_data = event.raw_data if isinstance(event, LogIngestedEvent) else event.get("raw_data")
        event_id = str(event.event_id) if isinstance(event, LogIngestedEvent) else "N/A"
        tenant_str = str(tenant_id) if tenant_id else "global"

        span_attributes = {
            "event.type": "LogIngestedEvent",
            "event.id": event_id,
            "tenant_id": tenant_str,
            "log.source": str(source or "unknown"),
            "log.payload_size": len(str(raw_data or "")),
        }

        start_time = time.perf_counter()
        status = "success"

        with trace_span("Event.LogIngested", attributes=span_attributes):
            try:
                logger.info(
                    "EVENT_HANDLED | LogIngestedEvent tenant_id=%s source=%s len_data=%d",
                    tenant_id,
                    source,
                    len(str(raw_data or "")),
                    extra={"correlation_id": event_id, "tenant": tenant_str},
                )
                # Encaminhar para análise de risco em tempo real
            except Exception as exc:
                status = "failure"
                logger.error(
                    "EVENT_HANDLER_ERROR | LogIngestedEvent tenant_id=%s error=%s",
                    tenant_id,
                    exc,
                    extra={"correlation_id": event_id, "tenant": tenant_str},
                )
                raise
            finally:
                duration = time.perf_counter() - start_time
                DOMAIN_EVENTS_TOTAL.labels(
                    event_type="LogIngestedEvent",
                    tenant=tenant_str,
                    status=status,
                ).inc()
                DOMAIN_EVENT_HANDLER_DURATION_SECONDS.labels(
                    event_type="LogIngestedEvent",
                    tenant=tenant_str,
                ).observe(duration)

