"""
Handler de Eventos de Domínio para Tenants
GovSec Shield — Infrastructure Event Handlers
"""

import logging
import time
from typing import Any

from src.core.domain.events import TenantCreatedEvent
from src.shared.observability.metrics import DOMAIN_EVENT_HANDLER_DURATION_SECONDS, DOMAIN_EVENTS_TOTAL
from src.shared.observability.tracing import trace_span

logger = logging.getLogger("govsec.event_handlers.tenant")


class TenantEventHandler:
    """
    Processador de eventos do ciclo de vida de Tenants.

    Instrumentado com OpenTelemetry Spans e Prometheus Counters para
    rastreamento distribuído e monitoramento de volume de eventos.
    """

    async def handle_tenant_created(self, event: dict[str, Any] | TenantCreatedEvent) -> None:
        tenant_id = event.tenant_id if isinstance(event, TenantCreatedEvent) else event.get("tenant_id")
        name = event.name if isinstance(event, TenantCreatedEvent) else event.get("name")
        slug = event.slug if isinstance(event, TenantCreatedEvent) else event.get("slug")
        event_id = str(event.event_id) if isinstance(event, TenantCreatedEvent) else "N/A"
        tenant_str = str(tenant_id) if tenant_id else "global"

        span_attributes = {
            "event.type": "TenantCreatedEvent",
            "event.id": event_id,
            "tenant_id": tenant_str,
        }

        start_time = time.perf_counter()
        status = "success"

        with trace_span("Event.TenantCreated", attributes=span_attributes):
            try:
                logger.info(
                    "EVENT_HANDLED | TenantCreatedEvent tenant_id=%s name=%s slug=%s",
                    tenant_id,
                    name,
                    slug,
                    extra={"correlation_id": event_id, "tenant": tenant_str},
                )
                # Notificar subsistemas de segurança e invalidar cache de tenants
            except Exception as exc:
                status = "failure"
                logger.error(
                    "EVENT_HANDLER_ERROR | TenantCreatedEvent tenant_id=%s error=%s",
                    tenant_id,
                    exc,
                    extra={"correlation_id": event_id, "tenant": tenant_str},
                )
                raise
            finally:
                duration = time.perf_counter() - start_time
                DOMAIN_EVENTS_TOTAL.labels(
                    event_type="TenantCreatedEvent",
                    tenant=tenant_str,
                    status=status,
                ).inc()
                DOMAIN_EVENT_HANDLER_DURATION_SECONDS.labels(
                    event_type="TenantCreatedEvent",
                    tenant=tenant_str,
                ).observe(duration)

