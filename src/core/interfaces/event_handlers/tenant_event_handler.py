"""
Handler de Eventos de Domínio para Tenants
GovSec Shield — Infrastructure Event Handlers
"""

import logging
from typing import Any

from src.core.domain.events import TenantCreatedEvent

logger = logging.getLogger("govsec.event_handlers.tenant")


class TenantEventHandler:
    """
    Processador de eventos do ciclo de vida de Tenants.
    """

    async def handle_tenant_created(self, event: dict[str, Any] | TenantCreatedEvent) -> None:
        tenant_id = event.tenant_id if isinstance(event, TenantCreatedEvent) else event.get("tenant_id")
        name = event.name if isinstance(event, TenantCreatedEvent) else event.get("name")
        slug = event.slug if isinstance(event, TenantCreatedEvent) else event.get("slug")

        logger.info(
            "EVENT_HANDLED | TenantCreatedEvent tenant_id=%s name=%s slug=%s",
            tenant_id,
            name,
            slug,
        )
        # Notificar subsistemas de segurança e invalidar cache de tenants
