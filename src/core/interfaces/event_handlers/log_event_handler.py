"""
Handler de Eventos de Domínio para Telemetria e Logs
GovSec Shield — Infrastructure Event Handlers
"""

import logging
from typing import Any

from src.core.domain.events import LogIngestedEvent

logger = logging.getLogger("govsec.event_handlers.log")


class LogEventHandler:
    """
    Processador de eventos de ingestão de telemetrias e logs brutos.
    """

    async def handle_log_ingested(self, event: dict[str, Any] | LogIngestedEvent) -> None:
        tenant_id = event.tenant_id if isinstance(event, LogIngestedEvent) else event.get("tenant_id")
        source = event.source if isinstance(event, LogIngestedEvent) else event.get("source")
        raw_data = event.raw_data if isinstance(event, LogIngestedEvent) else event.get("raw_data")

        logger.info(
            "EVENT_HANDLED | LogIngestedEvent tenant_id=%s source=%s len_data=%d",
            tenant_id,
            source,
            len(str(raw_data or "")),
        )
        # Encaminhar para análise de risco em tempo real
