"""
Configuração de Logs Estruturados JSON (Loki Compliant)
GovSec Shield — Shared Observability
"""

import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from opentelemetry import trace

# ContextVars para propagação assíncrona de correlation_id e tenant
correlation_id_ctx: ContextVar[str | None] = ContextVar("correlation_id", default=None)
tenant_ctx: ContextVar[str | None] = ContextVar("tenant", default=None)


class GovSecJSONFormatter(logging.Formatter):
    """
    Formatador de Log JSON compatível com Grafana Loki e os padrões do GovSec Shield.
    Campos obrigatórios: timestamp, level, logger, message, correlation_id, tenant.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Obter timestamp ISO-8601 UTC
        now_utc = datetime.now(timezone.utc).isoformat()

        # Extrair OpenTelemetry trace_id e span_id se existir span ativo
        current_span = trace.get_current_span()
        span_context = current_span.get_span_context() if current_span else None

        trace_id = None
        span_id = None
        if span_context and span_context.is_valid:
            trace_id = f"{span_context.trace_id:032x}"
            span_id = f"{span_context.span_id:016x}"

        # Resolver correlation_id e tenant a partir de atributos do record ou contextvars
        corr_id = getattr(record, "correlation_id", None) or correlation_id_ctx.get() or trace_id or "N/A"
        tenant_id = getattr(record, "tenant", None) or tenant_ctx.get() or "global"

        log_payload: dict[str, Any] = {
            "timestamp": now_utc,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": corr_id,
            "tenant": tenant_id,
        }

        if trace_id:
            log_payload["trace_id"] = trace_id
        if span_id:
            log_payload["span_id"] = span_id

        # Adicionar informações de exceção se houver
        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        # Adicionar campos extras dinâmicos passados via extra={...}
        for key, val in record.__dict__.items():
            if key not in (
                "args",
                "asctime",
                "created",
                "exc_info",
                "exc_text",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "message",
                "msg",
                "name",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "thread",
                "threadName",
                "correlation_id",
                "tenant",
            ):
                log_payload[key] = val

        return json.dumps(log_payload, ensure_ascii=False)


def setup_structured_logging(log_level: int = logging.INFO) -> None:
    """
    Configura o handler de log raiz (root logger) com o formatador JSON estruturado.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remover handlers existentes para evitar logs duplicados
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(GovSecJSONFormatter())
    root_logger.addHandler(stream_handler)
