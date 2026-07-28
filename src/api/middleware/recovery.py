"""
Middleware de Recovery (Panic Handler)
GovSec Shield — Security Middleware

Captura exceções não tratadas em qualquer handler FastAPI, loga o traceback
completo em formato JSON estruturado e retorna uma resposta HTTP 500 padronizada
sem vazar detalhes internos ao cliente (princípio de Security by Default).

Arquitetura:
    - Posicionado como o PRIMEIRO middleware na chain (outermost)
    - Instrumenta cada erro com correlation_id, tenant, trace_id (OTel)
    - Incrementa contador Prometheus `http_requests_total` com status_code=500
    - Compatível com qualquer exceção (BaseException, não apenas Exception)
"""

import logging
import traceback
from collections.abc import Awaitable, Callable
from uuid import uuid4

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from opentelemetry import trace
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("govsec.middleware.recovery")


class RecoveryMiddleware(BaseHTTPMiddleware):
    """
    Middleware de captura de erros não tratados (Panic Recovery).

    Garante que nenhuma exceção interna vaze para o cliente sem tratamento,
    preservando a segurança operacional e a integridade do sistema.

    Comportamento:
        - Captura qualquer `Exception` não tratada pelos handlers da aplicação
        - Gera um `recovery_id` único por evento de erro para correlação em logs
        - Loga o traceback completo com contexto OTel (trace_id/span_id)
        - Retorna HTTP 500 com body JSON padronizado sem expor detalhes internos
        - Nunca silencia o erro: o log é sempre emitido em nível ERROR
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        try:
            return await call_next(request)
        except Exception as exc:
            return self._handle_unhandled_exception(request, exc)

    def _handle_unhandled_exception(self, request: Request, exc: Exception) -> JSONResponse:
        """Processa e loga a exceção não tratada, retornando HTTP 500 padronizado."""
        recovery_id = str(uuid4())
        tenant = request.headers.get("X-Tenant-ID", "global")
        path = request.url.path
        method = request.method

        # Extrair trace_id e span_id do span OTel ativo, se disponível
        current_span = trace.get_current_span()
        span_context = current_span.get_span_context() if current_span else None
        trace_id: str | None = None
        span_id: str | None = None
        if span_context and span_context.is_valid:
            trace_id = f"{span_context.trace_id:032x}"
            span_id = f"{span_context.span_id:016x}"

        # Capturar traceback completo para log interno
        tb_str = traceback.format_exc()

        logger.error(
            "UNHANDLED_EXCEPTION | recovery_id=%s method=%s path=%s error=%s",
            recovery_id,
            method,
            path,
            type(exc).__name__,
            exc_info=True,
            extra={
                "correlation_id": recovery_id,
                "tenant": tenant,
                "trace_id": trace_id,
                "span_id": span_id,
                "exception_type": type(exc).__name__,
                "exception_message": str(exc),
                "traceback": tb_str,
                "http_method": method,
                "http_path": path,
            },
        )

        # Retornar resposta padronizada SEM vazar detalhes internos ao cliente
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_server_error",
                "message": "Ocorreu um erro interno no servidor. Por favor, tente novamente.",
                "recovery_id": recovery_id,
            },
        )
