"""
Implementação do CommandBus com Validação de Políticas OPA
GovSec Shield — Infrastructure Messaging
"""

import logging
import time
from collections.abc import Callable
from typing import Any

from src.core.application.commands import Command
from src.core.infrastructure.messaging.dlq import DeadLetterQueue
from src.core.infrastructure.policies.opa_client import OPAClient
from src.core.infrastructure.security.kernel import SecurityKernel
from src.shared.observability import (
    CQRS_COMMAND_DURATION_SECONDS,
    CQRS_COMMANDS_TOTAL,
    trace_span,
)

logger = logging.getLogger("govsec.messaging.command_bus")


class CircuitBreakerOpenError(Exception):
    """Exceção disparada quando o Circuit Breaker está aberto."""


class CircuitBreakerMiddleware:
    """Middleware para prevenção de sobrecarga por cascata de falhas."""

    def __init__(self, failure_threshold: int = 3, recovery_time: float = 10.0):
        self.failure_threshold = failure_threshold
        self.recovery_time = recovery_time
        self.failures: dict[str, int] = {}
        self.last_failure_time: dict[str, float] = {}

    async def execute(self, command_name: str, next_func: Callable[[], Any]) -> Any:
        now = time.time()
        # Verificar se circuito está aberto
        if self.failures.get(command_name, 0) >= self.failure_threshold:
            last_failed = self.last_failure_time.get(command_name, 0.0)
            if now - last_failed < self.recovery_time:
                logger.error("CIRCUIT_BREAKER_OPEN | command_name=%s", command_name)
                raise CircuitBreakerOpenError(
                    f"Circuito aberto para o Command '{command_name}'. Tente novamente mais tarde."
                )
            # Reset temporário para testar recuperação
            self.failures[command_name] = 0

        try:
            result = await next_func()
            self.failures[command_name] = 0
            return result
        except Exception as exc:
            self.failures[command_name] = self.failures.get(command_name, 0) + 1
            self.last_failure_time[command_name] = now
            raise exc


class CommandBus:
    """
    CommandBus com orquestração de 4 Middlewares (Logging, Audit, CircuitBreaker, Retry + DLQ),
    verificação OPA Policy Engine (INV-005) e instrumentação OpenTelemetry + Prometheus.
    """

    def __init__(
        self,
        opa_client: OPAClient | None = None,
        dlq: DeadLetterQueue | None = None,
        max_retries: int = 3,
    ):
        self._handlers: dict[str, Callable[..., Any]] = {}
        self.opa_client = opa_client or OPAClient()
        self.dlq = dlq or DeadLetterQueue()
        self.max_retries = max_retries
        self.circuit_breaker = CircuitBreakerMiddleware()

    def register(self, command_name: str, handler_func: Callable[..., Any]) -> None:
        self._handlers[command_name] = handler_func
        logger.info("Handler registrado para Command '%s'", command_name)

    async def send(self, command: Command) -> Any:
        command_name = command.metadata.command_name
        command_id = str(command.metadata.command_id)
        tenant = command.metadata.tenant or "global"
        user_id = str(getattr(command.metadata, "user_id", "system"))
        start_time = time.time()

        span_attributes = {
            "command.name": command_name,
            "command.id": command_id,
            "tenant": tenant,
            "user_id": user_id,
        }

        with trace_span(f"Command.{command_name}", attributes=span_attributes):
            # 1. Logging Middleware — Início
            logger.info(
                "COMMAND_DISPATCH | name=%s id=%s tenant=%s user_id=%s",
                command_name,
                command_id,
                tenant,
                user_id,
                extra={"correlation_id": command_id, "tenant": tenant},
            )

            # 2. OPA Policy Engine Check (INV-005)
            allowed = await self.opa_client.evaluate_policy(
                command_name=command_name,
                tenant=tenant,
                context=command.metadata.model_dump(mode="json"),
            )

            if not allowed:
                SecurityKernel.audit(
                    user={"user_id": user_id, "tenant": tenant},
                    action=command_name,
                    resource="command_bus",
                    success=False,
                )
                CQRS_COMMANDS_TOTAL.labels(
                    command_name=command_name, tenant=tenant, status="denied"
                ).inc()
                raise PermissionError(
                    f"[POLICY DENIED] Execução do Command '{command_name}' negada pelo Policy Engine."
                )

            handler = self._handlers.get(command_name)
            if not handler:
                CQRS_COMMANDS_TOTAL.labels(
                    command_name=command_name, tenant=tenant, status="unhandled"
                ).inc()
                raise ValueError(f"Nenhum Handler registrado para o Command '{command_name}'")

            # Função interna de disparo sob Retry e Circuit Breaker
            async def _run_handler() -> Any:
                attempts = 0
                last_exception: Exception | None = None

                while attempts < self.max_retries:
                    attempts += 1
                    try:
                        res = await handler(command)
                        # 3. Audit Middleware — Sucesso
                        SecurityKernel.audit(
                            user={"user_id": user_id, "tenant": tenant},
                            action=command_name,
                            resource="command_bus",
                            success=True,
                        )
                        duration = time.time() - start_time
                        CQRS_COMMANDS_TOTAL.labels(
                            command_name=command_name, tenant=tenant, status="success"
                        ).inc()
                        CQRS_COMMAND_DURATION_SECONDS.labels(
                            command_name=command_name, tenant=tenant
                        ).observe(duration)

                        logger.info(
                            "COMMAND_SUCCESS | name=%s id=%s duration_ms=%.2fms",
                            command_name,
                            command_id,
                            duration * 1000,
                            extra={"correlation_id": command_id, "tenant": tenant},
                        )
                        return res
                    except Exception as exc:
                        last_exception = exc
                        logger.warning(
                            "COMMAND_RETRY | attempt=%d/%d name=%s error=%s",
                            attempts,
                            self.max_retries,
                            command_name,
                            exc,
                            extra={"correlation_id": command_id, "tenant": tenant},
                        )



                # Exaustão de tentativas -> Enviar para Dead Letter Queue (DLQ)
                CQRS_COMMANDS_TOTAL.labels(
                    command_name=command_name, tenant=tenant, status="failure"
                ).inc()
                self.dlq.send_to_dlq(
                    message={
                        "type": command_name,
                        "command_id": command_id,
                        "tenant": tenant,
                        "payload": command.metadata.model_dump(mode="json"),
                    },
                    error=last_exception or Exception("Max retries exceeded"),
                )
                if last_exception:
                    raise last_exception
                raise RuntimeError(
                    f"Command '{command_name}' falhou após {self.max_retries} tentativas."
                )

            # Execução empacotada pelo Circuit Breaker Middleware
            return await self.circuit_breaker.execute(command_name, _run_handler)


