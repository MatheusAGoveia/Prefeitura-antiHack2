"""
Implementação do CommandBus com Validação de Políticas OPA
GovSec Shield — Infrastructure Messaging
"""

import logging
from typing import Dict, Any, Callable
from src.core.application.commands import Command
from src.core.infrastructure.policies.opa_client import OPAClient

logger = logging.getLogger(__name__)

class CommandBus:
    """
    CommandBus responsável pelo roteamento de Commands para seus Handlers,
    garantindo que o Policy Engine (OPA) seja consultado ANTES da execução (INV-005).
    """

    def __init__(self, opa_client: Optional[OPAClient] = None):
        self._handlers: Dict[str, Callable] = {}
        self.opa_client = opa_client or OPAClient()

    def register(self, command_name: str, handler_func: Callable) -> None:
        self._handlers[command_name] = handler_func
        logger.info(f"Handler registrado para Command '{command_name}'")

    async def send(self, command: Command) -> Any:
        command_name = command.metadata.command_name
        tenant = command.metadata.tenant or "global"

        # Validação obrigatória de políticas (INV-005)
        allowed = await self.opa_client.evaluate_policy(
            command_name=command_name,
            tenant=tenant,
            context=command.metadata.model_dump(mode="json")
        )

        if not allowed:
            raise PermissionError(f"[POLICY DENIED] Execução do Command '{command_name}' negada pelo Policy Engine.")

        handler = self._handlers.get(command_name)
        if not handler:
            raise ValueError(f"Nenhum Handler registrado para o Command '{command_name}'")

        logger.info(f"[COMMAND DISPATCHED] {command_name} ID={command.metadata.command_id}")
        return await handler(command)
