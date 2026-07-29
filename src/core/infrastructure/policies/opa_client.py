"""
Cliente de Validação de Políticas OPA (Mock / Real)
GovSec Shield — Infrastructure Policies
"""

import logging
from typing import Any

import httpx

from src.core.infrastructure.config import settings

logger = logging.getLogger(__name__)


class OPAClient:
    """Cliente para avaliação de políticas OPA com fallback mock apenas em dev."""

    def __init__(self, opa_url: str | None = None, mock_mode: bool | None = None):
        self.opa_url = opa_url or settings.GOVSEC_OPA_URL
        # Em staging e production, mock_mode é ESTRITAMENTE proibido
        if settings.GOVSEC_ENV != "dev":
            self.mock_mode = False
        else:
            self.mock_mode = True if mock_mode is None else mock_mode


    async def evaluate_policy(
        self, command_name: str, tenant: str, context: dict[str, Any]
    ) -> bool:
        if self.mock_mode:
            logger.info(
                f"[OPA MOCK] Policy permitida para Command '{command_name}' no Tenant '{tenant}'"
            )
            return True

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                payload = {"input": {"command": command_name, "tenant": tenant, "context": context}}
                response = await client.post(self.opa_url, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    return bool(data.get("result", False))
                return False
        except Exception as e:
            logger.error(f"Erro ao consultar OPA Engine: {e}. Aplicando Fail-Closed.")
            return False

    async def evaluate(self, user: dict[str, Any], action: str, resource: str) -> bool:
        if self.mock_mode:
            logger.info(
                f"[OPA MOCK] Permissão concedida para action='{action}' no recurso='{resource}'"
            )
            return True

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                payload = {"input": {"user": user, "action": action, "resource": resource}}
                response = await client.post(self.opa_url, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    return bool(data.get("result", False))
                return False
        except Exception as e:
            logger.error(f"Erro ao consultar OPA Engine: {e}. Aplicando Fail-Closed.")
            return False

