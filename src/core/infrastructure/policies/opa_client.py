"""
Cliente de Validação de Políticas OPA (Mock / Real)
GovSec Shield — Infrastructure Policies
"""

import logging
from typing import Dict, Any
import httpx
from src.core.infrastructure.config import settings

logger = logging.getLogger(__name__)

class OPAClient:
    """Cliente para avaliação de políticas OPA com fallback mock."""
    
    def __init__(self, opa_url: str = settings.GOVSEC_OPA_URL, mock_mode: bool = True):
        self.opa_url = opa_url
        self.mock_mode = mock_mode

    async def evaluate_policy(self, command_name: str, tenant: str, context: Dict[str, Any]) -> bool:
        if self.mock_mode:
            logger.info(f"[OPA MOCK] Policy permitida para Command '{command_name}' no Tenant '{tenant}'")
            return True

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                payload = {
                    "input": {
                        "command": command_name,
                        "tenant": tenant,
                        "context": context
                    }
                }
                response = await client.post(self.opa_url, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    return data.get("result", False)
                return False
        except Exception as e:
            logger.error(f"Erro ao consultar OPA Engine: {e}. Aplicando Fail-Closed.")
            return False
