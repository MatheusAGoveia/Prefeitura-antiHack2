"""
Interface / Porta para Provedores de Autenticação (Clean Architecture)
GovSec Shield — Application Layer Interfaces
"""

from abc import ABC, abstractmethod
from typing import Any


class AuthenticationProviderPort(ABC):
    """Porta de Aplicação para integração com Provedores de Identidade Externos (OIDC/OAuth2/Keycloak)."""

    @abstractmethod
    async def authenticate_credentials(
        self, email: str, password: str, tenant_id: str | None = None
    ) -> dict[str, Any]:
        """
        Autentica credenciais e retorna dicionário com os atributos do usuário (sub, tenant_id, roles).
        Pode lançar AuthenticationProviderUnavailableError ou InvalidCredentialsError.
        """
        pass
