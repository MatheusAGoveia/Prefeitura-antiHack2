"""
Implementação Padrão do Provedor de Autenticação OIDC (Fail-Closed)
GovSec Shield — Infrastructure Security
"""

from typing import Any

from src.core.application.interfaces.auth_provider import AuthenticationProviderPort
from src.core.domain.exceptions import AuthenticationProviderUnavailableError


class DefaultOIDCAuthenticationProvider(AuthenticationProviderPort):
    """
    Implementação de infraestrutura Fail-Closed para OIDC/OAuth2.
    Lança exceção de domínio caso a integração não esteja disponível em staging/produção.
    Sem qualquer acoplamento com FastAPI ou Starlette.
    """

    async def authenticate_credentials(
        self, email: str, password: str, tenant_id: str | None = None
    ) -> dict[str, Any]:
        raise AuthenticationProviderUnavailableError(
            "Provedor de Identidade (OIDC/OAuth2) não configurado para staging/produção (Fail-Closed)."
        )
