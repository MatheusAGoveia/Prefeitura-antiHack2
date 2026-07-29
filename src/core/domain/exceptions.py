"""
Exceções de Domínio do GovSec Shield
GovSec Shield — Domain Exceptions
"""


class DomainError(Exception):
    """Exceção base para regras de negócio e violações de domínio."""

    pass


class AuthenticationProviderUnavailableError(DomainError):
    """Lançada quando o Provedor de Identidade externo não está disponível ou configurado."""

    pass


class InvalidCredentialsError(DomainError):
    """Lançada quando a autenticação de credenciais falha."""

    pass


class CrossTenantAccessDeniedError(DomainError):
    """Lançada quando uma operação cross-tenant não autorizada é solicitada."""

    pass

