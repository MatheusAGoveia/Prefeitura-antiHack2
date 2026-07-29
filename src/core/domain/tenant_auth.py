"""
Serviço de Autorização de Tenant (Domain Authorization Service)
GovSec Shield — Domain Layer

Este módulo pertence à camada de domínio e NÃO importa infraestrutura.
Utiliza Protocol (duck typing estrutural) para desacoplar de implementações concretas.
"""

import logging
from typing import Protocol, runtime_checkable
from uuid import UUID

from src.core.domain.exceptions import CrossTenantAccessDeniedError

logger = logging.getLogger("govsec.domain.tenant_auth")


@runtime_checkable
class AuthenticatedUserProtocol(Protocol):
    """Protocolo estrutural que define o contrato mínimo de um usuário autenticado."""

    @property
    def user_id(self) -> str: ...

    @property
    def tenant(self) -> str: ...

    @property
    def roles(self) -> list[str]: ...


class TenantAuthorizationService:
    """
    Centraliza as regras de isolamento multi-tenant da plataforma GovSec Shield.
    Garante que usuários comuns operem estritamente dentro de seu próprio tenant,
    e audita qualquer tentativa de acesso cross-tenant via logging estruturado.

    A auditoria via SecurityKernel deve ser realizada pela camada de interfaces (routers),
    não pela camada de domínio, preservando a separação arquitetural.
    """

    @staticmethod
    def _normalize_tenant_identifier(value: str) -> str:
        """
        Normaliza o identificador de tenant para comparação canônica.
        UUIDs são comparados case-insensitive; strings são comparadas verbatim.
        """
        stripped = value.strip()
        try:
            return str(UUID(stripped))
        except ValueError:
            return stripped

    @staticmethod
    def authorize_tenant_access(
        current_user: AuthenticatedUserProtocol,
        target_tenant: str | UUID | None = None,
        action: str = "ACCESS",
    ) -> str:
        """
        Valida a permissão de acesso ao tenant e retorna o tenant_id efetivo da operação.
        Lança CrossTenantAccessDeniedError se um usuário comum tentar operar fora de seu tenant.

        Args:
            current_user: Usuário autenticado (Protocol, sem dependência de infraestrutura).
            target_tenant: Tenant alvo da operação (UUID ou slug).
            action: Nome da ação para logging.

        Returns:
            O tenant_id efetivo (string) para a operação.
        """
        user_tenant = current_user.tenant
        is_sys_admin = "system_admin" in current_user.roles

        if target_tenant is None:
            return user_tenant

        target_str = str(target_tenant).strip()
        if not target_str:
            return user_tenant

        # Normalizar ambos para comparação canônica (UUID case-insensitive)
        normalized_user = TenantAuthorizationService._normalize_tenant_identifier(user_tenant)
        normalized_target = TenantAuthorizationService._normalize_tenant_identifier(target_str)

        if normalized_target == normalized_user:
            return user_tenant

        # Operação Cross-Tenant solicitada
        if not is_sys_admin:
            logger.warning(
                "CROSS_TENANT_ACCESS_DENIED | user_id=%s user_tenant=%s target_tenant=%s action=%s",
                current_user.user_id,
                user_tenant,
                target_str,
                action,
            )
            raise CrossTenantAccessDeniedError(
                f"Acesso negado. Usuário do tenant '{user_tenant}' não possui "
                f"permissão para realizar a ação '{action}' no tenant '{target_str}'."
            )

        # Usuário system_admin realizando operação cross-tenant autorizada
        logger.info(
            "CROSS_TENANT_ACCESS_AUTHORIZED | user_id=%s origin_tenant=%s target_tenant=%s action=%s",
            current_user.user_id,
            user_tenant,
            target_str,
            action,
        )
        return target_str
