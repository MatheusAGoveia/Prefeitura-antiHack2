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
    def _parse_uuid(val: str | UUID) -> UUID | None:
        if isinstance(val, UUID):
            return val
        val_str = str(val).strip()
        if not val_str:
            return None
        try:
            return UUID(val_str)
        except ValueError:
            return None

    @staticmethod
    def authorize_tenant_access(
        current_user: AuthenticatedUserProtocol,
        target_tenant: str | UUID | None = None,
        action: str = "ACCESS",
    ) -> UUID:
        """
        Valida a permissão de acesso ao tenant e retorna o tenant_id (UUID) efetivo da operação.
        Lança CrossTenantAccessDeniedError se um usuário comum tentar operar fora de seu tenant.
        """
        user_tenant_uuid = (
            current_user.tenant_id
            if hasattr(current_user, "tenant_id") and isinstance(current_user.tenant_id, UUID)
            else UUID(str(current_user.tenant))
        )
        is_sys_admin = "system_admin" in current_user.roles

        if target_tenant is None:
            return user_tenant_uuid

        target_uuid = TenantAuthorizationService._parse_uuid(target_tenant)
        if target_uuid is None:
            # Se target_tenant não for um UUID válido e for passado, trata-se de slug ou id inválido
            if not is_sys_admin:
                raise CrossTenantAccessDeniedError(
                    f"Acesso negado. Usuário do tenant '{user_tenant_uuid}' não possui "
                    f"permissão para acessar tenant inválido ou de outro escopo ('{target_tenant}')."
                )
            # Para sysadmin permitimos fallback ou busca
            return user_tenant_uuid

        if target_uuid == user_tenant_uuid:
            return user_tenant_uuid

        # Operação Cross-Tenant solicitada
        if not is_sys_admin:
            logger.warning(
                "CROSS_TENANT_ACCESS_DENIED | user_id=%s user_tenant=%s target_tenant=%s action=%s",
                current_user.user_id,
                user_tenant_uuid,
                target_uuid,
                action,
            )
            raise CrossTenantAccessDeniedError(
                f"Acesso negado. Usuário do tenant '{user_tenant_uuid}' não possui "
                f"permissão para realizar a ação '{action}' no tenant '{target_uuid}'."
            )

        # Usuário system_admin realizando operação cross-tenant autorizada
        logger.info(
            "CROSS_TENANT_ACCESS_AUTHORIZED | user_id=%s origin_tenant=%s target_tenant=%s action=%s",
            current_user.user_id,
            user_tenant_uuid,
            target_uuid,
            action,
        )
        return target_uuid
