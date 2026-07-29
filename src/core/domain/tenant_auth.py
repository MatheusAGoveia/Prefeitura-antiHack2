"""
Serviço de Autorização de Tenant (Domain Authorization Service)
GovSec Shield — Domain Layer
"""

import logging
from uuid import UUID

from src.core.domain.exceptions import CrossTenantAccessDeniedError
from src.core.infrastructure.security.kernel import AuthenticatedUser, SecurityKernel

logger = logging.getLogger("govsec.domain.tenant_auth")


class TenantAuthorizationService:
    """
    Centraliza as regras de isolamento multi-tenant da plataforma GovSec Shield.
    Garante que usuários comuns operem estritamente dentro de seu próprio tenant,
    e audita qualquer acesso cross-tenant realizado por 'system_admin'.
    """

    @staticmethod
    def authorize_tenant_access(
        current_user: AuthenticatedUser,
        target_tenant: str | UUID | None = None,
        action: str = "ACCESS",
    ) -> str:
        """
        Valida a permissão de acesso ao tenant e retorna o tenant_id efetivo da operação.
        Lança CrossTenantAccessDeniedError se um usuário comum tentar operar fora de seu tenant.
        """
        user_tenant = current_user.tenant
        is_sys_admin = "system_admin" in current_user.roles

        if target_tenant is None:
            return user_tenant

        target_str = str(target_tenant).strip()
        if not target_str or target_str == user_tenant:
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
            SecurityKernel.audit(
                user=current_user,
                action=f"CROSS_TENANT_{action}",
                resource=f"tenant:{target_str}",
                success=False,
            )
            raise CrossTenantAccessDeniedError(
                f"Acesso negado. Usuário do tenant '{user_tenant}' não possui permissão para realizar a ação '{action}' no tenant '{target_str}'."
            )

        # Usuário system_admin realizando operação cross-tenant autorizada
        logger.info(
            "CROSS_TENANT_ACCESS_AUTHORIZED | user_id=%s origin_tenant=%s target_tenant=%s action=%s",
            current_user.user_id,
            user_tenant,
            target_str,
            action,
        )
        SecurityKernel.audit(
            user=current_user,
            action=f"CROSS_TENANT_{action}",
            resource=f"tenant:{target_str}",
            success=True,
        )
        return target_str
