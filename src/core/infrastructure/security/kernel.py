"""
Security Kernel (Autenticação, Autorização, Zero Trust)
GovSec Shield — Infrastructure Security Kernel
"""

import logging
from typing import Any

from pydantic import BaseModel

from src.core.infrastructure.security.jwt import JWTHandler
from src.core.infrastructure.security.rbac import RBACManager, UserRole

logger = logging.getLogger("govsec.security.kernel")


class AuthenticatedUser(BaseModel):
    user_id: str
    tenant: str
    roles: list[str]


class SecurityKernel:
    """
    Guardião da plataforma GovSec Shield. Nega acesso implícito por padrão (Zero Trust).
    """

    @staticmethod
    def authenticate(token: str) -> AuthenticatedUser:
        payload = JWTHandler.verify_token(token)
        if not payload:
            raise PermissionError("Token de autenticação inválido, expirado ou revogado.")

        user_id = payload.get("sub", "")
        tenant = payload.get("tenant_id") or payload.get("tenant", "")
        roles = payload.get("roles", [])

        return AuthenticatedUser(user_id=user_id, tenant=tenant, roles=roles)

    @staticmethod
    def authorize(
        user: dict[str, Any] | AuthenticatedUser,
        command_or_role: str | UserRole,
        resource: str = "",
        action: str = "GET",
    ) -> bool:
        if isinstance(command_or_role, UserRole):
            roles = user.roles if isinstance(user, AuthenticatedUser) else user.get("roles", [])
            if not RBACManager.has_required_role(roles, command_or_role):
                raise PermissionError(f"Acesso negado. A role '{command_or_role.value}' é exigida.")
            return True

        # RBAC Check by resource & action
        if resource:
            user_dict = user.model_dump() if isinstance(user, AuthenticatedUser) else user
            if not RBACManager.has_permission(user_dict, resource=resource, action=action):
                raise PermissionError(
                    f"Acesso negado para ação '{action}' no recurso '{resource}'."
                )
            return True

        return True

    @staticmethod
    def audit(
        user: dict[str, Any] | AuthenticatedUser | None,
        action: str,
        resource: str,
        success: bool,
    ) -> None:
        user_id = "anonymous"
        tenant_id = "system"

        if isinstance(user, AuthenticatedUser):
            user_id = user.user_id
            tenant_id = user.tenant
        elif isinstance(user, dict):
            user_id = user.get("user_id") or user.get("sub", "anonymous")
            tenant_id = user.get("tenant_id") or user.get("tenant", "system")

        status_str = "SUCCESS" if success else "DENIED"
        logger.info(
            "AUDIT_LOG | action=%s resource=%s user_id=%s tenant_id=%s status=%s",
            action,
            resource,
            user_id,
            tenant_id,
            status_str,
        )

