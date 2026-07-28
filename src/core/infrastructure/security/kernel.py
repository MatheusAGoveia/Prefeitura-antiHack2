"""
Security Kernel (Autenticação, Autorização, Zero Trust)
GovSec Shield — Infrastructure Security Kernel
"""

from typing import Dict, Any, List
from pydantic import BaseModel
from src.core.infrastructure.security.jwt import JWTUtils
from src.core.infrastructure.security.rbac import UserRole, RBACManager

class AuthenticatedUser(BaseModel):
    user_id: str
    tenant: str
    roles: List[str]

class SecurityKernel:
    """
    Guardião da plataforma. Nega acesso implícito por padrão (Zero Trust).
    """

    @staticmethod
    def authenticate(token: str) -> AuthenticatedUser:
        try:
            payload = JWTUtils.decode_token(token)
            return AuthenticatedUser(
                user_id=payload["sub"],
                tenant=payload["tenant"],
                roles=payload.get("roles", [])
            )
        except Exception as e:
            raise PermissionError(f"Token de autenticação inválido ou expirado: {e}")

    @staticmethod
    def authorize(user: AuthenticatedUser, required_role: UserRole) -> bool:
        if not RBACManager.has_required_role(user.roles, required_role):
            raise PermissionError(f"Acesso negado. A role '{required_role.value}' é exigida.")
        return True
