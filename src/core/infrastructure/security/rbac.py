"""
Definição de Roles e Controle de Acesso RBAC
GovSec Shield — Infrastructure Security
"""

from enum import StrEnum
from typing import List

class UserRole(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ENGINEER = "engineer"
    SECURITY_ADMIN = "security_admin"
    SYSTEM_ADMIN = "system_admin"

ROLE_HIERARCHY = {
    UserRole.VIEWER: 1,
    UserRole.ANALYST: 2,
    UserRole.ENGINEER: 3,
    UserRole.SECURITY_ADMIN: 4,
    UserRole.SYSTEM_ADMIN: 5,
}

class RBACManager:
    @staticmethod
    def has_required_role(user_roles: List[str], required_role: UserRole) -> bool:
        required_level = ROLE_HIERARCHY.get(required_role, 99)
        for role_str in user_roles:
            try:
                user_role = UserRole(role_str)
                if ROLE_HIERARCHY.get(user_role, 0) >= required_level:
                    return True
            except ValueError:
                continue
        return False
