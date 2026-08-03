"""
Definição de Roles e Controle de Acesso RBAC
GovSec Shield — Infrastructure Security
"""

from enum import StrEnum
from typing import Any


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


ROLE_PERMISSIONS: dict[UserRole, dict[str, set[str]]] = {
    UserRole.VIEWER: {
        "tenants": {"GET"},
        "logs": {"GET"},
        "incidents": {"GET"},
        "asset_groups": {"GET"},
        "scan_targets": {"GET"},
        "assets": {"GET"},
        "scanner_profiles": {"GET"},
        "scan_schedules": {"GET"},
        "scan_executions": {"GET"},
        "vulnerabilities": {"GET"},
    },
    UserRole.ANALYST: {
        "tenants": {"GET"},
        "logs": {"GET", "POST"},
        "incidents": {"GET", "POST", "PUT"},
        "asset_groups": {"GET"},
        "scan_targets": {"GET"},
        "assets": {"GET"},
        "scanner_profiles": {"GET"},
        "scan_schedules": {"GET"},
        "scan_executions": {"GET"},
        "vulnerabilities": {"GET", "PATCH"},
        "monitoring_integrations": {"GET"},
    },
    UserRole.ENGINEER: {
        "tenants": {"GET", "POST", "PUT"},
        "logs": {"GET", "POST"},
        "incidents": {"GET", "POST", "PUT"},
        "asset_groups": {"GET", "POST", "PATCH", "DELETE"},
        "scan_targets": {"GET", "POST", "PATCH", "DELETE"},
        "assets": {"GET", "PATCH"},
        "scanner_profiles": {"GET", "POST", "PATCH", "DELETE"},
        "scan_schedules": {"GET", "POST", "PATCH", "DELETE"},
        "scan_executions": {"GET", "POST", "EXECUTE", "CANCEL", "RETRY"},
        "vulnerabilities": {"GET", "PATCH"},
        "monitoring_integrations": {"GET", "POST", "PATCH", "SYNC"},
    },
    UserRole.SECURITY_ADMIN: {
        "tenants": {"GET", "POST", "PUT", "DELETE"},
        "logs": {"GET", "POST", "DELETE"},
        "incidents": {"GET", "POST", "PUT", "DELETE"},
        "policies": {"GET", "POST", "PUT", "DELETE"},
        "asset_groups": {"GET", "POST", "PATCH", "DELETE"},
        "scan_targets": {"GET", "POST", "PATCH", "DELETE"},
        "assets": {"GET", "PATCH"},
        "scanner_profiles": {"GET", "POST", "PATCH", "DELETE"},
        "scan_schedules": {"GET", "POST", "PATCH", "DELETE"},
        "scan_executions": {"GET", "POST", "EXECUTE", "CANCEL", "RETRY"},
        "vulnerabilities": {"GET", "PATCH"},
        "monitoring_integrations": {"GET", "POST", "PATCH", "DELETE", "SYNC"},
    },
    UserRole.SYSTEM_ADMIN: {
        "tenants": {"GET", "POST", "PUT", "DELETE"},
        "logs": {"GET", "POST", "PUT", "DELETE"},
        "incidents": {"GET", "POST", "PUT", "DELETE"},
        "policies": {"GET", "POST", "PUT", "DELETE"},
        "users": {"GET", "POST", "PUT", "DELETE"},
        "system": {"GET", "POST", "PUT", "DELETE"},
        "asset_groups": {"GET", "POST", "PATCH", "DELETE"},
        "scan_targets": {"GET", "POST", "PATCH", "DELETE"},
        "assets": {"GET", "PATCH"},
        "scanner_profiles": {"GET", "POST", "PATCH", "DELETE"},
        "scan_schedules": {"GET", "POST", "PATCH", "DELETE"},
        "scan_executions": {"GET", "POST", "EXECUTE", "CANCEL", "RETRY"},
        "vulnerabilities": {"GET", "PATCH"},
        "monitoring_integrations": {"GET", "POST", "PATCH", "DELETE", "SYNC"},
    },
}


class RBACManager:
    @staticmethod
    def has_required_role(user_roles: list[str], required_role: UserRole) -> bool:
        required_level = ROLE_HIERARCHY.get(required_role, 99)
        for role_str in user_roles:
            try:
                user_role = UserRole(role_str)
                if ROLE_HIERARCHY.get(user_role, 0) >= required_level:
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def has_permission(user: dict[str, Any] | Any, resource: str, action: str) -> bool:
        roles: list[str] = []
        if isinstance(user, dict):
            roles = user.get("roles", [])
        elif hasattr(user, "roles"):
            roles = getattr(user, "roles", [])

        action_upper = action.upper()
        resource_lower = resource.lower()

        for role_str in roles:
            try:
                role_enum = UserRole(role_str)
                if role_enum == UserRole.SYSTEM_ADMIN:
                    return True

                perms = ROLE_PERMISSIONS.get(role_enum, {})
                allowed_actions = perms.get(resource_lower, set())
                if action_upper in allowed_actions or "*" in allowed_actions:
                    return True
            except ValueError:
                continue

        return False


def has_permission(user: dict[str, Any] | Any, resource: str, action: str) -> bool:
    return RBACManager.has_permission(user, resource, action)


