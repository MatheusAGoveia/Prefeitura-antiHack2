"""
Suíte de Testes Unitários de Segurança & Autenticação (Sprint 0.2)
GovSec Shield — Security Tests
"""

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.core.infrastructure.policies.opa_client import OPAClient
from src.core.infrastructure.security.jwt import JWTHandler
from src.core.infrastructure.security.kernel import SecurityKernel
from src.core.infrastructure.security.rbac import UserRole, has_permission


# -----------------------------------------------------------------------------
# 1. Testes de Geração, Validação e Revogação JWT
# -----------------------------------------------------------------------------
def test_jwt_handler_generate_and_verify():
    user_id = "user-sec-01"
    tenant_id = "betim"
    roles = ["analyst"]

    token = JWTHandler.generate_token(user_id=user_id, tenant_id=tenant_id, roles=roles)
    assert token is not None

    payload = JWTHandler.verify_token(token)
    assert payload is not None
    assert payload["sub"] == user_id
    assert payload["tenant_id"] == tenant_id
    assert payload["roles"] == roles
    assert payload["token_type"] == "access"


def test_jwt_refresh_token_flow():
    user_id = "user-sec-02"
    tenant_id = "betim-saude"
    roles = ["engineer"]

    refresh_token = JWTHandler.generate_refresh_token(user_id=user_id, tenant_id=tenant_id, roles=roles)
    assert refresh_token is not None

    new_access_token = JWTHandler.refresh_token(refresh_token)
    assert new_access_token is not None

    payload = JWTHandler.verify_token(new_access_token)
    assert payload is not None
    assert payload["sub"] == user_id
    assert payload["token_type"] == "access"


def test_jwt_blacklist_logout():
    token = JWTHandler.generate_token(user_id="user-logout", tenant_id="betim", roles=["viewer"])
    assert JWTHandler.verify_token(token) is not None

    JWTHandler.blacklist_token(token)
    assert JWTHandler.verify_token(token) is None


# -----------------------------------------------------------------------------
# 2. Testes da Matriz RBAC para as 5 Roles
# -----------------------------------------------------------------------------
def test_rbac_permissions_matrix():
    viewer_user = {"roles": ["viewer"]}
    analyst_user = {"roles": ["analyst"]}
    engineer_user = {"roles": ["engineer"]}
    sec_admin_user = {"roles": ["security_admin"]}
    sys_admin_user = {"roles": ["system_admin"]}

    # Viewer
    assert has_permission(viewer_user, "tenants", "GET") is True
    assert has_permission(viewer_user, "tenants", "POST") is False
    assert has_permission(viewer_user, "incidents", "GET") is True
    assert has_permission(viewer_user, "incidents", "PUT") is False

    # Analyst
    assert has_permission(analyst_user, "logs", "POST") is True
    assert has_permission(analyst_user, "incidents", "PUT") is True
    assert has_permission(analyst_user, "tenants", "POST") is False

    # Engineer
    assert has_permission(engineer_user, "tenants", "POST") is True
    assert has_permission(engineer_user, "tenants", "PUT") is True
    assert has_permission(engineer_user, "tenants", "DELETE") is False

    # Security Admin
    assert has_permission(sec_admin_user, "tenants", "DELETE") is True
    assert has_permission(sec_admin_user, "policies", "POST") is True

    # System Admin (Todas as permissões)
    assert has_permission(sys_admin_user, "any_resource", "ANY_ACTION") is True


# -----------------------------------------------------------------------------
# 3. Testes do SecurityKernel (Authenticate, Authorize & Audit)
# -----------------------------------------------------------------------------
def test_security_kernel_flow():
    tenant_uuid = uuid4()
    token = JWTHandler.generate_token(user_id="sec-kernel-user", tenant_id=tenant_uuid, roles=["security_admin"])
    user = SecurityKernel.authenticate(token)

    assert user.user_id == "sec-kernel-user"
    assert user.tenant_id == tenant_uuid
    assert user.tenant == str(tenant_uuid)

    # Authorize por role
    assert SecurityKernel.authorize(user, UserRole.SECURITY_ADMIN) is True

    # Authorize por recurso e ação
    assert SecurityKernel.authorize(user, command_or_role="DeleteTenantCommand", resource="tenants", action="DELETE") is True

    # Audit sem exceções
    SecurityKernel.audit(user=user, action="DELETE_TENANT", resource="tenants", success=True)


# -----------------------------------------------------------------------------
# 4. Testes dos Endpoints REST (/api/v1/auth/login, /refresh, /logout)
# -----------------------------------------------------------------------------
def test_auth_endpoints_rest():
    client = TestClient(app)

    # 1. Login
    login_res = client.post("/api/v1/auth/login", json={"email": "admin@govsec.com", "password": "senha123"})
    assert login_res.status_code == 200
    data = login_res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "Bearer"

    access_token = data["access_token"]
    refresh_token = data["refresh_token"]

    # 2. Refresh Token
    refresh_res = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_res.status_code == 200
    assert "access_token" in refresh_res.json()

    # 3. Logout / Blacklist
    logout_res = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {access_token}"})
    assert logout_res.status_code == 200

    # 4. Tentar usar token revogado
    protected_res = client.get("/api/v1/tenants", headers={"Authorization": f"Bearer {access_token}"})
    assert protected_res.status_code == 401


# -----------------------------------------------------------------------------
# 5. Testes do OPA Client
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_opa_client_mock_evaluation():
    opa = OPAClient(mock_mode=True)
    res_cmd = await opa.evaluate_policy(command_name="CreateTenantCommand", tenant="betim", context={})
    assert res_cmd is True

    res_user = await opa.evaluate(user={"sub": "admin"}, action="POST", resource="tenants")
    assert res_user is True
