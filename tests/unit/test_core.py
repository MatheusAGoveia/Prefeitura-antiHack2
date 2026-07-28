"""
Testes Unitários do Módulo Core
GovSec Shield — Unit Tests
"""

import pytest
from uuid import uuid4
from datetime import datetime
from src.core.domain.entities import Tenant, TenantStatus
from src.core.domain.events import TenantCreatedEvent
from src.core.application.commands import CreateTenantCommand, IngestLogCommand
from src.core.application.handlers import CreateTenantHandler, IngestLogHandler
from src.core.infrastructure.security.jwt import JWTUtils
from src.core.infrastructure.security.kernel import SecurityKernel
from src.core.infrastructure.security.rbac import UserRole

class MockTenantRepository:
    def __init__(self):
        self.tenants = {}

    async def save(self, tenant: Tenant) -> Tenant:
        self.tenants[tenant.id] = tenant
        return tenant

    async def get_by_id(self, tenant_id):
        return self.tenants.get(tenant_id)

    async def get_by_slug(self, slug: str):
        for t in self.tenants.values():
            if t.slug == slug:
                return t
        return None

    async def list(self, skip: int = 0, limit: int = 100):
        return list(self.tenants.values())[skip:skip+limit]

class MockEventPublisher:
    def __init__(self):
        self.published = []

    async def publish(self, event):
        self.published.append(event)

@pytest.mark.asyncio
async def test_create_tenant_handler_success():
    repo = MockTenantRepository()
    pub = MockEventPublisher()
    handler = CreateTenantHandler(repo, pub)

    cmd = CreateTenantCommand(name="Prefeitura de Betim", slug="prefeitura-betim")
    res = await handler.handle(cmd)

    assert res.name == "Prefeitura de Betim"
    assert res.slug == "prefeitura-betim"
    assert len(pub.published) == 1
    assert isinstance(pub.published[0], TenantCreatedEvent)

@pytest.mark.asyncio
async def test_create_tenant_duplicate_slug_raises_error():
    repo = MockTenantRepository()
    pub = MockEventPublisher()
    handler = CreateTenantHandler(repo, pub)

    cmd1 = CreateTenantCommand(name="Prefeitura de Betim", slug="betim")
    await handler.handle(cmd1)

    cmd2 = CreateTenantCommand(name="Outra Betim", slug="betim")
    with pytest.raises(ValueError, match="Já existe um Tenant registrado"):
        await handler.handle(cmd2)

@pytest.mark.asyncio
async def test_ingest_log_handler():
    pub = MockEventPublisher()
    handler = IngestLogHandler(pub)
    tenant_id = uuid4()

    cmd = IngestLogCommand(source="wazuh", raw_data="Unauthorized login attempt", tenant_id=tenant_id)
    await handler.handle(cmd)

    assert len(pub.published) == 1
    assert pub.published[0].source == "wazuh"
    assert pub.published[0].tenant_id == tenant_id

def test_jwt_and_security_kernel_flow():
    token = JWTUtils.create_access_token(
        user_id="usr-123",
        tenant="betim",
        roles=["system_admin"]
    )
    user = SecurityKernel.authenticate(token)
    assert user.user_id == "usr-123"
    assert user.tenant == "betim"
    assert "system_admin" in user.roles

    assert SecurityKernel.authorize(user, UserRole.VIEWER) is True
    assert SecurityKernel.authorize(user, UserRole.SYSTEM_ADMIN) is True

def test_security_kernel_unauthorized():
    token = JWTUtils.create_access_token(
        user_id="usr-456",
        tenant="betim",
        roles=["viewer"]
    )
    user = SecurityKernel.authenticate(token)
    with pytest.raises(PermissionError, match="Acesso negado"):
        SecurityKernel.authorize(user, UserRole.SYSTEM_ADMIN)
