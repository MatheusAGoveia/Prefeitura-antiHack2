"""
Testes Unitários do Módulo Core
GovSec Shield — Unit Tests
"""

from uuid import uuid4

import pytest

from src.core.application.commands import CreateTenantCommand, IngestLogCommand
from src.core.application.handlers import CreateTenantHandler, IngestLogHandler
from src.core.domain.entities import Tenant
from src.core.domain.events import TenantCreatedEvent
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

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        search: str | None = None,
        status: str | None = None,
        tenant_filter: str | None = None,
    ):
        res = list(self.tenants.values())
        if tenant_filter:
            res = [
                t for t in res
                if str(t.id) == tenant_filter or t.slug == tenant_filter or t.name == tenant_filter
            ]
        if search:
            res = [
                t
                for t in res
                if search.lower() in t.name.lower() or search.lower() in t.slug.lower()
            ]
        if status:
            res = [t for t in res if t.status == status or t.status.value == status]
        return res[skip : skip + limit]

    async def delete(self, tenant_id) -> bool:
        tenant = self.tenants.get(tenant_id)
        if tenant:
            tenant.deactivate()
            return True
        return False




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

    cmd = IngestLogCommand(
        source="wazuh", raw_data="Unauthorized login attempt", tenant_id=tenant_id
    )
    await handler.handle(cmd)

    assert len(pub.published) == 1
    assert pub.published[0].source == "wazuh"
    assert pub.published[0].tenant_id == tenant_id


def test_jwt_and_security_kernel_flow():
    token = JWTUtils.create_access_token(user_id="usr-123", tenant="betim", roles=["system_admin"])
    user = SecurityKernel.authenticate(token)
    assert user.user_id == "usr-123"
    assert user.tenant == "betim"
    assert "system_admin" in user.roles

    assert SecurityKernel.authorize(user, UserRole.VIEWER) is True
    assert SecurityKernel.authorize(user, UserRole.SYSTEM_ADMIN) is True


def test_security_kernel_unauthorized():
    token = JWTUtils.create_access_token(user_id="usr-456", tenant="betim", roles=["viewer"])
    user = SecurityKernel.authenticate(token)
    with pytest.raises(PermissionError, match="Acesso negado"):
        SecurityKernel.authorize(user, UserRole.SYSTEM_ADMIN)


def test_rest_api_endpoints_sprint1():
    from fastapi.testclient import TestClient

    from src.api.main import app
    from src.core.application.handlers import (
        CreateTenantHandler,
        DeleteTenantHandler,
        IngestLogHandler,
        UpdateTenantHandler,
    )
    from src.core.application.queries import TenantQueryHandler
    from src.core.infrastructure.db.repositories import InMemoryLogRepository
    from src.core.infrastructure.messaging.command_bus import CommandBus
    from src.core.infrastructure.messaging.event_bus import EventBus
    from src.core.interfaces.rest.dependencies import (
        get_command_bus,
        get_log_query_handler,
        get_query_handler,
    )

    mock_repo = MockTenantRepository()
    event_bus = EventBus(use_kafka=False)
    log_repo = InMemoryLogRepository()
    cmd_bus = CommandBus()

    create_handler = CreateTenantHandler(mock_repo, event_bus)
    update_handler = UpdateTenantHandler(mock_repo)
    delete_handler = DeleteTenantHandler(mock_repo)
    ingest_handler = IngestLogHandler(event_bus, log_repo)

    cmd_bus.register("CreateTenantCommand", lambda cmd: create_handler.handle(cmd))
    cmd_bus.register("UpdateTenantCommand", lambda cmd: update_handler.handle(cmd))
    cmd_bus.register("DeleteTenantCommand", lambda cmd: delete_handler.handle(cmd))
    cmd_bus.register("IngestLogCommand", lambda cmd: ingest_handler.handle(cmd))

    async def override_get_command_bus():
        return cmd_bus

    async def override_get_query_handler():
        return TenantQueryHandler(mock_repo)

    async def override_get_log_query_handler():
        from src.core.application.queries import LogQueryHandler
        return LogQueryHandler(log_repo)

    app.dependency_overrides[get_command_bus] = override_get_command_bus
    app.dependency_overrides[get_query_handler] = override_get_query_handler
    app.dependency_overrides[get_log_query_handler] = override_get_log_query_handler


    try:
        client = TestClient(app)

        # 1. Gerar token de admin
        token_res = client.post(
            "/api/v1/auth/token",
            json={"user_id": "admin-test", "tenant": "betim", "roles": ["system_admin", "analyst", "viewer"]},
        )
        assert token_res.status_code == 200
        token = token_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. POST /api/v1/tenants (Criar tenant)
        create_res = client.post(
            "/api/v1/tenants", json={"name": "Prefeitura Teste", "slug": "prefeitura-teste"}, headers=headers
        )
        assert create_res.status_code == 201
        tenant_data = create_res.json()
        tenant_id = tenant_data["id"]
        assert tenant_data["name"] == "Prefeitura Teste"
        assert tenant_data["status"] == "ACTIVE"

        # 3. GET /api/v1/tenants (Listar tenants)
        list_res = client.get("/api/v1/tenants?skip=0&limit=50", headers=headers)
        assert list_res.status_code == 200
        assert len(list_res.json()) >= 1

        # 4. GET /api/v1/tenants/{id} (Buscar por ID)
        get_res = client.get(f"/api/v1/tenants/{tenant_id}", headers=headers)
        assert get_res.status_code == 200
        assert get_res.json()["id"] == tenant_id

        # 5. PUT /api/v1/tenants/{id} (Atualizar tenant)
        update_res = client.put(
            f"/api/v1/tenants/{tenant_id}",
            json={"name": "Prefeitura Teste Renomeada", "status": "ACTIVE"},
            headers=headers,
        )
        assert update_res.status_code == 200
        assert update_res.json()["name"] == "Prefeitura Teste Renomeada"

        # 6. POST /api/v1/logs (Ingestão de Log)
        log_res = client.post(
            "/api/v1/logs",
            json={
                "source": "wazuh-unit-test",
                "raw_data": "Log Event Test",
                "tenant_id": tenant_id,
            },
            headers=headers,
        )
        assert log_res.status_code == 202
        assert log_res.json()["status"] == "accepted"

        # 7. GET /api/v1/logs (Listar logs com filtro)
        logs_list_res = client.get(f"/api/v1/logs?tenant_id={tenant_id}", headers=headers)
        assert logs_list_res.status_code == 200
        logs_data = logs_list_res.json()
        assert len(logs_data) >= 1
        assert logs_data[0]["source"] == "wazuh-unit-test"

        # 8. DELETE /api/v1/tenants/{id} (Soft Delete)
        del_res = client.delete(f"/api/v1/tenants/{tenant_id}", headers=headers)
        assert del_res.status_code == 204
    finally:
        app.dependency_overrides.clear()


