"""
Testes Unitários para Handlers e Queries do Domínio Tenant (Sprint 1)
GovSec Shield — Unit Tests
"""

import pytest

from src.core.application.commands import (
    CreateTenantCommand,
    DeleteTenantCommand,
    UpdateTenantCommand,
)
from src.core.application.handlers import (
    CreateTenantHandler,
    DeleteTenantHandler,
    UpdateTenantHandler,
)
from src.core.application.interfaces import IEventPublisher
from src.core.application.queries import (
    GetTenantByIdQuery,
    ListTenantsQuery,
    TenantQueryHandler,
)
from src.core.domain.entities import Tenant, TenantStatus
from src.core.domain.events import DomainEvent
from src.core.domain.repositories import TenantRepository


class DummyEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published_events: list[DomainEvent] = []

    async def publish(self, event: DomainEvent) -> None:
        self.published_events.append(event)


class DummyTenantRepository(TenantRepository):
    def __init__(self) -> None:
        self.tenants: dict[str, Tenant] = {}

    async def save(self, tenant: Tenant) -> Tenant:
        self.tenants[str(tenant.id)] = tenant
        return tenant

    async def get_by_id(self, tenant_id) -> Tenant | None:
        return self.tenants.get(str(tenant_id))

    async def get_by_slug(self, slug: str) -> Tenant | None:
        for tenant in self.tenants.values():
            if tenant.slug == slug:
                return tenant
        return None

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        search: str | None = None,
        status: str | None = None,
    ) -> list[Tenant]:
        res = list(self.tenants.values())
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
        tenant = self.tenants.get(str(tenant_id))
        if tenant:
            tenant.deactivate()
            return True
        return False


@pytest.mark.asyncio
async def test_create_tenant_handler_success():
    repo = DummyTenantRepository()
    pub = DummyEventPublisher()
    handler = CreateTenantHandler(repo, pub)

    cmd = CreateTenantCommand(name="Prefeitura de Betim", slug="betim")
    dto = await handler.handle(cmd)

    assert dto.name == "Prefeitura de Betim"
    assert dto.slug == "betim"
    assert dto.status == "ACTIVE"
    assert len(pub.published_events) == 1


@pytest.mark.asyncio
async def test_create_tenant_duplicate_slug_raises_error():
    repo = DummyTenantRepository()
    pub = DummyEventPublisher()
    handler = CreateTenantHandler(repo, pub)

    cmd1 = CreateTenantCommand(name="Prefeitura de Betim", slug="betim")
    await handler.handle(cmd1)

    cmd2 = CreateTenantCommand(name="Outra Betim", slug="betim")
    with pytest.raises(ValueError, match="slug 'betim'"):
        await handler.handle(cmd2)


@pytest.mark.asyncio
async def test_update_tenant_handler():
    repo = DummyTenantRepository()
    pub = DummyEventPublisher()
    create_handler = CreateTenantHandler(repo, pub)
    created = await create_handler.handle(CreateTenantCommand(name="Prefeitura Original"))

    update_handler = UpdateTenantHandler(repo)
    cmd = UpdateTenantCommand(
        tenant_id=created.id, name="Prefeitura Atualizada", status="SUSPENDED"
    )
    updated = await update_handler.handle(cmd)

    assert updated.name == "Prefeitura Atualizada"
    assert updated.status == "SUSPENDED"


@pytest.mark.asyncio
async def test_delete_tenant_handler_soft_delete():
    repo = DummyTenantRepository()
    pub = DummyEventPublisher()
    create_handler = CreateTenantHandler(repo, pub)
    created = await create_handler.handle(CreateTenantCommand(name="Prefeitura Temp"))

    delete_handler = DeleteTenantHandler(repo)
    cmd = DeleteTenantCommand(tenant_id=created.id)
    success = await delete_handler.handle(cmd)

    assert success is True
    found = await repo.get_by_id(created.id)
    assert found is not None
    assert found.status == TenantStatus.INACTIVE


@pytest.mark.asyncio
async def test_tenant_query_handler_search_and_get():
    repo = DummyTenantRepository()
    pub = DummyEventPublisher()
    create_handler = CreateTenantHandler(repo, pub)

    t1 = await create_handler.handle(CreateTenantCommand(name="Saude Betim", slug="betim-saude"))
    await create_handler.handle(CreateTenantCommand(name="Educacao Betim", slug="betim-edu"))

    query_handler = TenantQueryHandler(repo)

    # Test Get by ID
    by_id = await query_handler.get_by_id(GetTenantByIdQuery(tenant_id=t1.id))
    assert by_id is not None
    assert by_id.slug == "betim-saude"

    # Test List with search filter
    filtered = await query_handler.list(ListTenantsQuery(search="saude"))
    assert len(filtered) == 1
    assert filtered[0].slug == "betim-saude"
