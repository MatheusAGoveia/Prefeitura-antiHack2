"""
Testes de Integração com Banco de Dados em Memória / SQLite / Async Postgres
GovSec Shield — Integration Tests
"""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from src.core.infrastructure.db.models import Base
from src.core.infrastructure.db.repositories import PostgresTenantRepository
from src.core.domain.entities import Tenant, TenantStatus

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

@pytest_asyncio.fixture
async def async_session():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()

@pytest.mark.asyncio
async def test_postgres_tenant_repository_flow(async_session: AsyncSession):
    repo = PostgresTenantRepository(async_session)

    tenant = Tenant(name="Prefeitura de Contagem", slug="contagem", status=TenantStatus.ACTIVE)
    saved = await repo.save(tenant)
    await async_session.commit()

    assert saved.id == tenant.id
    assert saved.name == "Prefeitura de Contagem"

    by_id = await repo.get_by_id(tenant.id)
    assert by_id is not None
    assert by_id.slug == "contagem"

    by_slug = await repo.get_by_slug("contagem")
    assert by_slug is not None
    assert by_slug.id == tenant.id

    all_tenants = await repo.list()
    assert len(all_tenants) == 1
