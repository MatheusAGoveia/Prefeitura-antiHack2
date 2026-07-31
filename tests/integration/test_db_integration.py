"""
Testes de Integração com Banco de Dados em Memória / SQLite / Async Postgres
GovSec Shield — Integration Tests
"""

from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.domain.entities import AlertAcknowledgement, AuditLog, Tenant, TenantStatus
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.models import Base
from src.core.infrastructure.db.repositories import (
    PostgresAlertAcknowledgementRepository,
    PostgresLogRepository,
    PostgresTenantRepository,
)

TEST_DATABASE_URL = settings.GOVSEC_DB_URL


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
async def test_postgres_tenant_repository_flow(async_session: AsyncSession) -> None:
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


@pytest.mark.asyncio
async def test_postgres_log_repository_real_persistence(async_session: AsyncSession) -> None:
    log_repo = PostgresLogRepository(async_session)
    tenant_id = uuid4()

    audit_log = AuditLog(
        tenant_id=tenant_id,
        source="firewall-wazuh",
        raw_data="SSH Brute Force Attempt detected on port 22",
    )

    saved_log = await log_repo.save(audit_log)
    await async_session.commit()

    assert saved_log.id == audit_log.id
    assert saved_log.source == "firewall-wazuh"

    logs = await log_repo.list(skip=0, limit=10, tenant_id=tenant_id)
    assert len(logs) == 1
    assert logs[0].id == audit_log.id
    assert logs[0].raw_data == "SSH Brute Force Attempt detected on port 22"


@pytest.mark.asyncio
async def test_postgres_alert_acknowledgement_repository_real_persistence(
    async_session: AsyncSession,
) -> None:
    ack_repo = PostgresAlertAcknowledgementRepository(async_session)

    tenant_uuid = uuid4()
    ack = AlertAcknowledgement(
        alert_id="ServiceDown-01",
        fingerprint="fp-real-pg-test-9999",
        reason="Servidor reiniciado graciosamente pela equipe SRE",
        acknowledged_by="operador-sre",
        tenant_id=tenant_uuid,
    )

    saved_ack = await ack_repo.save(ack)
    await async_session.commit()

    assert saved_ack.fingerprint == "fp-real-pg-test-9999"

    retrieved = await ack_repo.get_by_fingerprint("fp-real-pg-test-9999", tenant_uuid)
    assert retrieved is not None
    assert retrieved.alert_id == "ServiceDown-01"
    assert retrieved.reason == "Servidor reiniciado graciosamente pela equipe SRE"
    assert retrieved.acknowledged_by == "operador-sre"
