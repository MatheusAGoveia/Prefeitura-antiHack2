"""
Testes de Integração com Banco de Dados e Migrações Alembic — Capability M3.1
GovSec Shield — Integration Tests
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.domain.correlation import CorrelationRuleVersion
from src.core.domain.incidents import Asset, SecurityEvent, SecurityEventSeverity
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.models import Base
from src.core.infrastructure.db.repositories import (
    PostgresAssetRepository,
    PostgresCorrelationRuleVersionRepository,
    PostgresSecurityEventRepository,
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


def test_migration_0005_definition_and_reversibility() -> None:
    """Valida que a migração 0005 está estruturada corretamente na árvore do Alembic e possui downgrade."""
    config = Config("alembic.ini")
    script = ScriptDirectory.from_config(config)

    rev = script.get_revision("0005_create_m3_assets_security_events")
    assert rev is not None
    assert rev.down_revision == "0004_alert_ack_tenant_id_uuid"
    assert rev.module.upgrade is not None
    assert rev.module.downgrade is not None


@pytest.mark.asyncio
async def test_postgres_asset_repository_save_and_resolve(async_session: AsyncSession) -> None:
    """Valida persistência e resolução de ativo no repositório PostgreSQL via AsyncSession."""
    repo = PostgresAssetRepository(async_session)
    tenant_a = uuid4()
    tenant_b = uuid4()

    asset_a = Asset(
        tenant_id=tenant_a,
        name="GovSec Core API",
        asset_type="service",
        service_name="govsec-core-api",
        environment="development",
        criticality="HIGH",
        is_active=True,
    )

    saved = await repo.save(asset_a)
    await async_session.flush()

    assert saved.asset_id == asset_a.asset_id

    # Busca por ID e tenant
    found = await repo.get_by_id(saved.asset_id, tenant_a)
    assert found is not None
    assert found.name == "GovSec Core API"

    # Isolamento: Tenant B não encontra o ativo do Tenant A
    found_b = await repo.get_by_id(saved.asset_id, tenant_b)
    assert found_b is None

    # Resolução por service_name e environment
    resolved = await repo.resolve_active_asset(tenant_a, "govsec-core-api", "development")
    assert resolved is not None
    assert resolved.asset_id == saved.asset_id


@pytest.mark.asyncio
async def test_postgres_security_event_atomic_idempotency(async_session: AsyncSession) -> None:
    """Valida idempotência atômica e supressão de duplicidade no repositório de eventos."""
    repo = PostgresSecurityEventRepository(async_session)
    tenant_id = uuid4()
    now = datetime.now(timezone.utc)

    event = SecurityEvent(
        tenant_id=tenant_id,
        source="Alertmanager",
        event_type="HighCpu",
        severity=SecurityEventSeverity.HIGH,
        occurred_at=now,
        received_at=now,
        asset_id=None,
        payload={"cpu": 95},
        idempotency_key="idemp-atomic-100",
    )

    # Primeira inserção: created = True
    saved_evt, created1 = await repo.save(event)
    await async_session.flush()
    assert created1 is True
    assert saved_evt.idempotency_key == "idemp-atomic-100"

    # Reenvio com mesmo tenant, source e idempotency_key: created = False
    dup_evt = SecurityEvent(
        tenant_id=tenant_id,
        source="Alertmanager",
        event_type="HighCpu",
        severity=SecurityEventSeverity.HIGH,
        occurred_at=now,
        received_at=now,
        asset_id=None,
        payload={"cpu": 98},
        idempotency_key="idemp-atomic-100",
    )

    saved_dup, created2 = await repo.save(dup_evt)
    assert created2 is False
    assert saved_dup.event_id == saved_evt.event_id


@pytest.mark.asyncio
async def test_postgres_correlation_rule_version_repository(async_session: AsyncSession) -> None:
    """Valida a persistência e listagem de versões de regras de correlação."""
    repo = PostgresCorrelationRuleVersionRepository(async_session)

    rule_ver = CorrelationRuleVersion(
        rule_version_id=uuid4(),
        rule_id="R-CPU-001",
        rule_version="1.0.0",
        name="Regra CPU Alta",
        category="performance",
        is_active=True,
    )

    await repo.save(rule_ver)
    await async_session.flush()

    retrieved = await repo.get_by_rule_and_version("R-CPU-001", "1.0.0")
    assert retrieved is not None
    assert retrieved.name == "Regra CPU Alta"

    active_list = await repo.list_active()
    assert len(active_list) >= 1
    assert any(r.rule_id == "R-CPU-001" for r in active_list)
