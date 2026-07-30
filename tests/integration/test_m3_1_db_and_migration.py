"""
Testes de Integração com Banco de Dados e Migrações Alembic — Capability M3.1 (Bloqueadores)
GovSec Shield — Integration Tests
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.domain.correlation import CorrelationRuleVersion
from src.core.domain.incidents import Asset, SecurityEvent, SecurityEventSeverity
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.models import AssetModel, Base, SecurityEventModel
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
async def test_cross_tenant_asset_event_constraint_violation(async_session: AsyncSession) -> None:
    """Valida que o banco de dados rejeita via FK composta associar SecurityEvent do Tenant A a Ativo do Tenant B."""
    tenant_a = uuid4()
    tenant_b = uuid4()
    asset_id_b = uuid4()

    # 1. Cria ativo pertencente ao Tenant B
    asset_b_model = AssetModel(
        asset_id=asset_id_b,
        tenant_id=tenant_b,
        name="Servidor Tenant B",
        asset_type="service",
        service_name="api-tenant-b",
        environment="production",
        criticality="HIGH",
        is_active=True,
    )
    async_session.add(asset_b_model)
    await async_session.flush()

    # 2. Tenta criar um SecurityEvent pertencente ao Tenant A associado ao ativo do Tenant B
    now = datetime.now(timezone.utc)
    cross_tenant_event = SecurityEventModel(
        event_id=uuid4(),
        tenant_id=tenant_a,  # Tenant A!
        asset_id=asset_id_b,  # Ativo do Tenant B!
        source="Alertmanager",
        event_type="UnauthorizedAccess",
        severity="HIGH",
        occurred_at=now,
        received_at=now,
        payload={"msg": "cross tenant attempt"},
        evidence_hash="hash-123",
        idempotency_key="idemp-cross-tenant-1",
        is_asset_resolved=True,
    )

    async_session.add(cross_tenant_event)

    with pytest.raises(IntegrityError) as exc_info:
        await async_session.flush()

    # Confirma que a exceção foi uma violação de chave estrangeira (FK) de integridade
    assert (
        "FOREIGN KEY" in str(exc_info.value).upper()
        or "FOREIGNKEY" in str(exc_info.value).upper()
        or "CONSTRAINT" in str(exc_info.value).upper()
    )


@pytest.mark.asyncio
async def test_real_database_constraints_inspection(async_session: AsyncSession) -> None:
    """Valida via Inspector do SQLAlchemy que as constraints únicas e FK compostas existem no schema real."""
    conn = await async_session.connection()

    def inspect_tables(sync_conn):
        inspector = inspect(sync_conn)

        # 1. Tablas existentes
        table_names = inspector.get_table_names()
        assert "assets" in table_names
        assert "security_events" in table_names
        assert "correlation_rule_versions" in table_names

        # 2. Foreign Keys de security_events
        fks = inspector.get_foreign_keys("security_events")
        has_composite_fk = any(
            fk["constrained_columns"] == ["tenant_id", "asset_id"]
            and fk["referred_table"] == "assets"
            and fk["referred_columns"] == ["tenant_id", "asset_id"]
            for fk in fks
        )
        assert (
            has_composite_fk
        ), f"FK composta (tenant_id, asset_id) não encontrada em security_events: {fks}"

        # 3. Unique constraints de assets
        asset_uqs = inspector.get_unique_constraints("assets")
        has_tenant_asset_uq = any(
            set(uq["column_names"]) == {"tenant_id", "asset_id"} for uq in asset_uqs
        )
        assert (
            has_tenant_asset_uq
        ), f"Unique constraint (tenant_id, asset_id) não encontrada em assets: {asset_uqs}"

    await conn.run_sync(inspect_tables)


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
