"""
Testes de Integração com Banco de Dados e Migrações Alembic Reais — Capability M3.1
GovSec Shield — Integration Tests
"""

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.domain.incidents import SecurityEvent, SecurityEventSeverity
from src.core.domain.outbox import OutboxEvent
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.models import AssetModel, Base, OutboxEventModel, SecurityEventModel
from src.core.infrastructure.db.repositories import (
    PostgresOutboxRepository,
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


def test_alembic_migration_chain_upgrade_downgrade_real() -> None:
    """
    Valida a execução REAL das migrations Alembic (upgrade head -> downgrade 0004 -> upgrade head)
    em um banco SQLite descartável e inspeciona o schema resultante.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_db_path = Path(tmp_dir) / "test_migration.db"
        sqlite_url = f"sqlite:///{tmp_db_path.as_posix()}"

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", sqlite_url)

        # 1. Executa upgrade head
        command.upgrade(alembic_cfg, "head")

        # 2. Executa downgrade até a revisão 0004
        command.downgrade(alembic_cfg, "0004_alert_ack_tenant_id_uuid")

        # 3. Executa upgrade head novamente
        command.upgrade(alembic_cfg, "head")

        # 4. Inspeciona o banco resultante
        from sqlalchemy import create_engine
        sync_engine = create_engine(f"sqlite:///{tmp_db_path.as_posix()}", echo=False)
        with sync_engine.connect() as conn:
            inspector = inspect(conn)

            # Tabelas obrigatórias
            table_names = inspector.get_table_names()
            assert "assets" in table_names
            assert "security_events" in table_names
            assert "correlation_rule_versions" in table_names
            assert "outbox_events" in table_names

            # FK composta tenant_id + asset_id
            fks = inspector.get_foreign_keys("security_events")
            has_composite_fk = any(
                fk["constrained_columns"] == ["tenant_id", "asset_id"]
                and fk["referred_table"] == "assets"
                and fk["referred_columns"] == ["tenant_id", "asset_id"]
                for fk in fks
            )
            assert has_composite_fk, f"FK composta (tenant_id, asset_id) não encontrada: {fks}"

            # Unique constraint de outbox
            outbox_uqs = inspector.get_unique_constraints("outbox_events")
            has_outbox_idemp = any(
                set(uq["column_names"]) == {"tenant_id", "idempotency_key"}
                for uq in outbox_uqs
            )
            assert has_outbox_idemp, f"Unique idempotency em outbox_events não encontrada: {outbox_uqs}"

        sync_engine.dispose()


@pytest.mark.asyncio
async def test_cross_tenant_asset_event_constraint_violation(async_session: AsyncSession) -> None:
    """Valida que o banco de dados rejeita via FK composta associar SecurityEvent do Tenant A a Ativo do Tenant B."""
    tenant_a = uuid4()
    tenant_b = uuid4()
    asset_id_b = uuid4()

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

    now = datetime.now(timezone.utc)
    cross_tenant_event = SecurityEventModel(
        event_id=uuid4(),
        tenant_id=tenant_a,  # Tenant A
        asset_id=asset_id_b,  # Ativo do Tenant B
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

    assert (
        "FOREIGN KEY" in str(exc_info.value).upper()
        or "FOREIGNKEY" in str(exc_info.value).upper()
        or "CONSTRAINT" in str(exc_info.value).upper()
    )


@pytest.mark.asyncio
async def test_same_idempotency_key_allowed_across_different_tenants(async_session: AsyncSession) -> None:
    """Valida que a mesma idempotency_key é permitida para tenants diferentes."""
    repo = PostgresSecurityEventRepository(async_session)
    tenant_a = uuid4()
    tenant_b = uuid4()
    now = datetime.now(timezone.utc)
    shared_key = "idemp-shared-key-100"

    event_a = SecurityEvent(
        tenant_id=tenant_a,
        source="Alertmanager",
        event_type="HighCpu",
        severity=SecurityEventSeverity.HIGH,
        occurred_at=now,
        received_at=now,
        asset_id=None,
        payload={},
        idempotency_key=shared_key,
    )
    event_b = SecurityEvent(
        tenant_id=tenant_b,
        source="Alertmanager",
        event_type="HighCpu",
        severity=SecurityEventSeverity.HIGH,
        occurred_at=now,
        received_at=now,
        asset_id=None,
        payload={},
        idempotency_key=shared_key,
    )

    saved_a, created_a = await repo.save(event_a)
    saved_b, created_b = await repo.save(event_b)
    await async_session.flush()

    assert created_a is True
    assert created_b is True
    assert saved_a.event_id != saved_b.event_id


@pytest.mark.asyncio
async def test_postgres_outbox_repository_claim_and_mark(async_session: AsyncSession) -> None:
    """Valida gravação, busca/claim e alteração de status no PostgresOutboxRepository."""
    repo = PostgresOutboxRepository(async_session)
    tenant_id = uuid4()

    entry = OutboxEvent(
        tenant_id=tenant_id,
        aggregate_type="SecurityEvent",
        aggregate_id=uuid4(),
        event_type="SecurityEventReceivedEvent",
        payload={"msg": "test outbox"},
        idempotency_key="idemp-pg-outbox-1",
    )

    saved = await repo.save(entry)
    await async_session.flush()
    assert saved.outbox_event_id == entry.outbox_event_id

    # Claim
    claimed = await repo.fetch_pending_and_claim(limit=10, lock_for_update=False)
    assert len(claimed) == 1
    assert claimed[0].status == "processing"

    # Mark published
    await repo.mark_published(entry.outbox_event_id)
    await async_session.flush()

    model = (
        await async_session.execute(
            select(OutboxEventModel).where(OutboxEventModel.outbox_event_id == entry.outbox_event_id)
        )
    ).scalar_one()
    assert model.status == "published"
    assert model.published_at is not None


@pytest.mark.asyncio
async def test_concurrent_sessions_postgres_security_event_idempotency() -> None:
    """Valida a proteção contra duplicidade em duas sessões concorrentes simuladas."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    tenant_id = uuid4()
    now = datetime.now(timezone.utc)
    shared_key = "idemp-concurrent-key"

    evt1 = SecurityEvent(
        tenant_id=tenant_id,
        source="Alertmanager",
        event_type="DiskFull",
        severity=SecurityEventSeverity.CRITICAL,
        occurred_at=now,
        received_at=now,
        asset_id=None,
        payload={},
        idempotency_key=shared_key,
    )

    async with async_session_factory() as session1, async_session_factory() as session2:
        repo1 = PostgresSecurityEventRepository(session1)
        repo2 = PostgresSecurityEventRepository(session2)

        res1, created1 = await repo1.save(evt1)
        await session1.commit()

        res2, created2 = await repo2.save(evt1)
        await session2.commit()

        assert created1 is True
        assert created2 is False
        assert res1.event_id == res2.event_id

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()
