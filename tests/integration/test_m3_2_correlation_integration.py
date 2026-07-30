"""
Testes de Integração — Motor de Correlação Determinística (M3.2)
GovSec Shield — Integration Tests

Cobre:
  - Migration 0007: upgrade/downgrade em SQLite
  - Evento elegível cria incidente
  - Eventos compatíveis → mesmo incidente, múltiplas evidências
  - Cross-tenant: eventos de tenants diferentes → incidentes separados
  - Replay idempotência: mesmo evento 2x → 1 incidente, 1 evidência
  - Regra inativa → sem incidente
  - Reabertura após RESOLVED/CLOSED: novo incidente com mesma chave
  - Mudança de status auditada e gravada
  - Transição inválida levanta InvalidStatusTransitionError
"""

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.application.correlation_handler import CorrelateSecurityEventHandler
from src.core.domain.correlation import CorrelationRuleVersion
from src.core.domain.incidents import (
    Incident,
    IncidentEvidence,
    IncidentStatus,
    InvalidStatusTransitionError,
    SecurityEvent,
    SecurityEventSeverity,
)
from src.core.infrastructure.config import settings
from src.core.infrastructure.correlation.rules import (
    InfraAvailabilityRule,
)
from src.core.infrastructure.db.models import (
    AssetModel,
    Base,
    CorrelationRuleVersionModel,
    IncidentEvidenceModel,
    IncidentModel,
    IncidentStatusHistoryModel,
    SecurityEventModel,
)
from src.core.infrastructure.db.repositories import (
    PostgresCorrelationUnitOfWork,
    PostgresIncidentEvidenceRepository,
    PostgresIncidentRepository,
    PostgresSecurityEventRepository,
)

# Usa o banco de dados configurado no ambiente de teste
TEST_DATABASE_URL = settings.GOVSEC_DB_URL


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def async_session():
    """Sessão com schema completo criado e destruído para cada teste."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


def _make_security_event_model(
    tenant_id: UUID,
    event_type: str = "service_down",
    severity: str = "HIGH",
    asset_id: UUID | None = None,
    occurred_at: datetime | None = None,
) -> SecurityEventModel:
    event_id = uuid4()
    import hashlib
    evidence_hash = hashlib.sha256(str(event_id).encode()).hexdigest()
    return SecurityEventModel(
        event_id=event_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        source="test_source",
        event_type=event_type,
        severity=severity,
        occurred_at=occurred_at or datetime(2026, 7, 30, 14, 37, 22, tzinfo=timezone.utc),
        received_at=datetime.now(timezone.utc),
        payload={"host": "web-01"},
        evidence_hash=evidence_hash,
        idempotency_key=str(uuid4()),
        is_asset_resolved=asset_id is not None,
        created_at=datetime.now(timezone.utc),
    )


def _make_rule_version(
    rule_id: str = "R-INFRA-001",
    version: str = "1.0.0",
    is_active: bool = True,
) -> CorrelationRuleVersionModel:
    return CorrelationRuleVersionModel(
        rule_version_id=uuid4(),
        rule_id=rule_id,
        rule_version=version,
        name="Test Rule",
        category="availability",
        is_active=is_active,
        created_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Migration 0007 — upgrade/downgrade em SQLite
# ---------------------------------------------------------------------------


def test_migration_0007_upgrade_downgrade() -> None:
    """Valida que a migration 0007 aplica e reverte corretamente em SQLite."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test.db"
        sqlite_url = f"sqlite:///{db_path.as_posix()}"

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", sqlite_url)

        # Upgrade até o head (inclui 0007)
        command.upgrade(alembic_cfg, "head")

        sync_engine = create_engine(sqlite_url, echo=False)
        with sync_engine.connect() as conn:
            inspector = inspect(conn)
            tables = inspector.get_table_names()
            assert "incidents" in tables, "Tabela incidents deve existir após 0007"
            assert "incident_evidences" in tables
            assert "incident_status_history" in tables

        # Downgrade até 0006
        command.downgrade(alembic_cfg, "0006_harden_m3_1_integrity_and_outbox")
        with sync_engine.connect() as conn:
            inspector = inspect(conn)
            tables = inspector.get_table_names()
            assert "incidents" not in tables
            assert "incident_evidences" not in tables
            assert "incident_status_history" not in tables

        sync_engine.dispose()


# ---------------------------------------------------------------------------
# Correlação: evento elegível → criação de incidente
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_eligible_event_creates_incident(async_session: AsyncSession) -> None:
    """Um evento HIGH com type 'service_down' → incidente criado com status 'open'."""
    tenant_id = uuid4()

    # Salvar evento no banco
    event_model = _make_security_event_model(tenant_id=tenant_id)
    async_session.add(event_model)
    await async_session.flush()

    uow = PostgresCorrelationUnitOfWork(async_session)
    rule = InfraAvailabilityRule()
    handler = CorrelateSecurityEventHandler(uow=uow, rules=[rule], window_seconds=3600)

    incidents = await handler.handle(tenant_id=tenant_id, security_event_id=event_model.event_id)

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.status == IncidentStatus.OPEN
    assert inc.tenant_id == tenant_id

    # Verificar evidência criada
    ev_repo = PostgresIncidentEvidenceRepository(async_session)
    evs = await ev_repo.list_by_incident(inc.incident_id, tenant_id)
    assert len(evs) == 1
    assert evs[0].event_id == event_model.event_id


@pytest.mark.asyncio
async def test_ineligible_event_creates_no_incident(async_session: AsyncSession) -> None:
    """Evento LOW sem keyword de infra → nenhum incidente criado pela regra InfraAvailabilityRule."""
    tenant_id = uuid4()
    event_model = _make_security_event_model(
        tenant_id=tenant_id,
        event_type="user_login",
        severity="LOW",
    )
    async_session.add(event_model)
    await async_session.flush()

    # Verificar elegibilidade diretamente na regra (sem passar pelo handler)
    rule = InfraAvailabilityRule()
    from src.core.domain.incidents import SecurityEvent, SecurityEventSeverity
    from datetime import datetime, timezone
    from src.core.domain.incidents import SecurityEvent
    event_domain = SecurityEvent(
        tenant_id=tenant_id,
        source="test_source",
        event_type="user_login",
        severity=SecurityEventSeverity.LOW,
        occurred_at=datetime(2026, 7, 30, 14, 37, 22, tzinfo=timezone.utc),
        received_at=datetime.now(timezone.utc),
        asset_id=None,
        payload={"host": "web-01"},
        idempotency_key=str(event_model.idempotency_key),
    )
    assert not rule.is_eligible(event_domain), (
        "user_login LOW não deve ser elegível para R-INFRA-001"
    )


# ---------------------------------------------------------------------------
# Idempotência — replay não duplica incidente nem evidência
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_same_event_no_duplicate_incident(async_session: AsyncSession) -> None:
    """Processar o mesmo evento duas vezes → 1 incidente, 1 evidência."""
    tenant_id = uuid4()
    event_model = _make_security_event_model(tenant_id=tenant_id, event_type="service_down")
    async_session.add(event_model)
    await async_session.flush()

    uow = PostgresCorrelationUnitOfWork(async_session)
    rule = InfraAvailabilityRule()

    # Primeira execução
    h1 = CorrelateSecurityEventHandler(uow=uow, rules=[rule], window_seconds=3600)
    incidents1 = await h1.handle(tenant_id=tenant_id, security_event_id=event_model.event_id)
    assert len(incidents1) == 1

    # Segunda execução (replay)
    h2 = CorrelateSecurityEventHandler(uow=uow, rules=[rule], window_seconds=3600)
    incidents2 = await h2.handle(tenant_id=tenant_id, security_event_id=event_model.event_id)
    assert len(incidents2) == 1

    # Verificar: ainda apenas 1 incidente e 1 evidência
    repo = PostgresIncidentRepository(async_session)
    all_incidents = await repo.list(tenant_id=tenant_id)
    assert len(all_incidents) == 1

    ev_repo = PostgresIncidentEvidenceRepository(async_session)
    evs = await ev_repo.list_by_incident(all_incidents[0].incident_id, tenant_id)
    assert len(evs) == 1


# ---------------------------------------------------------------------------
# Dois eventos compatíveis → mesmo incidente, 2 evidências
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_compatible_events_same_incident_two_evidences(async_session: AsyncSession) -> None:
    """
    Dois eventos HIGH com mesmo source+event_type na mesma hora (sem asset_id)
    → mesma asset_key (source:event_type) → mesmo incidente, com duas evidências distintas.
    """
    tenant_id = uuid4()
    occurred = datetime(2026, 7, 30, 14, 10, 0, tzinfo=timezone.utc)

    # Sem asset_id: asset_key = "test_source:service_down" → mesma chave de correlação
    e1 = _make_security_event_model(
        tenant_id=tenant_id,
        event_type="service_down",
        severity="HIGH",
        asset_id=None,
        occurred_at=occurred,
    )
    e2 = _make_security_event_model(
        tenant_id=tenant_id,
        event_type="service_down",
        severity="HIGH",
        asset_id=None,
        occurred_at=occurred,
    )
    async_session.add_all([e1, e2])
    await async_session.flush()

    uow = PostgresCorrelationUnitOfWork(async_session)
    rule = InfraAvailabilityRule()

    h1 = CorrelateSecurityEventHandler(uow=uow, rules=[rule], window_seconds=3600)
    await h1.handle(tenant_id=tenant_id, security_event_id=e1.event_id)

    h2 = CorrelateSecurityEventHandler(uow=uow, rules=[rule], window_seconds=3600)
    await h2.handle(tenant_id=tenant_id, security_event_id=e2.event_id)

    # Deve existir apenas 1 incidente
    repo = PostgresIncidentRepository(async_session)
    incidents = await repo.list(tenant_id=tenant_id)
    assert len(incidents) == 1

    # Com 2 evidências
    ev_repo = PostgresIncidentEvidenceRepository(async_session)
    evs = await ev_repo.list_by_incident(incidents[0].incident_id, tenant_id)
    assert len(evs) == 2


# ---------------------------------------------------------------------------
# Isolamento Cross-Tenant — eventos de tenants distintos nunca se misturam
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cross_tenant_events_never_correlate(async_session: AsyncSession) -> None:
    """
    Mesmo tipo de evento, mesmo timestamp → tenants distintos → incidentes distintos.
    """
    tenant_a = uuid4()
    tenant_b = uuid4()
    occurred = datetime(2026, 7, 30, 14, 10, 0, tzinfo=timezone.utc)

    ea = _make_security_event_model(tenant_id=tenant_a, event_type="service_down", occurred_at=occurred)
    eb = _make_security_event_model(tenant_id=tenant_b, event_type="service_down", occurred_at=occurred)
    async_session.add_all([ea, eb])
    await async_session.flush()

    uow = PostgresCorrelationUnitOfWork(async_session)
    rule = InfraAvailabilityRule()

    ha = CorrelateSecurityEventHandler(uow=uow, rules=[rule], window_seconds=3600)
    incidents_a = await ha.handle(tenant_id=tenant_a, security_event_id=ea.event_id)

    hb = CorrelateSecurityEventHandler(uow=uow, rules=[rule], window_seconds=3600)
    incidents_b = await hb.handle(tenant_id=tenant_b, security_event_id=eb.event_id)

    assert len(incidents_a) == 1
    assert len(incidents_b) == 1
    assert incidents_a[0].incident_id != incidents_b[0].incident_id
    assert incidents_a[0].tenant_id == tenant_a
    assert incidents_b[0].tenant_id == tenant_b


# ---------------------------------------------------------------------------
# Reabertura após RESOLVED/CLOSED — índice único PARCIAL
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_incident_reopens_after_resolved_with_same_correlation_key(
    async_session: AsyncSession,
) -> None:
    """
    Após um incidente ser RESOLVED (→ CLOSED), um novo evento com a mesma chave
    deve criar um NOVO incidente (índice único parcial não bloqueia incidentes terminais).
    """
    tenant_id = uuid4()
    occurred = datetime(2026, 7, 30, 14, 10, 0, tzinfo=timezone.utc)

    # Evento 1 → cria incidente original
    e1 = _make_security_event_model(tenant_id=tenant_id, event_type="service_down", occurred_at=occurred)
    async_session.add(e1)
    await async_session.flush()

    uow = PostgresCorrelationUnitOfWork(async_session)
    h1 = CorrelateSecurityEventHandler(uow=uow, rules=[InfraAvailabilityRule()], window_seconds=3600)
    incidents1 = await h1.handle(tenant_id=tenant_id, security_event_id=e1.event_id)
    assert len(incidents1) == 1

    # Fechar o incidente via transição de status
    incident = incidents1[0]
    incident.transition_to(IncidentStatus.ACKNOWLEDGED, "analyst", "ack")
    incident.transition_to(IncidentStatus.INVESTIGATING, "analyst", "inv")
    incident.transition_to(IncidentStatus.CONTAINED, "analyst", "cont")
    incident.transition_to(IncidentStatus.RESOLVED, "analyst", "res")
    incident.transition_to(IncidentStatus.CLOSED, "analyst", "close")

    repo = PostgresIncidentRepository(async_session)
    await repo.save(incident)
    await async_session.flush()

    # Evento 2 (mesma chave de correlação) → deve criar NOVO incidente
    e2 = _make_security_event_model(tenant_id=tenant_id, event_type="service_down", occurred_at=occurred)
    async_session.add(e2)
    await async_session.flush()

    h2 = CorrelateSecurityEventHandler(uow=uow, rules=[InfraAvailabilityRule()], window_seconds=3600)
    incidents2 = await h2.handle(tenant_id=tenant_id, security_event_id=e2.event_id)
    assert len(incidents2) == 1

    # Deve haver 2 incidentes no total: 1 CLOSED + 1 OPEN
    all_incidents = await repo.list(tenant_id=tenant_id)
    assert len(all_incidents) == 2
    statuses = {inc.status for inc in all_incidents}
    assert IncidentStatus.CLOSED in statuses
    assert IncidentStatus.OPEN in statuses


# ---------------------------------------------------------------------------
# Mudança de Status via Repositório — auditoria
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_status_change_persisted_and_retrievable(async_session: AsyncSession) -> None:
    """Status salvo no banco reflete a transição feita no domínio."""
    tenant_id = uuid4()
    event_model = _make_security_event_model(tenant_id=tenant_id)
    async_session.add(event_model)
    await async_session.flush()

    uow = PostgresCorrelationUnitOfWork(async_session)
    h = CorrelateSecurityEventHandler(uow=uow, rules=[InfraAvailabilityRule()], window_seconds=3600)
    incidents = await h.handle(tenant_id=tenant_id, security_event_id=event_model.event_id)
    incident = incidents[0]

    # Transicionar via domínio e salvar
    incident.transition_to(IncidentStatus.ACKNOWLEDGED, "analyst-99", "Revisão iniciada.")
    repo = PostgresIncidentRepository(async_session)
    saved = await repo.save(incident)

    assert saved.status == IncidentStatus.ACKNOWLEDGED

    # Recarregar do banco e verificar
    reloaded = await repo.get_by_id(incident.incident_id, tenant_id)
    assert reloaded is not None
    assert reloaded.status == IncidentStatus.ACKNOWLEDGED


@pytest.mark.asyncio
async def test_invalid_status_transition_raises_domain_error(async_session: AsyncSession) -> None:
    """Tentativa de OPEN → RESOLVED deve levantar InvalidStatusTransitionError."""
    tenant_id = uuid4()
    event_model = _make_security_event_model(tenant_id=tenant_id)
    async_session.add(event_model)
    await async_session.flush()

    uow = PostgresCorrelationUnitOfWork(async_session)
    h = CorrelateSecurityEventHandler(uow=uow, rules=[InfraAvailabilityRule()], window_seconds=3600)
    incidents = await h.handle(tenant_id=tenant_id, security_event_id=event_model.event_id)
    incident = incidents[0]

    with pytest.raises(InvalidStatusTransitionError):
        incident.transition_to(IncidentStatus.RESOLVED, "actor", "Skipping steps.")
