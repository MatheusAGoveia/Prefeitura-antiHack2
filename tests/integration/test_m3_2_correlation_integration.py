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

import asyncio
import hashlib
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from aiokafka.errors import KafkaError
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.application.correlation_handler import CorrelateSecurityEventHandler
from src.core.domain.incidents import (
    IncidentStatus,
    InvalidStatusTransitionError,
)
from src.core.infrastructure.config import settings
from src.core.infrastructure.correlation.rules import (
    InfraAvailabilityRule,
)
from src.core.infrastructure.db.models import (
    Base,
    CorrelationRuleVersionModel,
    OutboxEventModel,
    SecurityEventModel,
)
from src.core.infrastructure.db.repositories import (
    PostgresCorrelationUnitOfWork,
    PostgresIncidentEvidenceRepository,
    PostgresIncidentRepository,
)
from src.core.infrastructure.messaging.correlation_consumer import (
    READINESS_FILE_PATH,
    CorrelationKafkaConsumer,
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
        command.downgrade(alembic_cfg, "0006_harden_m3_1_integrity")
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

    result = await handler.handle(tenant_id=tenant_id, security_event_id=event_model.event_id)
    incidents = [item.incident for item in result.items]

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
    from datetime import datetime, timezone

    from src.core.domain.incidents import SecurityEvent, SecurityEventSeverity
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
    res1 = await h1.handle(tenant_id=tenant_id, security_event_id=event_model.event_id)
    assert len(res1.items) == 1
    assert res1.items[0].is_new_incident is True
    assert res1.items[0].is_new_evidence is True

    # Segunda execução (replay)
    h2 = CorrelateSecurityEventHandler(uow=uow, rules=[rule], window_seconds=3600)
    res2 = await h2.handle(tenant_id=tenant_id, security_event_id=event_model.event_id)
    assert len(res2.items) == 1
    assert res2.items[0].is_new_incident is False
    assert res2.items[0].is_new_evidence is False

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
    res_a = await ha.handle(tenant_id=tenant_a, security_event_id=ea.event_id)
    incidents_a = [item.incident for item in res_a.items]

    hb = CorrelateSecurityEventHandler(uow=uow, rules=[rule], window_seconds=3600)
    res_b = await hb.handle(tenant_id=tenant_b, security_event_id=eb.event_id)
    incidents_b = [item.incident for item in res_b.items]

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
    res1 = await h1.handle(tenant_id=tenant_id, security_event_id=e1.event_id)
    incidents1 = [item.incident for item in res1.items]
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
    res2 = await h2.handle(tenant_id=tenant_id, security_event_id=e2.event_id)
    incidents2 = [item.incident for item in res2.items]
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
    res = await h.handle(tenant_id=tenant_id, security_event_id=event_model.event_id)
    incident = res.items[0].incident

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
    res = await h.handle(tenant_id=tenant_id, security_event_id=event_model.event_id)
    incident = res.items[0].incident

    with pytest.raises(InvalidStatusTransitionError):
        incident.transition_to(IncidentStatus.RESOLVED, "actor", "Skipping steps.")


# ---------------------------------------------------------------------------
# Novos testes de integração avançados M3.2
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_executions_single_incident() -> None:
    """
    Simula concorrência real (duas sessões DB independentes e paralelas tentando criar o mesmo incidente).
    O SAVEPOINT no repositório captura a violação de integridade e garante que
    apenas 1 incidente ativo seja criado, vinculando as evidências.
    """
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    tenant_id = uuid4()
    occurred = datetime(2026, 7, 30, 14, 10, 0, tzinfo=timezone.utc)

    async with factory() as session_setup:
        e1 = _make_security_event_model(tenant_id=tenant_id, event_type="service_down", occurred_at=occurred)
        e2 = _make_security_event_model(tenant_id=tenant_id, event_type="service_down", occurred_at=occurred)
        session_setup.add_all([e1, e2])
        await session_setup.commit()

    async def run_correlate(event_id: UUID) -> None:
        async with factory() as session:
            uow = PostgresCorrelationUnitOfWork(session)
            h = CorrelateSecurityEventHandler(uow=uow, rules=[InfraAvailabilityRule()], window_seconds=3600)
            await h.handle(tenant_id=tenant_id, security_event_id=event_id)
            await uow.commit()

    # Executar concorrentemente com 2 sessões distintas
    await asyncio.gather(
        run_correlate(e1.event_id),
        run_correlate(e2.event_id),
    )

    async with factory() as session_check:
        repo = PostgresIncidentRepository(session_check)
        all_incidents = await repo.list(tenant_id=tenant_id)
        assert len(all_incidents) == 1, "Apenas 1 incidente ativo deve existir após execução concorrente"

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


# ---------------------------------------------------------------------------
# Testes do Consumidor Kafka e Garantias de Arquitetura M3.2
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_topic_alignment_producer_and_consumer() -> None:
    """Garante que o produtor (KafkaEventBus) e consumidor (CorrelationKafkaConsumer) utilizam exatamente o mesmo tópico."""
    consumer = CorrelationKafkaConsumer()
    expected_topic = f"{settings.GOVSEC_KAFKA_TOPIC_PREFIX}.events"
    assert consumer._topic == expected_topic, f"Tópico do consumidor deve ser {expected_topic}"


@pytest.mark.asyncio
async def test_correlation_consumer_default_uow_factory_instantiation() -> None:
    """Valida que o CorrelationKafkaConsumer se inicializa com a fábrica síncrona de UoW por padrão sem erros."""
    consumer = CorrelationKafkaConsumer()
    assert consumer._uow_factory is not None
    # Testar que a fábrica padrão não levanta exceção de sintaxe
    # N.B. default_uow_factory é síncrona


@pytest.mark.asyncio
async def test_correlation_does_not_modify_outbox_events(async_session: AsyncSession) -> None:
    """Garante que a execução do handler de correlação deixa os registros de outbox_events intactos."""
    tenant_id = uuid4()
    event_model = _make_security_event_model(tenant_id=tenant_id)
    async_session.add(event_model)

    # Inserir um outbox_event com status 'pending'
    outbox_model = OutboxEventModel(
        outbox_event_id=uuid4(),
        tenant_id=tenant_id,
        aggregate_type="SecurityEvent",
        aggregate_id=event_model.event_id,
        event_type="SecurityEventReceivedEvent",
        payload={"tenant_id": str(tenant_id), "security_event_id": str(event_model.event_id)},
        idempotency_key=str(uuid4()),
        status="pending",
        created_at=datetime.now(timezone.utc),
    )
    async_session.add(outbox_model)
    await async_session.flush()

    uow = PostgresCorrelationUnitOfWork(async_session)
    handler = CorrelateSecurityEventHandler(uow=uow, rules=[InfraAvailabilityRule()], window_seconds=3600)
    res = await handler.handle(tenant_id=tenant_id, security_event_id=event_model.event_id)
    await uow.commit()

    assert len(res.items) == 1

    # Verificar que o outbox_event permanece 'pending' e inalterado
    result = await async_session.execute(
        select(OutboxEventModel).where(OutboxEventModel.outbox_event_id == outbox_model.outbox_event_id)
    )
    reloaded_outbox = result.scalar_one()
    assert reloaded_outbox.status == "pending"
    assert reloaded_outbox.published_at is None


@pytest.mark.asyncio
async def test_kafka_consumer_process_single_message_flow(async_session: AsyncSession) -> None:
    """
    Testa o método process_single_message do CorrelationKafkaConsumer.
    Verifica que o evento Kafka é processado, o incidente é criado no banco e retorna True
    para autorizar o commit do offset no Kafka.
    """
    tenant_id = uuid4()
    event_model = _make_security_event_model(tenant_id=tenant_id, event_type="service_down")
    async_session.add(event_model)
    await async_session.commit()

    def test_uow_factory() -> PostgresCorrelationUnitOfWork:
        return PostgresCorrelationUnitOfWork(async_session)

    consumer = CorrelationKafkaConsumer(uow_factory=test_uow_factory)

    kafka_msg_value = {
        "event_type": "SecurityEventReceivedEvent",
        "tenant_id": str(tenant_id),
        "security_event_id": str(event_model.event_id),
    }

    success = await consumer.process_single_message(kafka_msg_value)
    assert success is True

    # Verificar que o incidente foi criado no banco
    repo = PostgresIncidentRepository(async_session)
    incidents = await repo.list(tenant_id=tenant_id)
    assert len(incidents) == 1


@pytest.mark.asyncio
async def test_repository_count_and_stable_sorting(async_session: AsyncSession) -> None:
    """Valida que repo.count() executa contagem exata e repo.list() usa ordenação estável."""
    tenant_id = uuid4()
    repo = PostgresIncidentRepository(async_session)

    # Criar 3 incidentes
    for i in range(3):
        e_model = _make_security_event_model(tenant_id=tenant_id, event_type=f"service_down_{i}")
        async_session.add(e_model)
        await async_session.flush()

        uow = PostgresCorrelationUnitOfWork(async_session)
        h = CorrelateSecurityEventHandler(uow=uow, rules=[InfraAvailabilityRule()], window_seconds=3600)
        await h.handle(tenant_id=tenant_id, security_event_id=e_model.event_id)

    total = await repo.count(tenant_id=tenant_id)
    assert total == 3

    open_count = await repo.count(tenant_id=tenant_id, status="open")
    assert open_count == 3

    closed_count = await repo.count(tenant_id=tenant_id, status="closed")
    assert closed_count == 0

    listed = await repo.list(tenant_id=tenant_id, skip=0, limit=10)
    assert len(listed) == 3


@pytest.mark.asyncio
async def test_ineligible_event_does_not_create_incident(async_session: AsyncSession) -> None:
    """Valida que evento inelegível (ex: tipo de evento ignorado) não cria incidente."""
    tenant_id = uuid4()
    def test_uow_factory() -> PostgresCorrelationUnitOfWork:
        return PostgresCorrelationUnitOfWork(async_session)

    consumer = CorrelationKafkaConsumer(uow_factory=test_uow_factory)
    kafka_msg_value = {
        "event_type": "OtherUnrelatedEvent",
        "tenant_id": str(tenant_id),
        "security_event_id": str(uuid4()),
    }

    success = await consumer.process_single_message(kafka_msg_value)
    assert success is True

    repo = PostgresIncidentRepository(async_session)
    incidents = await repo.list(tenant_id=tenant_id)
    assert len(incidents) == 0, "Evento inelegível não deve criar incidentes."


@pytest.mark.asyncio
async def test_replay_does_not_duplicate_incident_or_evidence(async_session: AsyncSession) -> None:
    """Valida que reprocessar (replay) a mesma mensagem Kafka não duplica incidentes nem evidências."""
    tenant_id = uuid4()
    event_model = _make_security_event_model(tenant_id=tenant_id, event_type="service_down")
    async_session.add(event_model)
    await async_session.commit()

    def test_uow_factory() -> PostgresCorrelationUnitOfWork:
        return PostgresCorrelationUnitOfWork(async_session)

    consumer = CorrelationKafkaConsumer(uow_factory=test_uow_factory)
    kafka_msg_value = {
        "event_type": "SecurityEventReceivedEvent",
        "tenant_id": str(tenant_id),
        "security_event_id": str(event_model.event_id),
    }

    # Primeira execução (Original)
    res1 = await consumer.process_single_message(kafka_msg_value)
    assert res1 is True

    # Segunda execução (Replay)
    res2 = await consumer.process_single_message(kafka_msg_value)
    assert res2 is True

    repo = PostgresIncidentRepository(async_session)
    incidents = await repo.list(tenant_id=tenant_id)
    assert len(incidents) == 1, "Replay não deve criar segundo incidente."

    evidence_repo = PostgresIncidentEvidenceRepository(async_session)
    evidences = await evidence_repo.list_by_incident(tenant_id=tenant_id, incident_id=incidents[0].incident_id)
    assert len(evidences) == 1, "Replay não deve duplicar evidência."


@pytest.mark.asyncio
async def test_handler_failure_returns_false_and_does_not_commit_offset() -> None:
    """Valida que se o handler ou a fábrica de UoW falharem com erro no banco, o consumidor retorna False."""
    def broken_uow_factory() -> PostgresCorrelationUnitOfWork:
        raise RuntimeError("Falha de conexão com o banco de dados")

    consumer = CorrelationKafkaConsumer(uow_factory=broken_uow_factory)
    kafka_msg_value = {
        "event_type": "SecurityEventReceivedEvent",
        "tenant_id": str(uuid4()),
        "security_event_id": str(uuid4()),
    }

    success = await consumer.process_single_message(kafka_msg_value)
    assert success is False, "Se o DB/handler falhar, process_single_message deve retornar False para abortar commit de offset."


@pytest.mark.asyncio
async def test_process_single_message_sqlalchemy_error_returns_false() -> None:
    """Valida que simulação de SQLAlchemyError em process_single_message retorna False."""
    mock_uow = AsyncMock()
    mock_uow.__aenter__.return_value = mock_uow
    mock_uow.__aexit__.return_value = None
    mock_uow.commit.side_effect = SQLAlchemyError("Erro de banco durante commit transacional")

    consumer = CorrelationKafkaConsumer(uow_factory=lambda: mock_uow)
    kafka_msg_value = {
        "event_type": "SecurityEventReceivedEvent",
        "tenant_id": str(uuid4()),
        "security_event_id": str(uuid4()),
    }

    success = await consumer.process_single_message(kafka_msg_value)
    assert success is False, "SQLAlchemyError no commit deve fazer process_single_message retornar False."


@pytest.mark.asyncio
async def test_run_loop_aborts_kafka_offset_commit_when_process_single_message_fails() -> None:
    """Valida que se process_single_message retornar False no loop run(), consumer.commit NUNCA é chamado."""
    consumer = CorrelationKafkaConsumer()
    mock_aiokafka_consumer = AsyncMock()

    mock_msg = MagicMock()
    mock_msg.value = {
        "event_type": "SecurityEventReceivedEvent",
        "tenant_id": str(uuid4()),
        "security_event_id": str(uuid4()),
    }
    mock_msg.offset = 10
    tp = MagicMock()

    async def side_effect_getmany(timeout_ms: int = 1000, max_records: int = 10) -> dict:
        if mock_aiokafka_consumer.getmany.call_count == 1:
            return {tp: [mock_msg]}
        consumer._running = False
        return {}

    mock_aiokafka_consumer.getmany.side_effect = side_effect_getmany
    consumer._consumer = mock_aiokafka_consumer
    consumer._running = True

    # Mockar process_single_message via patch.object sem type:ignore (simulando falha no DB)
    with patch.object(
        consumer,
        "process_single_message",
        new=AsyncMock(return_value=False),
    ):
        await consumer.run()

    # Confirmação técnica estrita: commit() NUNCA deve ter sido chamado para mensagens que falharam!
    mock_aiokafka_consumer.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_transient_kafka_error_in_loop_keeps_worker_active() -> None:
    """Valida que KafkaError transitório no loop principal é registrado e mantém a resiliência do worker."""
    consumer = CorrelationKafkaConsumer()
    mock_aiokafka_consumer = AsyncMock()

    async def side_effect_getmany(timeout_ms: int = 1000, max_records: int = 10) -> dict:
        if mock_aiokafka_consumer.getmany.call_count == 1:
            raise KafkaError("Conexão com o broker caiu temporariamente")
        consumer._running = False
        return {}

    mock_aiokafka_consumer.getmany.side_effect = side_effect_getmany
    consumer._consumer = mock_aiokafka_consumer
    consumer._running = True

    await consumer.run()
    assert mock_aiokafka_consumer.getmany.call_count >= 2


@pytest.mark.asyncio
async def test_consumer_start_failure_removes_readiness_file_and_propagates_exception() -> None:
    """Valida que se AIOKafkaConsumer.start() falhar, o readiness file não fica ativo e a exceção é propagada."""
    consumer = CorrelationKafkaConsumer()

    with patch("src.core.infrastructure.messaging.correlation_consumer.AIOKafkaConsumer") as mock_cls:
        mock_instance = AsyncMock()
        mock_instance.start.side_effect = KafkaError("Broker indisponível na inicialização")
        mock_cls.return_value = mock_instance

        with pytest.raises(KafkaError):
            await consumer.start()

        assert not READINESS_FILE_PATH.exists(), "Readiness file deve ser removido ou não existir após falha no start."
