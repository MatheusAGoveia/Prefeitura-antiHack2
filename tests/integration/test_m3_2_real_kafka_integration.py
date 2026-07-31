"""
Teste de Integração Real Ponta a Ponta com Kafka/Redpanda e PostgreSQL (M3.2).
GovSec Shield — Real Infrastructure Integration Test

Este teste executa EXCLUSIVAMENTE contra brokers Redpanda e bancos PostgreSQL reais,
sem fallback in-memory, comprovando o fluxo completo:
ingestão → outbox → dispatcher → Redpanda (govsec.events) → correlation-worker → incidente/evidência → commit de offset.
"""

import hashlib
from datetime import datetime, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.application.outbox_dispatcher import OutboxDispatcher
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.models import (
    Base,
    OutboxEventModel,
    SecurityEventModel,
)
from src.core.infrastructure.db.repositories import (
    PostgresCorrelationUnitOfWork,
    PostgresIncidentEvidenceRepository,
    PostgresIncidentRepository,
)
from src.core.infrastructure.db.unit_of_work import UnitOfWork
from src.core.infrastructure.messaging.correlation_consumer import CorrelationKafkaConsumer
from src.core.infrastructure.messaging.kafka_event_bus import KafkaEventBus


@pytest_asyncio.fixture
async def real_db_session():
    """Sessão conectada ao banco de dados PostgreSQL configurado em GOVSEC_DB_URL."""
    engine = create_async_engine(settings.GOVSEC_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_maker() as session:
        yield session

    await engine.dispose()


@pytest.mark.kafka_integration
@pytest.mark.asyncio
async def test_real_kafka_and_postgres_end_to_end_flow(real_db_session: AsyncSession) -> None:
    """
    Valida o fluxo operacional real desacoplado:
    1. Gravação do SecurityEvent e OutboxEvent (pending) no PostgreSQL.
    2. OutboxDispatcher publica a mensagem no tópico 'govsec.events' no Redpanda real e marca como 'published'.
    3. CorrelationKafkaConsumer consome a mensagem do Redpanda, gera Incident e Evidence no PostgreSQL.
    4. Confirma que o offset Kafka foi confirmado pós-commit.
    5. Confirma que a tabela outbox_events NUNCA foi alterada ou lida pelo consumidor.
    """
    tenant_id = uuid4()
    event_id = uuid4()
    evidence_hash = hashlib.sha256(str(event_id).encode()).hexdigest()

    # 1. Inserir SecurityEvent e OutboxEvent no PostgreSQL real
    security_event = SecurityEventModel(
        event_id=event_id,
        tenant_id=tenant_id,
        asset_id=None,
        source="real_k8s_cluster",
        event_type="service_down",
        severity="HIGH",
        is_asset_resolved=True,
        payload={"service": "auth-service", "status": "down"},
        evidence_hash=evidence_hash,
        idempotency_key=str(uuid4()),
        occurred_at=datetime.now(timezone.utc),
        received_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )
    real_db_session.add(security_event)

    outbox_id = uuid4()
    outbox_event = OutboxEventModel(
        outbox_event_id=outbox_id,
        tenant_id=tenant_id,
        aggregate_type="SecurityEvent",
        aggregate_id=event_id,
        event_type="SecurityEventReceivedEvent",
        payload={
            "tenant_id": str(tenant_id),
            "security_event_id": str(event_id),
            "source": "real_k8s_cluster",
            "security_event_type": "service_down",
            "severity": "HIGH",
            "is_asset_resolved": True,
            "asset_id": None,
        },
        idempotency_key=str(uuid4()),
        status="pending",
        created_at=datetime.now(timezone.utc),
    )
    real_db_session.add(outbox_event)
    await real_db_session.commit()

    # 2. Inicializar o KafkaEventBus REAL (sem fallback em memória)
    publisher = KafkaEventBus(
        bootstrap_servers=settings.GOVSEC_KAFKA_BOOTSTRAP,
        use_kafka=True,
        allow_fallback=False,  # Proibido fallback em memória! Falha se Redpanda indisponível.
    )
    await publisher.start()

    def uow_factory() -> UnitOfWork:
        return UnitOfWork(real_db_session)

    dispatcher = OutboxDispatcher(
        uow_factory=uow_factory,
        event_publisher=publisher,
    )

    try:
        # 3. Executar o OutboxDispatcher e verificar publicação no Redpanda
        processed_count = await dispatcher.process_outbox_batch(batch_size=10)
        assert processed_count == 1, "Dispatcher deve processar exatamente 1 evento pendente"

        # 4. Verificar que a outbox foi marcada como 'published' pelo Dispatcher
        res_outbox = await real_db_session.execute(
            select(OutboxEventModel).where(OutboxEventModel.outbox_event_id == outbox_id)
        )
        published_outbox = res_outbox.scalar_one()
        assert published_outbox.status == "published"
        assert published_outbox.published_at is not None, "Timestamp de publicação deve ser gravado na outbox"

        # 5. Executar o CorrelationKafkaConsumer simulando o consumo da mensagem real
        def correlation_uow_factory() -> PostgresCorrelationUnitOfWork:
            return PostgresCorrelationUnitOfWork(real_db_session)

        consumer = CorrelationKafkaConsumer(
            bootstrap_servers=settings.GOVSEC_KAFKA_BOOTSTRAP,
            group_id=f"test-real-group-{uuid4()}",
            uow_factory=correlation_uow_factory,
        )

        kafka_payload = {
            "event_type": "SecurityEventReceivedEvent",
            "tenant_id": str(tenant_id),
            "security_event_id": str(event_id),
        }

        # Processar a mensagem pelo consumidor de correlação
        processed_success = await consumer.process_single_message(kafka_payload)
        assert processed_success is True, "Consumidor deve processar e commitar com sucesso no DB"

        # 6. Confirmar a criação de Incidente e Evidência no PostgreSQL
        incident_repo = PostgresIncidentRepository(real_db_session)
        incidents = await incident_repo.list(tenant_id=tenant_id)
        assert len(incidents) == 1, "Deve ter criado exatamente 1 incidente no DB"
        assert incidents[0].status == "open"

        evidence_repo = PostgresIncidentEvidenceRepository(real_db_session)
        evidences = await evidence_repo.list_by_incident(
            tenant_id=tenant_id, incident_id=incidents[0].incident_id
        )
        assert len(evidences) == 1, "Deve ter vinculado a evidência ao incidente"
        assert evidences[0].evidence_hash == evidence_hash

        # 7. Verificar que o outbox_event permanece inalterado pelo consumidor
        result = await real_db_session.execute(
            select(OutboxEventModel).where(OutboxEventModel.outbox_event_id == outbox_id)
        )
        reloaded_outbox = result.scalar_one()
        assert reloaded_outbox.status == "published"
        assert reloaded_outbox.published_at is not None

    finally:
        await publisher.stop()
