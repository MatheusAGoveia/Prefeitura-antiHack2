"""
Suíte de Testes Reais do Loop do Consumidor Kafka (M3.3)
Valida a execução do método run(), do cliente AIOKafkaConsumer mockado (getmany/commit) e a ordem exata entre:
  1. uow.commit() (PostgreSQL)
  2. observabilidade segura
  3. consumer._consumer.commit({topic_partition: offset + 1}) (Kafka Offset)
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from src.core.infrastructure.messaging.correlation_consumer import CorrelationKafkaConsumer


class DummyKafkaMessage:
    """Mensagem Kafka dummy com atributos imutáveis reais (sem comportamentos indesejados de MagicMock)."""

    def __init__(self, value: dict, offset: int):
        self.value = value
        self.offset = offset


class DummyAsyncUoW:
    """Helper de teste que implementa perfeitamente o protocolo AsyncContextManager do UoW."""

    def __init__(self, commit_side_effect=None):
        self.commit = AsyncMock(side_effect=commit_side_effect)
        self.correlation_rules = MagicMock()
        self.correlation_rules.list_active = AsyncMock(return_value=[])

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.mark.asyncio
async def test_run_loop_full_success_calls_consumer_commit_with_exact_offset_and_order() -> None:
    """
    Testa o loop run() com sucesso completo:
    getmany() -> uow.commit() -> metrics -> consumer.commit({topic_partition: offset + 1})
    """
    execution_order: list[str] = []

    async def fake_uow_commit():
        execution_order.append("uow.commit")

    mock_uow = DummyAsyncUoW(commit_side_effect=fake_uow_commit)

    consumer = CorrelationKafkaConsumer(uow_factory=lambda: mock_uow)

    # Mockar consumidor Kafka (AIOKafkaConsumer)
    mock_kafka_consumer = AsyncMock()
    consumer._consumer = mock_kafka_consumer
    consumer._running = True

    topic_partition = "govsec.events-0"
    tenant_id = str(uuid4())
    event_id = str(uuid4())

    mock_msg = DummyKafkaMessage(
        value={
            "event_type": "SecurityEventReceivedEvent",
            "tenant_id": tenant_id,
            "security_event_id": event_id,
        },
        offset=105,
    )

    getmany_call_count = 0

    async def fake_getmany(timeout_ms, max_records):
        nonlocal getmany_call_count
        getmany_call_count += 1
        if getmany_call_count == 1:
            return {topic_partition: [mock_msg]}
        consumer._running = False
        return {}

    mock_kafka_consumer.getmany = AsyncMock(side_effect=fake_getmany)

    async def fake_kafka_commit(offset_dict):
        execution_order.append("consumer.commit")

    mock_kafka_consumer.commit = AsyncMock(side_effect=fake_kafka_commit)

    mock_result_item = MagicMock()
    mock_result_item.is_new_incident = False
    mock_result_item.is_new_evidence = True
    mock_result_item.rule_id = "brute_force"

    mock_corr_result = MagicMock()
    mock_corr_result.items = [mock_result_item]

    mock_handler = AsyncMock()
    mock_handler.handle = AsyncMock(return_value=mock_corr_result)

    with (
        patch(
            "src.core.infrastructure.messaging.correlation_consumer.CorrelateSecurityEventHandler",
            return_value=mock_handler,
        ),
        patch(
            "src.shared.observability.metrics.safe_record_incident_evidence_added",
            side_effect=lambda rule_id: execution_order.append("metrics"),
        ),
    ):
        await consumer.run()

    # Confirmar que a ordem foi uow.commit -> metrics -> consumer.commit
    assert execution_order == ["uow.commit", "metrics", "consumer.commit"]
    mock_uow.commit.assert_called_once()
    mock_kafka_consumer.commit.assert_called_once_with({topic_partition: 106})


@pytest.mark.asyncio
async def test_run_loop_metrics_failure_post_commit_still_executes_consumer_commit() -> None:
    """
    Testa o loop run() onde a instrumentação de métrica falha pós-commit:
    uow.commit() tem sucesso, métrica lança exceção (capturada no adaptador safe_*), e o consumer.commit() É EXECUTADO NORMALMENTE.
    """
    mock_uow = DummyAsyncUoW()

    consumer = CorrelationKafkaConsumer(uow_factory=lambda: mock_uow)

    mock_kafka_consumer = AsyncMock()
    consumer._consumer = mock_kafka_consumer
    consumer._running = True

    topic_partition = "govsec.events-0"
    mock_msg = DummyKafkaMessage(
        value={
            "event_type": "SecurityEventReceivedEvent",
            "tenant_id": str(uuid4()),
            "security_event_id": str(uuid4()),
        },
        offset=200,
    )

    getmany_call_count = 0

    async def fake_getmany(timeout_ms, max_records):
        nonlocal getmany_call_count
        getmany_call_count += 1
        if getmany_call_count == 1:
            return {topic_partition: [mock_msg]}
        consumer._running = False
        return {}

    mock_kafka_consumer.getmany = AsyncMock(side_effect=fake_getmany)

    mock_result_item = MagicMock()
    mock_result_item.is_new_evidence = True

    mock_corr_result = MagicMock()
    mock_corr_result.items = [mock_result_item]

    mock_handler = AsyncMock()
    mock_handler.handle = AsyncMock(return_value=mock_corr_result)

    with (
        patch(
            "src.core.infrastructure.messaging.correlation_consumer.CorrelateSecurityEventHandler",
            return_value=mock_handler,
        ),
        patch(
            "src.shared.observability.metrics.record_incident_evidence_added",
            side_effect=RuntimeError("Prometheus Crash"),
        ),
    ):
        await consumer.run()

    mock_uow.commit.assert_called_once()
    mock_kafka_consumer.commit.assert_called_once_with({topic_partition: 201})


@pytest.mark.asyncio
async def test_run_loop_db_commit_failure_aborts_consumer_commit() -> None:
    """
    Testa o loop run() quando uow.commit() lança exceção:
    uow.commit() falha -> métrica não é chamada -> consumer.commit() NUNCA É CHAMADO.
    """
    mock_uow = DummyAsyncUoW(commit_side_effect=SQLAlchemyError("PostgreSQL connection error"))

    consumer = CorrelationKafkaConsumer(uow_factory=lambda: mock_uow)

    mock_kafka_consumer = AsyncMock()
    consumer._consumer = mock_kafka_consumer
    consumer._running = True

    topic_partition = "govsec.events-0"
    mock_msg = DummyKafkaMessage(
        value={
            "event_type": "SecurityEventReceivedEvent",
            "tenant_id": str(uuid4()),
            "security_event_id": str(uuid4()),
        },
        offset=300,
    )

    getmany_call_count = 0

    async def fake_getmany(timeout_ms, max_records):
        nonlocal getmany_call_count
        getmany_call_count += 1
        if getmany_call_count == 1:
            return {topic_partition: [mock_msg]}
        consumer._running = False
        return {}

    mock_kafka_consumer.getmany = AsyncMock(side_effect=fake_getmany)

    mock_corr_result = MagicMock()
    mock_corr_result.items = [MagicMock(is_new_evidence=True)]

    mock_handler = AsyncMock()
    mock_handler.handle = AsyncMock(return_value=mock_corr_result)

    metrics_called = False

    def fake_metrics(rule_id):
        nonlocal metrics_called
        metrics_called = True

    with (
        patch(
            "src.core.infrastructure.messaging.correlation_consumer.CorrelateSecurityEventHandler",
            return_value=mock_handler,
        ),
        patch(
            "src.shared.observability.metrics.safe_record_incident_evidence_added",
            side_effect=fake_metrics,
        ),
    ):
        await consumer.run()

    mock_uow.commit.assert_called_once()
    assert metrics_called is False
    # O offset no Kafka NÃO foi confirmado!
    mock_kafka_consumer.commit.assert_not_called()


@pytest.mark.asyncio
async def test_run_loop_processing_failure_before_db_aborts_commit_and_consumer_commit() -> None:
    """
    Testa o loop run() quando ocorre falha antes da transação de banco:
    process_single_message falha -> uow.commit() não é chamado -> consumer.commit() NÃO É CHAMADO.
    """
    mock_uow = DummyAsyncUoW()

    consumer = CorrelationKafkaConsumer(uow_factory=lambda: mock_uow)

    mock_kafka_consumer = AsyncMock()
    consumer._consumer = mock_kafka_consumer
    consumer._running = True

    topic_partition = "govsec.events-0"
    mock_msg = DummyKafkaMessage(
        value={
            "event_type": "SecurityEventReceivedEvent",
            "tenant_id": str(uuid4()),
            "security_event_id": str(uuid4()),
        },
        offset=400,
    )

    getmany_call_count = 0

    async def fake_getmany(timeout_ms, max_records):
        nonlocal getmany_call_count
        getmany_call_count += 1
        if getmany_call_count == 1:
            return {topic_partition: [mock_msg]}
        consumer._running = False
        return {}

    mock_kafka_consumer.getmany = AsyncMock(side_effect=fake_getmany)

    mock_handler = AsyncMock()
    mock_handler.handle = AsyncMock(side_effect=ValueError("Invalid Security Payload"))

    with patch(
        "src.core.infrastructure.messaging.correlation_consumer.CorrelateSecurityEventHandler",
        return_value=mock_handler,
    ):
        await consumer.run()

    mock_uow.commit.assert_not_called()
    mock_kafka_consumer.commit.assert_not_called()


@pytest.mark.asyncio
async def test_run_loop_scenario_5_replay_confirms_offset_without_duplicate_metrics() -> None:
    """
    Cenário 5 — Replay dentro do loop run():
    Evento já correlacionado é reentregue pelo Kafka.
    O handler reconhece a idempotência e retorna items vazios (0 novos incidentes/evidências).
    O consumidor confirma o offset no Kafka, uow.commit() é chamado, mas NENHUMA métrica histórica é incrementada.
    """
    mock_uow = DummyAsyncUoW()

    consumer = CorrelationKafkaConsumer(uow_factory=lambda: mock_uow)

    mock_kafka_consumer = AsyncMock()
    consumer._consumer = mock_kafka_consumer
    consumer._running = True

    topic_partition = "govsec.events-0"
    mock_msg = DummyKafkaMessage(
        value={
            "event_type": "SecurityEventReceivedEvent",
            "tenant_id": str(uuid4()),
            "security_event_id": str(uuid4()),
        },
        offset=500,
    )

    getmany_call_count = 0

    async def fake_getmany(timeout_ms, max_records):
        nonlocal getmany_call_count
        getmany_call_count += 1
        if getmany_call_count == 1:
            return {topic_partition: [mock_msg]}
        consumer._running = False
        return {}

    mock_kafka_consumer.getmany = AsyncMock(side_effect=fake_getmany)

    # Em caso de replay idempotente, o handler retorna items vazios (0 novas evidências/incidentes)
    mock_corr_result = MagicMock()
    mock_corr_result.items = []

    mock_handler = AsyncMock()
    mock_handler.handle = AsyncMock(return_value=mock_corr_result)

    metrics_called = False

    def fake_metrics(rule_id):
        nonlocal metrics_called
        metrics_called = True

    with (
        patch(
            "src.core.infrastructure.messaging.correlation_consumer.CorrelateSecurityEventHandler",
            return_value=mock_handler,
        ),
        patch(
            "src.shared.observability.metrics.safe_record_incident_evidence_added",
            side_effect=fake_metrics,
        ),
    ):
        await consumer.run()

    # No replay: transação DB é confirmada, offset no Kafka É CONFIRMADO, mas métricas NÃO SÃO INCREMENTADAS!
    mock_uow.commit.assert_called_once()
    mock_kafka_consumer.commit.assert_called_once_with({topic_partition: 501})
    assert metrics_called is False
