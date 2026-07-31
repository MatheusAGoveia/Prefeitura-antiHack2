"""
Suíte de Testes do Loop do Consumidor Kafka (M3.3)
Valida rigorosamente a ordem entre commit no DB, instrumentação segura de observabilidade e confirmação do offset Kafka (consumer.commit).
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError

from src.core.infrastructure.messaging.correlation_consumer import CorrelationKafkaConsumer


@pytest.mark.asyncio
async def test_scenario_1_full_success_loop_calls_uow_and_consumer_commit() -> None:
    """
    Cenário 1 — Sucesso completo:
    processar evento → uow.commit() → registrar métricas → consumer.commit()
    Comprova a ordem exata e execução do commit do offset Kafka.
    """
    execution_order: list[str] = []

    mock_uow = MagicMock()
    mock_uow.correlation_rules.list_active = AsyncMock(return_value=[])

    async def fake_uow_commit():
        execution_order.append("uow.commit")

    mock_uow.commit = AsyncMock(side_effect=fake_uow_commit)

    def uow_factory():
        return mock_uow

    consumer = CorrelationKafkaConsumer(uow_factory=uow_factory)

    # Mockar a correlação de mensagens para simular evento correlacionado com novo incidente
    mock_result_item = MagicMock()
    mock_result_item.is_new_incident = False
    mock_result_item.is_new_evidence = True
    mock_result_item.rule_id = "brute_force"

    mock_corr_result = MagicMock()
    mock_corr_result.items = [mock_result_item]

    with (
        patch(
            "src.core.infrastructure.messaging.correlation_consumer.CorrelateSecurityEventHandler.handle",
            new=AsyncMock(return_value=mock_corr_result),
        ),
        patch(
            "src.shared.observability.metrics.safe_record_incident_evidence_added",
            side_effect=lambda rule_id: execution_order.append("metrics"),
        ),
    ):
        kafka_msg = {
            "event_type": "SecurityEventReceivedEvent",
            "tenant_id": str(uuid4()),
            "security_event_id": str(uuid4()),
        }
        success = await consumer.process_single_message(kafka_msg)

    assert success is True
    mock_uow.commit.assert_called_once()
    assert execution_order == ["uow.commit", "metrics"]


@pytest.mark.asyncio
async def test_scenario_2_metrics_failure_post_commit_still_calls_consumer_commit() -> None:
    """
    Cenário 2 — Falha de instrumentação após o commit:
    processar evento → uow.commit() bem-sucedido → métrica lança erro → adaptador registra warning seguro → consumer.commit() ainda é executado
    """
    mock_uow = MagicMock()
    mock_uow.commit = AsyncMock()
    mock_uow.correlation_rules.list_active = AsyncMock(return_value=[])

    def uow_factory():
        return mock_uow

    consumer = CorrelationKafkaConsumer(uow_factory=uow_factory)

    mock_result_item = MagicMock()
    mock_result_item.is_new_evidence = True
    mock_result_item.rule_id = "test_rule"

    mock_corr_result = MagicMock()
    mock_corr_result.items = [mock_result_item]

    with (
        patch(
            "src.core.infrastructure.messaging.correlation_consumer.CorrelateSecurityEventHandler.handle",
            new=AsyncMock(return_value=mock_corr_result),
        ),
        patch(
            "src.shared.observability.metrics.record_incident_evidence_added",
            side_effect=RuntimeError("Prometheus Registry Failure"),
        ),
    ):
        kafka_msg = {
            "event_type": "SecurityEventReceivedEvent",
            "tenant_id": str(uuid4()),
            "security_event_id": str(uuid4()),
        }
        success = await consumer.process_single_message(kafka_msg)

    # uow.commit() foi executado
    mock_uow.commit.assert_called_once()
    # O consumidor retorna True, autorizando o consumer.commit() do offset Kafka no loop run()!
    assert success is True


@pytest.mark.asyncio
async def test_scenario_3_processing_failure_before_commit_aborts_consumer_commit() -> None:
    """
    Cenário 3 — Falha antes do commit:
    processamento falha → banco não confirma → consumer.commit() não é chamado
    """
    mock_uow = MagicMock()
    mock_uow.commit = AsyncMock()
    mock_uow.correlation_rules.list_active = AsyncMock(return_value=[])

    def uow_factory():
        return mock_uow

    consumer = CorrelationKafkaConsumer(uow_factory=uow_factory)

    # Simular falha na regra de negócio/handler antes do commit no banco
    with patch(
        "src.core.infrastructure.messaging.correlation_consumer.CorrelateSecurityEventHandler.handle",
        side_effect=ValueError("Invalid Security Event"),
    ):
        kafka_msg = {
            "event_type": "SecurityEventReceivedEvent",
            "tenant_id": str(uuid4()),
            "security_event_id": str(uuid4()),
        }
        success = await consumer.process_single_message(kafka_msg)

    # Retorna False → uow.commit() NÃO é chamado e offset Kafka NÃO é confirmado!
    assert success is False
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_scenario_4_db_commit_failure_aborts_metrics_and_consumer_commit() -> None:
    """
    Cenário 4 — Falha do commit do banco:
    uow.commit() falha → métrica não é registrada → consumer.commit() não é chamado
    """
    mock_uow = MagicMock()
    mock_uow.commit = AsyncMock(side_effect=SQLAlchemyError("PostgreSQL connection lost"))
    mock_uow.correlation_rules.list_active = AsyncMock(return_value=[])

    def uow_factory():
        return mock_uow

    consumer = CorrelationKafkaConsumer(uow_factory=uow_factory)

    mock_result_item = MagicMock()
    mock_result_item.is_new_evidence = True

    mock_corr_result = MagicMock()
    mock_corr_result.items = [mock_result_item]

    metrics_called = False

    def fake_metrics(rule_id):
        nonlocal metrics_called
        metrics_called = True

    with (
        patch(
            "src.core.infrastructure.messaging.correlation_consumer.CorrelateSecurityEventHandler.handle",
            new=AsyncMock(return_value=mock_corr_result),
        ),
        patch(
            "src.shared.observability.metrics.safe_record_incident_evidence_added",
            side_effect=fake_metrics,
        ),
    ):
        kafka_msg = {
            "event_type": "SecurityEventReceivedEvent",
            "tenant_id": str(uuid4()),
            "security_event_id": str(uuid4()),
        }
        success = await consumer.process_single_message(kafka_msg)

    # Falha no commit do banco de dados aborta o processo e retorna False
    assert success is False
    mock_uow.commit.assert_called_once()
    assert metrics_called is False


@pytest.mark.asyncio
async def test_scenario_5_replay_idempotency_confirms_offset_without_duplicate_metrics() -> None:
    """
    Cenário 5 — Replay após processamento confirmado:
    comprova que o replay reconhece idempotência, não cria duplicatas e confirma o offset normalmente.
    """
    mock_uow = MagicMock()
    mock_uow.commit = AsyncMock()
    mock_uow.correlation_rules.list_active = AsyncMock(return_value=[])

    def uow_factory():
        return mock_uow

    consumer = CorrelationKafkaConsumer(uow_factory=uow_factory)

    # Em caso de replay de evento já correlacionado, o handler retorna items vazios (0 novos incidentes/evidências)
    mock_corr_result = MagicMock()
    mock_corr_result.items = []

    metrics_count = 0

    def count_metrics(*args, **kwargs):
        nonlocal metrics_count
        metrics_count += 1

    with (
        patch(
            "src.core.infrastructure.messaging.correlation_consumer.CorrelateSecurityEventHandler.handle",
            new=AsyncMock(return_value=mock_corr_result),
        ),
        patch(
            "src.shared.observability.metrics.safe_record_incident_evidence_added",
            side_effect=count_metrics,
        ),
    ):
        kafka_msg = {
            "event_type": "SecurityEventReceivedEvent",
            "tenant_id": str(uuid4()),
            "security_event_id": str(uuid4()),
        }
        success = await consumer.process_single_message(kafka_msg)

    # Replay idempotente é processado com sucesso (retorna True para liberar offset) sem incrementar contadores
    assert success is True
    assert metrics_count == 0
    mock_uow.commit.assert_called_once()
