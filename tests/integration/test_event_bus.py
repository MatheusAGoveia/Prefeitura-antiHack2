"""
Suíte de Testes de Integração de Mensageria e Event Bus (Sprint 0.3)
GovSec Shield — Messaging Integration Tests
"""

from uuid import uuid4

import pytest

from src.core.application.commands import Command, CommandMetadata
from src.core.domain.events import TenantCreatedEvent
from src.core.infrastructure.messaging.command_bus import (
    CircuitBreakerOpenError,
    CommandBus,
)
from src.core.infrastructure.messaging.dlq import DeadLetterQueue
from src.core.infrastructure.messaging.kafka_event_bus import KafkaEventBus
from src.core.infrastructure.policies.opa_client import OPAClient
from src.core.interfaces.event_handlers.log_event_handler import LogEventHandler
from src.core.interfaces.event_handlers.tenant_event_handler import TenantEventHandler


# -----------------------------------------------------------------------------
# 1. Testes de Publicação, Inscrição e Idempotência no Event Bus
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_kafka_event_bus_publish_and_subscribe():
    bus = KafkaEventBus(use_kafka=False)
    await bus.start()

    received_events = []

    async def sample_handler(evt):
        received_events.append(evt)

    bus.subscribe("TenantCreatedEvent", sample_handler)

    event = TenantCreatedEvent(
        tenant_id=uuid4(),
        name="Prefeitura Teste",
        slug="prefeitura-teste",
    )

    await bus.publish(event)
    assert len(received_events) == 1
    assert received_events[0].name == "Prefeitura Teste"

    await bus.stop()


@pytest.mark.asyncio
async def test_kafka_event_bus_idempotency_deduplication():
    bus = KafkaEventBus(use_kafka=False)
    await bus.start()

    received_events = []

    async def sample_handler(evt):
        received_events.append(evt)

    bus.subscribe("GenericEvent", sample_handler)

    dict_event = {
        "id": "evt-dup-12345",
        "type": "GenericEvent",
        "correlation_id": "corr-dup-999",
        "payload": {"data": "test"},
    }

    # Primeira publicação -> aceita
    await bus.publish(dict_event)
    assert len(received_events) == 1

    # Segunda publicação com mesmo correlation_id -> desduplicada
    await bus.publish(dict_event)
    assert len(received_events) == 1  # Mantém 1 (desduplicado)

    await bus.stop()


# -----------------------------------------------------------------------------
# 2. Testes dos Event Handlers
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_event_handlers_execution():
    tenant_handler = TenantEventHandler()
    log_handler = LogEventHandler()
    test_tenant_uuid = str(uuid4())

    # Executa sem exceções
    await tenant_handler.handle_tenant_created({"tenant_id": test_tenant_uuid, "name": "Betim", "slug": "betim"})
    await log_handler.handle_log_ingested({"tenant_id": test_tenant_uuid, "source": "wazuh", "raw_data": "LOG DATA"})


# -----------------------------------------------------------------------------
# 3. Testes dos Middlewares do Command Bus & DLQ
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_command_bus_retry_and_dlq_integration():
    dlq = DeadLetterQueue()
    dlq.clear()
    cmd_bus = CommandBus(opa_client=OPAClient(mock_mode=True), dlq=dlq, max_retries=2)
    test_tenant_uuid = str(uuid4())

    class FailingCommand(Command):
        pass

    async def failing_handler(cmd):
        raise ValueError("Simulated Handler Failure")

    cmd_bus.register("FailingCommand", failing_handler)

    fail_cmd = FailingCommand(
        metadata=CommandMetadata(command_name="FailingCommand", tenant=test_tenant_uuid),
        payload={},
    )

    with pytest.raises(ValueError, match="Simulated Handler Failure"):
        await cmd_bus.send(fail_cmd)

    # Verificar se mensagem foi para DLQ pós-retries
    failed_msgs = dlq.get_failed_messages()
    assert len(failed_msgs) >= 1
    assert failed_msgs[-1]["message"]["type"] == "FailingCommand"

    # Re-queue test
    dlq_id = failed_msgs[-1]["dlq_id"]
    requeued = dlq.requeue_message(dlq_id, bus=cmd_bus)
    assert requeued is True


@pytest.mark.asyncio
async def test_command_bus_circuit_breaker():
    dlq = DeadLetterQueue()
    dlq.clear()
    cmd_bus = CommandBus(opa_client=OPAClient(mock_mode=True), dlq=dlq, max_retries=1)
    cmd_bus.circuit_breaker.failure_threshold = 2
    cmd_bus.circuit_breaker.recovery_time = 60.0
    test_tenant_uuid = str(uuid4())

    class FlakyCommand(Command):
        pass

    async def flaky_handler(cmd):
        raise RuntimeError("Flaky error")

    cmd_bus.register("FlakyCommand", flaky_handler)
    cmd = FlakyCommand(
        metadata=CommandMetadata(command_name="FlakyCommand", tenant=test_tenant_uuid),
        payload={},
    )

    # Falha 1
    with pytest.raises(RuntimeError):
        await cmd_bus.send(cmd)

    # Falha 2
    with pytest.raises(RuntimeError):
        await cmd_bus.send(cmd)

    # Tentativa 3 -> Dispara CircuitBreakerOpenError sem nem chamar o handler
    with pytest.raises(CircuitBreakerOpenError):
        await cmd_bus.send(cmd)
