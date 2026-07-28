"""
Testes Unitários para IngestLogHandler e LogQueryHandler (Sprint 1)
GovSec Shield — Unit Tests
"""

from uuid import uuid4

import pytest

from src.core.application.commands import IngestLogCommand
from src.core.application.handlers import IngestLogHandler
from src.core.application.interfaces import IEventPublisher
from src.core.application.queries import ListLogsQuery, LogQueryHandler
from src.core.domain.events import DomainEvent
from src.core.infrastructure.db.repositories import InMemoryLogRepository


class DummyEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published_events: list[DomainEvent] = []

    async def publish(self, event: DomainEvent) -> None:
        self.published_events.append(event)


@pytest.mark.asyncio
async def test_ingest_log_handler_saves_and_publishes():
    pub = DummyEventPublisher()
    log_repo = InMemoryLogRepository()
    handler = IngestLogHandler(event_publisher=pub, log_repo=log_repo)

    tenant_id = uuid4()
    cmd = IngestLogCommand(
        source="wazuh-agent-test",
        raw_data='{"event": "LOGIN_FAILED", "ip": "10.0.0.1"}',
        tenant_id=tenant_id,
    )

    await handler.handle(cmd)

    assert len(pub.published_events) == 1
    stored_logs = await log_repo.list()
    assert len(stored_logs) == 1
    assert stored_logs[0].source == "wazuh-agent-test"
    assert stored_logs[0].tenant_id == tenant_id


@pytest.mark.asyncio
async def test_log_query_handler_filters():
    pub = DummyEventPublisher()
    log_repo = InMemoryLogRepository()
    ingest_handler = IngestLogHandler(event_publisher=pub, log_repo=log_repo)

    t1_id = uuid4()
    t2_id = uuid4()

    await ingest_handler.handle(
        IngestLogCommand(source="firewall-01", raw_data="data1", tenant_id=t1_id)
    )
    await ingest_handler.handle(
        IngestLogCommand(source="zabbix-02", raw_data="data2", tenant_id=t2_id)
    )

    query_handler = LogQueryHandler(log_repo)

    # List all
    all_logs = await query_handler.list(ListLogsQuery())
    assert len(all_logs) == 2

    # Filter by tenant
    t1_logs = await query_handler.list(ListLogsQuery(tenant_id=t1_id))
    assert len(t1_logs) == 1
    assert t1_logs[0].source == "firewall-01"

    # Filter by source
    zabbix_logs = await query_handler.list(ListLogsQuery(source="zabbix"))
    assert len(zabbix_logs) == 1
    assert zabbix_logs[0].tenant_id == t2_id
