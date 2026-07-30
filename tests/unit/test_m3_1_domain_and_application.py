"""
Testes Unitários de Domínio, Aplicação e Transactional Outbox — Capability M3.1
GovSec Shield — Unit Tests
"""

import ast
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.seed.seed_m3_assets import seed_dev_assets
from src.core.application.commands import IngestSecurityEventCommand
from src.core.application.handlers import IngestSecurityEventHandler
from src.core.application.outbox_dispatcher import OutboxDispatcher
from src.core.domain.entities import Tenant, TenantStatus
from src.core.domain.events import DomainEvent, SecurityEventReceivedEvent
from src.core.domain.exceptions import DomainError
from src.core.domain.incidents import Asset, sanitize_payload
from src.core.domain.outbox import OutboxEvent
from src.core.infrastructure.db.repositories import (
    InMemorySecurityEventUnitOfWork,
    InMemoryTenantRepository,
)


class MockEventPublisher:
    def __init__(self, should_fail: bool = False) -> None:
        self.published_events: list[DomainEvent] = []
        self.should_fail = should_fail

    async def publish(self, event: DomainEvent) -> None:
        if self.should_fail:
            raise RuntimeError("Falha simulada no broker de mensagens")
        self.published_events.append(event)


@pytest.mark.asyncio
async def test_asset_resolution_by_tenant_service_env() -> None:
    """Valida que a resolução de ativos busca estritamente por tenant_id, service_name e environment."""
    uow = InMemorySecurityEventUnitOfWork()
    tenant_a = uuid4()
    tenant_b = uuid4()

    asset_a = Asset(
        tenant_id=tenant_a,
        name="GovSec Core API Dev",
        asset_type="service",
        service_name="govsec-core-api",
        environment="development",
        criticality="HIGH",
        is_active=True,
    )
    await uow.assets.save(asset_a)

    resolved = await uow.assets.resolve_active_asset(tenant_a, "govsec-core-api", "development")
    assert resolved is not None
    assert resolved.asset_id == asset_a.asset_id

    # Busca em ambiente diferente retorna None
    resolved_diff_env = await uow.assets.resolve_active_asset(
        tenant_a, "govsec-core-api", "production"
    )
    assert resolved_diff_env is None

    # Isolamento por tenant
    resolved_b = await uow.assets.resolve_active_asset(tenant_b, "govsec-core-api", "development")
    assert resolved_b is None


@pytest.mark.asyncio
async def test_ingest_security_event_handler_persists_outbox_transactionally() -> None:
    """Valida que a ingestão gera mensagem no Outbox dentro da transação sem publicar diretamente."""
    uow = InMemorySecurityEventUnitOfWork()
    handler = IngestSecurityEventHandler(uow=uow)

    tenant_id = uuid4()
    now = datetime.now(timezone.utc)

    asset = Asset(
        tenant_id=tenant_id,
        name="GovSec Core API",
        asset_type="service",
        service_name="govsec-core-api",
        environment="development",
        criticality="HIGH",
    )
    await uow.assets.save(asset)

    cmd = IngestSecurityEventCommand(
        tenant_id=tenant_id,
        source="Alertmanager",
        event_type="HighCpuUsage",
        severity="high",  # Normalização de string
        occurred_at=now,
        received_at=now,
        idempotency_key="idemp-outbox-001",
        payload={"user": "admin", "password": "SecretPassword123"},
        service_name="govsec-core-api",
        environment="development",
    )

    result = await handler.handle(cmd)

    assert uow.committed is True
    assert result.is_duplicate_suppressed is False

    # Mensagem gravada no outbox
    claimed = await uow.outbox.fetch_pending_and_claim()
    assert len(claimed) == 1
    outbox_entry = claimed[0]
    assert outbox_entry.event_type == "SecurityEventReceivedEvent"
    assert outbox_entry.payload["tenant_id"] == str(tenant_id)

    # Payload sanitizado na entidade de domínio
    saved_events = await uow.security_events.list(tenant_id=tenant_id)
    assert len(saved_events) == 1
    assert saved_events[0].payload["password"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_outbox_dispatcher_processes_pending_and_publishes() -> None:
    """Valida que o OutboxDispatcher busca mensagens pending, publica via IEventPublisher e marca como published."""
    uow = InMemorySecurityEventUnitOfWork()
    publisher = MockEventPublisher()

    def uow_factory():
        return uow

    dispatcher = OutboxDispatcher(uow_factory=uow_factory, event_publisher=publisher)

    tenant_id = uuid4()
    outbox_entry = OutboxEvent(
        tenant_id=tenant_id,
        aggregate_type="SecurityEvent",
        aggregate_id=uuid4(),
        event_type="SecurityEventReceivedEvent",
        payload={
            "tenant_id": str(tenant_id),
            "security_event_id": str(uuid4()),
            "source": "Alertmanager",
            "security_event_type": "HighCpu",
            "severity": "HIGH",
            "is_asset_resolved": True,
            "asset_id": str(uuid4()),
        },
        idempotency_key="idemp-outbox-dispatch-1",
    )
    await uow.outbox.save(outbox_entry)

    count = await dispatcher.process_outbox_batch()
    assert count == 1
    assert len(publisher.published_events) == 1
    assert isinstance(publisher.published_events[0], SecurityEventReceivedEvent)

    # Mensagem marcada como published no outbox
    assert uow.outbox.events[outbox_entry.outbox_event_id].status == "published"


@pytest.mark.asyncio
async def test_outbox_dispatcher_handles_retry_on_publisher_failure() -> None:
    """Valida o mecanismo de retry e backoff do OutboxDispatcher quando o broker falha."""
    uow = InMemorySecurityEventUnitOfWork()
    failing_publisher = MockEventPublisher(should_fail=True)

    def uow_factory():
        return uow

    dispatcher = OutboxDispatcher(
        uow_factory=uow_factory,
        event_publisher=failing_publisher,
        max_retries=3,
        backoff_seconds=2,
    )

    tenant_id = uuid4()
    outbox_entry = OutboxEvent(
        tenant_id=tenant_id,
        aggregate_type="SecurityEvent",
        aggregate_id=uuid4(),
        event_type="SecurityEventReceivedEvent",
        payload={
            "tenant_id": str(tenant_id),
            "security_event_id": str(uuid4()),
            "source": "Alertmanager",
            "security_event_type": "HighCpu",
            "severity": "HIGH",
            "is_asset_resolved": False,
            "asset_id": None,
        },
        idempotency_key="idemp-outbox-retry-1",
    )
    await uow.outbox.save(outbox_entry)

    processed_count = await dispatcher.process_outbox_batch()
    assert processed_count == 0  # Falhou

    evt_after = uow.outbox.events[outbox_entry.outbox_event_id]
    assert evt_after.status == "failed"
    assert evt_after.retry_count == 1
    assert evt_after.next_retry_at is not None
    assert "Falha simulada" in str(evt_after.last_error)


@pytest.mark.asyncio
async def test_idempotent_replay_no_duplicate_audit_no_outbox() -> None:
    """Valida que o replay duplicado não gera segundo log nem nova mensagem no outbox."""
    uow = InMemorySecurityEventUnitOfWork()
    handler = IngestSecurityEventHandler(uow=uow)

    tenant_id = uuid4()
    now = datetime.now(timezone.utc)

    cmd = IngestSecurityEventCommand(
        tenant_id=tenant_id,
        source="Alertmanager",
        event_type="UnknownAlert",
        severity="HIGH",
        occurred_at=now,
        received_at=now,
        idempotency_key="idemp-unresolved-dup",
        payload={},
        service_name="servico-inexistente",
        environment="development",
    )

    # 1. Envio inicial
    res1 = await handler.handle(cmd)
    assert res1.is_duplicate_suppressed is False
    assert len(uow.outbox.events) == 1

    # 2. Reenvio duplicado
    res2 = await handler.handle(cmd)
    assert res2.is_duplicate_suppressed is True
    assert len(uow.outbox.events) == 1  # Mensagem outbox não foi duplicada!


@pytest.mark.asyncio
async def test_input_validations_and_mandatory_occurred_at() -> None:
    """Valida que occurred_at ausente/inválido e severidades inválidas são rejeitados com DomainError."""
    uow = InMemorySecurityEventUnitOfWork()
    handler = IngestSecurityEventHandler(uow=uow)
    tenant_id = uuid4()
    now = datetime.now(timezone.utc)

    # occurred_at ausente (None)
    cmd_no_occurred = IngestSecurityEventCommand(
        tenant_id=tenant_id,
        source="Alertmanager",
        event_type="Test",
        severity="HIGH",
        occurred_at=now,
        received_at=now,
        idempotency_key="k-no-occ",
        payload={},
    )
    cmd_no_occurred.payload["occurred_at"] = None
    with pytest.raises(DomainError) as exc_occ:
        await handler.handle(cmd_no_occurred)
    assert "occurred_at é obrigatório" in str(exc_occ.value)

    # Severidade inválida
    with pytest.raises(DomainError) as exc_sev:
        await handler.handle(
            IngestSecurityEventCommand(
                tenant_id=tenant_id,
                source="Alertmanager",
                event_type="ServiceDown",
                severity="SUPER_CRITICAL_INVALID",
                occurred_at=now,
                idempotency_key="k1",
                payload={},
            )
        )
    assert "Severidade de segurança inválida" in str(exc_sev.value)

    # Payload não-dict (sem usar type: ignore)
    cmd_invalid_payload = IngestSecurityEventCommand(
        tenant_id=tenant_id,
        source="Alertmanager",
        event_type="ServiceDown",
        severity="HIGH",
        occurred_at=now,
        idempotency_key="k3",
        payload={},
    )
    cmd_invalid_payload.payload["payload"] = "not_a_dict"
    with pytest.raises(DomainError) as exc_pay:
        await handler.handle(cmd_invalid_payload)
    assert "payload deve ser um dict" in str(exc_pay.value)


@pytest.mark.asyncio
async def test_seed_script_direct_evaluations() -> None:
    """Valida o script de seed cobrindo ambientes recusados, tenants inexistentes/inativos e idempotência."""
    uow = InMemorySecurityEventUnitOfWork()
    tenant_repo = InMemoryTenantRepository()

    tenant_active = Tenant(name="Active Tenant", slug="active", status=TenantStatus.ACTIVE)
    tenant_inactive = Tenant(name="Inactive Tenant", slug="inactive", status=TenantStatus.INACTIVE)
    await tenant_repo.save(tenant_active)
    await tenant_repo.save(tenant_inactive)

    uow_mock = InMemorySecurityEventUnitOfWork(
        assets=uow.assets,
        security_events=uow.security_events,
        logs=uow.logs,
        outbox=uow.outbox,
    )
    uow_mock._tenants = tenant_repo  # type: ignore[attr-defined]

    # Ambiente production recusado
    with pytest.raises(RuntimeError) as exc_prod:
        await seed_dev_assets(tenant_id=tenant_active.id, uow=uow_mock, env_override="production")
    assert "estritamente proibidos fora" in str(exc_prod.value)

    # Ambiente staging recusado
    with pytest.raises(RuntimeError) as exc_stag:
        await seed_dev_assets(tenant_id=tenant_active.id, uow=uow_mock, env_override="staging")
    assert "estritamente proibidos fora" in str(exc_stag.value)

    # Tenant inexistente recusado
    with pytest.raises(ValueError) as exc_nonexist:
        await seed_dev_assets(tenant_id=uuid4(), uow=uow_mock, env_override="development")
    assert "não foi localizado" in str(exc_nonexist.value)

    # Tenant inativo recusado
    with pytest.raises(ValueError) as exc_inact:
        await seed_dev_assets(tenant_id=tenant_inactive.id, uow=uow_mock, env_override="development")
    assert "tenants ativos" in str(exc_inact.value)

    # Tenant ativo permitido
    asset1 = await seed_dev_assets(
        tenant_id=tenant_active.id, uow=uow_mock, env_override="development"
    )
    assert asset1 is not None
    assert asset1.service_name == "govsec-core-api"

    # Repetição não cria outro ativo (idempotente)
    asset2 = await seed_dev_assets(
        tenant_id=tenant_active.id, uow=uow_mock, env_override="development"
    )
    assert asset2.asset_id == asset1.asset_id


@pytest.mark.asyncio
async def test_sanitize_payload_recursive() -> None:
    """Valida a sanitização de payload recursiva sem alterar o objeto original se for imutável."""
    raw = {
        "user": "admin",
        "secret": "my-secret-key",
        "nested": {"token": "bearer-123", "public": 42},
        "list": [{"password": "123"}, "clean"],
    }

    sanitized = sanitize_payload(raw)
    assert sanitized["user"] == "admin"
    assert sanitized["secret"] == "[REDACTED]"
    assert sanitized["nested"]["token"] == "[REDACTED]"
    assert sanitized["nested"]["public"] == 42
    assert sanitized["list"][0]["password"] == "[REDACTED]"


def test_domain_layer_m3_1_zero_infrastructure_imports() -> None:
    """Valida arquiteturalmente que os módulos de domínio de M3 não possuem imports de infraestrutura."""
    domain_dir = Path("src/core/domain")
    domain_files = list(domain_dir.glob("*.py"))

    forbidden = {
        "fastapi",
        "starlette",
        "sqlalchemy",
        "alembic",
        "redis",
        "kafka",
        "aiokafka",
        "requests",
        "httpx",
    }

    for file_path in domain_files:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    pkg = alias.name.split(".")[0]
                    assert pkg not in forbidden, f"Arquivo '{file_path.name}' importou '{pkg}'"
            elif isinstance(node, ast.ImportFrom) and node.module:
                pkg = node.module.split(".")[0]
                assert pkg not in forbidden, f"Arquivo '{file_path.name}' importou '{pkg}'"
