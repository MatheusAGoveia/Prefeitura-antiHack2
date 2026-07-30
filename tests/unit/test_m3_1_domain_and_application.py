"""
Testes Unitários de Domínio, Aplicação e CQRS — Capability M3.1
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
from src.core.domain.correlation import CorrelationRuleVersion
from src.core.domain.events import DomainEvent, SecurityEventReceivedEvent
from src.core.domain.incidents import Asset
from src.core.infrastructure.db.repositories import (
    InMemoryAssetRepository,
    InMemoryCorrelationRuleVersionRepository,
    InMemoryLogRepository,
    InMemorySecurityEventRepository,
)


class MockEventPublisher:
    def __init__(self) -> None:
        self.published_events: list[DomainEvent] = []

    async def publish(self, event: DomainEvent) -> None:
        self.published_events.append(event)


@pytest.mark.asyncio
async def test_asset_resolution_by_tenant_service_env() -> None:
    """Valida que a resolução de ativos busca estritamente por tenant_id, service_name e environment."""
    asset_repo = InMemoryAssetRepository()
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
    await asset_repo.save(asset_a)

    # Resolução bem-sucedida no Tenant A
    resolved = await asset_repo.resolve_active_asset(tenant_a, "govsec-core-api", "development")
    assert resolved is not None
    assert resolved.asset_id == asset_a.asset_id

    # Isolamento de Tenant: Tenant B não resolve o ativo do Tenant A
    resolved_b = await asset_repo.resolve_active_asset(tenant_b, "govsec-core-api", "development")
    assert resolved_b is None

    # Ambiente diferente não resolve
    resolved_prod = await asset_repo.resolve_active_asset(tenant_a, "govsec-core-api", "production")
    assert resolved_prod is None


@pytest.mark.asyncio
async def test_ingest_security_event_handler_with_resolved_asset() -> None:
    """Valida o fluxo completo de ingestão quando o ativo é localizado no tenant."""
    asset_repo = InMemoryAssetRepository()
    security_event_repo = InMemorySecurityEventRepository()
    publisher = MockEventPublisher()
    log_repo = InMemoryLogRepository()

    handler = IngestSecurityEventHandler(
        asset_repo=asset_repo,
        security_event_repo=security_event_repo,
        event_publisher=publisher,
        log_repo=log_repo,
    )

    tenant_id = uuid4()
    now = datetime.now(timezone.utc)

    # Cadastra o ativo
    asset = Asset(
        tenant_id=tenant_id,
        name="GovSec Core API",
        asset_type="service",
        service_name="govsec-core-api",
        environment="development",
        criticality="HIGH",
        is_active=True,
    )
    await asset_repo.save(asset)

    cmd = IngestSecurityEventCommand(
        tenant_id=tenant_id,
        source="Alertmanager",
        event_type="HighCpuUsage",
        severity="HIGH",
        occurred_at=now,
        received_at=now,
        idempotency_key="idemp-cmd-001",
        payload={"user": "admin", "password": "SecretPassword123!"},
        service_name="govsec-core-api",
        environment="development",
    )

    result = await handler.handle(cmd)

    assert result.tenant_id == tenant_id
    assert result.asset_id == asset.asset_id
    assert result.is_asset_resolved is True
    assert result.is_duplicate_suppressed is False

    # Valida que o evento publicado no EventBus ocorreu pós-commit
    assert len(publisher.published_events) == 1
    pub_evt = publisher.published_events[0]
    assert isinstance(pub_evt, SecurityEventReceivedEvent)
    assert pub_evt.security_event_id == result.event_id
    assert pub_evt.is_asset_resolved is True

    # Valida sanitização de payload persistido
    saved_evt = await security_event_repo.get_by_id(result.event_id, tenant_id)
    assert saved_evt is not None
    assert saved_evt.payload["password"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_ingest_security_event_unresolved_asset_flow() -> None:
    """Valida que evento sem ativo gera is_asset_resolved=False e UnresolvedAssetEvent sem publicar broker antecipado."""
    asset_repo = InMemoryAssetRepository()
    security_event_repo = InMemorySecurityEventRepository()
    publisher = MockEventPublisher()
    log_repo = InMemoryLogRepository()

    handler = IngestSecurityEventHandler(
        asset_repo=asset_repo,
        security_event_repo=security_event_repo,
        event_publisher=publisher,
        log_repo=log_repo,
    )

    tenant_id = uuid4()
    now = datetime.now(timezone.utc)

    # Comando sem ativo existente
    cmd = IngestSecurityEventCommand(
        tenant_id=tenant_id,
        source="Alertmanager",
        event_type="UnknownHostAlert",
        severity="MEDIUM",
        occurred_at=now,
        received_at=now,
        idempotency_key="idemp-unresolved-1",
        payload={"ip": "10.0.0.99"},
        service_name="servico-inexistente",
        environment="development",
    )

    result = await handler.handle(cmd)

    assert result.asset_id is None
    assert result.is_asset_resolved is False

    # Registrou log de auditoria de UnresolvedAssetEvent
    logs = await log_repo.list(tenant_id=tenant_id)
    assert any("UnresolvedAssetEvent" in log.raw_data for log in logs)

    # Evento de publicação pós-commit indica is_asset_resolved=False
    assert len(publisher.published_events) == 1
    assert publisher.published_events[0].is_asset_resolved is False


@pytest.mark.asyncio
async def test_idempotency_replay_suppression() -> None:
    """Valida que o envio duplicado com mesma (tenant_id, source, idempotency_key) retorna evento existente e suprime republicação."""
    asset_repo = InMemoryAssetRepository()
    security_event_repo = InMemorySecurityEventRepository()
    publisher = MockEventPublisher()
    log_repo = InMemoryLogRepository()

    handler = IngestSecurityEventHandler(
        asset_repo=asset_repo,
        security_event_repo=security_event_repo,
        event_publisher=publisher,
        log_repo=log_repo,
    )

    tenant_id = uuid4()
    now = datetime.now(timezone.utc)

    cmd = IngestSecurityEventCommand(
        tenant_id=tenant_id,
        source="Alertmanager",
        event_type="DiskFull",
        severity="CRITICAL",
        occurred_at=now,
        received_at=now,
        idempotency_key="idemp-dup-001",
        payload={"disk": "/var/log"},
    )

    # Primeiro envio
    res1 = await handler.handle(cmd)
    assert res1.is_duplicate_suppressed is False
    assert len(publisher.published_events) == 1

    # Reenvio duplicado
    res2 = await handler.handle(cmd)
    assert res2.is_duplicate_suppressed is True
    assert res2.event_id == res1.event_id

    # Não republicou no EventBus
    assert len(publisher.published_events) == 1


@pytest.mark.asyncio
async def test_idempotency_key_allowed_across_different_tenants() -> None:
    """Valida que tenants diferentes podem usar a mesma chave de idempotência sem conflito."""
    asset_repo = InMemoryAssetRepository()
    security_event_repo = InMemorySecurityEventRepository()
    publisher = MockEventPublisher()

    handler = IngestSecurityEventHandler(
        asset_repo=asset_repo,
        security_event_repo=security_event_repo,
        event_publisher=publisher,
    )

    tenant_a = uuid4()
    tenant_b = uuid4()
    now = datetime.now(timezone.utc)

    cmd_a = IngestSecurityEventCommand(
        tenant_id=tenant_a,
        source="Alertmanager",
        event_type="ServiceDown",
        severity="HIGH",
        occurred_at=now,
        received_at=now,
        idempotency_key="idemp-compartilhada-123",
        payload={},
    )
    cmd_b = IngestSecurityEventCommand(
        tenant_id=tenant_b,
        source="Alertmanager",
        event_type="ServiceDown",
        severity="HIGH",
        occurred_at=now,
        received_at=now,
        idempotency_key="idemp-compartilhada-123",
        payload={},
    )

    res_a = await handler.handle(cmd_a)
    res_b = await handler.handle(cmd_b)

    assert res_a.event_id != res_b.event_id
    assert res_a.is_duplicate_suppressed is False
    assert res_b.is_duplicate_suppressed is False
    assert len(publisher.published_events) == 2


@pytest.mark.asyncio
async def test_correlation_rule_version_domain_and_repository() -> None:
    """Valida o contrato de domínio e repositório de CorrelationRuleVersion."""
    repo = InMemoryCorrelationRuleVersionRepository()

    rule_ver = CorrelationRuleVersion(
        rule_version_id=uuid4(),
        rule_id="RULE-SERVICE-DOWN",
        rule_version="1.0.0",
        name="Regra de Indisponibilidade de Serviço",
        category="availability",
        is_active=True,
    )

    saved = await repo.save(rule_ver)
    assert saved.rule_id == "RULE-SERVICE-DOWN"

    retrieved = await repo.get_by_rule_and_version("RULE-SERVICE-DOWN", "1.0.0")
    assert retrieved is not None
    assert retrieved.rule_version_id == rule_ver.rule_version_id

    active_list = await repo.list_active()
    assert len(active_list) == 1


@pytest.mark.asyncio
async def test_seed_script_safety_guard_staging_production(monkeypatch: pytest.MonkeyPatch) -> None:
    """Valida que o script de seed local recusa execução em ambientes staging e production."""
    monkeypatch.setattr("src.core.infrastructure.config.settings.GOVSEC_ENV", "production")

    with pytest.raises(RuntimeError) as exc_info:
        await seed_dev_assets(tenant_id=uuid4())
    assert "estritamente proibidos" in str(exc_info.value)


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
