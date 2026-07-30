"""
Testes Unitários de Arquitetura e Contratos de Domínio — Capability M3.0
GovSec Shield — Unit Tests
"""

import ast
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from src.core.domain.correlation import CorrelationKey
from src.core.domain.exceptions import DomainError
from src.core.domain.incidents import (
    Asset,
    Incident,
    IncidentStatus,
    InvalidStatusTransitionError,
    SecurityEvent,
    SecurityEventSeverity,
    sanitize_payload,
)
from src.core.domain.m4_contracts import Engagement, ScopeTarget, SecurityJob, ToolAdapter


def test_tenant_uuid_invariants_across_m3_entities() -> None:
    """Valida que tenant_id deve ser estritamente um UUID válido em todas as entidades M3."""
    tenant_id = uuid4()
    str(tenant_id)
    invalid_tenant_id = "tenant-slug-invalido"

    # Asset
    asset = Asset(
        asset_id=uuid4(),
        tenant_id=tenant_id,
        name="Servidor Central",
        hostname_or_ip="192.168.1.10",
        asset_type="SERVER",
        criticality="HIGH",
    )
    assert asset.tenant_id == tenant_id

    with pytest.raises(DomainError):
        Asset(
            asset_id=uuid4(),
            tenant_id=invalid_tenant_id,  # type: ignore[arg-type]
            name="Servidor Central",
            hostname_or_ip="192.168.1.10",
            asset_type="SERVER",
            criticality="HIGH",
        )

    # SecurityEvent
    event = SecurityEvent(
        event_id=uuid4(),
        tenant_id=tenant_id,
        source="Alertmanager",
        event_type="ServiceDown",
        severity=SecurityEventSeverity.HIGH,
        occurred_at=datetime.now(timezone.utc),
        received_at=datetime.now(timezone.utc),
        asset_id=asset.asset_id,
        payload={"message": "Service offline"},
        idempotency_key="idemp-123",
        is_asset_resolved=True,
    )
    assert event.tenant_id == tenant_id

    with pytest.raises(DomainError):
        SecurityEvent(
            event_id=uuid4(),
            tenant_id=invalid_tenant_id,  # type: ignore[arg-type]
            source="Alertmanager",
            event_type="ServiceDown",
            severity=SecurityEventSeverity.HIGH,
            occurred_at=datetime.now(timezone.utc),
            received_at=datetime.now(timezone.utc),
            asset_id=asset.asset_id,
            payload={},
            idempotency_key="idemp-123",
            is_asset_resolved=True,
        )

    # CorrelationKey
    ckey = CorrelationKey(
        tenant_id=tenant_id,
        rule_id="R-001",
        asset_key=str(asset.asset_id),
        category="availability",
        time_window="5m",
    )
    assert ckey.tenant_id == tenant_id

    with pytest.raises(DomainError):
        CorrelationKey(
            tenant_id=invalid_tenant_id,  # type: ignore[arg-type]
            rule_id="R-001",
            asset_key="asset-1",
            category="availability",
            time_window="5m",
        )


def test_deterministic_correlation_key_generation() -> None:
    """Valida que CorrelationKey é determinística e produz strings/hashes reproduzíveis."""
    tenant_id = UUID("11111111-1111-1111-1111-111111111111")
    ckey1 = CorrelationKey(
        tenant_id=tenant_id,
        rule_id="RULE-SERVICE-DOWN",
        asset_key="srv-01",
        category="availability",
        time_window="2026-07-30T09:00:00Z_5m",
    )
    ckey2 = CorrelationKey(
        tenant_id=tenant_id,
        rule_id="RULE-SERVICE-DOWN",
        asset_key="srv-01",
        category="availability",
        time_window="2026-07-30T09:00:00Z_5m",
    )

    expected_canonical = (
        "11111111-1111-1111-1111-111111111111:RULE-SERVICE-DOWN:srv-01:availability:2026-07-30T09:00:00Z_5m"
    )
    assert ckey1.to_canonical_string() == expected_canonical
    assert ckey2.to_canonical_string() == expected_canonical
    assert ckey1.to_hash() == ckey2.to_hash()
    assert str(ckey1) == expected_canonical


def test_incident_status_valid_transitions() -> None:
    """Valida o fluxo feliz de transição de estados do incidente: OPEN -> ACKNOWLEDGED -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED."""
    tenant_id = uuid4()
    incident = Incident(
        incident_id=uuid4(),
        tenant_id=tenant_id,
        title="Indisponibilidade Portal Saúde",
        description="Portal de agendamento inacessível",
        severity=SecurityEventSeverity.CRITICAL,
        status=IncidentStatus.OPEN,
        correlation_key="ckey-123",
    )

    actor = "analyst-01"

    # OPEN -> ACKNOWLEDGED
    incident.transition_to(IncidentStatus.ACKNOWLEDGED, actor_id=actor, reason="Alerta reconhecido pelo operador SOC")
    assert incident.status == IncidentStatus.ACKNOWLEDGED
    assert len(incident.audit_history) == 1
    assert incident.audit_history[0].from_status == IncidentStatus.OPEN
    assert incident.audit_history[0].to_status == IncidentStatus.ACKNOWLEDGED
    assert incident.audit_history[0].actor_id == actor

    # ACKNOWLEDGED -> INVESTIGATING
    incident.transition_to(IncidentStatus.INVESTIGATING, actor_id=actor, reason="Análise de causa raiz iniciada")
    assert incident.status == IncidentStatus.INVESTIGATING
    assert len(incident.audit_history) == 2

    # INVESTIGATING -> CONTAINED
    incident.transition_to(IncidentStatus.CONTAINED, actor_id=actor, reason="Tráfego malicioso bloqueado")
    assert incident.status == IncidentStatus.CONTAINED
    assert len(incident.audit_history) == 3

    # CONTAINED -> RESOLVED
    incident.transition_to(IncidentStatus.RESOLVED, actor_id=actor, reason="Serviço restaurado e validado")
    assert incident.status == IncidentStatus.RESOLVED
    assert len(incident.audit_history) == 4

    # RESOLVED -> CLOSED
    incident.transition_to(IncidentStatus.CLOSED, actor_id=actor, reason="Incidente encerrado no relatório final")
    assert incident.status == IncidentStatus.CLOSED
    assert len(incident.audit_history) == 5


def test_incident_status_invalid_transitions_raised() -> None:
    """Valida que saltar estados ou realizar transições não permitidas lança InvalidStatusTransitionError."""
    tenant_id = uuid4()
    incident = Incident(
        incident_id=uuid4(),
        tenant_id=tenant_id,
        title="Incidente de Teste",
        description="Descrição",
        severity=SecurityEventSeverity.MEDIUM,
        status=IncidentStatus.OPEN,
        correlation_key="ckey-test",
    )

    # Tenta saltar de OPEN direto para RESOLVED (Inválido)
    with pytest.raises(InvalidStatusTransitionError) as exc_info:
        incident.transition_to(IncidentStatus.RESOLVED, actor_id="analyst", reason="Tentando resolver direto")
    assert "Transição inválida" in str(exc_info.value)

    # Tenta avançar de CLOSED (Estado Terminal)
    incident.status = IncidentStatus.CLOSED
    with pytest.raises(InvalidStatusTransitionError):
        incident.transition_to(IncidentStatus.OPEN, actor_id="analyst", reason="Reabrindo")


def test_incident_transition_requires_actor_and_reason() -> None:
    """Valida que transição de estado exige identificador de ator e justificativa preenchida."""
    tenant_id = uuid4()
    incident = Incident(
        incident_id=uuid4(),
        tenant_id=tenant_id,
        title="Incidente Auditável",
        description="Descrição",
        severity=SecurityEventSeverity.LOW,
        status=IncidentStatus.OPEN,
        correlation_key="ckey-audit",
    )

    with pytest.raises(DomainError) as exc1:
        incident.transition_to(IncidentStatus.ACKNOWLEDGED, actor_id="", reason="Justificativa sem ator")
    assert "actor_id é obrigatório" in str(exc1.value)

    with pytest.raises(DomainError) as exc2:
        incident.transition_to(IncidentStatus.ACKNOWLEDGED, actor_id="analyst", reason="  ")
    assert "reason" in str(exc2.value)


def test_security_event_unresolved_asset_flag() -> None:
    """Valida que eventos sem ativo associado (asset_id is None) são marcados como não resolvidos."""
    tenant_id = uuid4()
    event_no_asset = SecurityEvent(
        event_id=uuid4(),
        tenant_id=tenant_id,
        source="Alertmanager",
        event_type="UnknownHostAlert",
        severity=SecurityEventSeverity.HIGH,
        occurred_at=datetime.now(timezone.utc),
        received_at=datetime.now(timezone.utc),
        asset_id=None,
        payload={"ip": "10.0.0.99"},
        idempotency_key="idemp-no-asset",
        is_asset_resolved=True,  # Deve ser sobrescrito para False devido a asset_id is None
    )

    assert event_no_asset.asset_id is None
    assert event_no_asset.is_asset_resolved is False


def test_security_event_payload_redaction() -> None:
    """Valida a sanitização/redaction de segredos e credenciais em payloads de eventos."""
    raw_payload = {
        "user": "admin",
        "password": "SuperSecretPassword123!",
        "auth": {
            "token": "bearer-jwt-token-string",
            "api_key": "secret-key-xyz",
        },
        "items": [{"cookie": "session_id=12345"}],
    }

    sanitized = sanitize_payload(raw_payload)

    assert sanitized["user"] == "admin"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["auth"]["token"] == "[REDACTED]"
    assert sanitized["auth"]["api_key"] == "[REDACTED]"
    assert sanitized["items"][0]["cookie"] == "[REDACTED]"


def test_m4_preparatory_contracts_stubs_without_execution() -> None:
    """Valida a instanciação dos contratos estáticos preparatórios de M4."""
    tenant_id = uuid4()

    target = ScopeTarget(
        target_id=uuid4(),
        tenant_id=tenant_id,
        target_identifier="192.168.1.0/24",
        is_allowed=True,
    )
    assert target.is_allowed is True

    engagement = Engagement(
        engagement_id=uuid4(),
        tenant_id=tenant_id,
        title="Auditoria de Segurança Semestral",
        scope_targets=[target],
    )
    assert engagement.status == "DRAFT"

    job = SecurityJob(
        job_id=uuid4(),
        tenant_id=tenant_id,
        job_type="PORT_SCAN_PREP",
        target_identifier="192.168.1.10",
    )
    assert job.status == "PENDING"

    # ToolAdapter é ABC pura
    class DummyToolAdapter(ToolAdapter):
        @property
        def adapter_id(self) -> str:
            return "dummy-adapter"

        @property
        def tool_name(self) -> str:
            return "dummy-tool"

        def execute_job(self, job: SecurityJob) -> dict[str, str]:
            return {"status": "not_implemented_m3"}

    adapter = DummyToolAdapter()
    assert adapter.adapter_id == "dummy-adapter"
    assert adapter.execute_job(job)["status"] == "not_implemented_m3"


def test_domain_layer_has_zero_infrastructure_imports() -> None:
    """
    Teste de Arquitetura: Garante estritamente que os módulos de domínio de M3
    não importam infraestrutura, frameworks web, ORMs ou bibliotecas externas.
    """
    domain_dir = Path("src/core/domain")
    m3_files = [
        domain_dir / "incidents.py",
        domain_dir / "correlation.py",
        domain_dir / "m4_contracts.py",
    ]

    forbidden_imports = {
        "fastapi",
        "starlette",
        "sqlalchemy",
        "alembic",
        "redis",
        "kafka",
        "aiokafka",
        "pydantic",
        "requests",
        "httpx",
    }

    for file_path in m3_files:
        assert file_path.exists(), f"Arquivo de domínio {file_path} não foi encontrado."
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    pkg = alias.name.split(".")[0]
                    assert (
                        pkg not in forbidden_imports
                    ), f"Módulo de domínio '{file_path.name}' importou infraestrutura proibida: '{pkg}'"

            elif isinstance(node, ast.ImportFrom) and node.module:
                pkg = node.module.split(".")[0]
                assert (
                    pkg not in forbidden_imports
                ), f"Módulo de domínio '{file_path.name}' importou infraestrutura proibida: '{pkg}'"
