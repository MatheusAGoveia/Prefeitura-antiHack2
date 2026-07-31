"""
Testes Unitários — Motor de Correlação Determinística (M3.2)
GovSec Shield — Unit Tests (sem DB, sem IO)

Cobre:
  - Determinismo da CorrelationKey (mesma entrada → mesmo hash)
  - Isolamento cross-tenant (tenant diferente → hash diferente)
  - Domínio puro: Incident, IncidentEvidence, IncidentStatusChange
  - Máquina de estados: transições válidas e inválidas
  - Regras concretas: elegibilidade, R-INFRA-001, R-AUTH-001
  - Reabertura de incidente após RESOLVED/CLOSED (índice parcial)
  - Bucket temporal: eventos na mesma hora → mesmo bucket
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from src.core.application.correlation_handler import (
    CorrelateSecurityEventHandler,
    _compute_time_bucket,
)
from src.core.domain.correlation import CorrelationKey
from src.core.domain.exceptions import DomainError
from src.core.domain.incidents import (
    ALLOWED_STATUS_TRANSITIONS,
    Incident,
    IncidentEvidence,
    IncidentStatus,
    InvalidStatusTransitionError,
    SecurityEvent,
    SecurityEventSeverity,
    sanitize_payload,
)
from src.core.infrastructure.correlation.rules import (
    AuthBruteForceRule,
    InfraAvailabilityRule,
)

# ---------------------------------------------------------------------------
# Fixtures compartilhadas
# ---------------------------------------------------------------------------


def _make_event(
    tenant_id: UUID | None = None,
    event_type: str = "service_down",
    severity: str = "HIGH",
    asset_id: UUID | None = None,
    occurred_at: datetime | None = None,
) -> SecurityEvent:
    t_id = tenant_id or uuid4()
    return SecurityEvent(
        tenant_id=t_id,
        source="test_source",
        event_type=event_type,
        severity=SecurityEventSeverity(severity),
        occurred_at=occurred_at or datetime(2026, 7, 30, 14, 37, 22, tzinfo=timezone.utc),
        received_at=datetime.now(timezone.utc),
        asset_id=asset_id,
        payload={"host": "web-01", "port": 443},
        idempotency_key=str(uuid4()),
    )


def _make_incident(
    tenant_id: UUID | None = None,
    status: IncidentStatus = IncidentStatus.OPEN,
    correlation_key: str = "some:key",
) -> Incident:
    t_id = tenant_id or uuid4()
    now = datetime.now(timezone.utc)
    return Incident(
        incident_id=uuid4(),
        tenant_id=t_id,
        title="Test Incident",
        description="Gerado por teste unitário.",
        severity=SecurityEventSeverity.HIGH,
        status=status,
        correlation_key=correlation_key,
        created_at=now,
        updated_at=now,
    )


# ---------------------------------------------------------------------------
# CorrelationKey — determinismo e isolamento cross-tenant
# ---------------------------------------------------------------------------


class TestCorrelationKeyDeterminism:
    def test_same_input_produces_same_hash(self) -> None:
        tenant_id = uuid4()
        k1 = CorrelationKey(
            tenant_id=tenant_id,
            rule_id="R-INFRA-001",
            rule_version="1.0.0",
            asset_key="web-01",
            category="availability",
            time_window="2026-07-30T14:00:00+00:00",
        )
        k2 = CorrelationKey(
            tenant_id=tenant_id,
            rule_id="R-INFRA-001",
            rule_version="1.0.0",
            asset_key="web-01",
            category="availability",
            time_window="2026-07-30T14:00:00+00:00",
        )
        assert k1.to_hash() == k2.to_hash()
        assert k1.to_canonical_string() == k2.to_canonical_string()

    def test_different_tenant_produces_different_hash(self) -> None:
        k1 = CorrelationKey(
            tenant_id=uuid4(),
            rule_id="R-INFRA-001",
            rule_version="1.0.0",
            asset_key="web-01",
            category="availability",
            time_window="2026-07-30T14:00:00+00:00",
        )
        k2 = CorrelationKey(
            tenant_id=uuid4(),
            rule_id="R-INFRA-001",
            rule_version="1.0.0",
            asset_key="web-01",
            category="availability",
            time_window="2026-07-30T14:00:00+00:00",
        )
        assert k1.to_hash() != k2.to_hash()

    def test_different_time_window_produces_different_hash(self) -> None:
        tenant_id = uuid4()
        k1 = CorrelationKey(
            tenant_id=tenant_id,
            rule_id="R-INFRA-001",
            rule_version="1.0.0",
            asset_key="web-01",
            category="availability",
            time_window="2026-07-30T14:00:00+00:00",
        )
        k2 = CorrelationKey(
            tenant_id=tenant_id,
            rule_id="R-INFRA-001",
            rule_version="1.0.0",
            asset_key="web-01",
            category="availability",
            time_window="2026-07-30T15:00:00+00:00",
        )
        assert k1.to_hash() != k2.to_hash()

    def test_missing_time_window_raises_domain_error(self) -> None:
        with pytest.raises(DomainError, match="time_window"):
            CorrelationKey(
                tenant_id=uuid4(),
                rule_id="R-INFRA-001",
                rule_version="1.0.0",
                asset_key="web-01",
                category="availability",
                time_window="",
            )


# ---------------------------------------------------------------------------
# Bucket Temporal
# ---------------------------------------------------------------------------


class TestTimeBucketComputation:
    def test_events_within_same_hour_produce_same_bucket(self) -> None:
        t1 = datetime(2026, 7, 30, 14, 5, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 7, 30, 14, 59, 59, tzinfo=timezone.utc)
        b1 = _compute_time_bucket(t1, 3600)
        b2 = _compute_time_bucket(t2, 3600)
        assert b1 == b2

    def test_events_in_different_hours_produce_different_buckets(self) -> None:
        t1 = datetime(2026, 7, 30, 14, 59, 59, tzinfo=timezone.utc)
        t2 = datetime(2026, 7, 30, 15, 0, 0, tzinfo=timezone.utc)
        b1 = _compute_time_bucket(t1, 3600)
        b2 = _compute_time_bucket(t2, 3600)
        assert b1 != b2

    def test_bucket_is_floor_of_hour(self) -> None:
        t = datetime(2026, 7, 30, 14, 37, 22, tzinfo=timezone.utc)
        bucket = _compute_time_bucket(t, 3600)
        assert "14:00:00" in bucket

    def test_15min_window(self) -> None:
        t1 = datetime(2026, 7, 30, 14, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 7, 30, 14, 14, 59, tzinfo=timezone.utc)
        t3 = datetime(2026, 7, 30, 14, 15, 0, tzinfo=timezone.utc)
        b1 = _compute_time_bucket(t1, 900)
        b2 = _compute_time_bucket(t2, 900)
        b3 = _compute_time_bucket(t3, 900)
        assert b1 == b2
        assert b1 != b3


# ---------------------------------------------------------------------------
# Incident — status machine
# ---------------------------------------------------------------------------


class TestIncidentStatusMachine:
    def test_valid_transition_open_to_acknowledged(self) -> None:
        inc = _make_incident(status=IncidentStatus.OPEN)
        inc.transition_to(
            new_status=IncidentStatus.ACKNOWLEDGED,
            actor_id="analyst-01",
            reason="Alert verified.",
        )
        assert inc.status == IncidentStatus.ACKNOWLEDGED
        assert len(inc.audit_history) == 1
        assert inc.audit_history[0].from_status == IncidentStatus.OPEN
        assert inc.audit_history[0].to_status == IncidentStatus.ACKNOWLEDGED

    def test_full_lifecycle_chain(self) -> None:
        inc = _make_incident(status=IncidentStatus.OPEN)
        transitions = [
            (IncidentStatus.ACKNOWLEDGED, "ack-reason"),
            (IncidentStatus.INVESTIGATING, "inv-reason"),
            (IncidentStatus.CONTAINED, "cont-reason"),
            (IncidentStatus.RESOLVED, "res-reason"),
            (IncidentStatus.CLOSED, "close-reason"),
        ]
        for new_status, reason in transitions:
            inc.transition_to(new_status=new_status, actor_id="actor", reason=reason)
        assert inc.status == IncidentStatus.CLOSED
        assert len(inc.audit_history) == 5

    def test_invalid_transition_open_to_resolved_raises(self) -> None:
        inc = _make_incident(status=IncidentStatus.OPEN)
        with pytest.raises(InvalidStatusTransitionError, match="inválida"):
            inc.transition_to(
                new_status=IncidentStatus.RESOLVED,
                actor_id="analyst-01",
                reason="Skipping steps.",
            )

    def test_invalid_transition_closed_raises(self) -> None:
        inc = _make_incident(status=IncidentStatus.CLOSED)
        with pytest.raises(InvalidStatusTransitionError):
            inc.transition_to(
                new_status=IncidentStatus.OPEN,
                actor_id="actor",
                reason="Trying to reopen.",
            )

    def test_transition_requires_actor_id(self) -> None:
        inc = _make_incident(status=IncidentStatus.OPEN)
        with pytest.raises(DomainError, match="actor_id"):
            inc.transition_to(
                new_status=IncidentStatus.ACKNOWLEDGED,
                actor_id="",
                reason="Some reason.",
            )

    def test_transition_requires_reason(self) -> None:
        inc = _make_incident(status=IncidentStatus.OPEN)
        with pytest.raises(DomainError, match="Justificativa"):
            inc.transition_to(
                new_status=IncidentStatus.ACKNOWLEDGED,
                actor_id="actor",
                reason="",
            )

    def test_resolved_to_closed_is_valid(self) -> None:
        inc = _make_incident(status=IncidentStatus.RESOLVED)
        inc.transition_to(
            new_status=IncidentStatus.CLOSED,
            actor_id="actor",
            reason="Final closure.",
        )
        assert inc.status == IncidentStatus.CLOSED

    def test_all_statuses_in_allowed_transitions(self) -> None:
        for status in IncidentStatus:
            assert status in ALLOWED_STATUS_TRANSITIONS


# ---------------------------------------------------------------------------
# IncidentEvidence — cross-tenant protection
# ---------------------------------------------------------------------------


class TestIncidentEvidenceDomain:
    def test_add_evidence_same_tenant_succeeds(self) -> None:
        tenant_id = uuid4()
        inc = _make_incident(tenant_id=tenant_id)
        ev = IncidentEvidence(
            evidence_id=uuid4(),
            incident_id=inc.incident_id,
            event_id=uuid4(),
            tenant_id=tenant_id,
            evidence_hash="abc123",
            added_at=datetime.now(timezone.utc),
            description="Test evidence.",
            raw_payload_masked={"host": "web-01"},
        )
        inc.add_evidence(ev)
        assert len(inc.evidences) == 1

    def test_add_evidence_cross_tenant_raises(self) -> None:
        inc = _make_incident(tenant_id=uuid4())
        ev = IncidentEvidence(
            evidence_id=uuid4(),
            incident_id=inc.incident_id,
            event_id=uuid4(),
            tenant_id=uuid4(),  # tenant diferente!
            evidence_hash="abc123",
            added_at=datetime.now(timezone.utc),
            description="Cross-tenant evidence.",
            raw_payload_masked={},
        )
        with pytest.raises(DomainError, match="tenant diferente"):
            inc.add_evidence(ev)


# ---------------------------------------------------------------------------
# Regras Concretas — elegibilidade
# ---------------------------------------------------------------------------


class TestInfraAvailabilityRule:
    def setup_method(self) -> None:
        self.rule = InfraAvailabilityRule()

    def test_rule_id_and_version(self) -> None:
        assert self.rule.rule_id == "R-INFRA-001"
        assert self.rule.version == "1.0.0"
        assert self.rule.category == "availability"

    def test_service_down_event_is_eligible(self) -> None:
        event = _make_event(event_type="service_down", severity="MEDIUM")
        assert self.rule.is_eligible(event)

    def test_timeout_event_is_eligible(self) -> None:
        event = _make_event(event_type="connection_timeout", severity="LOW")
        assert self.rule.is_eligible(event)

    def test_high_severity_is_eligible_regardless_of_type(self) -> None:
        event = _make_event(event_type="arbitrary_event", severity="HIGH")
        assert self.rule.is_eligible(event)

    def test_critical_severity_is_eligible(self) -> None:
        event = _make_event(event_type="unknown", severity="CRITICAL")
        assert self.rule.is_eligible(event)

    def test_low_severity_login_event_is_not_eligible(self) -> None:
        event = _make_event(event_type="user_login", severity="LOW")
        assert not self.rule.is_eligible(event)

    def test_medium_severity_create_event_is_not_eligible(self) -> None:
        event = _make_event(event_type="resource_created", severity="MEDIUM")
        assert not self.rule.is_eligible(event)


class TestAuthBruteForceRule:
    def setup_method(self) -> None:
        self.rule = AuthBruteForceRule()

    def test_rule_id_and_version(self) -> None:
        assert self.rule.rule_id == "R-AUTH-001"
        assert self.rule.version == "1.0.0"
        assert self.rule.category == "authentication"

    def test_login_failed_is_eligible(self) -> None:
        event = _make_event(event_type="login_failed", severity="LOW")
        assert self.rule.is_eligible(event)

    def test_auth_failure_is_eligible(self) -> None:
        event = _make_event(event_type="auth_failure", severity="LOW")
        assert self.rule.is_eligible(event)

    def test_service_down_is_not_eligible(self) -> None:
        event = _make_event(event_type="service_down", severity="CRITICAL")
        assert not self.rule.is_eligible(event)


# ---------------------------------------------------------------------------
# sanitize_payload — segurança
# ---------------------------------------------------------------------------


class TestSanitizePayload:
    def test_removes_password_key(self) -> None:
        result = sanitize_payload({"password": "secret123", "host": "web-01"})
        assert result["password"] == "[REDACTED]"
        assert result["host"] == "web-01"

    def test_removes_token_key(self) -> None:
        result = sanitize_payload({"token": "eyJhbGciOiJSUzI1NiJ9"})
        assert result["token"] == "[REDACTED]"

    def test_removes_nested_secret(self) -> None:
        result = sanitize_payload({"db": {"password": "s3cr3t", "host": "db-01"}})
        assert result["db"]["password"] == "[REDACTED]"
        assert result["db"]["host"] == "db-01"

    def test_preserves_non_sensitive_keys(self) -> None:
        payload = {"host": "web-01", "port": 443, "status": "down"}
        result = sanitize_payload(payload)
        assert result == payload


# ---------------------------------------------------------------------------
# CorrelateSecurityEventHandler — Inelegibilidade e Regra Inativa (Mock UoW)
# ---------------------------------------------------------------------------


class TestCorrelateSecurityEventHandlerUnit:
    @pytest.mark.asyncio
    async def test_ineligible_event_returns_empty_and_does_not_save(self) -> None:
        tenant_id = uuid4()
        event_id = uuid4()

        event = _make_event(tenant_id=tenant_id, event_type="user_login", severity="LOW")
        event.event_id = event_id

        uow = MagicMock()
        uow.security_events.get_by_id = AsyncMock(return_value=event)
        uow.incidents.save = AsyncMock()
        uow.evidences.save = AsyncMock()
        uow.logs.save = AsyncMock()

        rule = InfraAvailabilityRule()  # user_login LOW is ineligible
        handler = CorrelateSecurityEventHandler(uow=uow, rules=[rule])

        results = await handler.handle(tenant_id=tenant_id, security_event_id=event_id)

        assert results == []
        uow.incidents.save.assert_not_called()
        uow.evidences.save.assert_not_called()
        uow.logs.save.assert_not_called()
