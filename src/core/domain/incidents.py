"""
Contratos do Domínio de Incidentes e Eventos de Segurança.
GovSec Shield — Domain Layer (M3.0)

Este módulo utiliza exclusivamente a biblioteca padrão do Python para garantir
isolamento total de frameworks web, ORMs e componentes de infraestrutura.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID

from src.core.domain.exceptions import DomainError


class InvalidStatusTransitionError(DomainError):
    """Lançada quando é solicitada uma transição inválida de estado de incidente."""

    pass


class IncidentStatus(StrEnum):
    """Estados do ciclo de vida de um incidente."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class SecurityEventSeverity(StrEnum):
    """Níveis de severidade para eventos e incidentes de segurança."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Teias de transição permitidas no ciclo de vida do incidente
ALLOWED_STATUS_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.OPEN: {IncidentStatus.ACKNOWLEDGED},
    IncidentStatus.ACKNOWLEDGED: {IncidentStatus.INVESTIGATING},
    IncidentStatus.INVESTIGATING: {IncidentStatus.CONTAINED},
    IncidentStatus.CONTAINED: {IncidentStatus.RESOLVED},
    IncidentStatus.RESOLVED: {IncidentStatus.CLOSED},
    IncidentStatus.CLOSED: set(),  # Estado terminal
}


SENSITIVE_KEYS: set[str] = {
    "password",
    "secret",
    "token",
    "authorization",
    "cookie",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
    "credential",
}


def sanitize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Sanitiza recursivamente um payload mascarando chaves sensíveis.
    Garante Zero Trust e previne vazamento de dados confidenciais.
    """
    sanitized: dict[str, Any] = {}
    for key, value in payload.items():
        key_lower = str(key).lower()
        if any(sensitive in key_lower for sensitive in SENSITIVE_KEYS):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_payload(value)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_payload(item) if isinstance(item, dict) else item for item in value
            ]
        else:
            sanitized[key] = value
    return sanitized


@dataclass(frozen=True)
class Asset:
    """Entidade de Domínio representando um Ativo de TI/Infraestrutura."""

    asset_id: UUID
    tenant_id: UUID
    name: str
    hostname_or_ip: str
    asset_type: str
    criticality: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise DomainError(f"tenant_id deve ser um UUID válido, recebido: {type(self.tenant_id)}")
        if not isinstance(self.asset_id, UUID):
            raise DomainError(f"asset_id deve ser um UUID válido, recebido: {type(self.asset_id)}")


@dataclass
class SecurityEvent:
    """Contrato de Evento de Segurança Normalizado."""

    event_id: UUID
    tenant_id: UUID
    source: str
    event_type: str
    severity: SecurityEventSeverity
    occurred_at: datetime
    received_at: datetime
    asset_id: UUID | None
    payload: dict[str, Any]
    idempotency_key: str
    is_asset_resolved: bool
    evidence_hash: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise DomainError(f"tenant_id deve ser um UUID válido, recebido: {type(self.tenant_id)}")
        if not isinstance(self.event_id, UUID):
            raise DomainError(f"event_id deve ser um UUID válido, recebido: {type(self.event_id)}")

        # Redaction de segurança no payload
        self.payload = sanitize_payload(self.payload)

        # Regra de ativo não resolvido
        if self.asset_id is None:
            self.is_asset_resolved = False

        # Gera evidência criptográfica se não fornecida
        if not self.evidence_hash:
            raw = f"{self.event_id}:{self.tenant_id}:{self.source}:{self.event_type}:{self.idempotency_key}"
            self.evidence_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IncidentEvidence:
    """Registro de Evidência associada a um Incidente."""

    evidence_id: UUID
    incident_id: UUID
    event_id: UUID
    tenant_id: UUID
    evidence_hash: str
    added_at: datetime
    description: str
    raw_payload_masked: dict[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise DomainError(f"tenant_id deve ser um UUID válido, recebido: {type(self.tenant_id)}")


@dataclass(frozen=True)
class IncidentStatusChange:
    """Registro auditável de mudança de estado de um incidente."""

    from_status: IncidentStatus
    to_status: IncidentStatus
    actor_id: str
    reason: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Incident:
    """Agregado de Domínio representando um Incidente de Segurança."""

    incident_id: UUID
    tenant_id: UUID
    title: str
    description: str
    severity: SecurityEventSeverity
    status: IncidentStatus
    correlation_key: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidences: list[IncidentEvidence] = field(default_factory=list)
    audit_history: list[IncidentStatusChange] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise DomainError(f"tenant_id deve ser um UUID válido, recebido: {type(self.tenant_id)}")
        if not isinstance(self.incident_id, UUID):
            raise DomainError(f"incident_id deve ser um UUID válido, recebido: {type(self.incident_id)}")

    def transition_to(
        self,
        new_status: IncidentStatus,
        actor_id: str,
        reason: str,
        timestamp: datetime | None = None,
    ) -> None:
        """
        Transiciona o estado do incidente validando a máquina de estados.
        Toda alteração exige actor_id, justificativa e registro auditável.
        """
        if not actor_id or not actor_id.strip():
            raise DomainError("actor_id é obrigatório para transição de estado de incidente.")
        if not reason or not reason.strip():
            raise DomainError("Justificativa (reason) é obrigatória para transição de estado.")

        allowed = ALLOWED_STATUS_TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            raise InvalidStatusTransitionError(
                f"Transição inválida de '{self.status}' para '{new_status}'. "
                f"Transições permitidas a partir de '{self.status}': {[s.value for s in allowed]}"
            )

        ts = timestamp or datetime.now(timezone.utc)
        change_record = IncidentStatusChange(
            from_status=self.status,
            to_status=new_status,
            actor_id=actor_id,
            reason=reason,
            timestamp=ts,
        )
        self.audit_history.append(change_record)
        self.status = new_status
        self.updated_at = ts

    def add_evidence(self, evidence: IncidentEvidence) -> None:
        """Adiciona uma nova evidência vinculada ao incidente."""
        if evidence.tenant_id != self.tenant_id:
            raise DomainError("Evidência pertence a um tenant diferente do incidente.")
        self.evidences.append(evidence)
        self.updated_at = datetime.now(timezone.utc)
