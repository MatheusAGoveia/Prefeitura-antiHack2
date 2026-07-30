"""
DTOs do Módulo Core
GovSec Shield — Application Layer DTOs
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CreateTenantDTO(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    slug: str | None = Field(None, min_length=2, max_length=64)


class UpdateTenantDTO(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=128)
    status: str | None = Field(None, pattern="^(ACTIVE|INACTIVE|SUSPENDED)$")


class TenantResponseDTO(BaseModel):
    id: UUID
    name: str
    slug: str
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IngestLogDTO(BaseModel):
    source: str = Field(..., min_length=1, max_length=64)
    raw_data: str = Field(..., min_length=1)
    tenant_id: UUID
    timestamp: datetime | None = None

    @field_validator("tenant_id", mode="before")
    @classmethod
    def _validate_tenant_id(cls, v: Any) -> UUID:
        if isinstance(v, UUID):
            return v
        try:
            return UUID(str(v))
        except (ValueError, TypeError) as err:
            raise ValueError(f"tenant_id deve ser um UUID válido, recebido: '{v}'") from err


class LogResponseDTO(BaseModel):
    id: UUID
    source: str
    raw_data: str
    tenant_id: UUID
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class AcknowledgeAlertDTO(BaseModel):
    alert_id: str = Field(..., min_length=1, max_length=128, examples=["ServiceDown-Betim-01"])
    fingerprint: str = Field(..., min_length=1, max_length=128, examples=["a1b2c3d4e5f6"])
    reason: str = Field(
        ...,
        min_length=5,
        max_length=512,
        examples=["Incidente verificado e servidor em reinício manual."],
    )
    tenant_id: UUID | None = None

    @field_validator("tenant_id", mode="before")
    @classmethod
    def _validate_tenant_id(cls, v: Any) -> UUID | None:
        if v is None:
            return None
        if isinstance(v, UUID):
            return v
        try:
            return UUID(str(v))
        except (ValueError, TypeError) as err:
            raise ValueError(f"tenant_id deve ser um UUID válido, recebido: '{v}'") from err


class AlertAcknowledgementResponseDTO(BaseModel):
    id: UUID
    alert_id: str
    fingerprint: str
    reason: str
    acknowledged_by: str
    tenant_id: UUID
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class IngestSecurityEventDTO(BaseModel):
    tenant_id: UUID
    source: str = Field(..., min_length=1, max_length=64)
    event_type: str = Field(..., min_length=1, max_length=64)
    severity: str = Field(..., min_length=1, max_length=32)
    occurred_at: datetime
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    idempotency_key: str = Field(..., min_length=1, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)
    service_name: str | None = Field(None, max_length=128)
    environment: str | None = Field(None, max_length=64)

    @field_validator("tenant_id", mode="before")
    @classmethod
    def _validate_tenant_id(cls, v: Any) -> UUID:
        if isinstance(v, UUID):
            return v
        try:
            return UUID(str(v))
        except (ValueError, TypeError) as err:
            raise ValueError(f"tenant_id deve ser um UUID válido, recebido: '{v}'") from err


class SecurityEventResponseDTO(BaseModel):
    event_id: UUID
    tenant_id: UUID
    asset_id: UUID | None
    source: str
    event_type: str
    severity: str
    occurred_at: datetime
    received_at: datetime
    idempotency_key: str
    is_asset_resolved: bool
    evidence_hash: str
    is_duplicate_suppressed: bool = False

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# M3.2 — DTOs de Incidentes
# ---------------------------------------------------------------------------

# Status válidos para filtro de listagem e resposta (convenção lowercase)
VALID_INCIDENT_STATUSES = frozenset(
    ["open", "acknowledged", "investigating", "contained", "resolved", "closed"]
)


class ChangeIncidentStatusDTO(BaseModel):
    """
    Payload para mudança de status de incidente via API.
    tenant_id e actor_id NUNCA são aceitos do cliente:
      - tenant_id vem do JWT (obrigatório)
      - actor_id é o user_id do JWT autenticado
    """

    new_status: str = Field(
        ...,
        description="Novo status do incidente (lowercase: open, acknowledged, investigating, contained, resolved, closed).",
        examples=["investigating"],
    )
    reason: str = Field(
        ...,
        min_length=5,
        max_length=1024,
        description="Justificativa obrigatória para a mudança de status.",
        examples=["Investigação iniciada — host isolado da rede."],
    )

    @field_validator("new_status")
    @classmethod
    def _validate_status(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in VALID_INCIDENT_STATUSES:
            raise ValueError(
                f"Status inválido: '{v}'. Valores aceitos: {sorted(VALID_INCIDENT_STATUSES)}"
            )
        return normalized


class EvidenceResponseDTO(BaseModel):
    """DTO de resposta para uma evidência de incidente."""

    evidence_id: UUID
    incident_id: UUID
    event_id: UUID
    tenant_id: UUID
    evidence_hash: str
    description: str
    added_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentResponseDTO(BaseModel):
    """DTO de resposta completo para um incidente."""

    incident_id: UUID
    tenant_id: UUID
    title: str
    description: str
    severity: str
    status: str
    correlation_key: str
    created_at: datetime
    updated_at: datetime
    evidence_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class IncidentListResponseDTO(BaseModel):
    """DTO de resposta paginada para listagem de incidentes."""

    items: list[IncidentResponseDTO]
    total: int
    skip: int
    limit: int
