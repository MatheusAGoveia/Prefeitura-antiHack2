"""
Contrato de Domínio para Eventos Outbox (Transactional Outbox Pattern).
GovSec Shield — Domain Outbox

Este módulo utiliza exclusivamente a biblioteca padrão do Python para garantir
isolamento total de infraestrutura e frameworks externos.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from src.core.domain.exceptions import DomainError
from src.core.domain.validation import validate_utc_datetime


@dataclass
class OutboxEvent:
    """
    Entidade de Domínio representando uma mensagem de evento pendente de publicação no broker.
    Garante o padrão Transactional Outbox.
    """

    tenant_id: UUID
    aggregate_type: str
    aggregate_id: UUID
    event_type: str
    payload: dict[str, Any]
    idempotency_key: str
    outbox_event_id: UUID = field(default_factory=uuid4)
    status: str = "pending"  # pending, processing, published, failed
    retry_count: int = 0
    next_retry_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    published_at: datetime | None = None
    last_error: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise DomainError(f"tenant_id deve ser um UUID válido, recebido: {type(self.tenant_id)}")
        if not isinstance(self.outbox_event_id, UUID):
            raise DomainError(
                f"outbox_event_id deve ser um UUID válido, recebido: {type(self.outbox_event_id)}"
            )
        if not isinstance(self.aggregate_id, UUID):
            raise DomainError(
                f"aggregate_id deve ser um UUID válido, recebido: {type(self.aggregate_id)}"
            )
        if not self.aggregate_type or not self.aggregate_type.strip():
            raise DomainError("aggregate_type é obrigatório.")
        if not self.event_type or not self.event_type.strip():
            raise DomainError("event_type é obrigatório.")
        if not self.idempotency_key or not self.idempotency_key.strip():
            raise DomainError("idempotency_key é obrigatória.")
        if not isinstance(self.payload, dict):
            raise DomainError(f"payload deve ser um dict, recebido: {type(self.payload).__name__}")
        if self.status not in ("pending", "processing", "published", "failed"):
            raise DomainError(f"status inválido para OutboxEvent: '{self.status}'")

        validate_utc_datetime(self.created_at, "created_at")
        if self.next_retry_at is not None:
            validate_utc_datetime(self.next_retry_at, "next_retry_at")
        if self.published_at is not None:
            validate_utc_datetime(self.published_at, "published_at")
