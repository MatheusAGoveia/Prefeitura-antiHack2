"""
Entidades e Enums para Execuções de Scanner (ScanExecution e ScanExecutionTarget).
GovSec Shield — Domain Layer (M3.4)
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from src.asset.domain.exceptions import AssetDomainError, InvalidStatusTransitionError
from src.core.domain.validation import validate_utc_datetime


class TriggerType(StrEnum):
    """Gatilho de disparo da execução."""

    MANUAL = "manual"
    SCHEDULED = "scheduled"
    API = "api"
    RETRY = "retry"


class ExecutionStatus(StrEnum):
    """Estados do ciclo de vida da execução de um scanner."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


ALLOWED_EXECUTION_TRANSITIONS: dict[ExecutionStatus, set[ExecutionStatus]] = {
    ExecutionStatus.PENDING: {ExecutionStatus.QUEUED, ExecutionStatus.CANCELLED, ExecutionStatus.FAILED},
    ExecutionStatus.QUEUED: {ExecutionStatus.RUNNING, ExecutionStatus.CANCELLED, ExecutionStatus.FAILED},
    ExecutionStatus.RUNNING: {
        ExecutionStatus.COMPLETED,
        ExecutionStatus.PARTIALLY_COMPLETED,
        ExecutionStatus.FAILED,
        ExecutionStatus.CANCELLED,
    },
    ExecutionStatus.COMPLETED: set(),  # Terminal
    ExecutionStatus.PARTIALLY_COMPLETED: set(),  # Terminal
    ExecutionStatus.FAILED: set(),  # Terminal
    ExecutionStatus.CANCELLED: set(),  # Terminal
}


@dataclass
class ScanExecutionTarget:
    """Detalhamento da execução de um scanner para um alvo específico."""

    id: UUID
    tenant_id: UUID
    execution_id: UUID
    target_id: UUID
    status: ExecutionStatus
    assets_discovered: int
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        if self.started_at is not None:
            validate_utc_datetime(self.started_at, "started_at")
        if self.finished_at is not None:
            validate_utc_datetime(self.finished_at, "finished_at")


@dataclass
class ScanExecution:
    """Registro de uma execução de scanner autorizada."""

    id: UUID
    tenant_id: UUID
    scanner_profile_id: UUID
    trigger_type: TriggerType
    status: ExecutionStatus
    targets_total: int
    targets_processed: int
    assets_discovered: int
    services_discovered: int
    vulnerabilities_discovered: int
    created_at: datetime
    updated_at: datetime
    schedule_id: UUID | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    requested_by: UUID | None = None
    error_summary: str | None = None

    def __post_init__(self) -> None:
        validate_utc_datetime(self.created_at, "created_at")
        validate_utc_datetime(self.updated_at, "updated_at")
        if self.started_at is not None:
            validate_utc_datetime(self.started_at, "started_at")
        if self.finished_at is not None:
            validate_utc_datetime(self.finished_at, "finished_at")

    @classmethod
    def create(
        cls,
        tenant_id: UUID,
        scanner_profile_id: UUID,
        targets_total: int,
        trigger_type: TriggerType = TriggerType.MANUAL,
        schedule_id: UUID | None = None,
        requested_by: UUID | None = None,
    ) -> "ScanExecution":
        if targets_total < 1:
            raise AssetDomainError("Uma execução deve possuir pelo menos um alvo.")

        now = datetime.now(timezone.utc)
        return cls(
            id=uuid4(),
            tenant_id=tenant_id,
            schedule_id=schedule_id,
            scanner_profile_id=scanner_profile_id,
            trigger_type=trigger_type,
            status=ExecutionStatus.QUEUED,
            started_at=None,
            finished_at=None,
            requested_by=requested_by,
            targets_total=targets_total,
            targets_processed=0,
            assets_discovered=0,
            services_discovered=0,
            vulnerabilities_discovered=0,
            error_summary=None,
            created_at=now,
            updated_at=now,
        )

    def transition_to(self, new_status: ExecutionStatus, error_summary: str | None = None) -> None:
        """Executa a transição de estado validando as regras do ciclo de vida."""
        allowed = ALLOWED_EXECUTION_TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            raise InvalidStatusTransitionError(
                f"Transição inválida de estado de execução de '{self.status}' para '{new_status}'."
            )

        now = datetime.now(timezone.utc)
        self.status = new_status
        self.updated_at = now

        if new_status == ExecutionStatus.RUNNING and self.started_at is None:
            self.started_at = now

        if new_status in (ExecutionStatus.COMPLETED, ExecutionStatus.PARTIALLY_COMPLETED, ExecutionStatus.FAILED, ExecutionStatus.CANCELLED):
            self.finished_at = now
            if error_summary:
                self.error_summary = error_summary[:512]

    def cancel(self, reason: str | None = None) -> None:
        """Cancela uma execução pendente ou enfileirada."""
        if self.status not in (ExecutionStatus.PENDING, ExecutionStatus.QUEUED):
            raise InvalidStatusTransitionError(
                f"Apenas execuções em estado 'pending' ou 'queued' podem ser canceladas. Estado atual: '{self.status}'."
            )
        self.transition_to(ExecutionStatus.CANCELLED, error_summary=reason or "Cancelado pelo usuário.")
