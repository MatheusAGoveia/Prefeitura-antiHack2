"""
Entidades e Enums para Agendamentos de Varredura (ScanSchedule).
GovSec Shield — Domain Layer (M3.4)
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

try:
    from croniter import croniter  # type: ignore[import-untyped]
    _HAS_CRONITER = True
except ImportError:
    _HAS_CRONITER = False

from src.asset.domain.exceptions import AssetDomainError
from src.core.domain.validation import validate_utc_datetime


class FrequencyType(StrEnum):
    """Frequência de execução de um agendamento."""

    MANUAL = "manual"
    ONCE = "once"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CRON = "cron"


class OverlapPolicy(StrEnum):
    """Política de tratamento para sobreposição de execuções."""

    SKIP = "skip"
    QUEUE = "queue"
    CANCEL_PREVIOUS = "cancel_previous"


@dataclass
class ScanScheduleTarget:
    """Relacionamento N:N entre agendamento e alvos de scanner."""

    schedule_id: UUID
    target_id: UUID
    created_at: datetime

    def __post_init__(self) -> None:
        validate_utc_datetime(self.created_at, "created_at")


def _get_zoneinfo(tz_name: str) -> timezone | ZoneInfo:
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return timezone.utc


def _compute_next_cron_run(cron_expr: str, base_time: datetime) -> datetime | None:
    """Calcula a próxima execução para expressões cron."""
    if _HAS_CRONITER:
        try:
            iter_obj = croniter(cron_expr, base_time.timestamp())
            next_ts = iter_obj.get_next(float)
            return datetime.fromtimestamp(next_ts, tz=timezone.utc)
        except Exception:  # nosec B110
            pass

    # Fallback para expressões cron padrão de 5 campos (ex: "0 2 * * *")
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        return None

    try:
        target_min = int(parts[0]) if parts[0] != "*" else 0
        target_hour = int(parts[1]) if parts[1] != "*" else 0

        next_dt = base_time.replace(minute=target_min, second=0, microsecond=0)
        if parts[1] != "*":
            next_dt = next_dt.replace(hour=target_hour)

        if next_dt <= base_time:
            next_dt += timedelta(days=1)

        return next_dt
    except Exception:
        return None


@dataclass
class ScanSchedule:
    """Configuração de agendamento automático ou manual de varredura."""

    id: UUID
    tenant_id: UUID
    name: str
    scanner_profile_id: UUID
    frequency_type: FrequencyType
    timezone: str
    enabled: bool
    overlap_policy: OverlapPolicy
    created_at: datetime
    updated_at: datetime
    created_by: UUID
    description: str | None = None
    cron_expression: str | None = None
    start_at: datetime | None = None
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None
    updated_by: UUID | None = None
    target_ids: list[UUID] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise AssetDomainError("O nome do agendamento é obrigatório.")
        self.name = self.name.strip()

        if not self.timezone or not self.timezone.strip():
            raise AssetDomainError("O fuso horário é obrigatório.")

        if self.frequency_type == FrequencyType.CRON and (not self.cron_expression or not self.cron_expression.strip()):
            raise AssetDomainError("A expressão cron é obrigatória quando a frequência é 'cron'.")

        validate_utc_datetime(self.created_at, "created_at")
        validate_utc_datetime(self.updated_at, "updated_at")
        if self.start_at is not None:
            validate_utc_datetime(self.start_at, "start_at")
        if self.next_run_at is not None:
            validate_utc_datetime(self.next_run_at, "next_run_at")
        if self.last_run_at is not None:
            validate_utc_datetime(self.last_run_at, "last_run_at")

    @classmethod
    def create(
        cls,
        tenant_id: UUID,
        name: str,
        scanner_profile_id: UUID,
        target_ids: list[UUID],
        created_by: UUID,
        description: str | None = None,
        frequency_type: FrequencyType = FrequencyType.MANUAL,
        cron_expression: str | None = None,
        tz_name: str = "UTC",
        start_at: datetime | None = None,
        overlap_policy: OverlapPolicy = OverlapPolicy.SKIP,
        enabled: bool = True,
    ) -> "ScanSchedule":
        if not target_ids:
            raise AssetDomainError("Um agendamento deve possuir pelo menos um alvo associado.")

        now = datetime.now(timezone.utc)
        schedule = cls(
            id=uuid4(),
            tenant_id=tenant_id,
            name=name,
            description=description,
            scanner_profile_id=scanner_profile_id,
            frequency_type=frequency_type,
            cron_expression=cron_expression.strip() if cron_expression else None,
            timezone=tz_name,
            start_at=start_at,
            next_run_at=None,
            last_run_at=None,
            enabled=enabled,
            overlap_policy=overlap_policy,
            created_at=now,
            updated_at=now,
            created_by=created_by,
            updated_by=None,
            target_ids=list(set(target_ids)),
        )
        schedule.calculate_next_run()
        return schedule

    def calculate_next_run(self, from_time: datetime | None = None) -> datetime | None:
        """Calcula a próxima execução de acordo com a frequência e timezone."""
        if not self.enabled or self.frequency_type == FrequencyType.MANUAL:
            self.next_run_at = None
            return None

        base_time = from_time or datetime.now(timezone.utc)
        if self.frequency_type == FrequencyType.CRON and self.cron_expression:
            self.next_run_at = _compute_next_cron_run(self.cron_expression, base_time)
        else:
            self.next_run_at = None

        return self.next_run_at

    def update(
        self,
        name: str | None = None,
        description: str | None = None,
        scanner_profile_id: UUID | None = None,
        target_ids: list[UUID] | None = None,
        frequency_type: FrequencyType | None = None,
        cron_expression: str | None = None,
        tz_name: str | None = None,
        start_at: datetime | None = None,
        overlap_policy: OverlapPolicy | None = None,
        enabled: bool | None = None,
        updated_by: UUID | None = None,
    ) -> None:
        if name is not None:
            if not name or not name.strip():
                raise AssetDomainError("O nome do agendamento é obrigatório.")
            self.name = name.strip()

        if description is not None:
            self.description = description

        if scanner_profile_id is not None:
            self.scanner_profile_id = scanner_profile_id

        if target_ids is not None:
            if not target_ids:
                raise AssetDomainError("Um agendamento deve possuir pelo menos um alvo associado.")
            self.target_ids = list(set(target_ids))

        if frequency_type is not None:
            self.frequency_type = frequency_type

        if cron_expression is not None:
            self.cron_expression = cron_expression.strip() if cron_expression else None

        if tz_name is not None:
            if not tz_name or not tz_name.strip():
                raise AssetDomainError("O fuso horário é obrigatório.")
            self.timezone = tz_name

        if start_at is not None:
            self.start_at = start_at

        if overlap_policy is not None:
            self.overlap_policy = overlap_policy

        if enabled is not None:
            self.enabled = enabled

        self.updated_at = datetime.now(timezone.utc)
        if updated_by is not None:
            self.updated_by = updated_by

        self.__post_init__()
        self.calculate_next_run()
