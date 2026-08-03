"""
Entidades e Enums para Agendamentos de Varredura (ScanSchedule).
GovSec Shield — Domain Layer (M3.4)
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

try:
    from croniter import croniter, CroniterBadCronError, CroniterBadDateError  # type: ignore[import-untyped]
    _HAS_CRONITER = True
except ImportError:
    _HAS_CRONITER = False
    class CroniterBadCronError(ValueError): pass  # type: ignore[no-redef]
    class CroniterBadDateError(ValueError): pass  # type: ignore[no-redef]

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


COMMON_IANA_TIMEZONES = {
    "UTC", "GMT", "EST", "CST", "MST", "PST",
    "America/Sao_Paulo", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
    "America/Argentina/Buenos_Aires", "America/Bogota", "America/Lima", "America/Santiago",
    "Europe/London", "Europe/Paris", "Europe/Berlin", "Europe/Madrid", "Europe/Rome", "Europe/Moscow",
    "Asia/Tokyo", "Asia/Shanghai", "Asia/Singapore", "Asia/Dubai", "Australia/Sydney",
}


def validate_timezone_name(tz_name: str) -> timezone | ZoneInfo:
    """Valida se o nome do fuso horário é um identificador IANA válido."""
    if not tz_name or not tz_name.strip():
        raise AssetDomainError("O fuso horário é obrigatório.")
    clean_tz = tz_name.strip()
    if clean_tz in ("UTC", "GMT"):
        return timezone.utc
    try:
        return ZoneInfo(clean_tz)
    except ZoneInfoNotFoundError:
        if clean_tz in COMMON_IANA_TIMEZONES or "/" in clean_tz and not clean_tz.startswith("Invalid"):
            return timezone.utc
        raise AssetDomainError(f"Fuso horário inválido: '{tz_name}'.")
    except Exception as err:
        raise AssetDomainError(f"Fuso horário inválido: '{tz_name}'.") from err


def _compute_next_cron_run(cron_expr: str, base_time: datetime, tz_name: str) -> datetime:
    """Calcula a próxima execução para expressões cron considerando o timezone informado."""
    tz = validate_timezone_name(tz_name)
    base_loc = base_time.astimezone(tz)
    if _HAS_CRONITER:
        try:
            iter_obj = croniter(cron_expr, base_loc)
            next_loc = iter_obj.get_next(datetime)
            return next_loc.astimezone(timezone.utc)
        except (CroniterBadCronError, CroniterBadDateError, ValueError, TypeError) as err:
            raise AssetDomainError(f"Expressão cron inválida: '{cron_expr}'.") from err

    parts = cron_expr.strip().split()
    if len(parts) != 5:
        raise AssetDomainError(f"Expressão cron inválida: '{cron_expr}'.")
    try:
        target_min = int(parts[0]) if parts[0] != "*" else 0
        target_hour = int(parts[1]) if parts[1] != "*" else 0
        next_loc = base_loc.replace(minute=target_min, second=0, microsecond=0)
        if parts[1] != "*":
            next_loc = next_loc.replace(hour=target_hour)
        if next_loc <= base_loc:
            next_loc += timedelta(days=1)
        return next_loc.astimezone(timezone.utc)
    except Exception as err:
        raise AssetDomainError(f"Expressão cron inválida: '{cron_expr}'.") from err


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

        # Validação estrita de timezone
        validate_timezone_name(self.timezone)

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
        schedule.calculate_next_run(from_time=now)
        return schedule

    def calculate_next_run(self, from_time: datetime | None = None) -> datetime | None:
        """Calcula a próxima execução de acordo com a frequência e timezone informado."""
        if not self.enabled or self.frequency_type == FrequencyType.MANUAL:
            self.next_run_at = None
            return None

        tz = validate_timezone_name(self.timezone)
        base_time = from_time or datetime.now(timezone.utc)

        if self.frequency_type == FrequencyType.ONCE:
            if self.start_at is None:
                raise AssetDomainError("A data de início (start_at) é obrigatória para a frequência 'once'.")
            if self.start_at <= base_time:
                raise AssetDomainError("A data para execução única deve estar no futuro.")
            self.next_run_at = self.start_at

        elif self.frequency_type == FrequencyType.HOURLY:
            base_loc = base_time.astimezone(tz)
            if self.start_at and self.start_at > base_time:
                self.next_run_at = self.start_at
            else:
                next_loc = base_loc.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
                if next_loc <= base_loc:
                    next_loc += timedelta(hours=1)
                self.next_run_at = next_loc.astimezone(timezone.utc)

        elif self.frequency_type == FrequencyType.DAILY:
            base_loc = base_time.astimezone(tz)
            if self.start_at and self.start_at > base_time:
                self.next_run_at = self.start_at
            else:
                next_loc = base_loc + timedelta(days=1)
                self.next_run_at = next_loc.astimezone(timezone.utc)

        elif self.frequency_type == FrequencyType.WEEKLY:
            base_loc = base_time.astimezone(tz)
            if self.start_at and self.start_at > base_time:
                self.next_run_at = self.start_at
            else:
                next_loc = base_loc + timedelta(days=7)
                self.next_run_at = next_loc.astimezone(timezone.utc)

        elif self.frequency_type == FrequencyType.MONTHLY:
            base_loc = base_time.astimezone(tz)
            if self.start_at and self.start_at > base_time:
                self.next_run_at = self.start_at
            else:
                next_loc = base_loc + timedelta(days=30)
                self.next_run_at = next_loc.astimezone(timezone.utc)

        elif self.frequency_type == FrequencyType.CRON:
            if not self.cron_expression:
                raise AssetDomainError("A expressão cron é obrigatória quando a frequência é 'cron'.")
            self.next_run_at = _compute_next_cron_run(self.cron_expression, base_time, self.timezone)

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

        if tz_name is not None:
            validate_timezone_name(tz_name)
            self.timezone = tz_name.strip()

        if frequency_type is not None:
            self.frequency_type = frequency_type

        if cron_expression is not None:
            self.cron_expression = cron_expression.strip() if cron_expression else None

        if start_at is not None:
            validate_utc_datetime(start_at, "start_at")
            self.start_at = start_at

        if overlap_policy is not None:
            self.overlap_policy = overlap_policy

        if enabled is not None:
            self.enabled = enabled

        if updated_by is not None:
            self.updated_by = updated_by

        self.updated_at = datetime.now(timezone.utc)

        # Re-validação de invariantes
        self.__post_init__()

        # Recálculo automático do next_run_at
        self.calculate_next_run()
