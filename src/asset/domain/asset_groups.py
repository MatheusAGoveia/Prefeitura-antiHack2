"""
Entidades e Enums para Grupos de Ativos (AssetGroup).
GovSec Shield — Domain Layer (M3.4)
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from src.asset.domain.exceptions import AssetDomainError
from src.core.domain.validation import validate_utc_datetime


class AssetEnvironment(StrEnum):
    """Ambientes de homologação/operação de redes de ativos."""

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    ADMINISTRATIVE = "administrative"
    UNKNOWN = "unknown"


class AssetCriticality(StrEnum):
    """Níveis de criticidade de ativos e grupos."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AssetGroup:
    """Representa um grupo lógico de ativos (rede, prédio, secretaria, datacenter)."""

    id: UUID
    tenant_id: UUID
    name: str
    description: str | None
    environment: AssetEnvironment
    unit_name: str | None
    location: str | None
    criticality: AssetCriticality
    active: bool
    created_at: datetime
    updated_at: datetime
    created_by: UUID
    updated_by: UUID | None = None

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise AssetDomainError("O nome do grupo de ativos é obrigatório.")
        self.name = self.name.strip()
        validate_utc_datetime(self.created_at, "created_at")
        validate_utc_datetime(self.updated_at, "updated_at")

    @classmethod
    def create(
        cls,
        tenant_id: UUID,
        name: str,
        created_by: UUID,
        description: str | None = None,
        environment: AssetEnvironment = AssetEnvironment.UNKNOWN,
        unit_name: str | None = None,
        location: str | None = None,
        criticality: AssetCriticality = AssetCriticality.MEDIUM,
    ) -> "AssetGroup":
        now = datetime.now(timezone.utc)
        return cls(
            id=uuid4(),
            tenant_id=tenant_id,
            name=name,
            description=description,
            environment=environment,
            unit_name=unit_name,
            location=location,
            criticality=criticality,
            active=True,
            created_at=now,
            updated_at=now,
            created_by=created_by,
            updated_by=None,
        )

    def deactivate(self, updated_by: UUID) -> None:
        """Inativa o grupo de ativos (soft delete/inativação)."""
        self.active = False
        self.updated_by = updated_by
        self.updated_at = datetime.now(timezone.utc)
