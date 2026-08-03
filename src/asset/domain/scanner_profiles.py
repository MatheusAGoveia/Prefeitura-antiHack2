"""
Entidades e Enums para Perfis de Scanner (ScannerProfile).
GovSec Shield — Domain Layer (M3.4)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from src.asset.domain.exceptions import AssetDomainError, InvalidPortError
from src.core.domain.validation import validate_utc_datetime


class ScannerType(StrEnum):
    """Tipos de perfil de scanner defensivo."""

    NETWORK_DISCOVERY = "network_discovery"
    SERVICE_DISCOVERY = "service_discovery"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    COMBINED = "combined"


class PortStrategy(StrEnum):
    """Estratégia de seleção de portas para varredura."""

    COMMON = "common"
    TOP_100 = "top_100"
    TOP_1000 = "top_1000"
    CUSTOM = "custom"


@dataclass
class ScannerProfile:
    """Perfil que define os parâmetros e verificações defensivas autorizadas."""

    id: UUID
    tenant_id: UUID
    name: str
    description: str | None
    scanner_type: ScannerType
    discovery_enabled: bool
    service_detection_enabled: bool
    vulnerability_detection_enabled: bool
    port_strategy: PortStrategy
    timeout_seconds: int
    max_parallelism: int
    rate_limit_per_second: int
    active: bool
    created_at: datetime
    updated_at: datetime
    created_by: UUID
    custom_ports: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise AssetDomainError("O nome do perfil de scanner é obrigatório.")
        self.name = self.name.strip()

        if self.port_strategy == PortStrategy.CUSTOM:
            if not self.custom_ports:
                raise AssetDomainError("Ao utilizar a estratégia 'custom', ao menos uma porta deve ser especificada.")
            for p in self.custom_ports:
                if not (1 <= p <= 65535):
                    raise InvalidPortError(f"Porta customizada inválida no perfil: {p}.")

        if not (1 <= self.timeout_seconds <= 3600):
            raise AssetDomainError("O timeout deve estar entre 1 e 3600 segundos.")

        if not (1 <= self.max_parallelism <= 100):
            raise AssetDomainError("O paralelismo máximo deve estar entre 1 e 100.")

        if not (1 <= self.rate_limit_per_second <= 1000):
            raise AssetDomainError("A taxa de requisições deve estar entre 1 e 1000 por segundo.")

        validate_utc_datetime(self.created_at, "created_at")
        validate_utc_datetime(self.updated_at, "updated_at")

    @classmethod
    def create(
        cls,
        tenant_id: UUID,
        name: str,
        created_by: UUID,
        scanner_type: ScannerType = ScannerType.NETWORK_DISCOVERY,
        description: str | None = None,
        discovery_enabled: bool = True,
        service_detection_enabled: bool = False,
        vulnerability_detection_enabled: bool = False,
        port_strategy: PortStrategy = PortStrategy.COMMON,
        custom_ports: list[int] | None = None,
        timeout_seconds: int = 30,
        max_parallelism: int = 10,
        rate_limit_per_second: int = 50,
    ) -> "ScannerProfile":
        now = datetime.now(timezone.utc)
        return cls(
            id=uuid4(),
            tenant_id=tenant_id,
            name=name,
            description=description,
            scanner_type=scanner_type,
            discovery_enabled=discovery_enabled,
            service_detection_enabled=service_detection_enabled,
            vulnerability_detection_enabled=vulnerability_detection_enabled,
            port_strategy=port_strategy,
            custom_ports=custom_ports or [],
            timeout_seconds=timeout_seconds,
            max_parallelism=max_parallelism,
            rate_limit_per_second=rate_limit_per_second,
            active=True,
            created_at=now,
            updated_at=now,
            created_by=created_by,
        )
