"""
Entidades e Enums para Ativos Descobertos e Serviços (Asset e AssetService).
GovSec Shield — Domain Layer (M3.4)
"""

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from src.asset.domain.asset_groups import AssetCriticality
from src.asset.domain.exceptions import AssetDomainError, InvalidPortError
from src.core.domain.validation import validate_utc_datetime
from src.shared.observability.sanitizer import data_masker


class AssetStatus(StrEnum):
    """Estados operacionais de um ativo descoberto."""

    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"
    UNREACHABLE = "unreachable"
    DISABLED = "disabled"


class ServiceProtocol(StrEnum):
    """Protocolos de transporte para serviços descobertos."""

    TCP = "tcp"
    UDP = "udp"
    OTHER = "other"


class ServiceState(StrEnum):
    """Estados da porta/serviço."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


@dataclass
class Asset:
    """Representa um equipamento/host identificado em uma descoberta."""

    id: UUID
    tenant_id: UUID
    asset_group_id: UUID
    ip_address: str
    status: AssetStatus
    criticality: AssetCriticality
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    scan_target_id: UUID | None = None
    hostname: str | None = None
    mac_address: str | None = None
    operating_system: str | None = None
    device_type: str | None = None
    manufacturer: str | None = None
    last_scanned_at: datetime | None = None
    zabbix_host_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Validar IP
        try:
            ip_obj = ipaddress.ip_address(self.ip_address.strip())
            self.ip_address = str(ip_obj)
        except ValueError as e:
            raise AssetDomainError(f"Endereço IP inválido para o ativo: '{self.ip_address}'.") from e

        validate_utc_datetime(self.first_seen_at, "first_seen_at")
        validate_utc_datetime(self.last_seen_at, "last_seen_at")
        validate_utc_datetime(self.created_at, "created_at")
        validate_utc_datetime(self.updated_at, "updated_at")
        if self.last_scanned_at is not None:
            validate_utc_datetime(self.last_scanned_at, "last_scanned_at")

        # Sanitizar metadados para garantir que não armazenem credenciais
        if self.metadata:
            self.metadata = data_masker.mask_dict(self.metadata)

    @classmethod
    def create(
        cls,
        tenant_id: UUID,
        asset_group_id: UUID,
        ip_address: str,
        scan_target_id: UUID | None = None,
        hostname: str | None = None,
        mac_address: str | None = None,
        operating_system: str | None = None,
        device_type: str | None = None,
        manufacturer: str | None = None,
        status: AssetStatus = AssetStatus.ONLINE,
        criticality: AssetCriticality = AssetCriticality.MEDIUM,
        metadata: dict[str, Any] | None = None,
    ) -> "Asset":
        now = datetime.now(timezone.utc)
        return cls(
            id=uuid4(),
            tenant_id=tenant_id,
            asset_group_id=asset_group_id,
            scan_target_id=scan_target_id,
            ip_address=ip_address,
            hostname=hostname.strip() if hostname else None,
            mac_address=mac_address.strip() if mac_address else None,
            operating_system=operating_system.strip() if operating_system else None,
            device_type=device_type.strip() if device_type else None,
            manufacturer=manufacturer.strip() if manufacturer else None,
            status=status,
            criticality=criticality,
            first_seen_at=now,
            last_seen_at=now,
            last_scanned_at=None,
            zabbix_host_id=None,
            metadata=metadata or {},
            created_at=now,
            updated_at=now,
        )

    def touch_seen(self, now: datetime | None = None) -> None:
        """Atualiza a data de última visualização do ativo."""
        now_dt = now or datetime.now(timezone.utc)
        validate_utc_datetime(now_dt, "last_seen_at")
        self.last_seen_at = now_dt
        self.updated_at = now_dt


@dataclass
class AssetService:
    """Representa um serviço/porta aberto ou identificado em um ativo."""

    id: UUID
    tenant_id: UUID
    asset_id: UUID
    port: int
    protocol: ServiceProtocol
    state: ServiceState
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None

    def __post_init__(self) -> None:
        if not (1 <= self.port <= 65535):
            raise InvalidPortError(f"Número de porta inválido: {self.port}. Deve estar entre 1 e 65535.")

        validate_utc_datetime(self.first_seen_at, "first_seen_at")
        validate_utc_datetime(self.last_seen_at, "last_seen_at")
        validate_utc_datetime(self.created_at, "created_at")
        validate_utc_datetime(self.updated_at, "updated_at")

        # Sanitizar banner se houver
        if self.banner:
            self.banner = data_masker.mask_text(self.banner[:1024])

    @classmethod
    def create(
        cls,
        tenant_id: UUID,
        asset_id: UUID,
        port: int,
        protocol: ServiceProtocol = ServiceProtocol.TCP,
        state: ServiceState = ServiceState.OPEN,
        service_name: str | None = None,
        product: str | None = None,
        version: str | None = None,
        banner: str | None = None,
    ) -> "AssetService":
        now = datetime.now(timezone.utc)
        return cls(
            id=uuid4(),
            tenant_id=tenant_id,
            asset_id=asset_id,
            port=port,
            protocol=protocol,
            service_name=service_name,
            product=product,
            version=version,
            state=state,
            banner=banner,
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )

    def touch_seen(self, now: datetime | None = None) -> None:
        """Atualiza a data de última redescoberta do serviço."""
        now_dt = now or datetime.now(timezone.utc)
        validate_utc_datetime(now_dt, "last_seen_at")
        self.last_seen_at = now_dt
        self.updated_at = now_dt
