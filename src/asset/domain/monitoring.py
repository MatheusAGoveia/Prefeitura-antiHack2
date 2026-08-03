"""
Abstrações, Contratos e Entidades para Integrações de Monitoramento (Zabbix).
GovSec Shield — Domain Layer (M3.4)
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID, uuid4

from src.asset.domain.discovered_assets import Asset
from src.asset.domain.exceptions import AssetDomainError
from src.asset.domain.vulnerabilities import VulnerabilityFinding
from src.core.domain.validation import validate_utc_datetime


class MonitoringProvider(StrEnum):
    """Provedores de monitoramento suportados."""

    ZABBIX = "zabbix"


class SyncStatus(StrEnum):
    """Estados de execução da sincronização com o monitoramento."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class MonitoringIntegration:
    """Configuração de integração com ferramenta externa de monitoramento (ex: Zabbix)."""

    id: UUID
    tenant_id: UUID
    provider: MonitoringProvider
    name: str
    base_url: str
    enabled: bool
    verify_tls: bool
    credential_reference: str
    created_at: datetime
    updated_at: datetime
    last_sync_at: datetime | None = None
    last_sync_status: SyncStatus | None = None

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise AssetDomainError("O nome da integração de monitoramento é obrigatório.")
        self.name = self.name.strip()

        if not self.base_url or not (self.base_url.startswith("http://") or self.base_url.startswith("https://")):
            raise AssetDomainError("A URL base da integração deve iniciar com 'http://' ou 'https://'.")

        if not self.credential_reference or not self.credential_reference.strip():
            raise AssetDomainError("A referência de credencial (credential_reference) é obrigatória.")

        validate_utc_datetime(self.created_at, "created_at")
        validate_utc_datetime(self.updated_at, "updated_at")
        if self.last_sync_at is not None:
            validate_utc_datetime(self.last_sync_at, "last_sync_at")

    @classmethod
    def create(
        cls,
        tenant_id: UUID,
        name: str,
        base_url: str,
        credential_reference: str,
        provider: MonitoringProvider = MonitoringProvider.ZABBIX,
        enabled: bool = True,
        verify_tls: bool = True,
    ) -> "MonitoringIntegration":
        now = datetime.now(timezone.utc)
        return cls(
            id=uuid4(),
            tenant_id=tenant_id,
            provider=provider,
            name=name,
            base_url=base_url.strip(),
            enabled=enabled,
            verify_tls=verify_tls,
            credential_reference=credential_reference.strip(),
            last_sync_at=None,
            last_sync_status=None,
            created_at=now,
            updated_at=now,
        )

    def update_configuration(
        self,
        name: str | None = None,
        base_url: str | None = None,
        credential_reference: str | None = None,
        enabled: bool | None = None,
        verify_tls: bool | None = None,
    ) -> None:
        if name is not None:
            if not name.strip():
                raise AssetDomainError("O nome da integração de monitoramento não pode ser vazio.")
            self.name = name.strip()
        if base_url is not None:
            if not (base_url.startswith("http://") or base_url.startswith("https://")):
                raise AssetDomainError("A URL base da integração deve iniciar com 'http://' ou 'https://'.")
            self.base_url = base_url.strip()
        if credential_reference is not None:
            if not credential_reference.strip():
                raise AssetDomainError("A referência de credencial não pode ser vazia.")
            self.credential_reference = credential_reference.strip()
        if enabled is not None:
            self.enabled = enabled
        if verify_tls is not None:
            self.verify_tls = verify_tls
        self.updated_at = datetime.now(timezone.utc)

    update = update_configuration


@dataclass
class MonitoringSyncExecution:
    """Histórico de execuções de sincronização com o monitoramento."""

    id: UUID
    tenant_id: UUID
    integration_id: UUID
    status: SyncStatus
    started_at: datetime
    finished_at: datetime | None
    assets_processed: int
    assets_created: int
    assets_updated: int
    errors_count: int
    error_summary: str | None

    def __post_init__(self) -> None:
        validate_utc_datetime(self.started_at, "started_at")
        if self.finished_at is not None:
            validate_utc_datetime(self.finished_at, "finished_at")


class MonitoringGateway(Protocol):
    """Interface / Protocolo de Domínio para Integração com Monitoramento Externo (Zabbix)."""

    async def find_host_by_ip(self, ip_address: str, tenant_id: UUID) -> dict[str, Any] | None:
        """Consulta se um ativo existe na plataforma de monitoramento pelo IP."""
        ...

    async def register_or_update_asset(self, asset: Asset, tenant_id: UUID) -> str:
        """Registra ou atualiza um ativo na plataforma e retorna o ID do host externo (zabbix_host_id)."""
        ...

    async def update_vulnerability_status(
        self, finding: VulnerabilityFinding, tenant_id: UUID
    ) -> bool:
        """Sincroniza a alteração de status de uma vulnerabilidade no monitoramento."""
        ...
