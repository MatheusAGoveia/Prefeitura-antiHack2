"""
Data Transfer Objects (DTOs) e Schemas Pydantic v2 para o Módulo de Ativos e Scanners.
GovSec Shield — Application Layer (M3.4)
"""

from datetime import datetime
from decimal import Decimal
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from src.asset.domain.asset_groups import AssetCriticality, AssetEnvironment
from src.asset.domain.discovered_assets import AssetStatus, ServiceProtocol, ServiceState
from src.asset.domain.monitoring import MonitoringProvider, SyncStatus
from src.asset.domain.scan_executions import ExecutionStatus, TriggerType
from src.asset.domain.scan_schedules import FrequencyType, OverlapPolicy
from src.asset.domain.scan_targets import TargetType
from src.asset.domain.scanner_profiles import PortStrategy, ScannerType
from src.asset.domain.vulnerabilities import VulnerabilitySeverity, VulnerabilityStatus

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Contrato de resposta paginada padrão do projeto."""

    items: list[T]
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1, le=100)
    total: int = Field(..., ge=0)
    pages: int = Field(..., ge=0)


# --- AssetGroup DTOs ---
class AssetGroupCreateDTO(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = None
    environment: AssetEnvironment = AssetEnvironment.UNKNOWN
    unit_name: str | None = None
    location: str | None = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM


class AssetGroupPatchDTO(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = None
    environment: AssetEnvironment | None = None
    unit_name: str | None = None
    location: str | None = None
    criticality: AssetCriticality | None = None
    active: bool | None = None


class AssetGroupResponseDTO(BaseModel):
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
    updated_by: UUID | None


# --- ScanTarget DTOs ---
class ScanTargetCreateDTO(BaseModel):
    asset_group_id: UUID
    name: str = Field(..., min_length=1, max_length=128)
    target_type: TargetType
    target_value: str = Field(..., min_length=1, max_length=256)
    description: str | None = None
    authorization_reference: str | None = None
    enabled: bool = True
    allow_public_targets: bool = False


class ScanTargetPatchDTO(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = None
    enabled: bool | None = None
    authorization_reference: str | None = None


class TargetValidateRequestDTO(BaseModel):
    target_type: TargetType
    target_value: str
    allow_public_targets: bool = False


class TargetValidationResponseDTO(BaseModel):
    is_valid: bool
    target_type: TargetType
    normalized_value: str
    first_ip: str | None
    last_ip: str | None
    estimated_addresses: int
    security_warnings: list[str]
    error_message: str | None = None


class ScanTargetResponseDTO(BaseModel):
    id: UUID
    tenant_id: UUID
    asset_group_id: UUID
    name: str
    target_type: TargetType
    target_value: str
    description: str | None
    enabled: bool
    authorization_reference: str | None
    last_discovered_at: datetime | None
    created_at: datetime
    updated_at: datetime
    created_by: UUID
    updated_by: UUID | None


# --- Asset & Service DTOs ---
class AssetPatchDTO(BaseModel):
    hostname: str | None = None
    criticality: AssetCriticality | None = None
    device_type: str | None = None
    operating_system: str | None = None
    manufacturer: str | None = None
    status: AssetStatus | None = None


class ServiceResponseDTO(BaseModel):
    id: UUID
    tenant_id: UUID
    asset_id: UUID
    port: int
    protocol: ServiceProtocol
    service_name: str | None
    product: str | None
    version: str | None
    state: ServiceState
    banner: str | None
    first_seen_at: datetime
    last_seen_at: datetime


class AssetResponseDTO(BaseModel):
    id: UUID
    tenant_id: UUID
    asset_group_id: UUID
    scan_target_id: UUID | None
    ip_address: str
    hostname: str | None
    mac_address: str | None
    operating_system: str | None
    device_type: str | None
    manufacturer: str | None
    status: AssetStatus
    criticality: AssetCriticality
    first_seen_at: datetime
    last_seen_at: datetime
    last_scanned_at: datetime | None
    zabbix_host_id: str | None
    metadata: dict[str, Any]
    open_services_count: int = 0
    open_vulnerabilities_count: int = 0
    max_vulnerability_severity: VulnerabilitySeverity | None = None
    created_at: datetime
    updated_at: datetime


# --- ScannerProfile DTOs ---
class ScannerProfileCreateDTO(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = None
    scanner_type: ScannerType = ScannerType.NETWORK_DISCOVERY
    discovery_enabled: bool = True
    service_detection_enabled: bool = False
    vulnerability_detection_enabled: bool = False
    port_strategy: PortStrategy = PortStrategy.COMMON
    custom_ports: list[int] = Field(default_factory=list)
    timeout_seconds: int = Field(default=30, ge=1, le=3600)
    max_parallelism: int = Field(default=10, ge=1, le=100)
    rate_limit_per_second: int = Field(default=50, ge=1, le=1000)


class ScannerProfilePatchDTO(BaseModel):
    name: str | None = None
    description: str | None = None
    scanner_type: ScannerType | None = None
    discovery_enabled: bool | None = None
    service_detection_enabled: bool | None = None
    vulnerability_detection_enabled: bool | None = None
    port_strategy: PortStrategy | None = None
    custom_ports: list[int] | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=3600)
    max_parallelism: int | None = Field(default=None, ge=1, le=100)
    rate_limit_per_second: int | None = Field(default=None, ge=1, le=1000)
    active: bool | None = None


UpdateScannerProfileDTO = ScannerProfilePatchDTO


class ScannerProfileResponseDTO(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    description: str | None
    scanner_type: ScannerType
    discovery_enabled: bool
    service_detection_enabled: bool
    vulnerability_detection_enabled: bool
    port_strategy: PortStrategy
    custom_ports: list[int]
    timeout_seconds: int
    max_parallelism: int
    rate_limit_per_second: int
    active: bool
    created_at: datetime
    updated_at: datetime
    created_by: UUID


# --- ScanSchedule DTOs ---
class ScanScheduleCreateDTO(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = None
    scanner_profile_id: UUID
    target_ids: list[UUID] = Field(..., min_length=1)
    frequency_type: FrequencyType = FrequencyType.MANUAL
    cron_expression: str | None = None
    timezone: str = "UTC"
    start_at: datetime | None = None
    overlap_policy: OverlapPolicy = OverlapPolicy.SKIP
    enabled: bool = True


class ScanSchedulePatchDTO(BaseModel):
    name: str | None = None
    description: str | None = None
    scanner_profile_id: UUID | None = None
    target_ids: list[UUID] | None = None
    frequency_type: FrequencyType | None = None
    cron_expression: str | None = None
    timezone: str | None = None
    overlap_policy: OverlapPolicy | None = None
    enabled: bool | None = None


class ScanScheduleResponseDTO(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    description: str | None
    scanner_profile_id: UUID
    frequency_type: FrequencyType
    cron_expression: str | None
    timezone: str
    start_at: datetime | None
    next_run_at: datetime | None
    last_run_at: datetime | None
    enabled: bool
    overlap_policy: OverlapPolicy
    target_ids: list[UUID]
    created_at: datetime
    updated_at: datetime
    created_by: UUID
    updated_by: UUID | None


# --- ScanExecution DTOs ---
class ScanExecutionCreateDTO(BaseModel):
    scanner_profile_id: UUID
    target_ids: list[UUID] = Field(..., min_length=1)


class ExecutionDispatchResponseDTO(BaseModel):
    """Resposta 202 Accepted para execução assíncrona enfileirada."""

    execution_id: UUID
    status: ExecutionStatus
    targets_total: int
    created_at: datetime


class ScanExecutionResponseDTO(BaseModel):
    id: UUID
    tenant_id: UUID
    schedule_id: UUID | None
    scanner_profile_id: UUID
    trigger_type: TriggerType
    status: ExecutionStatus
    started_at: datetime | None
    finished_at: datetime | None
    requested_by: UUID | None
    targets_total: int
    targets_processed: int
    assets_discovered: int
    services_discovered: int
    vulnerabilities_discovered: int
    progress_percentage: float = 0.0
    error_summary: str | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    @field_validator("progress_percentage", mode="before")
    def compute_progress(cls, v: Any, info: Any) -> float:
        total = info.data.get("targets_total", 0)
        proc = info.data.get("targets_processed", 0)
        if total > 0:
            return float(round((proc / total) * 100.0, 2))
        return 0.0


# --- Vulnerability DTOs ---
class VulnerabilityTriagePatchDTO(BaseModel):
    status: VulnerabilityStatus
    justification: str | None = None


class VulnerabilityHistoryResponseDTO(BaseModel):
    id: UUID
    tenant_id: UUID
    finding_id: UUID
    from_status: VulnerabilityStatus
    to_status: VulnerabilityStatus
    justification: str | None
    changed_by: UUID
    changed_at: datetime


class VulnerabilityResponseDTO(BaseModel):
    id: UUID
    tenant_id: UUID
    asset_id: UUID
    asset_service_id: UUID | None
    scan_execution_id: UUID
    external_id: str | None
    cve_id: str | None
    title: str
    description: str | None
    severity: VulnerabilitySeverity
    cvss_score: Decimal | None
    status: VulnerabilityStatus
    evidence: dict[str, Any]
    remediation: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime


# --- Monitoring DTOs ---
class MonitoringIntegrationCreateDTO(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    base_url: str = Field(..., min_length=1, max_length=256)
    credential_reference: str = Field(..., min_length=1, max_length=256)
    provider: MonitoringProvider = MonitoringProvider.ZABBIX
    enabled: bool = True
    verify_tls: bool = True


class MonitoringIntegrationPatchDTO(BaseModel):
    name: str | None = None
    base_url: str | None = None
    credential_reference: str | None = None
    enabled: bool | None = None
    verify_tls: bool | None = None
    active: bool | None = None


class MonitoringIntegrationResponseDTO(BaseModel):
    id: UUID
    tenant_id: UUID
    provider: MonitoringProvider
    name: str
    base_url: str
    enabled: bool
    verify_tls: bool
    credentials_configured: bool = True
    last_sync_at: datetime | None
    last_sync_status: SyncStatus | None
    created_at: datetime
    updated_at: datetime


class MonitoringTestResponseDTO(BaseModel):
    status: str
    message: str
    latency_ms: float


class MonitoringSyncExecutionResponseDTO(BaseModel):
    id: UUID
    tenant_id: UUID
    integration_id: UUID
    status: str
    started_at: datetime
    finished_at: datetime | None
    assets_processed: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    errors_count: int = 0
    error_summary: str | None = None


# --- Update DTOs para Scanner Profiles, Schedules e Targets ---
class UpdateScannerProfileDTO(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    scanner_type: ScannerType | None = None
    description: str | None = None
    discovery_enabled: bool | None = None
    service_detection_enabled: bool | None = None
    vulnerability_detection_enabled: bool | None = None
    port_strategy: PortStrategy | None = None
    custom_ports: list[int] | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=3600)
    max_parallelism: int | None = Field(default=None, ge=1, le=100)
    rate_limit_per_second: int | None = Field(default=None, ge=1, le=1000)
    active: bool | None = None


class UpdateScanScheduleDTO(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    scanner_profile_id: UUID | None = None
    target_ids: list[UUID] | None = None
    description: str | None = None
    frequency_type: FrequencyType | None = None
    cron_expression: str | None = None
    timezone: str | None = None
    start_at: datetime | None = None
    overlap_policy: OverlapPolicy | None = None
    active: bool | None = None


class UpdateScanTargetDTO(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    asset_group_id: UUID | None = None
    target_type: TargetType | None = None
    target_value: str | None = Field(default=None, min_length=1, max_length=256)
    description: str | None = None
    enabled: bool | None = None
    authorization_reference: str | None = Field(default=None, min_length=1, max_length=128)
    allow_public_targets: bool = False


# --- DTOs de Importação em Massa de Alvos ---
class TargetImportPreviewItemDTO(BaseModel):
    line_number: int
    original_text: str
    normalized_value: str
    target_type: str
    valid: bool
    duplicate: bool = False
    errors: list[str] = Field(default_factory=list)
    estimated_addresses: int = 1
    warnings: list[str] = Field(default_factory=list)


class TargetImportPreviewResponseDTO(BaseModel):
    total_received: int
    valid: int
    invalid: int
    duplicates: int
    items: list[TargetImportPreviewItemDTO]


class TargetBulkRequestDTO(BaseModel):
    asset_group_id: UUID
    authorization_reference: str = Field(..., min_length=1, max_length=128)
    raw_paste: str | None = None
    items: list[str] | None = None
    allow_public_targets: bool = False


class TargetImportResultDTO(BaseModel):
    total_received: int
    created_count: int
    skipped_duplicates: int
    invalid_count: int
    target_ids: list[UUID]
