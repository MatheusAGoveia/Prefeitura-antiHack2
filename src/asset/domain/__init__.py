"""
Módulo de Domínio de Ativos e Scanners.
GovSec Shield — Domain Layer (M3.4)
"""

from src.asset.domain.asset_groups import AssetCriticality, AssetEnvironment, AssetGroup
from src.asset.domain.discovered_assets import (
    Asset,
    AssetService,
    AssetStatus,
    ServiceProtocol,
    ServiceState,
)
from src.asset.domain.exceptions import (
    AssetDomainError,
    InvalidCVSSError,
    InvalidPortError,
    InvalidStatusTransitionError,
    InvalidTargetError,
    ScheduleOverlapError,
    TargetNotFoundError,
    UnauthorizedPublicTargetError,
)
from src.asset.domain.monitoring import (
    MonitoringGateway,
    MonitoringIntegration,
    MonitoringProvider,
    MonitoringSyncExecution,
    SyncStatus,
)
from src.asset.domain.scan_executions import (
    ExecutionStatus,
    ScanExecution,
    ScanExecutionTarget,
    TriggerType,
)
from src.asset.domain.scan_schedules import (
    FrequencyType,
    OverlapPolicy,
    ScanSchedule,
    ScanScheduleTarget,
)
from src.asset.domain.scan_targets import (
    IPTargetValidator,
    ScanTarget,
    TargetType,
    TargetValidationResult,
)
from src.asset.domain.scanner_profiles import PortStrategy, ScannerProfile, ScannerType
from src.asset.domain.vulnerabilities import (
    VulnerabilityFinding,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    VulnerabilityStatusHistory,
)

__all__ = [
    "AssetGroup",
    "AssetEnvironment",
    "AssetCriticality",
    "ScanTarget",
    "TargetType",
    "IPTargetValidator",
    "TargetValidationResult",
    "Asset",
    "AssetStatus",
    "AssetService",
    "ServiceProtocol",
    "ServiceState",
    "ScannerProfile",
    "ScannerType",
    "PortStrategy",
    "ScanSchedule",
    "ScanScheduleTarget",
    "FrequencyType",
    "OverlapPolicy",
    "ScanExecution",
    "ScanExecutionTarget",
    "TriggerType",
    "ExecutionStatus",
    "VulnerabilityFinding",
    "VulnerabilitySeverity",
    "VulnerabilityStatus",
    "VulnerabilityStatusHistory",
    "MonitoringIntegration",
    "MonitoringProvider",
    "SyncStatus",
    "MonitoringSyncExecution",
    "MonitoringGateway",
    "AssetDomainError",
    "InvalidTargetError",
    "InvalidStatusTransitionError",
    "TargetNotFoundError",
    "ScheduleOverlapError",
    "UnauthorizedPublicTargetError",
    "InvalidPortError",
    "InvalidCVSSError",
]
