"""
Módulo de Infraestrutura de Ativos e Scanners.
GovSec Shield — Infrastructure Layer (M3.4)
"""

from src.asset.infrastructure.adapters.fake_monitoring_adapter import FakeMonitoringGateway
from src.asset.infrastructure.db.models import (
    AssetGroupModel,
    AssetServiceModel,
    DiscoveredAssetModel,
    MonitoringIntegrationModel,
    MonitoringSyncExecutionModel,
    ScanExecutionModel,
    ScanExecutionTargetModel,
    ScannerProfileModel,
    ScanScheduleModel,
    ScanScheduleTargetModel,
    ScanTargetModel,
    VulnerabilityFindingModel,
    VulnerabilityHistoryModel,
)
from src.asset.infrastructure.db.repositories import PostgresAssetRepository
from src.asset.infrastructure.db.scanner_repositories import (
    PostgresMonitoringRepository,
    PostgresScanExecutionRepository,
    PostgresScannerProfileRepository,
    PostgresScanScheduleRepository,
    PostgresVulnerabilityRepository,
)

__all__ = [
    "AssetGroupModel",
    "ScanTargetModel",
    "DiscoveredAssetModel",
    "AssetServiceModel",
    "ScannerProfileModel",
    "ScanScheduleModel",
    "ScanScheduleTargetModel",
    "ScanExecutionModel",
    "ScanExecutionTargetModel",
    "VulnerabilityFindingModel",
    "VulnerabilityHistoryModel",
    "MonitoringIntegrationModel",
    "MonitoringSyncExecutionModel",
    "PostgresAssetRepository",
    "PostgresScannerProfileRepository",
    "PostgresScanScheduleRepository",
    "PostgresScanExecutionRepository",
    "PostgresVulnerabilityRepository",
    "PostgresMonitoringRepository",
    "FakeMonitoringGateway",
]
