"""
Modelos ORM SQLAlchemy para o Módulo de Ativos e Scanners (M3.4).
GovSec Shield — Infrastructure DB Models
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.core.infrastructure.db.models import Base


class AssetGroupModel(Base):
    """Modelo relacional para a tabela asset_groups."""

    __tablename__ = "asset_groups"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_asset_groups_tenant_name"),
        Index("idx_asset_groups_tenant_env", "tenant_id", "environment"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    environment: Mapped[str] = mapped_column(String(32), nullable=False)
    unit_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    location: Mapped[str | None] = mapped_column(String(128), nullable=True)
    criticality: Mapped[str] = mapped_column(String(32), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    created_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    updated_by: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)


class ScanTargetModel(Base):
    """Modelo relacional para a tabela scan_targets."""

    __tablename__ = "scan_targets"
    __table_args__ = (
        ForeignKeyConstraint(["asset_group_id"], ["asset_groups.id"], ondelete="CASCADE"),
        UniqueConstraint("tenant_id", "target_type", "target_value", name="uq_scan_targets_tenant_type_val"),
        Index("idx_scan_targets_tenant_group", "tenant_id", "asset_group_id"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    asset_group_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_value: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    authorization_reference: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    created_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    updated_by: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)


class DiscoveredAssetModel(Base):
    """Modelo relacional para a tabela discovered_assets."""

    __tablename__ = "discovered_assets"
    __table_args__ = (
        ForeignKeyConstraint(["asset_group_id"], ["asset_groups.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["scan_target_id"], ["scan_targets.id"], ondelete="SET NULL"),
        UniqueConstraint("tenant_id", "asset_group_id", "ip_address", name="uq_disc_assets_tenant_group_ip"),
        Index("idx_disc_assets_tenant_status", "tenant_id", "status"),
        Index("idx_disc_assets_tenant_ip", "tenant_id", "ip_address"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    asset_group_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    scan_target_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(256), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    operating_system: Mapped[str | None] = mapped_column(String(128), nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    manufacturer: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    criticality: Mapped[str] = mapped_column(String(32), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    zabbix_host_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class AssetServiceModel(Base):
    """Modelo relacional para a tabela asset_services."""

    __tablename__ = "asset_services"
    __table_args__ = (
        ForeignKeyConstraint(["asset_id"], ["discovered_assets.id"], ondelete="CASCADE"),
        UniqueConstraint("asset_id", "port", "protocol", name="uq_asset_services_asset_port_proto"),
        CheckConstraint("port >= 1 AND port <= 65535", name="chk_asset_services_port_range"),
        Index("idx_asset_services_tenant_port", "tenant_id", "port", "protocol"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    port: Mapped[int] = mapped_column(nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class ScannerProfileModel(Base):
    """Modelo relacional para a tabela scanner_profiles."""

    __tablename__ = "scanner_profiles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_scanner_profiles_tenant_name"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanner_type: Mapped[str] = mapped_column(String(64), nullable=False)
    discovery_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    service_detection_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    vulnerability_detection_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    port_strategy: Mapped[str] = mapped_column(String(32), nullable=False)
    custom_ports_json: Mapped[list[int]] = mapped_column(JSONB, nullable=False, default=list)
    timeout_seconds: Mapped[int] = mapped_column(nullable=False, default=30)
    max_parallelism: Mapped[int] = mapped_column(nullable=False, default=10)
    rate_limit_per_second: Mapped[int] = mapped_column(nullable=False, default=50)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    created_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)


class ScanScheduleModel(Base):
    """Modelo relacional para a tabela scan_schedules."""

    __tablename__ = "scan_schedules"
    __table_args__ = (
        ForeignKeyConstraint(["scanner_profile_id"], ["scanner_profiles.id"], ondelete="RESTRICT"),
        Index("idx_scan_schedules_tenant_enabled", "tenant_id", "enabled"),
        Index("idx_scan_schedules_next_run", "enabled", "next_run_at"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanner_profile_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    frequency_type: Mapped[str] = mapped_column(String(32), nullable=False)
    cron_expression: Mapped[str | None] = mapped_column(String(128), nullable=True)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    start_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    overlap_policy: Mapped[str] = mapped_column(String(32), nullable=False, default="skip")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    created_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    updated_by: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)


class ScanScheduleTargetModel(Base):
    """Modelo relacional para a tabela associativa scan_schedule_targets (N:N)."""

    __tablename__ = "scan_schedule_targets"
    __table_args__ = (
        ForeignKeyConstraint(["schedule_id"], ["scan_schedules.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["target_id"], ["scan_targets.id"], ondelete="CASCADE"),
    )

    schedule_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    target_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class ScanExecutionModel(Base):
    """Modelo relacional para a tabela scan_executions."""

    __tablename__ = "scan_executions"
    __table_args__ = (
        ForeignKeyConstraint(["schedule_id"], ["scan_schedules.id"], ondelete="SET NULL"),
        ForeignKeyConstraint(["scanner_profile_id"], ["scanner_profiles.id"], ondelete="RESTRICT"),
        Index("idx_scan_executions_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    schedule_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    scanner_profile_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    trigger_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    requested_by: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    targets_total: Mapped[int] = mapped_column(nullable=False, default=0)
    targets_processed: Mapped[int] = mapped_column(nullable=False, default=0)
    assets_discovered: Mapped[int] = mapped_column(nullable=False, default=0)
    services_discovered: Mapped[int] = mapped_column(nullable=False, default=0)
    vulnerabilities_discovered: Mapped[int] = mapped_column(nullable=False, default=0)
    error_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class ScanExecutionTargetModel(Base):
    """Modelo relacional para a tabela scan_execution_targets."""

    __tablename__ = "scan_execution_targets"
    __table_args__ = (
        ForeignKeyConstraint(["execution_id"], ["scan_executions.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["target_id"], ["scan_targets.id"], ondelete="CASCADE"),
        UniqueConstraint("execution_id", "target_id", name="uq_scan_exec_targets_exec_target"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    execution_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    target_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assets_discovered: Mapped[int] = mapped_column(nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class VulnerabilityFindingModel(Base):
    """Modelo relacional para a tabela vulnerability_findings."""

    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        ForeignKeyConstraint(["asset_id"], ["discovered_assets.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["asset_service_id"], ["asset_services.id"], ondelete="SET NULL"),
        ForeignKeyConstraint(["scan_execution_id"], ["scan_executions.id"], ondelete="CASCADE"),
        UniqueConstraint("tenant_id", "deduplication_hash", name="uq_vuln_findings_tenant_dedup"),
        CheckConstraint("cvss_score >= 0.0 AND cvss_score <= 10.0", name="chk_vuln_findings_cvss_range"),
        Index("idx_vuln_findings_tenant_status_sev", "tenant_id", "status", "severity"),
        Index("idx_vuln_findings_tenant_cve", "tenant_id", "cve_id"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    asset_service_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    scan_execution_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    deduplication_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class VulnerabilityHistoryModel(Base):
    """Modelo relacional para a tabela vulnerability_history."""

    __tablename__ = "vulnerability_history"
    __table_args__ = (
        ForeignKeyConstraint(["finding_id"], ["vulnerability_findings.id"], ondelete="CASCADE"),
        Index("idx_vuln_history_finding", "finding_id"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    finding_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    from_status: Mapped[str] = mapped_column(String(32), nullable=False)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class MonitoringIntegrationModel(Base):
    """Modelo relacional para a tabela monitoring_integrations."""

    __tablename__ = "monitoring_integrations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_monitoring_integrations_tenant_name"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    base_url: Mapped[str] = mapped_column(String(256), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    verify_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    credential_reference: Mapped[str] = mapped_column(String(256), nullable=False)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class MonitoringSyncExecutionModel(Base):
    """Modelo relacional para a tabela monitoring_sync_executions."""

    __tablename__ = "monitoring_sync_executions"
    __table_args__ = (
        ForeignKeyConstraint(["integration_id"], ["monitoring_integrations.id"], ondelete="CASCADE"),
        Index("idx_monitoring_sync_exec_integration", "integration_id"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    integration_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assets_processed: Mapped[int] = mapped_column(nullable=False, default=0)
    assets_created: Mapped[int] = mapped_column(nullable=False, default=0)
    assets_updated: Mapped[int] = mapped_column(nullable=False, default=0)
    errors_count: Mapped[int] = mapped_column(nullable=False, default=0)
    error_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
