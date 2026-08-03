"""create m3_4 asset scanner management tables

Revision ID: 0008_create_m3_4_asset_scanner_management
Revises: 0007_create_m3_2_incidents
Create Date: 2026-08-03 12:00:00.000000

Tabelas criadas:
- asset_groups
- scan_targets
- discovered_assets
- asset_services
- scanner_profiles
- scan_schedules
- scan_schedule_targets
- scan_executions
- scan_execution_targets
- vulnerability_findings
- vulnerability_history
- monitoring_integrations
- monitoring_sync_executions
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_create_m3_4_asset_scanner_management"
down_revision: str | None = "0007_create_m3_2_incidents"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # 1. asset_groups
    op.create_table(
        "asset_groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("environment", sa.String(length=32), nullable=False),
        sa.Column("unit_name", sa.String(length=128), nullable=True),
        sa.Column("location", sa.String(length=128), nullable=True),
        sa.Column("criticality", sa.String(length=32), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "name", name="uq_asset_groups_tenant_name"),
    )
    op.create_index("idx_asset_groups_tenant_id", "asset_groups", ["tenant_id"])
    op.create_index("idx_asset_groups_tenant_env", "asset_groups", ["tenant_id", "environment"])

    # 2. scan_targets
    op.create_table(
        "scan_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_group_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("target_value", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("authorization_reference", sa.String(length=128), nullable=True),
        sa.Column("last_discovered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["asset_group_id"], ["asset_groups.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "target_type", "target_value", name="uq_scan_targets_tenant_type_val"),
    )
    op.create_index("idx_scan_targets_tenant_id", "scan_targets", ["tenant_id"])
    op.create_index("idx_scan_targets_tenant_group", "scan_targets", ["tenant_id", "asset_group_id"])

    # 3. discovered_assets
    op.create_table(
        "discovered_assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_group_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=False),
        sa.Column("hostname", sa.String(length=256), nullable=True),
        sa.Column("mac_address", sa.String(length=64), nullable=True),
        sa.Column("operating_system", sa.String(length=128), nullable=True),
        sa.Column("device_type", sa.String(length=64), nullable=True),
        sa.Column("manufacturer", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("criticality", sa.String(length=32), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("zabbix_host_id", sa.String(length=128), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_group_id"], ["asset_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_target_id"], ["scan_targets.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("tenant_id", "asset_group_id", "ip_address", name="uq_disc_assets_tenant_group_ip"),
    )
    op.create_index("idx_disc_assets_tenant_id", "discovered_assets", ["tenant_id"])
    op.create_index("idx_disc_assets_tenant_status", "discovered_assets", ["tenant_id", "status"])
    op.create_index("idx_disc_assets_tenant_ip", "discovered_assets", ["tenant_id", "ip_address"])

    # 4. asset_services
    op.create_table(
        "asset_services",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("service_name", sa.String(length=128), nullable=True),
        sa.Column("product", sa.String(length=128), nullable=True),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["discovered_assets.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("asset_id", "port", "protocol", name="uq_asset_services_asset_port_proto"),
        sa.CheckConstraint("port >= 1 AND port <= 65535", name="chk_asset_services_port_range"),
    )
    op.create_index("idx_asset_services_tenant_id", "asset_services", ["tenant_id"])
    op.create_index("idx_asset_services_tenant_port", "asset_services", ["tenant_id", "port", "protocol"])

    # 5. scanner_profiles
    op.create_table(
        "scanner_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("scanner_type", sa.String(length=64), nullable=False),
        sa.Column("discovery_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("service_detection_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("vulnerability_detection_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("port_strategy", sa.String(length=32), nullable=False),
        sa.Column("custom_ports_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default=sa.text("30")),
        sa.Column("max_parallelism", sa.Integer(), nullable=False, server_default=sa.text("10")),
        sa.Column("rate_limit_per_second", sa.Integer(), nullable=False, server_default=sa.text("50")),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_scanner_profiles_tenant_name"),
    )
    op.create_index("idx_scanner_profiles_tenant_id", "scanner_profiles", ["tenant_id"])

    # 6. scan_schedules
    op.create_table(
        "scan_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("scanner_profile_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("frequency_type", sa.String(length=32), nullable=False),
        sa.Column("cron_expression", sa.String(length=128), nullable=True),
        sa.Column("timezone", sa.String(length=64), nullable=False, server_default=sa.text("'UTC'")),
        sa.Column("start_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("overlap_policy", sa.String(length=32), nullable=False, server_default=sa.text("'skip'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["scanner_profile_id"], ["scanner_profiles.id"], ondelete="RESTRICT"),
    )
    op.create_index("idx_scan_schedules_tenant_id", "scan_schedules", ["tenant_id"])
    op.create_index("idx_scan_schedules_tenant_enabled", "scan_schedules", ["tenant_id", "enabled"])
    op.create_index("idx_scan_schedules_next_run", "scan_schedules", ["enabled", "next_run_at"])

    # 7. scan_schedule_targets
    op.create_table(
        "scan_schedule_targets",
        sa.Column("schedule_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["schedule_id"], ["scan_schedules.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["scan_targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("schedule_id", "target_id"),
    )

    # 8. scan_executions
    op.create_table(
        "scan_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("schedule_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scanner_profile_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("trigger_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("targets_total", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("targets_processed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("assets_discovered", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("services_discovered", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("vulnerabilities_discovered", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["schedule_id"], ["scan_schedules.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scanner_profile_id"], ["scanner_profiles.id"], ondelete="RESTRICT"),
    )
    op.create_index("idx_scan_executions_tenant_id", "scan_executions", ["tenant_id"])
    op.create_index("idx_scan_executions_tenant_status", "scan_executions", ["tenant_id", "status"])

    # 9. scan_execution_targets
    op.create_table(
        "scan_execution_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assets_discovered", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["execution_id"], ["scan_executions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["scan_targets.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("execution_id", "target_id", name="uq_scan_exec_targets_exec_target"),
    )
    op.create_index("idx_scan_exec_targets_tenant_id", "scan_execution_targets", ["tenant_id"])

    # 10. vulnerability_findings
    op.create_table(
        "vulnerability_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_service_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scan_execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("external_id", sa.String(length=128), nullable=True),
        sa.Column("cve_id", sa.String(length=32), nullable=True),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("cvss_score", sa.Numeric(precision=3, scale=1), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("evidence_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("deduplication_hash", sa.String(length=64), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["discovered_assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_service_id"], ["asset_services.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_execution_id"], ["scan_executions.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "deduplication_hash", name="uq_vuln_findings_tenant_dedup"),
        sa.CheckConstraint("cvss_score >= 0.0 AND cvss_score <= 10.0", name="chk_vuln_findings_cvss_range"),
    )
    op.create_index("idx_vuln_findings_tenant_id", "vulnerability_findings", ["tenant_id"])
    op.create_index("idx_vuln_findings_tenant_status_sev", "vulnerability_findings", ["tenant_id", "status", "severity"])
    op.create_index("idx_vuln_findings_tenant_cve", "vulnerability_findings", ["tenant_id", "cve_id"])

    # 11. vulnerability_history
    op.create_table(
        "vulnerability_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("from_status", sa.String(length=32), nullable=False),
        sa.Column("to_status", sa.String(length=32), nullable=False),
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column("changed_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["vulnerability_findings.id"], ondelete="CASCADE"),
    )
    op.create_index("idx_vuln_history_tenant_id", "vulnerability_history", ["tenant_id"])
    op.create_index("idx_vuln_history_finding", "vulnerability_history", ["finding_id"])

    # 12. monitoring_integrations
    op.create_table(
        "monitoring_integrations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("base_url", sa.String(length=256), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("credential_reference", sa.String(length=256), nullable=False),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_status", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_monitoring_integrations_tenant_name"),
    )
    op.create_index("idx_monitoring_integrations_tenant_id", "monitoring_integrations", ["tenant_id"])

    # 13. monitoring_sync_executions
    op.create_table(
        "monitoring_sync_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("integration_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assets_processed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("assets_created", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("assets_updated", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("errors_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["integration_id"], ["monitoring_integrations.id"], ondelete="CASCADE"),
    )
    op.create_index("idx_monitoring_sync_exec_tenant_id", "monitoring_sync_executions", ["tenant_id"])
    op.create_index("idx_monitoring_sync_exec_integration", "monitoring_sync_executions", ["integration_id"])


def downgrade() -> None:
    op.drop_table("monitoring_sync_executions")
    op.drop_table("monitoring_integrations")
    op.drop_table("vulnerability_history")
    op.drop_table("vulnerability_findings")
    op.drop_table("scan_execution_targets")
    op.drop_table("scan_executions")
    op.drop_table("scan_schedule_targets")
    op.drop_table("scan_schedules")
    op.drop_table("scanner_profiles")
    op.drop_table("asset_services")
    op.drop_table("discovered_assets")
    op.drop_table("scan_targets")
    op.drop_table("asset_groups")
