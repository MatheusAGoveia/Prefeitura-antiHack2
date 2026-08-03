"""
Serviços de Aplicação e Casos de Uso para Gestão de Ativos, Scanners e Vulnerabilidades (M3.4).
GovSec Shield — Application Layer
"""

import logging
from typing import Any
from uuid import UUID

from src.asset.domain.asset_groups import AssetGroup
from src.asset.domain.exceptions import TargetNotFoundError
from src.asset.domain.scan_executions import ScanExecution, TriggerType
from src.asset.domain.scan_targets import ScanTarget
from src.asset.domain.vulnerabilities import VulnerabilityStatus
from src.asset.infrastructure.db.repositories import PostgresAssetRepository
from src.asset.infrastructure.db.scanner_repositories import (
    PostgresMonitoringRepository,
    PostgresScanExecutionRepository,
    PostgresScannerProfileRepository,
    PostgresScanScheduleRepository,
    PostgresVulnerabilityRepository,
)
from src.shared.observability.metrics import (
    GOVSEC_SCAN_EXECUTIONS_TOTAL,
    GOVSEC_SCAN_TARGETS_TOTAL,
)

logger = logging.getLogger(__name__)


class AssetManagementService:
    """Serviço de aplicação unificado para ativos, scanners, execuções e vulnerabilidades."""

    def __init__(
        self,
        asset_repo: PostgresAssetRepository,
        profile_repo: PostgresScannerProfileRepository,
        schedule_repo: PostgresScanScheduleRepository,
        execution_repo: PostgresScanExecutionRepository,
        vuln_repo: PostgresVulnerabilityRepository,
        monitoring_repo: PostgresMonitoringRepository,
    ) -> None:
        self._asset_repo = asset_repo
        self._profile_repo = profile_repo
        self._schedule_repo = schedule_repo
        self._execution_repo = execution_repo
        self._vuln_repo = vuln_repo
        self._monitoring_repo = monitoring_repo

    # --- Asset Group Use Cases ---
    async def create_asset_group(
        self,
        tenant_id: UUID,
        name: str,
        created_by: UUID,
        description: str | None = None,
        environment: Any = "unknown",
        unit_name: str | None = None,
        location: str | None = None,
        criticality: Any = "medium",
    ) -> AssetGroup:
        group = AssetGroup.create(
            tenant_id=tenant_id,
            name=name,
            created_by=created_by,
            description=description,
            environment=environment,
            unit_name=unit_name,
            location=location,
            criticality=criticality,
        )
        await self._asset_repo.save_group(group)
        logger.info("Grupo de Ativos criado com sucesso: id=%s tenant_id=%s", group.id, tenant_id)
        return group

    # --- Scan Target Use Cases ---
    async def create_scan_target(
        self,
        tenant_id: UUID,
        asset_group_id: UUID,
        name: str,
        target_type: Any,
        target_value: str,
        created_by: UUID,
        description: str | None = None,
        authorization_reference: str | None = None,
        enabled: bool = True,
        allow_public_targets: bool = False,
    ) -> ScanTarget:
        # Verificar existência do grupo
        group = await self._asset_repo.get_group_by_id(asset_group_id, tenant_id)
        if not group:
            raise TargetNotFoundError(f"Grupo de ativos não encontrado: {asset_group_id}")

        target = ScanTarget.create(
            tenant_id=tenant_id,
            asset_group_id=asset_group_id,
            name=name,
            target_type=target_type,
            target_value=target_value,
            created_by=created_by,
            description=description,
            authorization_reference=authorization_reference,
            enabled=enabled,
            allow_public_targets=allow_public_targets,
        )
        await self._asset_repo.save_target(target)
        GOVSEC_SCAN_TARGETS_TOTAL.labels(type=str(target.target_type), enabled=str(target.enabled)).inc()
        logger.info("Alvo de Scanner criado com sucesso: id=%s tenant_id=%s", target.id, tenant_id)
        return target

    # --- Scanner Execution Use Cases ---
    async def dispatch_manual_execution(
        self,
        tenant_id: UUID,
        scanner_profile_id: UUID,
        target_ids: list[UUID],
        requested_by: UUID,
    ) -> ScanExecution:
        profile = await self._profile_repo.get_by_id(scanner_profile_id, tenant_id)
        if not profile or not profile.active:
            raise TargetNotFoundError(f"Perfil de scanner ativo não encontrado: {scanner_profile_id}")

        # Validar pertencimento de alvos ao tenant
        for t_id in target_ids:
            target = await self._asset_repo.get_target_by_id(t_id, tenant_id)
            if not target:
                raise TargetNotFoundError(f"Alvo de scanner não encontrado no tenant: {t_id}")

        execution = ScanExecution.create(
            tenant_id=tenant_id,
            scanner_profile_id=scanner_profile_id,
            targets_total=len(target_ids),
            trigger_type=TriggerType.MANUAL,
            requested_by=requested_by,
        )
        await self._execution_repo.save(execution)
        GOVSEC_SCAN_EXECUTIONS_TOTAL.labels(status="queued", trigger_type="manual").inc()
        logger.info(
            "Execução de scanner enfileirada com sucesso (202 Accepted): id=%s tenant_id=%s targets=%d",
            execution.id,
            tenant_id,
            execution.targets_total,
        )
        return execution

    # --- Vulnerability Triage Use Cases ---
    async def triage_vulnerability(
        self,
        finding_id: UUID,
        tenant_id: UUID,
        new_status: VulnerabilityStatus,
        changed_by: UUID,
        justification: str | None = None,
    ) -> tuple[Any, Any]:
        finding = await self._vuln_repo.get_by_id(finding_id, tenant_id)
        if not finding:
            raise TargetNotFoundError(f"Vulnerabilidade não encontrada: {finding_id}")

        history = finding.change_status(new_status, changed_by=changed_by, justification=justification)
        await self._vuln_repo.save(finding)
        logger.info(
            "Triagem de vulnerabilidade realizada: finding_id=%s to_status=%s changed_by=%s",
            finding_id,
            new_status,
            changed_by,
        )
        return finding, history

    # --- Bulk Import Use Cases ---
    async def preview_import_targets(
        self,
        tenant_id: UUID,
        asset_group_id: UUID,
        filename: str | None = None,
        content: bytes | None = None,
        raw_paste: str | None = None,
        items_list: list[str] | None = None,
        allow_public_targets: bool = False,
    ) -> Any:
        from src.asset.application.target_importer import TargetBulkImporter

        group = await self._asset_repo.get_group_by_id(asset_group_id, tenant_id)
        if not group:
            raise TargetNotFoundError(f"Grupo de ativos não encontrado: {asset_group_id}")

        lines = TargetBulkImporter.parse_raw_content(
            filename=filename, content=content, raw_paste=raw_paste, items_list=items_list
        )
        existing_target_values = await self._asset_repo.get_existing_target_values(tenant_id, asset_group_id)

        return TargetBulkImporter.generate_preview(
            raw_lines=lines,
            existing_target_values=existing_target_values,
            allow_public_targets=allow_public_targets,
        )

    async def import_targets_bulk(
        self,
        tenant_id: UUID,
        asset_group_id: UUID,
        authorization_reference: str,
        created_by: UUID,
        filename: str | None = None,
        content: bytes | None = None,
        raw_paste: str | None = None,
        items_list: list[str] | None = None,
        allow_public_targets: bool = False,
    ) -> Any:
        from src.asset.application.dto import TargetImportResultDTO
        from src.asset.domain.scan_targets import TargetType

        preview = await self.preview_import_targets(
            tenant_id=tenant_id,
            asset_group_id=asset_group_id,
            filename=filename,
            content=content,
            raw_paste=raw_paste,
            items_list=items_list,
            allow_public_targets=allow_public_targets,
        )

        created_ids: list[UUID] = []
        for item in preview.items:
            if item.valid:
                target = ScanTarget.create(
                    tenant_id=tenant_id,
                    asset_group_id=asset_group_id,
                    name=f"Alvo {item.normalized_value}",
                    target_type=TargetType(item.target_type),
                    target_value=item.normalized_value,
                    created_by=created_by,
                    authorization_reference=authorization_reference,
                    allow_public_targets=allow_public_targets,
                )
                await self._asset_repo.save_target(target)
                created_ids.append(target.id)

        if created_ids:
            GOVSEC_SCAN_TARGETS_TOTAL.labels(type="bulk_import", enabled="true").inc(len(created_ids))

        logger.info(
            "Importação em massa de alvos realizada: tenant_id=%s group_id=%s criados=%d duplicados=%d invalidos=%d",
            tenant_id,
            asset_group_id,
            len(created_ids),
            preview.duplicates,
            preview.invalid,
        )

        return TargetImportResultDTO(
            total_received=preview.total_received,
            created_count=len(created_ids),
            skipped_duplicates=preview.duplicates,
            invalid_count=preview.invalid,
            target_ids=created_ids,
        )
