"""
Endpoints REST para Execuções de Scanner (ScanExecution).
GovSec Shield — Presentation Layer (M3.4)
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.asset.application.asset_service import AssetManagementService
from src.asset.application.dto import (
    ExecutionDispatchResponseDTO,
    PaginatedResponse,
    ScanExecutionCreateDTO,
    ScanExecutionResponseDTO,
    ScanTargetResponseDTO,
    VulnerabilityResponseDTO,
)
from src.asset.domain.exceptions import InvalidStatusTransitionError, TargetNotFoundError
from src.asset.domain.scan_executions import ScanExecution, TriggerType
from src.asset.infrastructure.db.repositories import PostgresAssetRepository
from src.asset.infrastructure.db.scanner_repositories import (
    PostgresMonitoringRepository,
    PostgresScanExecutionRepository,
    PostgresScannerProfileRepository,
    PostgresScanScheduleRepository,
    PostgresVulnerabilityRepository,
)
from src.core.infrastructure.db.unit_of_work import get_db_session
from src.core.infrastructure.security.kernel import AuthenticatedUser
from src.core.infrastructure.security.rbac import RBACManager
from src.core.interfaces.rest.dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scan-executions", tags=["Scan Executions"])


@router.post("", response_model=ExecutionDispatchResponseDTO, status_code=status.HTTP_202_ACCEPTED)
async def dispatch_scan_execution(
    payload: ScanExecutionCreateDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ExecutionDispatchResponseDTO:
    """Dispara manualmente a execução de um scanner retornando HTTP 202 Accepted."""
    if not RBACManager.has_permission(current_user, "scan_executions", "POST"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    service = AssetManagementService(
        asset_repo=PostgresAssetRepository(db),
        profile_repo=PostgresScannerProfileRepository(db),
        schedule_repo=PostgresScanScheduleRepository(db),
        execution_repo=PostgresScanExecutionRepository(db),
        vuln_repo=PostgresVulnerabilityRepository(db),
        monitoring_repo=PostgresMonitoringRepository(db),
    )

    try:
        execution = await service.dispatch_manual_execution(
            tenant_id=current_user.tenant_id,
            scanner_profile_id=payload.scanner_profile_id,
            target_ids=payload.target_ids,
            requested_by=UUID(str(current_user.user_id)),
        )
        await db.commit()

        return ExecutionDispatchResponseDTO(
            execution_id=execution.id,
            status=execution.status,
            targets_total=execution.targets_total,
            created_at=execution.created_at,
        )
    except TargetNotFoundError as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except Exception as e:
        await db.rollback()
        logger.error("Erro inesperado ao disparar execução de scanner: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno do servidor.") from e


@router.get("", response_model=PaginatedResponse[ScanExecutionResponseDTO])
async def list_scan_executions(
    status_filter: str | None = Query(default=None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[ScanExecutionResponseDTO]:
    if not RBACManager.has_permission(current_user, "scan_executions", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresScanExecutionRepository(db)
    items, total = await repo.list_executions(
        tenant_id=current_user.tenant_id,
        status=status_filter,
        page=page,
        page_size=page_size,
    )
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    dto_items = [
        ScanExecutionResponseDTO(
            id=e.id,
            tenant_id=e.tenant_id,
            schedule_id=e.schedule_id,
            scanner_profile_id=e.scanner_profile_id,
            trigger_type=e.trigger_type,
            status=e.status,
            started_at=e.started_at,
            finished_at=e.finished_at,
            requested_by=e.requested_by,
            targets_total=e.targets_total,
            targets_processed=e.targets_processed,
            assets_discovered=e.assets_discovered,
            services_discovered=e.services_discovered,
            vulnerabilities_discovered=e.vulnerabilities_discovered,
            error_summary=e.error_summary,
            created_at=e.created_at,
            updated_at=e.updated_at,
        )
        for e in items
    ]

    return PaginatedResponse(
        items=dto_items,
        page=page,
        page_size=page_size,
        total=total,
        pages=pages,
    )


@router.get("/{execution_id}", response_model=ScanExecutionResponseDTO)
async def get_scan_execution(
    execution_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ScanExecutionResponseDTO:
    if not RBACManager.has_permission(current_user, "scan_executions", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresScanExecutionRepository(db)
    e = await repo.get_by_id(execution_id, current_user.tenant_id)
    if not e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execução de scanner não encontrada.")

    return ScanExecutionResponseDTO(
        id=e.id,
        tenant_id=e.tenant_id,
        schedule_id=e.schedule_id,
        scanner_profile_id=e.scanner_profile_id,
        trigger_type=e.trigger_type,
        status=e.status,
        started_at=e.started_at,
        finished_at=e.finished_at,
        requested_by=e.requested_by,
        targets_total=e.targets_total,
        targets_processed=e.targets_processed,
        assets_discovered=e.assets_discovered,
        services_discovered=e.services_discovered,
        vulnerabilities_discovered=e.vulnerabilities_discovered,
        error_summary=e.error_summary,
        created_at=e.created_at,
        updated_at=e.updated_at,
    )


@router.post("/{execution_id}/cancel", response_model=ScanExecutionResponseDTO)
async def cancel_scan_execution(
    execution_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ScanExecutionResponseDTO:
    if not RBACManager.has_permission(current_user, "scan_executions", "CANCEL"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresScanExecutionRepository(db)
    e = await repo.get_by_id(execution_id, current_user.tenant_id)
    if not e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execução de scanner não encontrada.")

    try:
        e.cancel(reason=f"Cancelado pelo usuário {current_user.user_id}")
        await repo.save(e)
        await db.commit()
    except InvalidStatusTransitionError as err:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err

    return ScanExecutionResponseDTO(
        id=e.id,
        tenant_id=e.tenant_id,
        schedule_id=e.schedule_id,
        scanner_profile_id=e.scanner_profile_id,
        trigger_type=e.trigger_type,
        status=e.status,
        started_at=e.started_at,
        finished_at=e.finished_at,
        requested_by=e.requested_by,
        targets_total=e.targets_total,
        targets_processed=e.targets_processed,
        assets_discovered=e.assets_discovered,
        services_discovered=e.services_discovered,
        vulnerabilities_discovered=e.vulnerabilities_discovered,
        error_summary=e.error_summary,
        created_at=e.created_at,
        updated_at=e.updated_at,
    )


@router.post("/{execution_id}/retry", response_model=ExecutionDispatchResponseDTO, status_code=status.HTTP_202_ACCEPTED)
async def retry_scan_execution(
    execution_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ExecutionDispatchResponseDTO:
    if not RBACManager.has_permission(current_user, "scan_executions", "RETRY"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresScanExecutionRepository(db)
    old_e = await repo.get_by_id(execution_id, current_user.tenant_id)
    if not old_e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execução de scanner não encontrada.")

    # Re-enfileirar nova execução baseada no perfil anterior
    new_e = ScanExecution.create(
        tenant_id=current_user.tenant_id,
        scanner_profile_id=old_e.scanner_profile_id,
        targets_total=old_e.targets_total,
        trigger_type=TriggerType.RETRY,
        schedule_id=old_e.schedule_id,
        requested_by=UUID(str(current_user.user_id)),
    )
    await repo.save(new_e)
    await db.commit()

    return ExecutionDispatchResponseDTO(
        execution_id=new_e.id,
        status=new_e.status,
        targets_total=new_e.targets_total,
        created_at=new_e.created_at,
    )


@router.get("/{execution_id}/targets", response_model=PaginatedResponse[ScanTargetResponseDTO])
async def list_execution_targets(
    execution_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[ScanTargetResponseDTO]:
    if not RBACManager.has_permission(current_user, "scan_executions", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresScanExecutionRepository(db)
    e = await repo.get_by_id(execution_id, current_user.tenant_id)
    if not e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execução de scanner não encontrada.")

    items, total = await repo.list_execution_targets(
        execution_id=execution_id,
        tenant_id=current_user.tenant_id,
        page=page,
        page_size=page_size,
    )
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    dto_items = [
        ScanTargetResponseDTO(
            id=t.id,
            tenant_id=t.tenant_id,
            asset_group_id=t.asset_group_id,
            name=t.name,
            target_type=t.target_type,
            target_value=t.target_value,
            description=t.description,
            enabled=t.enabled,
            authorization_reference=t.authorization_reference,
            last_discovered_at=t.last_discovered_at,
            created_at=t.created_at,
            updated_at=t.updated_at,
            created_by=t.created_by,
            updated_by=t.updated_by,
        )
        for t in items
    ]

    return PaginatedResponse(items=dto_items, page=page, page_size=page_size, total=total, pages=pages)


@router.get("/{execution_id}/findings", response_model=PaginatedResponse[VulnerabilityResponseDTO])
async def list_execution_findings(
    execution_id: UUID,
    severity: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[VulnerabilityResponseDTO]:
    if not RBACManager.has_permission(current_user, "scan_executions", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresScanExecutionRepository(db)
    e = await repo.get_by_id(execution_id, current_user.tenant_id)
    if not e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execução de scanner não encontrada.")

    items, total = await repo.list_execution_findings(
        execution_id=execution_id,
        tenant_id=current_user.tenant_id,
        severity=severity,
        status=status_filter,
        page=page,
        page_size=page_size,
    )
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    dto_items = [
        VulnerabilityResponseDTO(
            id=v.id,
            tenant_id=v.tenant_id,
            asset_id=v.asset_id,
            asset_service_id=v.asset_service_id,
            scan_execution_id=v.scan_execution_id,
            external_id=v.external_id,
            cve_id=v.cve_id,
            title=v.title,
            description=v.description,
            severity=v.severity,
            cvss_score=v.cvss_score,
            status=v.status,
            evidence=v.evidence,
            remediation=v.remediation,
            first_seen_at=v.first_seen_at,
            last_seen_at=v.last_seen_at,
            resolved_at=v.resolved_at,
            created_at=v.created_at,
            updated_at=v.updated_at,
        )
        for v in items
    ]

    return PaginatedResponse(items=dto_items, page=page, page_size=page_size, total=total, pages=pages)
