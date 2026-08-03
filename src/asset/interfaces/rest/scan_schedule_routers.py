"""
Endpoints REST para Agendamentos de Scanner (ScanSchedule).
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
    ScanScheduleCreateDTO,
    ScanScheduleResponseDTO,
    UpdateScanScheduleDTO,
)
from src.asset.domain.exceptions import AssetDomainError
from src.asset.domain.scan_schedules import ScanSchedule
from src.asset.infrastructure.audit import record_asset_audit_log
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

router = APIRouter(prefix="/api/v1/scan-schedules", tags=["Scan Schedules"])


@router.post("", response_model=ScanScheduleResponseDTO, status_code=status.HTTP_201_CREATED)
async def create_scan_schedule(
    payload: ScanScheduleCreateDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ScanScheduleResponseDTO:
    if not RBACManager.has_permission(current_user, "scan_schedules", "POST"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    profile_repo = PostgresScannerProfileRepository(db)
    asset_repo = PostgresAssetRepository(db)
    schedule_repo = PostgresScanScheduleRepository(db)

    # Validar perfil
    profile = await profile_repo.get_by_id(payload.scanner_profile_id, current_user.tenant_id)
    if not profile or not profile.active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Perfil de scanner não encontrado ou inativo.")

    # Validar alvos
    for t_id in payload.target_ids:
        target = await asset_repo.get_target_by_id(t_id, current_user.tenant_id)
        if not target:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alvo de scanner não encontrado: {t_id}")

    try:
        schedule = ScanSchedule.create(
            tenant_id=current_user.tenant_id,
            name=payload.name,
            scanner_profile_id=payload.scanner_profile_id,
            target_ids=payload.target_ids,
            created_by=UUID(str(current_user.user_id)),
            description=payload.description,
            frequency_type=payload.frequency_type,
            cron_expression=payload.cron_expression,
            tz_name=payload.timezone,
            start_at=payload.start_at,
            overlap_policy=payload.overlap_policy,
            enabled=payload.enabled,
        )
        await schedule_repo.save(schedule)
        await record_asset_audit_log(
            db,
            current_user.tenant_id,
            current_user.user_id,
            "created",
            "scan_schedules",
            schedule.id,
            {"name": schedule.name, "frequency_type": str(schedule.frequency_type)},
        )
        await db.commit()

        return ScanScheduleResponseDTO(
            id=schedule.id,
            tenant_id=schedule.tenant_id,
            name=schedule.name,
            description=schedule.description,
            scanner_profile_id=schedule.scanner_profile_id,
            frequency_type=schedule.frequency_type,
            cron_expression=schedule.cron_expression,
            timezone=schedule.timezone,
            start_at=schedule.start_at,
            next_run_at=schedule.next_run_at,
            last_run_at=schedule.last_run_at,
            enabled=schedule.enabled,
            overlap_policy=schedule.overlap_policy,
            target_ids=schedule.target_ids,
            created_at=schedule.created_at,
            updated_at=schedule.updated_at,
            created_by=schedule.created_by,
            updated_by=schedule.updated_by,
        )
    except AssetDomainError as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.get("", response_model=PaginatedResponse[ScanScheduleResponseDTO])
async def list_scan_schedules(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[ScanScheduleResponseDTO]:
    if not RBACManager.has_permission(current_user, "scan_schedules", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    schedule_repo = PostgresScanScheduleRepository(db)
    items, total = await schedule_repo.list_schedules(current_user.tenant_id, page=page, page_size=page_size)
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    dto_items = [
        ScanScheduleResponseDTO(
            id=s.id,
            tenant_id=s.tenant_id,
            name=s.name,
            description=s.description,
            scanner_profile_id=s.scanner_profile_id,
            frequency_type=s.frequency_type,
            cron_expression=s.cron_expression,
            timezone=s.timezone,
            start_at=s.start_at,
            next_run_at=s.next_run_at,
            last_run_at=s.last_run_at,
            enabled=s.enabled,
            overlap_policy=s.overlap_policy,
            target_ids=s.target_ids,
            created_at=s.created_at,
            updated_at=s.updated_at,
            created_by=s.created_by,
            updated_by=s.updated_by,
        )
        for s in items
    ]

    return PaginatedResponse(
        items=dto_items,
        page=page,
        page_size=page_size,
        total=total,
        pages=pages,
    )


@router.get("/{schedule_id}", response_model=ScanScheduleResponseDTO)
async def get_scan_schedule(
    schedule_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ScanScheduleResponseDTO:
    if not RBACManager.has_permission(current_user, "scan_schedules", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    schedule_repo = PostgresScanScheduleRepository(db)
    s = await schedule_repo.get_by_id(schedule_id, current_user.tenant_id)
    if not s:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento não encontrado.")

    return ScanScheduleResponseDTO(
        id=s.id,
        tenant_id=s.tenant_id,
        name=s.name,
        description=s.description,
        scanner_profile_id=s.scanner_profile_id,
        frequency_type=s.frequency_type,
        cron_expression=s.cron_expression,
        timezone=s.timezone,
        start_at=s.start_at,
        next_run_at=s.next_run_at,
        last_run_at=s.last_run_at,
        enabled=s.enabled,
        overlap_policy=s.overlap_policy,
        target_ids=s.target_ids,
        created_at=s.created_at,
        updated_at=s.updated_at,
        created_by=s.created_by,
        updated_by=s.updated_by,
    )


@router.post("/{schedule_id}/enable", response_model=ScanScheduleResponseDTO)
async def enable_scan_schedule(
    schedule_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ScanScheduleResponseDTO:
    if not RBACManager.has_permission(current_user, "scan_schedules", "PATCH"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    schedule_repo = PostgresScanScheduleRepository(db)
    s = await schedule_repo.get_by_id(schedule_id, current_user.tenant_id)
    if not s:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento não encontrado.")

    s.enabled = True
    s.calculate_next_run()
    await schedule_repo.save(s)
    await db.commit()

    return ScanScheduleResponseDTO(
        id=s.id,
        tenant_id=s.tenant_id,
        name=s.name,
        description=s.description,
        scanner_profile_id=s.scanner_profile_id,
        frequency_type=s.frequency_type,
        cron_expression=s.cron_expression,
        timezone=s.timezone,
        start_at=s.start_at,
        next_run_at=s.next_run_at,
        last_run_at=s.last_run_at,
        enabled=s.enabled,
        overlap_policy=s.overlap_policy,
        target_ids=s.target_ids,
        created_at=s.created_at,
        updated_at=s.updated_at,
        created_by=s.created_by,
        updated_by=s.updated_by,
    )


@router.post("/{schedule_id}/disable", response_model=ScanScheduleResponseDTO)
async def disable_scan_schedule(
    schedule_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ScanScheduleResponseDTO:
    if not RBACManager.has_permission(current_user, "scan_schedules", "PATCH"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    schedule_repo = PostgresScanScheduleRepository(db)
    s = await schedule_repo.get_by_id(schedule_id, current_user.tenant_id)
    if not s:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento não encontrado.")

    s.enabled = False
    s.next_run_at = None
    await schedule_repo.save(s)
    await db.commit()

    return ScanScheduleResponseDTO(
        id=s.id,
        tenant_id=s.tenant_id,
        name=s.name,
        description=s.description,
        scanner_profile_id=s.scanner_profile_id,
        frequency_type=s.frequency_type,
        cron_expression=s.cron_expression,
        timezone=s.timezone,
        start_at=s.start_at,
        next_run_at=s.next_run_at,
        last_run_at=s.last_run_at,
        enabled=s.enabled,
        overlap_policy=s.overlap_policy,
        target_ids=s.target_ids,
        created_at=s.created_at,
        updated_at=s.updated_at,
        created_by=s.created_by,
        updated_by=s.updated_by,
    )


@router.post("/{schedule_id}/run", response_model=ExecutionDispatchResponseDTO, status_code=status.HTTP_202_ACCEPTED)
async def trigger_schedule_run(
    schedule_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ExecutionDispatchResponseDTO:
    """Dispara a execução imediata de um agendamento retornando HTTP 202 Accepted."""
    if not RBACManager.has_permission(current_user, "scan_executions", "EXECUTE"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    schedule_repo = PostgresScanScheduleRepository(db)
    s = await schedule_repo.get_by_id(schedule_id, current_user.tenant_id)
    if not s:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento não encontrado.")

    service = AssetManagementService(
        asset_repo=PostgresAssetRepository(db),
        profile_repo=PostgresScannerProfileRepository(db),
        schedule_repo=schedule_repo,
        execution_repo=PostgresScanExecutionRepository(db),
        vuln_repo=PostgresVulnerabilityRepository(db),
        monitoring_repo=PostgresMonitoringRepository(db),
    )

    execution = await service.dispatch_manual_execution(
        tenant_id=current_user.tenant_id,
        scanner_profile_id=s.scanner_profile_id,
        target_ids=s.target_ids,
        requested_by=UUID(str(current_user.user_id)),
    )
    await db.commit()

    return ExecutionDispatchResponseDTO(
        execution_id=execution.id,
        status=execution.status,
        targets_total=execution.targets_total,
        created_at=execution.created_at,
    )


@router.patch("/{schedule_id}", response_model=ScanScheduleResponseDTO)
async def patch_scan_schedule(
    schedule_id: UUID,
    payload: UpdateScanScheduleDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ScanScheduleResponseDTO:
    if not RBACManager.has_permission(current_user, "scan_schedules", "PATCH"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresScanScheduleRepository(db)
    s = await repo.get_by_id(schedule_id, current_user.tenant_id)
    if not s:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento não encontrado.")

    profile_repo = PostgresScannerProfileRepository(db)
    if payload.scanner_profile_id is not None:
        prof = await profile_repo.get_by_id(payload.scanner_profile_id, current_user.tenant_id)
        if not prof or not prof.active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Perfil de scanner inexistente ou inativo.",
            )

    if payload.target_ids is not None:
        asset_repo = PostgresAssetRepository(db)
        for tid in payload.target_ids:
            t = await asset_repo.get_target_by_id(tid, current_user.tenant_id)
            if not t:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Alvo de scanner '{tid}' não encontrado ou pertence a outro tenant.",
                )

    try:
        s.update(
            name=payload.name,
            description=payload.description,
            scanner_profile_id=payload.scanner_profile_id,
            target_ids=payload.target_ids,
            frequency_type=payload.frequency_type,
            cron_expression=payload.cron_expression,
            tz_name=payload.timezone,
            start_at=payload.start_at,
            overlap_policy=payload.overlap_policy,
            enabled=payload.active,
            updated_by=UUID(str(current_user.user_id)),
        )
        await repo.save(s)
        await record_asset_audit_log(
            db,
            current_user.tenant_id,
            current_user.user_id,
            "updated",
            "scan_schedules",
            s.id,
            {"name": s.name, "enabled": s.enabled, "frequency_type": str(s.frequency_type)},
        )
        await db.commit()
    except AssetDomainError as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    return ScanScheduleResponseDTO(
        id=s.id,
        tenant_id=s.tenant_id,
        name=s.name,
        description=s.description,
        scanner_profile_id=s.scanner_profile_id,
        frequency_type=s.frequency_type,
        cron_expression=s.cron_expression,
        timezone=s.timezone,
        start_at=s.start_at,
        next_run_at=s.next_run_at,
        last_run_at=s.last_run_at,
        enabled=s.enabled,
        overlap_policy=s.overlap_policy,
        created_at=s.created_at,
        updated_at=s.updated_at,
        created_by=s.created_by,
        updated_by=s.updated_by,
        target_ids=s.target_ids,
    )


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan_schedule(
    schedule_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> None:
    if not RBACManager.has_permission(current_user, "scan_schedules", "DELETE"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresScanScheduleRepository(db)
    deleted = await repo.delete_schedule(schedule_id, current_user.tenant_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento não encontrado.")
    await record_asset_audit_log(
        db,
        current_user.tenant_id,
        current_user.user_id,
        "deleted",
        "scan_schedules",
        schedule_id,
        {},
    )
    await db.commit()
