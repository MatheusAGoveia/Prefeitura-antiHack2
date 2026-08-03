"""
Endpoints REST para Alvos de Scanner (ScanTarget).
GovSec Shield — Presentation Layer (M3.4)
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.asset.application.dto import (
    PaginatedResponse,
    ScanTargetCreateDTO,
    ScanTargetPatchDTO,
    ScanTargetResponseDTO,
    TargetValidateRequestDTO,
    TargetValidationResponseDTO,
)
from src.asset.domain.exceptions import AssetDomainError, InvalidTargetError
from src.asset.domain.scan_targets import IPTargetValidator, ScanTarget
from src.asset.infrastructure.db.repositories import PostgresAssetRepository
from src.core.infrastructure.db.unit_of_work import get_db_session
from src.core.infrastructure.security.kernel import AuthenticatedUser
from src.core.infrastructure.security.rbac import RBACManager
from src.core.interfaces.rest.dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scan-targets", tags=["Scan Targets"])


@router.post("/validate", response_model=TargetValidationResponseDTO)
async def validate_scan_target(
    payload: TargetValidateRequestDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> TargetValidationResponseDTO:
    """Valida um alvo de scanner (IP, CIDR, Intervalo, Hostname) sem salvar nem iniciar o scanner."""
    res = IPTargetValidator.validate_and_normalize(
        target_type=payload.target_type,
        target_value=payload.target_value,
        allow_public_targets=payload.allow_public_targets,
    )
    return TargetValidationResponseDTO(
        is_valid=res.is_valid,
        target_type=res.target_type,
        normalized_value=res.normalized_value,
        first_ip=res.first_ip,
        last_ip=res.last_ip,
        estimated_addresses=res.estimated_addresses,
        security_warnings=res.security_warnings,
        error_message=res.error_message,
    )


@router.post("", response_model=ScanTargetResponseDTO, status_code=status.HTTP_201_CREATED)
async def create_scan_target(
    payload: ScanTargetCreateDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ScanTargetResponseDTO:
    if not RBACManager.has_permission(current_user, "scan_targets", "POST"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)

    # Validar grupo
    group = await repo.get_group_by_id(payload.asset_group_id, current_user.tenant_id)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grupo de ativos não encontrado.")

    try:
        dom_target = ScanTarget.create(
            tenant_id=current_user.tenant_id,
            asset_group_id=payload.asset_group_id,
            name=payload.name,
            target_type=payload.target_type,
            target_value=payload.target_value,
            created_by=UUID(str(current_user.user_id)),
            description=payload.description,
            authorization_reference=payload.authorization_reference,
            enabled=payload.enabled,
            allow_public_targets=payload.allow_public_targets,
        )
        await repo.save_target(dom_target)
        await db.commit()

        return ScanTargetResponseDTO(
            id=dom_target.id,
            tenant_id=dom_target.tenant_id,
            asset_group_id=dom_target.asset_group_id,
            name=dom_target.name,
            target_type=dom_target.target_type,
            target_value=dom_target.target_value,
            description=dom_target.description,
            enabled=dom_target.enabled,
            authorization_reference=dom_target.authorization_reference,
            last_discovered_at=dom_target.last_discovered_at,
            created_at=dom_target.created_at,
            updated_at=dom_target.updated_at,
            created_by=dom_target.created_by,
            updated_by=dom_target.updated_by,
        )
    except (InvalidTargetError, AssetDomainError) as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        await db.rollback()
        logger.error("Erro inesperado ao criar alvo de scanner: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno do servidor.") from e


@router.get("", response_model=PaginatedResponse[ScanTargetResponseDTO])
async def list_scan_targets(
    asset_group_id: UUID | None = None,
    target_type: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[ScanTargetResponseDTO]:
    if not RBACManager.has_permission(current_user, "scan_targets", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)
    items, total = await repo.list_targets(
        tenant_id=current_user.tenant_id,
        asset_group_id=asset_group_id,
        target_type=target_type,
        search=search,
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

    return PaginatedResponse(
        items=dto_items,
        page=page,
        page_size=page_size,
        total=total,
        pages=pages,
    )


@router.get("/{target_id}", response_model=ScanTargetResponseDTO)
async def get_scan_target(
    target_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ScanTargetResponseDTO:
    if not RBACManager.has_permission(current_user, "scan_targets", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)
    target = await repo.get_target_by_id(target_id, current_user.tenant_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alvo de scanner não encontrado.")

    return ScanTargetResponseDTO(
        id=target.id,
        tenant_id=target.tenant_id,
        asset_group_id=target.asset_group_id,
        name=target.name,
        target_type=target.target_type,
        target_value=target.target_value,
        description=target.description,
        enabled=target.enabled,
        authorization_reference=target.authorization_reference,
        last_discovered_at=target.last_discovered_at,
        created_at=target.created_at,
        updated_at=target.updated_at,
        created_by=target.created_by,
        updated_by=target.updated_by,
    )


@router.patch("/{target_id}", response_model=ScanTargetResponseDTO)
async def patch_scan_target(
    target_id: UUID,
    payload: ScanTargetPatchDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ScanTargetResponseDTO:
    if not RBACManager.has_permission(current_user, "scan_targets", "PATCH"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)
    target = await repo.get_target_by_id(target_id, current_user.tenant_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alvo de scanner não encontrado.")

    if payload.name is not None:
        target.name = payload.name
    if payload.description is not None:
        target.description = payload.description
    if payload.enabled is not None:
        target.enabled = payload.enabled
    if payload.authorization_reference is not None:
        target.authorization_reference = payload.authorization_reference

    target.updated_by = UUID(str(current_user.user_id))

    await repo.save_target(target)
    await db.commit()

    return ScanTargetResponseDTO(
        id=target.id,
        tenant_id=target.tenant_id,
        asset_group_id=target.asset_group_id,
        name=target.name,
        target_type=target.target_type,
        target_value=target.target_value,
        description=target.description,
        enabled=target.enabled,
        authorization_reference=target.authorization_reference,
        last_discovered_at=target.last_discovered_at,
        created_at=target.created_at,
        updated_at=target.updated_at,
        created_by=target.created_by,
        updated_by=target.updated_by,
    )
