"""
Endpoints REST para Perfis de Scanner (ScannerProfile).
GovSec Shield — Presentation Layer (M3.4)
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.asset.application.dto import (
    PaginatedResponse,
    ScannerProfileCreateDTO,
    ScannerProfileResponseDTO,
)
from src.asset.domain.exceptions import AssetDomainError
from src.asset.domain.scanner_profiles import ScannerProfile
from src.asset.infrastructure.db.scanner_repositories import PostgresScannerProfileRepository
from src.core.infrastructure.db.unit_of_work import get_db_session
from src.core.infrastructure.security.kernel import AuthenticatedUser
from src.core.infrastructure.security.rbac import RBACManager
from src.core.interfaces.rest.dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scanner-profiles", tags=["Scanner Profiles"])


@router.post("", response_model=ScannerProfileResponseDTO, status_code=status.HTTP_201_CREATED)
async def create_scanner_profile(
    payload: ScannerProfileCreateDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ScannerProfileResponseDTO:
    if not RBACManager.has_permission(current_user, "scanner_profiles", "POST"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresScannerProfileRepository(db)
    try:
        profile = ScannerProfile.create(
            tenant_id=current_user.tenant_id,
            name=payload.name,
            created_by=UUID(str(current_user.user_id)),
            scanner_type=payload.scanner_type,
            description=payload.description,
            discovery_enabled=payload.discovery_enabled,
            service_detection_enabled=payload.service_detection_enabled,
            vulnerability_detection_enabled=payload.vulnerability_detection_enabled,
            port_strategy=payload.port_strategy,
            custom_ports=payload.custom_ports,
            timeout_seconds=payload.timeout_seconds,
            max_parallelism=payload.max_parallelism,
            rate_limit_per_second=payload.rate_limit_per_second,
        )
        await repo.save(profile)
        await db.commit()

        return ScannerProfileResponseDTO(
            id=profile.id,
            tenant_id=profile.tenant_id,
            name=profile.name,
            description=profile.description,
            scanner_type=profile.scanner_type,
            discovery_enabled=profile.discovery_enabled,
            service_detection_enabled=profile.service_detection_enabled,
            vulnerability_detection_enabled=profile.vulnerability_detection_enabled,
            port_strategy=profile.port_strategy,
            custom_ports=profile.custom_ports,
            timeout_seconds=profile.timeout_seconds,
            max_parallelism=profile.max_parallelism,
            rate_limit_per_second=profile.rate_limit_per_second,
            active=profile.active,
            created_at=profile.created_at,
            updated_at=profile.updated_at,
            created_by=profile.created_by,
        )
    except AssetDomainError as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.get("", response_model=PaginatedResponse[ScannerProfileResponseDTO])
async def list_scanner_profiles(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[ScannerProfileResponseDTO]:
    if not RBACManager.has_permission(current_user, "scanner_profiles", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresScannerProfileRepository(db)
    items, total = await repo.list_profiles(current_user.tenant_id, page=page, page_size=page_size)
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    dto_items = [
        ScannerProfileResponseDTO(
            id=p.id,
            tenant_id=p.tenant_id,
            name=p.name,
            description=p.description,
            scanner_type=p.scanner_type,
            discovery_enabled=p.discovery_enabled,
            service_detection_enabled=p.service_detection_enabled,
            vulnerability_detection_enabled=p.vulnerability_detection_enabled,
            port_strategy=p.port_strategy,
            custom_ports=p.custom_ports,
            timeout_seconds=p.timeout_seconds,
            max_parallelism=p.max_parallelism,
            rate_limit_per_second=p.rate_limit_per_second,
            active=p.active,
            created_at=p.created_at,
            updated_at=p.updated_at,
            created_by=p.created_by,
        )
        for p in items
    ]

    return PaginatedResponse(
        items=dto_items,
        page=page,
        page_size=page_size,
        total=total,
        pages=pages,
    )


@router.get("/{profile_id}", response_model=ScannerProfileResponseDTO)
async def get_scanner_profile(
    profile_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> ScannerProfileResponseDTO:
    if not RBACManager.has_permission(current_user, "scanner_profiles", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresScannerProfileRepository(db)
    profile = await repo.get_by_id(profile_id, current_user.tenant_id)
    if not profile:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Perfil de scanner não encontrado.")

    return ScannerProfileResponseDTO(
        id=profile.id,
        tenant_id=profile.tenant_id,
        name=profile.name,
        description=profile.description,
        scanner_type=profile.scanner_type,
        discovery_enabled=profile.discovery_enabled,
        service_detection_enabled=profile.service_detection_enabled,
        vulnerability_detection_enabled=profile.vulnerability_detection_enabled,
        port_strategy=profile.port_strategy,
        custom_ports=profile.custom_ports,
        timeout_seconds=profile.timeout_seconds,
        max_parallelism=profile.max_parallelism,
        rate_limit_per_second=profile.rate_limit_per_second,
        active=profile.active,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
        created_by=profile.created_by,
    )
