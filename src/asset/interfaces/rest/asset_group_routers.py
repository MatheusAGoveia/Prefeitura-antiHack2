"""
Endpoints REST para Grupos de Ativos (AssetGroup).
GovSec Shield — Presentation Layer (M3.4)
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.asset.application.dto import (
    AssetGroupCreateDTO,
    AssetGroupPatchDTO,
    AssetGroupResponseDTO,
    PaginatedResponse,
)
from src.asset.domain.exceptions import AssetDomainError
from src.asset.infrastructure.db.repositories import PostgresAssetRepository
from src.core.infrastructure.db.unit_of_work import get_db_session
from src.core.infrastructure.security.kernel import AuthenticatedUser
from src.core.infrastructure.security.rbac import RBACManager
from src.core.interfaces.rest.dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/asset-groups", tags=["Asset Groups"])


@router.post("", response_model=AssetGroupResponseDTO, status_code=status.HTTP_201_CREATED)
async def create_asset_group(
    payload: AssetGroupCreateDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> AssetGroupResponseDTO:
    if not RBACManager.has_permission(current_user, "asset_groups", "POST"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)
    try:
        existing_groups, count = await repo.list_groups(current_user.tenant_id, search=payload.name, page_size=10)
        if count > 0:
            for g in existing_groups:
                if g.name.lower() == payload.name.strip().lower():
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"Grupo de ativos com nome '{payload.name}' já existe no tenant.",
                    )

        AssetGroupCreateDTO.model_validate(payload)
        from src.asset.domain.asset_groups import AssetGroup as DomainGroup
        dom_group = DomainGroup.create(
            tenant_id=current_user.tenant_id,
            name=payload.name,
            created_by=UUID(str(current_user.user_id)),
            description=payload.description,
            environment=payload.environment,
            unit_name=payload.unit_name,
            location=payload.location,
            criticality=payload.criticality,
        )
        await repo.save_group(dom_group)
        await db.commit()

        return AssetGroupResponseDTO(
            id=dom_group.id,
            tenant_id=dom_group.tenant_id,
            name=dom_group.name,
            description=dom_group.description,
            environment=dom_group.environment,
            unit_name=dom_group.unit_name,
            location=dom_group.location,
            criticality=dom_group.criticality,
            active=dom_group.active,
            created_at=dom_group.created_at,
            updated_at=dom_group.updated_at,
            created_by=dom_group.created_by,
            updated_by=dom_group.updated_by,
        )
    except AssetDomainError as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except HTTPException:
        await db.rollback()
        raise
    except Exception as e:
        await db.rollback()
        logger.error("Erro inesperado ao criar grupo de ativos: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno do servidor.") from e


@router.get("", response_model=PaginatedResponse[AssetGroupResponseDTO])
async def list_asset_groups(
    environment: str | None = None,
    active_only: bool = True,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[AssetGroupResponseDTO]:
    if not RBACManager.has_permission(current_user, "asset_groups", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)
    items, total = await repo.list_groups(
        tenant_id=current_user.tenant_id,
        environment=environment,
        active_only=active_only,
        search=search,
        page=page,
        page_size=page_size,
    )
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    dto_items = [
        AssetGroupResponseDTO(
            id=g.id,
            tenant_id=g.tenant_id,
            name=g.name,
            description=g.description,
            environment=g.environment,
            unit_name=g.unit_name,
            location=g.location,
            criticality=g.criticality,
            active=g.active,
            created_at=g.created_at,
            updated_at=g.updated_at,
            created_by=g.created_by,
            updated_by=g.updated_by,
        )
        for g in items
    ]

    return PaginatedResponse(
        items=dto_items,
        page=page,
        page_size=page_size,
        total=total,
        pages=pages,
    )


@router.get("/{group_id}", response_model=AssetGroupResponseDTO)
async def get_asset_group(
    group_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> AssetGroupResponseDTO:
    if not RBACManager.has_permission(current_user, "asset_groups", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)
    group = await repo.get_group_by_id(group_id, current_user.tenant_id)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grupo de ativos não encontrado.")

    return AssetGroupResponseDTO(
        id=group.id,
        tenant_id=group.tenant_id,
        name=group.name,
        description=group.description,
        environment=group.environment,
        unit_name=group.unit_name,
        location=group.location,
        criticality=group.criticality,
        active=group.active,
        created_at=group.created_at,
        updated_at=group.updated_at,
        created_by=group.created_by,
        updated_by=group.updated_by,
    )


@router.patch("/{group_id}", response_model=AssetGroupResponseDTO)
async def patch_asset_group(
    group_id: UUID,
    payload: AssetGroupPatchDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> AssetGroupResponseDTO:
    if not RBACManager.has_permission(current_user, "asset_groups", "PATCH"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)
    group = await repo.get_group_by_id(group_id, current_user.tenant_id)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grupo de ativos não encontrado.")

    if payload.name is not None:
        group.name = payload.name
    if payload.description is not None:
        group.description = payload.description
    if payload.environment is not None:
        group.environment = payload.environment
    if payload.unit_name is not None:
        group.unit_name = payload.unit_name
    if payload.location is not None:
        group.location = payload.location
    if payload.criticality is not None:
        group.criticality = payload.criticality
    if payload.active is not None:
        group.active = payload.active

    group.updated_by = UUID(str(current_user.user_id))

    try:
        await repo.save_group(group)
        await db.commit()
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    return AssetGroupResponseDTO(
        id=group.id,
        tenant_id=group.tenant_id,
        name=group.name,
        description=group.description,
        environment=group.environment,
        unit_name=group.unit_name,
        location=group.location,
        criticality=group.criticality,
        active=group.active,
        created_at=group.created_at,
        updated_at=group.updated_at,
        created_by=group.created_by,
        updated_by=group.updated_by,
    )


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset_group(
    group_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> None:
    if not RBACManager.has_permission(current_user, "asset_groups", "DELETE"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)
    group = await repo.get_group_by_id(group_id, current_user.tenant_id)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grupo de ativos não encontrado.")

    group.deactivate(updated_by=UUID(str(current_user.user_id)))
    await repo.save_group(group)
    await db.commit()
