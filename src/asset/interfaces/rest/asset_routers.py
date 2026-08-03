"""
Endpoints REST para Ativos Descobertos e Serviços (Asset e AssetService).
GovSec Shield — Presentation Layer (M3.4)
"""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.asset.application.dto import (
    AssetPatchDTO,
    AssetResponseDTO,
    PaginatedResponse,
    ServiceResponseDTO,
    VulnerabilityResponseDTO,
)
from src.asset.infrastructure.db.repositories import PostgresAssetRepository
from src.asset.infrastructure.db.scanner_repositories import (
    PostgresVulnerabilityRepository,
)
from src.core.infrastructure.db.unit_of_work import get_db_session
from src.core.infrastructure.security.kernel import AuthenticatedUser
from src.core.infrastructure.security.rbac import RBACManager
from src.core.interfaces.rest.dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/assets", tags=["Discovered Assets"])


@router.get("", response_model=PaginatedResponse[AssetResponseDTO])
async def list_assets(
    asset_group_id: UUID | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[AssetResponseDTO]:
    if not RBACManager.has_permission(current_user, "assets", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)
    items, total = await repo.list_assets(
        tenant_id=current_user.tenant_id,
        asset_group_id=asset_group_id,
        status=status_filter,
        search=search,
        page=page,
        page_size=page_size,
    )
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    dto_items = []
    for a in items:
        services = await repo.list_services(a.id, current_user.tenant_id)
        dto_items.append(
            AssetResponseDTO(
                id=a.id,
                tenant_id=a.tenant_id,
                asset_group_id=a.asset_group_id,
                scan_target_id=a.scan_target_id,
                ip_address=a.ip_address,
                hostname=a.hostname,
                mac_address=a.mac_address,
                operating_system=a.operating_system,
                device_type=a.device_type,
                manufacturer=a.manufacturer,
                status=a.status,
                criticality=a.criticality,
                first_seen_at=a.first_seen_at,
                last_seen_at=a.last_seen_at,
                last_scanned_at=a.last_scanned_at,
                zabbix_host_id=a.zabbix_host_id,
                metadata=a.metadata,
                open_services_count=len(services),
                open_vulnerabilities_count=0,
                max_vulnerability_severity=None,
                created_at=a.created_at,
                updated_at=a.updated_at,
            )
        )

    return PaginatedResponse(
        items=dto_items,
        page=page,
        page_size=page_size,
        total=total,
        pages=pages,
    )


@router.get("/{asset_id}", response_model=AssetResponseDTO)
async def get_asset(
    asset_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> AssetResponseDTO:
    if not RBACManager.has_permission(current_user, "assets", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)
    asset = await repo.get_asset_by_id(asset_id, current_user.tenant_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ativo não encontrado.")

    services = await repo.list_services(asset.id, current_user.tenant_id)

    return AssetResponseDTO(
        id=asset.id,
        tenant_id=asset.tenant_id,
        asset_group_id=asset.asset_group_id,
        scan_target_id=asset.scan_target_id,
        ip_address=asset.ip_address,
        hostname=asset.hostname,
        mac_address=asset.mac_address,
        operating_system=asset.operating_system,
        device_type=asset.device_type,
        manufacturer=asset.manufacturer,
        status=asset.status,
        criticality=asset.criticality,
        first_seen_at=asset.first_seen_at,
        last_seen_at=asset.last_seen_at,
        last_scanned_at=asset.last_scanned_at,
        zabbix_host_id=asset.zabbix_host_id,
        metadata=asset.metadata,
        open_services_count=len(services),
        open_vulnerabilities_count=0,
        max_vulnerability_severity=None,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


@router.patch("/{asset_id}", response_model=AssetResponseDTO)
async def patch_asset(
    asset_id: UUID,
    payload: AssetPatchDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> AssetResponseDTO:
    if not RBACManager.has_permission(current_user, "assets", "PATCH"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)
    asset = await repo.get_asset_by_id(asset_id, current_user.tenant_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ativo não encontrado.")

    if payload.hostname is not None:
        asset.hostname = payload.hostname
    if payload.criticality is not None:
        asset.criticality = payload.criticality
    if payload.device_type is not None:
        asset.device_type = payload.device_type
    if payload.operating_system is not None:
        asset.operating_system = payload.operating_system
    if payload.manufacturer is not None:
        asset.manufacturer = payload.manufacturer
    if payload.status is not None:
        asset.status = payload.status

    await repo.save_asset(asset)
    await db.commit()

    services = await repo.list_services(asset.id, current_user.tenant_id)

    return AssetResponseDTO(
        id=asset.id,
        tenant_id=asset.tenant_id,
        asset_group_id=asset.asset_group_id,
        scan_target_id=asset.scan_target_id,
        ip_address=asset.ip_address,
        hostname=asset.hostname,
        mac_address=asset.mac_address,
        operating_system=asset.operating_system,
        device_type=asset.device_type,
        manufacturer=asset.manufacturer,
        status=asset.status,
        criticality=asset.criticality,
        first_seen_at=asset.first_seen_at,
        last_seen_at=asset.last_seen_at,
        last_scanned_at=asset.last_scanned_at,
        zabbix_host_id=asset.zabbix_host_id,
        metadata=asset.metadata,
        open_services_count=len(services),
        open_vulnerabilities_count=0,
        max_vulnerability_severity=None,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


@router.get("/{asset_id}/services", response_model=list[ServiceResponseDTO])
async def list_asset_services(
    asset_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> list[ServiceResponseDTO]:
    if not RBACManager.has_permission(current_user, "assets", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresAssetRepository(db)
    asset = await repo.get_asset_by_id(asset_id, current_user.tenant_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ativo não encontrado.")

    services = await repo.list_services(asset_id, current_user.tenant_id)
    return [
        ServiceResponseDTO(
            id=s.id,
            tenant_id=s.tenant_id,
            asset_id=s.asset_id,
            port=s.port,
            protocol=s.protocol,
            service_name=s.service_name,
            product=s.product,
            version=s.version,
            state=s.state,
            banner=s.banner,
            first_seen_at=s.first_seen_at,
            last_seen_at=s.last_seen_at,
        )
        for s in services
    ]


@router.get("/{asset_id}/vulnerabilities", response_model=list[VulnerabilityResponseDTO])
async def list_asset_vulnerabilities(
    asset_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> list[VulnerabilityResponseDTO]:
    if not RBACManager.has_permission(current_user, "vulnerabilities", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    asset_repo = PostgresAssetRepository(db)
    vuln_repo = PostgresVulnerabilityRepository(db)

    asset = await asset_repo.get_asset_by_id(asset_id, current_user.tenant_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ativo não encontrado.")

    items, _ = await vuln_repo.list_findings(tenant_id=current_user.tenant_id, page_size=100)
    asset_vulns = [v for v in items if v.asset_id == asset_id]

    return [
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
        for v in asset_vulns
    ]


@router.get("/{asset_id}/scan-history")
async def get_asset_scan_history(
    asset_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> list[dict[str, Any]]:
    if not RBACManager.has_permission(current_user, "assets", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    asset_repo = PostgresAssetRepository(db)
    asset = await asset_repo.get_asset_by_id(asset_id, current_user.tenant_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ativo não encontrado.")

    return []
