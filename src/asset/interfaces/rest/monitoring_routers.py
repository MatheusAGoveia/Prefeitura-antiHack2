"""
Endpoints REST para Configuração e Sincronização com Zabbix (MonitoringIntegration).
GovSec Shield — Presentation Layer (M3.4)
"""

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.asset.application.dto import (
    MonitoringIntegrationCreateDTO,
    MonitoringIntegrationPatchDTO,
    MonitoringIntegrationResponseDTO,
    MonitoringSyncExecutionResponseDTO,
    MonitoringTestResponseDTO,
    PaginatedResponse,
)
from src.asset.domain.exceptions import AssetDomainError
from src.asset.domain.monitoring import MonitoringIntegration
from src.asset.infrastructure.adapters.fake_monitoring_adapter import FakeMonitoringGateway
from src.asset.infrastructure.audit import record_asset_audit_log
from src.asset.infrastructure.db.models import MonitoringSyncExecutionModel
from src.asset.infrastructure.db.scanner_repositories import PostgresMonitoringRepository
from src.core.infrastructure.db.models import OutboxEventModel
from src.core.infrastructure.db.unit_of_work import get_db_session
from src.core.infrastructure.security.kernel import AuthenticatedUser
from src.core.infrastructure.security.rbac import RBACManager
from src.core.interfaces.rest.dependencies import get_current_user
from src.shared.observability.metrics import GOVSEC_MONITORING_SYNC_TOTAL

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/monitoring-integrations", tags=["Monitoring Integrations"])


@router.post("", response_model=MonitoringIntegrationResponseDTO, status_code=status.HTTP_201_CREATED)
async def create_monitoring_integration(
    payload: MonitoringIntegrationCreateDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> MonitoringIntegrationResponseDTO:
    if not RBACManager.has_permission(current_user, "monitoring_integrations", "POST"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresMonitoringRepository(db)
    try:
        integration = MonitoringIntegration.create(
            tenant_id=current_user.tenant_id,
            name=payload.name,
            base_url=payload.base_url,
            credential_reference=payload.credential_reference,
            provider=payload.provider,
            enabled=payload.enabled,
            verify_tls=payload.verify_tls,
        )
        await repo.save(integration)
        await record_asset_audit_log(
            db,
            current_user.tenant_id,
            current_user.user_id,
            "created",
            "monitoring_integrations",
            integration.id,
            {"name": integration.name, "provider": str(integration.provider)},
        )
        await db.commit()

        return MonitoringIntegrationResponseDTO(
            id=integration.id,
            tenant_id=integration.tenant_id,
            provider=integration.provider,
            name=integration.name,
            base_url=integration.base_url,
            enabled=integration.enabled,
            verify_tls=integration.verify_tls,
            credentials_configured=True,
            last_sync_at=integration.last_sync_at,
            last_sync_status=integration.last_sync_status,
            created_at=integration.created_at,
            updated_at=integration.updated_at,
        )
    except AssetDomainError as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.get("", response_model=PaginatedResponse[MonitoringIntegrationResponseDTO])
async def list_monitoring_integrations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[MonitoringIntegrationResponseDTO]:
    if not RBACManager.has_permission(current_user, "monitoring_integrations", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresMonitoringRepository(db)
    items, total = await repo.list_integrations(current_user.tenant_id, page=page, page_size=page_size)
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    dto_items = [
        MonitoringIntegrationResponseDTO(
            id=m.id,
            tenant_id=m.tenant_id,
            provider=m.provider,
            name=m.name,
            base_url=m.base_url,
            enabled=m.enabled,
            verify_tls=m.verify_tls,
            credentials_configured=True,
            last_sync_at=m.last_sync_at,
            last_sync_status=m.last_sync_status,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )
        for m in items
    ]

    return PaginatedResponse(items=dto_items, page=page, page_size=page_size, total=total, pages=pages)


@router.get("/{integration_id}", response_model=MonitoringIntegrationResponseDTO)
async def get_monitoring_integration(
    integration_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> MonitoringIntegrationResponseDTO:
    if not RBACManager.has_permission(current_user, "monitoring_integrations", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresMonitoringRepository(db)
    m = await repo.get_by_id(integration_id, current_user.tenant_id)
    if not m:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integração de monitoramento não encontrada.")

    return MonitoringIntegrationResponseDTO(
        id=m.id,
        tenant_id=m.tenant_id,
        provider=m.provider,
        name=m.name,
        base_url=m.base_url,
        enabled=m.enabled,
        verify_tls=m.verify_tls,
        credentials_configured=True,
        last_sync_at=m.last_sync_at,
        last_sync_status=m.last_sync_status,
        created_at=m.created_at,
        updated_at=m.updated_at,
    )


@router.patch("/{integration_id}", response_model=MonitoringIntegrationResponseDTO)
async def patch_monitoring_integration(
    integration_id: UUID,
    payload: MonitoringIntegrationPatchDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> MonitoringIntegrationResponseDTO:
    if not RBACManager.has_permission(current_user, "monitoring_integrations", "PATCH"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresMonitoringRepository(db)
    m = await repo.get_by_id(integration_id, current_user.tenant_id)
    if not m:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integração de monitoramento não encontrada.")

    try:
        m.update(
            name=payload.name,
            base_url=payload.base_url,
            credential_reference=payload.credential_reference,
            enabled=payload.enabled,
            verify_tls=payload.verify_tls,
        )
        await repo.save(m)
        await record_asset_audit_log(
            db,
            current_user.tenant_id,
            current_user.user_id,
            "updated",
            "monitoring_integrations",
            m.id,
            {"name": m.name, "enabled": m.enabled},
        )
        await db.commit()

        return MonitoringIntegrationResponseDTO(
            id=m.id,
            tenant_id=m.tenant_id,
            provider=m.provider,
            name=m.name,
            base_url=m.base_url,
            enabled=m.enabled,
            verify_tls=m.verify_tls,
            credentials_configured=True,
            last_sync_at=m.last_sync_at,
            last_sync_status=m.last_sync_status,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )
    except AssetDomainError as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.delete("/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_monitoring_integration(
    integration_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> None:
    if not RBACManager.has_permission(current_user, "monitoring_integrations", "DELETE"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresMonitoringRepository(db)
    deleted = await repo.delete_integration(integration_id, current_user.tenant_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integração de monitoramento não encontrada.")
    await record_asset_audit_log(
        db,
        current_user.tenant_id,
        current_user.user_id,
        "deleted",
        "monitoring_integrations",
        integration_id,
        {},
    )
    await db.commit()


@router.get("/{integration_id}/sync-history", response_model=PaginatedResponse[MonitoringSyncExecutionResponseDTO])
async def list_integration_sync_history(
    integration_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[MonitoringSyncExecutionResponseDTO]:
    if not RBACManager.has_permission(current_user, "monitoring_integrations", "GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresMonitoringRepository(db)
    m = await repo.get_by_id(integration_id, current_user.tenant_id)
    if not m:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integração de monitoramento não encontrada.")

    items, total = await repo.list_integration_sync_history(
        integration_id=integration_id,
        tenant_id=current_user.tenant_id,
        page=page,
        page_size=page_size,
    )
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    dto_items = [
        MonitoringSyncExecutionResponseDTO(
            id=s.id,
            tenant_id=s.tenant_id,
            integration_id=s.integration_id,
            status=s.status,
            started_at=s.started_at,
            finished_at=s.finished_at,
            assets_processed=s.assets_processed,
            assets_created=s.assets_created,
            assets_updated=s.assets_updated,
            errors_count=s.errors_count,
            error_summary=s.error_summary,
        )
        for s in items
    ]

    return PaginatedResponse(items=dto_items, page=page, page_size=page_size, total=total, pages=pages)


@router.post("/{integration_id}/test", response_model=MonitoringTestResponseDTO)
async def test_monitoring_integration(
    integration_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> MonitoringTestResponseDTO:
    if not RBACManager.has_permission(current_user, "monitoring_integrations", "POST"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresMonitoringRepository(db)
    m = await repo.get_by_id(integration_id, current_user.tenant_id)
    if not m:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integração de monitoramento não encontrada.")

    gw = FakeMonitoringGateway()
    res = await gw.test_connection(m)

    await record_asset_audit_log(
        db,
        current_user.tenant_id,
        current_user.user_id,
        "tested",
        "monitoring_integrations",
        integration_id,
        {"success": res["success"], "message": res["message"]},
    )
    await db.commit()

    return MonitoringTestResponseDTO(
        success=res["success"],
        message=res["message"],
        response_time_ms=res.get("response_time_ms", 120.0),
        provider_version=res.get("provider_version", "Zabbix 6.4.0"),
    )


@router.post("/{integration_id}/sync", status_code=status.HTTP_202_ACCEPTED)
async def trigger_monitoring_sync(
    integration_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Inicia a sincronização assíncrona de ativos com o Zabbix retornando HTTP 202 Accepted, persistindo execução, outbox e auditoria na mesma transação."""
    if not RBACManager.has_permission(current_user, "monitoring_integrations", "SYNC"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada.")

    repo = PostgresMonitoringRepository(db)
    m = await repo.get_by_id(integration_id, current_user.tenant_id)
    if not m:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integração de monitoramento não encontrada.")

    if not m.enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Integração de monitoramento está desabilitada.",
        )

    now = datetime.now(timezone.utc)
    sync_exec_id = uuid4()
    correlation_id = uuid4()

    # 1. Persistir MonitoringSyncExecution com status "queued"
    sync_exec = MonitoringSyncExecutionModel(
        id=sync_exec_id,
        tenant_id=current_user.tenant_id,
        integration_id=integration_id,
        status="queued",
        started_at=now,
        assets_processed=0,
        assets_created=0,
        assets_updated=0,
        errors_count=0,
        error_summary=None,
    )
    await repo.save_sync_execution(sync_exec)

    # 2. Criar evento na Outbox na MESMA transação
    outbox_event = OutboxEventModel(
        outbox_event_id=uuid4(),
        tenant_id=current_user.tenant_id,
        aggregate_type="monitoring_integration",
        aggregate_id=integration_id,
        event_type="monitoring.sync.requested",
        payload={
            "tenant_id": str(current_user.tenant_id),
            "integration_id": str(integration_id),
            "sync_execution_id": str(sync_exec_id),
            "correlation_id": str(correlation_id),
            "requested_at": now.isoformat(),
        },
        idempotency_key=f"monitoring_sync_{sync_exec_id}",
        status="pending",
        retry_count=0,
    )
    db.add(outbox_event)

    # 3. Registrar auditoria na MESMA transação
    await record_asset_audit_log(
        db,
        current_user.tenant_id,
        current_user.user_id,
        "sync_requested",
        "monitoring_integrations",
        integration_id,
        {
            "sync_execution_id": str(sync_exec_id),
            "correlation_id": str(correlation_id),
            "status": "queued",
        },
        correlation_id=str(correlation_id),
    )

    # 4. Commit transacional único
    await db.commit()

    GOVSEC_MONITORING_SYNC_TOTAL.labels(provider=str(m.provider), status="queued").inc()

    logger.info(
        "Sincronização Zabbix solicitada e enfileirada via Outbox: tenant_id=%s integration_id=%s sync_execution_id=%s",
        current_user.tenant_id,
        integration_id,
        sync_exec_id,
    )

    return {
        "sync_execution_id": str(sync_exec_id),
        "integration_id": str(integration_id),
        "status": "queued",
        "created_at": now.isoformat(),
        "provider": m.provider,
        "message": "Sincronização assíncrona com Zabbix enfileirada e registrada na Outbox.",
    }
