"""
Rotas FastAPI para o Módulo Core
GovSec Shield — API Routers
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from src.core.application.dto import CreateTenantDTO, TenantResponseDTO, IngestLogDTO
from src.core.application.commands import CreateTenantCommand, IngestLogCommand
from src.core.application.queries import TenantQueryHandler, GetTenantByIdQuery, ListTenantsQuery
from src.core.infrastructure.messaging.command_bus import CommandBus
from src.core.infrastructure.security.kernel import AuthenticatedUser
from src.core.infrastructure.security.rbac import UserRole, SecurityKernel
from src.core.interfaces.rest.dependencies import get_command_bus, get_query_handler, get_current_user

router = APIRouter(prefix="/api/v1", tags=["Core Platform"])

@router.post("/tenants", response_model=TenantResponseDTO, status_code=status.HTTP_21_CREATED)
async def create_tenant(
    dto: CreateTenantDTO,
    command_bus: CommandBus = Depends(get_command_bus),
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    SecurityKernel.authorize(current_user, UserRole.SYSTEM_ADMIN)
    command = CreateTenantCommand(name=dto.name, slug=dto.slug)
    try:
        result = await command_bus.send(command)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

@router.get("/tenants", response_model=List[TenantResponseDTO])
async def list_tenants(
    skip: int = 0,
    limit: int = 100,
    query_handler: TenantQueryHandler = Depends(get_query_handler),
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    SecurityKernel.authorize(current_user, UserRole.VIEWER)
    query = ListTenantsQuery(skip=skip, limit=limit)
    return await query_handler.list(query)

@router.post("/logs", status_code=status.HTTP_202_ACCEPTED)
async def ingest_log(
    dto: IngestLogDTO,
    command_bus: CommandBus = Depends(get_command_bus),
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    SecurityKernel.authorize(current_user, UserRole.ANALYST)
    command = IngestLogCommand(
        source=dto.source,
        raw_data=dto.raw_data,
        tenant_id=dto.tenant_id,
        timestamp=dto.timestamp
    )
    try:
        await command_bus.send(command)
        return {"status": "accepted", "message": "Log enviado para fila de ingestão"}
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
