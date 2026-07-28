"""
Rotas FastAPI para o Módulo Core
GovSec Shield — API Routers
"""


from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from src.core.application.commands import (
    CreateTenantCommand,
    DeleteTenantCommand,
    IngestLogCommand,
    UpdateTenantCommand,
)
from src.core.application.dto import (
    CreateTenantDTO,
    IngestLogDTO,
    LogResponseDTO,
    TenantResponseDTO,
    UpdateTenantDTO,
)
from src.core.application.queries import (
    GetTenantByIdQuery,
    ListLogsQuery,
    ListTenantsQuery,
    LogQueryHandler,
    TenantQueryHandler,
)
from src.core.infrastructure.messaging.command_bus import CommandBus
from src.core.infrastructure.security.jwt import JWTUtils
from src.core.infrastructure.security.kernel import AuthenticatedUser, SecurityKernel
from src.core.infrastructure.security.rbac import UserRole
from src.core.interfaces.rest.dependencies import (
    get_command_bus,
    get_current_user,
    get_log_query_handler,
    get_query_handler,
)
from src.core.security import ScopeSafetyConfig

router = APIRouter(prefix="/api/v1", tags=["Core Platform"])


class TokenRequestDTO(BaseModel):
    user_id: str = Field(default="admin-01")
    tenant: str = Field(default="betim")
    roles: list[str] = Field(default=["system_admin"])


class ScopeCheckDTO(BaseModel):
    target_ip: str = Field(..., description="IP ou CIDR para validação de escopo")


@router.post("/auth/token")
async def generate_token(dto: TokenRequestDTO) -> dict[str, str]:
    """Gera token JWT assinado para autenticação na API."""
    token = JWTUtils.create_access_token(
        user_id=dto.user_id, tenant=dto.tenant, roles=dto.roles
    )
    return {"access_token": token, "token_type": "Bearer"}


@router.post("/security/check-scope")
async def check_scope(dto: ScopeCheckDTO) -> dict[str, str | bool]:
    """Valida se o IP informado está dentro das sub-redes autorizadas da prefeitura."""
    config = ScopeSafetyConfig()
    allowed = config.is_target_allowed(dto.target_ip)
    return {
        "target_ip": dto.target_ip,
        "is_allowed": allowed,
        "status": "AUTHORIZED" if allowed else "SCOPE_VIOLATION",
    }


# -----------------------------------------------------------------------------
# Tarefa 1.2: POST /api/v1/tenants (Criar Tenant)
# -----------------------------------------------------------------------------
@router.post("/tenants", response_model=TenantResponseDTO, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    dto: CreateTenantDTO,
    command_bus: CommandBus = Depends(get_command_bus),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> TenantResponseDTO:
    SecurityKernel.authorize(current_user, UserRole.SYSTEM_ADMIN)
    command = CreateTenantCommand(name=dto.name, slug=dto.slug)
    try:
        result = await command_bus.send(command)
        return result  # type: ignore[no-any-return]
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e


# -----------------------------------------------------------------------------
# Tarefa 1.1: GET /api/v1/tenants (Listar Tenants com Paginação e Filtros)
# -----------------------------------------------------------------------------
@router.get("/tenants", response_model=list[TenantResponseDTO])
async def list_tenants(
    skip: int = Query(0, ge=0, description="Offset de paginação"),
    limit: int = Query(100, ge=1, le=500, description="Limite por página"),
    search: str | None = Query(None, description="Filtro por nome ou slug"),
    status_filter: str | None = Query(None, alias="status", description="Filtro por status (ACTIVE, INACTIVE, SUSPENDED)"),
    query_handler: TenantQueryHandler = Depends(get_query_handler),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> list[TenantResponseDTO]:
    SecurityKernel.authorize(current_user, UserRole.VIEWER)
    query = ListTenantsQuery(skip=skip, limit=limit, search=search, status=status_filter)
    return await query_handler.list(query)


# -----------------------------------------------------------------------------
# Tarefa 1.3: GET /api/v1/tenants/{id} (Buscar Tenant por UUID)
# -----------------------------------------------------------------------------
@router.get("/tenants/{tenant_id}", response_model=TenantResponseDTO)
async def get_tenant_by_id(
    tenant_id: UUID,
    query_handler: TenantQueryHandler = Depends(get_query_handler),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> TenantResponseDTO:
    SecurityKernel.authorize(current_user, UserRole.VIEWER)
    query = GetTenantByIdQuery(tenant_id=tenant_id)
    tenant = await query_handler.get_by_id(query)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant com ID '{tenant_id}' não foi encontrado",
        )
    return tenant


# -----------------------------------------------------------------------------
# Tarefa 1.4: PUT /api/v1/tenants/{id} (Atualizar Tenant)
# -----------------------------------------------------------------------------
@router.put("/tenants/{tenant_id}", response_model=TenantResponseDTO)
async def update_tenant(
    tenant_id: UUID,
    dto: UpdateTenantDTO,
    command_bus: CommandBus = Depends(get_command_bus),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> TenantResponseDTO:
    SecurityKernel.authorize(current_user, UserRole.SYSTEM_ADMIN)
    command = UpdateTenantCommand(tenant_id=tenant_id, name=dto.name, status=dto.status)
    try:
        result = await command_bus.send(command)
        return result  # type: ignore[no-any-return]
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND if "não foi encontrado" in str(e) else status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e


# -----------------------------------------------------------------------------
# Tarefa 1.5: DELETE /api/v1/tenants/{id} (Soft Delete do Tenant)
# -----------------------------------------------------------------------------
@router.delete("/tenants/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(
    tenant_id: UUID,
    command_bus: CommandBus = Depends(get_command_bus),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> None:
    SecurityKernel.authorize(current_user, UserRole.SYSTEM_ADMIN)
    command = DeleteTenantCommand(tenant_id=tenant_id)
    try:
        await command_bus.send(command)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e


# -----------------------------------------------------------------------------
# Tarefa 1.7: POST /api/v1/logs (Ingestão de Logs)
# -----------------------------------------------------------------------------
@router.post("/logs", status_code=status.HTTP_202_ACCEPTED)
async def ingest_log(
    dto: IngestLogDTO,
    command_bus: CommandBus = Depends(get_command_bus),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, str]:
    SecurityKernel.authorize(current_user, UserRole.ANALYST)
    command = IngestLogCommand(
        source=dto.source, raw_data=dto.raw_data, tenant_id=dto.tenant_id, timestamp=dto.timestamp
    )
    try:
        await command_bus.send(command)
        return {"status": "accepted", "message": "Log enviado para fila de ingestão"}
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e


# -----------------------------------------------------------------------------
# Tarefa 1.6: GET /api/v1/logs (Listar Logs com Filtros)
# -----------------------------------------------------------------------------
@router.get("/logs", response_model=list[LogResponseDTO])
async def list_logs(
    skip: int = Query(0, ge=0, description="Offset de paginação"),
    limit: int = Query(100, ge=1, le=500, description="Limite por página"),
    tenant_id: UUID | None = Query(None, description="Filtro por UUID do Tenant"),
    source: str | None = Query(None, description="Filtro por nome da fonte ingestora"),
    query_handler: LogQueryHandler = Depends(get_log_query_handler),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> list[LogResponseDTO]:
    SecurityKernel.authorize(current_user, UserRole.VIEWER)
    query = ListLogsQuery(skip=skip, limit=limit, tenant_id=tenant_id, source=source)
    return await query_handler.list(query)

