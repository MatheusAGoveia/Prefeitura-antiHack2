"""
Rotas FastAPI para o Módulo Core
GovSec Shield — API Routers
"""


from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from src.core.application.commands import (
    AcknowledgeAlertCommand,
    CreateTenantCommand,
    DeleteTenantCommand,
    IngestLogCommand,
    UpdateTenantCommand,
)
from src.core.application.dto import (
    AcknowledgeAlertDTO,
    AlertAcknowledgementResponseDTO,
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
from src.core.infrastructure.config import settings
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
    """Gera token JWT assinado para autenticação na API (apenas dev)."""
    if settings.GOVSEC_ENV != "dev":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Endpoint de emissão direta de token desabilitado fora do ambiente 'dev'.",
        )
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
    try:
        SecurityKernel.authorize(current_user, UserRole.SYSTEM_ADMIN)
        command = CreateTenantCommand(name=dto.name, slug=dto.slug)
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
    try:
        SecurityKernel.authorize(current_user, UserRole.VIEWER)
        query = ListTenantsQuery(skip=skip, limit=limit, search=search, status=status_filter)
        return await query_handler.list(query)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e


# -----------------------------------------------------------------------------
# Tarefa 1.3: GET /api/v1/tenants/{id} (Buscar Tenant por UUID)
# -----------------------------------------------------------------------------
@router.get("/tenants/{tenant_id}", response_model=TenantResponseDTO)
async def get_tenant_by_id(
    tenant_id: UUID,
    query_handler: TenantQueryHandler = Depends(get_query_handler),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> TenantResponseDTO:
    try:
        SecurityKernel.authorize(current_user, UserRole.VIEWER)
        query = GetTenantByIdQuery(tenant_id=tenant_id)
        tenant = await query_handler.get_by_id(query)
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Tenant com ID '{tenant_id}' não foi encontrado",
            )
        return tenant
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e


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
    try:
        SecurityKernel.authorize(current_user, UserRole.SYSTEM_ADMIN)
        command = UpdateTenantCommand(tenant_id=tenant_id, name=dto.name, status=dto.status)
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
    try:
        SecurityKernel.authorize(current_user, UserRole.SYSTEM_ADMIN)
        command = DeleteTenantCommand(tenant_id=tenant_id)
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
    try:
        SecurityKernel.authorize(current_user, UserRole.ANALYST)

        # Isolamento Multi-Tenant Estrito: Não confiar em tenant_id do cliente para não-system_admin
        is_sys_admin = "system_admin" in current_user.roles
        if not is_sys_admin and dto.tenant_id and dto.tenant_id != current_user.tenant:
            raise PermissionError(
                f"Acesso negado. Usuário do tenant '{current_user.tenant}' não pode ingerir logs para o tenant '{dto.tenant_id}'."
            )
        effective_tenant = current_user.tenant if not is_sys_admin else (dto.tenant_id or current_user.tenant)

        command = IngestLogCommand(
            source=dto.source, raw_data=dto.raw_data, tenant_id=effective_tenant, timestamp=dto.timestamp
        )
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
    tenant_id: UUID | str | None = Query(None, description="Filtro por UUID/slug do Tenant"),
    source: str | None = Query(None, description="Filtro por nome da fonte ingestora"),
    query_handler: LogQueryHandler = Depends(get_log_query_handler),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> list[LogResponseDTO]:
    try:
        SecurityKernel.authorize(current_user, UserRole.VIEWER)

        # Isolamento Multi-Tenant Estrito
        is_sys_admin = "system_admin" in current_user.roles
        requested_tenant = str(tenant_id) if tenant_id else None

        if not is_sys_admin:
            if requested_tenant and requested_tenant != current_user.tenant:
                raise PermissionError(
                    f"Acesso negado. Usuário do tenant '{current_user.tenant}' não pode consultar logs do tenant '{requested_tenant}'."
                )
            effective_tenant: str | None = current_user.tenant
        else:
            effective_tenant = requested_tenant or current_user.tenant

        query = ListLogsQuery(skip=skip, limit=limit, tenant_id=effective_tenant, source=source)
        return await query_handler.list(query)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e


# -----------------------------------------------------------------------------
# M2 Capability: POST /api/v1/alerts/acknowledge (Acknowledgement Humano de Alerta)
# -----------------------------------------------------------------------------
@router.post("/alerts/acknowledge", response_model=AlertAcknowledgementResponseDTO, status_code=status.HTTP_200_OK)
async def acknowledge_alert(
    dto: AcknowledgeAlertDTO,
    command_bus: CommandBus = Depends(get_command_bus),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> AlertAcknowledgementResponseDTO:
    """
    Registra o acknowledgement humano auditável para um alerta ativo.
    Exige perfil mínimo 'analyst' e é escopado por tenant.
    """
    try:
        SecurityKernel.authorize(current_user, UserRole.ANALYST)

        # Isolamento Multi-Tenant Estrito
        is_sys_admin = "system_admin" in current_user.roles
        if not is_sys_admin and dto.tenant_id and dto.tenant_id != current_user.tenant:
            raise PermissionError(
                f"Acesso negado. Usuário do tenant '{current_user.tenant}' não pode reconhecer alertas do tenant '{dto.tenant_id}'."
            )
        effective_tenant = current_user.tenant if not is_sys_admin else (dto.tenant_id or current_user.tenant)

        command = AcknowledgeAlertCommand(
            alert_id=dto.alert_id,
            fingerprint=dto.fingerprint,
            reason=dto.reason,
            acknowledged_by=current_user.user_id,
            tenant_id=effective_tenant,
        )
        result = await command_bus.send(command)
        SecurityKernel.audit(
            user={"user_id": current_user.user_id, "tenant_id": effective_tenant},
            action="ACKNOWLEDGE_ALERT",
            resource=f"alert:{dto.fingerprint}",
            success=True,
        )
        return result  # type: ignore[no-any-return]
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e




