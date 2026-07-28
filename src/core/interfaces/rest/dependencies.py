"""
Contêiner de Injeção de Dependências da API FastAPI
GovSec Shield — API Dependencies
"""

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.application.handlers import (
    CreateTenantHandler,
    DeleteTenantHandler,
    IngestLogHandler,
    UpdateTenantHandler,
)
from src.core.application.queries import LogQueryHandler, TenantQueryHandler
from src.core.infrastructure.db.repositories import InMemoryLogRepository
from src.core.infrastructure.db.unit_of_work import UnitOfWork, get_db_session
from src.core.infrastructure.messaging.command_bus import CommandBus
from src.core.infrastructure.messaging.event_bus import EventBus
from src.core.infrastructure.security.kernel import AuthenticatedUser, SecurityKernel

# Instâncias singleton globais de barramento e repositórios para a aplicação
event_bus_instance = EventBus(use_kafka=False)
command_bus_instance = CommandBus()
log_repository_instance = InMemoryLogRepository()


# Inicialização de handlers
async def get_command_bus(session: AsyncSession = Depends(get_db_session)) -> CommandBus:
    uow = UnitOfWork(session)
    create_tenant_handler = CreateTenantHandler(uow.tenants, event_bus_instance)
    update_tenant_handler = UpdateTenantHandler(uow.tenants)
    delete_tenant_handler = DeleteTenantHandler(uow.tenants)
    ingest_log_handler = IngestLogHandler(event_bus_instance, log_repository_instance)

    command_bus_instance.register(
        "CreateTenantCommand", lambda cmd: create_tenant_handler.handle(cmd)
    )
    command_bus_instance.register(
        "UpdateTenantCommand", lambda cmd: update_tenant_handler.handle(cmd)
    )
    command_bus_instance.register(
        "DeleteTenantCommand", lambda cmd: delete_tenant_handler.handle(cmd)
    )
    command_bus_instance.register("IngestLogCommand", lambda cmd: ingest_log_handler.handle(cmd))
    return command_bus_instance


async def get_query_handler(session: AsyncSession = Depends(get_db_session)) -> TenantQueryHandler:
    uow = UnitOfWork(session)
    return TenantQueryHandler(uow.tenants)


async def get_log_query_handler() -> LogQueryHandler:
    return LogQueryHandler(log_repository_instance)


async def get_current_user(
    authorization: str = Header(..., alias="Authorization")
) -> AuthenticatedUser:
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header Authorization deve ser do tipo Bearer <token>",
        )
    token = authorization.split(" ")[1]
    try:
        return SecurityKernel.authenticate(token)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)) from e

