"""
Contêiner de Injeção de Dependências da API FastAPI
GovSec Shield — API Dependencies
"""

from typing import AsyncGenerator
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from src.core.infrastructure.db.unit_of_work import get_db_session, UnitOfWork
from src.core.infrastructure.messaging.event_bus import EventBus
from src.core.infrastructure.messaging.command_bus import CommandBus
from src.core.infrastructure.security.kernel import SecurityKernel, AuthenticatedUser
from src.core.application.handlers import CreateTenantHandler, IngestLogHandler
from src.core.application.queries import TenantQueryHandler

# Instâncias singleton globais de barramento para a aplicação
event_bus_instance = EventBus(use_kafka=False)
command_bus_instance = CommandBus()

# Inicialização de handlers
async def get_command_bus(session: AsyncSession = Depends(get_db_session)) -> CommandBus:
    uow = UnitOfWork(session)
    create_tenant_handler = CreateTenantHandler(uow.tenants, event_bus_instance)
    ingest_log_handler = IngestLogHandler(event_bus_instance)

    command_bus_instance.register(
        "CreateTenantCommand",
        lambda cmd: create_tenant_handler.handle(cmd)
    )
    command_bus_instance.register(
        "IngestLogCommand",
        lambda cmd: ingest_log_handler.handle(cmd)
    )
    return command_bus_instance

async def get_query_handler(session: AsyncSession = Depends(get_db_session)) -> TenantQueryHandler:
    uow = UnitOfWork(session)
    return TenantQueryHandler(uow.tenants)

async def get_current_user(authorization: str = Header(..., alias="Authorization")) -> AuthenticatedUser:
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header Authorization deve ser do tipo Bearer <token>"
        )
    token = authorization.split(" ")[1]
    try:
        return SecurityKernel.authenticate(token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
