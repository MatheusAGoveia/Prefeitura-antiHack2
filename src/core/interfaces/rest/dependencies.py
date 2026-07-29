"""
Contêiner de Injeção de Dependências da API FastAPI
GovSec Shield — API Dependencies
"""

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.application.handlers import (
    AcknowledgeAlertHandler,
    CreateTenantHandler,
    DeleteTenantHandler,
    IngestLogHandler,
    UpdateTenantHandler,
)
from src.core.application.queries import LogQueryHandler, TenantQueryHandler
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.repositories import (
    InMemoryAlertAcknowledgementRepository,
    InMemoryLogRepository,
)
from src.core.infrastructure.db.unit_of_work import UnitOfWork, get_db_session
from src.core.infrastructure.messaging.command_bus import CommandBus
from src.core.infrastructure.messaging.event_bus import EventBus
from src.core.infrastructure.security.kernel import AuthenticatedUser, SecurityKernel

# Instâncias singleton globais de barramento para a aplicação
_use_kafka = settings.GOVSEC_USE_KAFKA
if settings.GOVSEC_ENV in ("staging", "production") and not _use_kafka:
    raise ValueError(
        f"Em ambiente '{settings.GOVSEC_ENV}', GOVSEC_USE_KAFKA=True é obrigatório. "
        "A aplicação não pode operar em fallback de memória em produção."
    )

event_bus_instance = EventBus(use_kafka=_use_kafka)
log_repository_fallback = InMemoryLogRepository()
ack_repository_fallback = InMemoryAlertAcknowledgementRepository()



# Inicialização de handlers com suporte a UoW PostgreSQL
async def get_command_bus(session: AsyncSession = Depends(get_db_session)) -> CommandBus:
    bus = CommandBus()
    uow = UnitOfWork(session)
    create_tenant_handler = CreateTenantHandler(uow.tenants, event_bus_instance)
    update_tenant_handler = UpdateTenantHandler(uow.tenants)
    delete_tenant_handler = DeleteTenantHandler(uow.tenants)
    ingest_log_handler = IngestLogHandler(event_bus_instance, uow.logs)
    ack_alert_handler = AcknowledgeAlertHandler(uow.alert_acks, event_bus_instance)

    bus.register("CreateTenantCommand", lambda cmd: create_tenant_handler.handle(cmd))
    bus.register("UpdateTenantCommand", lambda cmd: update_tenant_handler.handle(cmd))
    bus.register("DeleteTenantCommand", lambda cmd: delete_tenant_handler.handle(cmd))
    bus.register("IngestLogCommand", lambda cmd: ingest_log_handler.handle(cmd))
    bus.register("AcknowledgeAlertCommand", lambda cmd: ack_alert_handler.handle(cmd))
    return bus



async def get_query_handler(session: AsyncSession = Depends(get_db_session)) -> TenantQueryHandler:
    uow = UnitOfWork(session)
    return TenantQueryHandler(uow.tenants)


async def get_log_query_handler(session: AsyncSession = Depends(get_db_session)) -> LogQueryHandler:
    uow = UnitOfWork(session)
    return LogQueryHandler(uow.logs)


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
        return await SecurityKernel.authenticate_async(token)
    except Exception as e:

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)) from e


