"""
Unit of Work com SQLAlchemy Async
GovSec Shield — Infrastructure Unit of Work
"""

from collections.abc import AsyncGenerator
from typing import Self

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.application.interfaces import SecurityEventUnitOfWork
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.repositories import (
    PostgresAlertAcknowledgementRepository,
    PostgresAssetRepository,
    PostgresCorrelationRuleVersionRepository,
    PostgresLogRepository,
    PostgresOutboxRepository,
    PostgresSecurityEventRepository,
    PostgresTenantRepository,
)

engine = create_async_engine(settings.GOVSEC_DB_URL, echo=False)

AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


class UnitOfWork(SecurityEventUnitOfWork):
    """
    Implementação concreta de UnitOfWork utilizando SQLAlchemy Async.
    Garante que todos os repositórios compartilhem a mesma AsyncSession.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self._tenants = PostgresTenantRepository(session)
        self._logs = PostgresLogRepository(session)
        self._alert_acks = PostgresAlertAcknowledgementRepository(session)
        self._assets = PostgresAssetRepository(session)
        self._security_events = PostgresSecurityEventRepository(session)
        self._rule_versions = PostgresCorrelationRuleVersionRepository(session)
        self._outbox = PostgresOutboxRepository(session)

    @property
    def tenants(self) -> PostgresTenantRepository:
        return self._tenants

    @property
    def logs(self) -> PostgresLogRepository:
        return self._logs

    @property
    def alert_acks(self) -> PostgresAlertAcknowledgementRepository:
        return self._alert_acks

    @property
    def assets(self) -> PostgresAssetRepository:
        return self._assets

    @property
    def security_events(self) -> PostgresSecurityEventRepository:
        return self._security_events

    @property
    def rule_versions(self) -> PostgresCorrelationRuleVersionRepository:
        return self._rule_versions

    @property
    def outbox(self) -> PostgresOutboxRepository:
        return self._outbox

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        if exc_type is not None:
            await self.rollback()
        await self.session.close()

    async def commit(self) -> None:
        await self.session.commit()

    async def rollback(self) -> None:
        await self.session.rollback()
