"""
Unit of Work com SQLAlchemy Async
GovSec Shield — Infrastructure Unit of Work
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.repositories import PostgresTenantRepository

engine = create_async_engine(settings.GOVSEC_DB_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

class UnitOfWork:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.tenants = PostgresTenantRepository(session)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            await self.rollback()
        await self.session.close()

    async def commit(self) -> None:
        await self.session.commit()

    async def rollback(self) -> None:
        await self.session.rollback()
