"""
Interface de Unit of Work para Ingestão de Eventos de Segurança.
GovSec Shield — Application Layer UnitOfWork Interface
"""

from abc import ABC, abstractmethod
from typing import Self

from src.core.domain.repositories import (
    AssetRepository,
    LogRepository,
    OutboxRepository,
    SecurityEventRepository,
)


class SecurityEventUnitOfWork(ABC):
    """
    Abstração tipada da Unidade Transacional para a Ingestão de Eventos de Segurança.
    Garante o padrão Unit of Work e o manuseio atômico de repositórios na mesma transação.
    """

    @property
    @abstractmethod
    def assets(self) -> AssetRepository:
        """Repositório de Ativos de TI."""
        pass

    @property
    @abstractmethod
    def security_events(self) -> SecurityEventRepository:
        """Repositório de Eventos de Segurança."""
        pass

    @property
    @abstractmethod
    def logs(self) -> LogRepository:
        """Repositório de Audit Logs."""
        pass

    @property
    @abstractmethod
    def outbox(self) -> OutboxRepository:
        """Repositório de Eventos Outbox."""
        pass

    @abstractmethod
    async def commit(self) -> None:
        """Confirma a transação no banco de dados."""
        pass

    @abstractmethod
    async def rollback(self) -> None:
        """Reverte a transação no banco de dados."""
        pass

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
