"""
Interface de Unit of Work para Ingestão de Eventos de Segurança e Correlação.
GovSec Shield — Application Layer UnitOfWork Interface
"""

from abc import ABC, abstractmethod
from typing import Self

from src.core.domain.repositories import (
    AssetRepository,
    CorrelationRuleVersionRepository,
    IncidentEvidenceRepository,
    IncidentRepository,
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


class CorrelationUnitOfWork(ABC):
    """
    Abstração tipada da Unidade Transacional para o Motor de Correlação (M3.2).
    Garante atomicidade entre criação/atualização de incidente, evidência e histórico de status.
    Operação assíncrona acionada pelo CorrelationWorker (outbox consumer).
    """

    @property
    @abstractmethod
    def security_events(self) -> SecurityEventRepository:
        """Repositório de Eventos de Segurança (leitura do evento a correlacionar)."""
        pass

    @property
    @abstractmethod
    def correlation_rules(self) -> CorrelationRuleVersionRepository:
        """Repositório de Versões de Regras de Correlação (carrega regras ativas do tenant)."""
        pass

    @property
    @abstractmethod
    def incidents(self) -> IncidentRepository:
        """Repositório de Incidentes."""
        pass

    @property
    @abstractmethod
    def evidences(self) -> IncidentEvidenceRepository:
        """Repositório de Evidências de Incidentes."""
        pass

    @property
    @abstractmethod
    def logs(self) -> LogRepository:
        """Repositório de Audit Logs."""
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
