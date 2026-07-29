"""
Interfaces de Repositório do Domínio Core
GovSec Shield — Domain Repositories
"""

from abc import ABC, abstractmethod
from uuid import UUID

from src.core.domain.entities import AlertAcknowledgement, AuditLog, Tenant


class TenantRepository(ABC):
    """
    Interface do Repositório de Tenants.
    """

    @abstractmethod
    async def save(self, tenant: Tenant) -> Tenant:
        """Persiste um tenant no repositório."""
        pass

    @abstractmethod
    async def get_by_id(self, tenant_id: UUID) -> Tenant | None:
        """Obtém um tenant pelo seu UUID."""
        pass

    @abstractmethod
    async def get_by_slug(self, slug: str) -> Tenant | None:
        """Obtém um tenant pelo seu slug único."""
        pass

    @abstractmethod
    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        search: str | None = None,
        status: str | None = None,
    ) -> list[Tenant]:
        """Lista tenants com paginação e filtros."""
        pass

    @abstractmethod
    async def delete(self, tenant_id: UUID) -> bool:
        """Realiza o Soft Delete do tenant alterando seu status para INACTIVE."""
        pass


class LogRepository(ABC):
    """
    Interface do Repositório de Logs de Auditoria.
    """

    @abstractmethod
    async def save(self, log: AuditLog) -> AuditLog:
        """Persiste um log de auditoria."""
        pass

    @abstractmethod
    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        tenant_id: UUID | None = None,
        source: str | None = None,
    ) -> list[AuditLog]:
        """Lista logs com paginação e filtros por tenant ou fonte."""
        pass


class AlertAcknowledgementRepository(ABC):
    """
    Interface do Repositório de Acknowledgements de Alertas.
    """

    @abstractmethod
    async def save(self, ack: AlertAcknowledgement) -> AlertAcknowledgement:
        """Persiste um acknowledgement no repositório."""
        pass

    @abstractmethod
    async def get_by_fingerprint(
        self, fingerprint: str, tenant_id: str
    ) -> AlertAcknowledgement | None:
        """Obtém acknowledgement existente por fingerprint e tenant para idempotência."""
        pass

    @abstractmethod
    async def list(
        self, tenant_id: str | None = None, skip: int = 0, limit: int = 100
    ) -> list[AlertAcknowledgement]:
        """Lista acknowledgements persistidos."""
        pass


