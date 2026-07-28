"""
Interfaces de Repositório do Domínio Core
GovSec Shield — Domain Repositories
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID
from src.core.domain.entities import Tenant

class TenantRepository(ABC):
    """
    Interface do Repositório de Tenants.
    """

    @abstractmethod
    async def save(self, tenant: Tenant) -> Tenant:
        """Persiste um tenant no repositório."""
        pass

    @abstractmethod
    async def get_by_id(self, tenant_id: UUID) -> Optional[Tenant]:
        """Obtém um tenant pelo seu UUID."""
        pass

    @abstractmethod
    async def get_by_slug(self, slug: str) -> Optional[Tenant]:
        """Obtém um tenant pelo seu slug único."""
        pass

    @abstractmethod
    async def list(self, skip: int = 0, limit: int = 100) -> List[Tenant]:
        """Lista tenants com paginação."""
        pass
