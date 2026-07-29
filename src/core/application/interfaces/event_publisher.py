"""
Interfaces para publicação de eventos de domínio (Clean Architecture)
GovSec Shield — Application Interfaces
"""

from abc import ABC, abstractmethod

from src.core.domain.events import DomainEvent


class IEventPublisher(ABC):
    """Interface abstrata para publicação de eventos de domínio."""

    @abstractmethod
    async def publish(self, event: DomainEvent) -> None:
        pass
