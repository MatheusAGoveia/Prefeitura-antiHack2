"""
Interfaces da Camada de Aplicação (Clean Architecture)
GovSec Shield — Application Layer Interfaces
"""

from src.core.application.interfaces.auth_provider import (
    AuthenticationProviderPort,
)
from src.core.application.interfaces.event_publisher import IEventPublisher

__all__ = ["AuthenticationProviderPort", "IEventPublisher"]
