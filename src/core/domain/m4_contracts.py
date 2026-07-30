"""
Contratos Preparatórios para Orquestração e Ferramentas (Capability M4).
GovSec Shield — Domain Layer (M3.0 -> M4)

ATENÇÃO: Estes contratos existem exclusivamente para prevenir ruptura arquitetural
entre M3 e M4. Não contêm lógica de execução, scanners, filas, subprocessos ou ferramentas.
Utilizam exclusivamente a biblioteca padrão do Python.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from src.core.domain.exceptions import DomainError


@dataclass(frozen=True)
class ScopeTarget:
    """Contrato preparatório para Alvo de Escopo Autorizado."""

    target_id: UUID
    tenant_id: UUID
    target_identifier: str
    is_allowed: bool
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise DomainError(f"tenant_id deve ser um UUID válido, recebido: {type(self.tenant_id)}")


@dataclass(frozen=True)
class Engagement:
    """Contrato preparatório para Engajamento de Segurança."""

    engagement_id: UUID
    tenant_id: UUID
    title: str
    scope_targets: list[ScopeTarget]
    status: str = "DRAFT"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise DomainError(f"tenant_id deve ser um UUID válido, recebido: {type(self.tenant_id)}")


@dataclass(frozen=True)
class SecurityJob:
    """Contrato preparatório para Job de Segurança (Sem execução em M3.0)."""

    job_id: UUID
    tenant_id: UUID
    job_type: str
    target_identifier: str
    status: str = "PENDING"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise DomainError(f"tenant_id deve ser um UUID válido, recebido: {type(self.tenant_id)}")


class ToolAdapter(ABC):
    """
    Interface abstrata preparatória para Adaptadores de Ferramentas (M4).
    Sem implementações reais ou executores nesta sprint.
    """

    @property
    @abstractmethod
    def adapter_id(self) -> str:
        """Identificador do adaptador."""
        pass

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Nome da ferramenta integrada."""
        pass

    @abstractmethod
    def execute_job(self, job: SecurityJob) -> dict[str, Any]:
        """
        Assinatura abstrata para execução de jobs.
        Nenhuma implementação concreta existe em M3.0.
        """
        pass
