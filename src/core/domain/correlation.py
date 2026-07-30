"""
Contratos de Domínio para Correlação Determinística.
GovSec Shield — Domain Layer (M3.0)

Este módulo utiliza exclusivamente a biblioteca padrão do Python para garantir
isolamento total de infraestrutura e frameworks externos.
"""

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from src.core.domain.exceptions import DomainError
from src.core.domain.incidents import SecurityEvent


@dataclass(frozen=True)
class CorrelationKey:
    """
    Value Object representando a chave estável, determinística e versionada de correlação.
    Garantia de que apenas um incidente estará aberto por (tenant_id, correlation_key).
    """

    tenant_id: UUID
    rule_id: str
    rule_version: str
    asset_key: str
    category: str
    time_window: str

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise DomainError(f"tenant_id deve ser um UUID válido, recebido: {type(self.tenant_id)}")
        if not self.rule_id or not self.rule_id.strip():
            raise DomainError("rule_id é obrigatório para CorrelationKey.")
        if not self.rule_version or not self.rule_version.strip():
            raise DomainError("rule_version é obrigatória para CorrelationKey.")
        if not self.asset_key or not self.asset_key.strip():
            raise DomainError("asset_key é obrigatório para CorrelationKey.")
        if not self.category or not self.category.strip():
            raise DomainError("category é obrigatório para CorrelationKey.")
        if not self.time_window or not self.time_window.strip():
            raise DomainError("time_window é obrigatório para CorrelationKey.")

    def to_canonical_string(self) -> str:
        """Retorna a representação textual determinística canônica."""
        return (
            f"{self.tenant_id}:{self.rule_id}:{self.rule_version}:"
            f"{self.asset_key}:{self.category}:{self.time_window}"
        )

    def to_hash(self) -> str:
        """Retorna o hash SHA-256 da chave de correlação."""
        return hashlib.sha256(self.to_canonical_string().encode("utf-8")).hexdigest()

    def __str__(self) -> str:
        return self.to_canonical_string()


class CorrelationRule(ABC):
    """
    Contrato abstrato base para regras de correlação determinísticas.
    Toda regra deve ser tipada, versionada e explicável.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Identificador único e estável da regra (ex: R-INFRA-001)."""
        pass

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Nome legível e explicativo da regra."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Versão SemVer da regra (ex: 1.0.0)."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Categoria funcional da regra (ex: availability, authentication, integrity)."""
        pass

    @abstractmethod
    def evaluate(self, events: Sequence[SecurityEvent]) -> list[CorrelationKey]:
        """
        Avalia uma sequência de eventos e retorna as chaves de correlação geradas.
        Se nenhum padrão for correlacionado, retorna lista vazia.
        """
        pass
