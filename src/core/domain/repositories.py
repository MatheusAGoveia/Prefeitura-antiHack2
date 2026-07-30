"""
Interfaces de Repositório do Domínio Core
GovSec Shield — Domain Repositories
"""

from abc import ABC, abstractmethod
from uuid import UUID

from src.core.domain.correlation import CorrelationRuleVersion
from src.core.domain.entities import AlertAcknowledgement, AuditLog, Tenant
from src.core.domain.incidents import Asset, SecurityEvent
from src.core.domain.outbox import OutboxEvent


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
        tenant_filter: UUID | None = None,
    ) -> list[Tenant]:
        """Lista tenants com paginação e filtros. tenant_filter restringe por UUID de tenant."""
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
        self, fingerprint: str, tenant_id: UUID
    ) -> AlertAcknowledgement | None:
        """Obtém acknowledgement existente por fingerprint e tenant para idempotência."""
        pass

    @abstractmethod
    async def list(
        self, tenant_id: UUID | None = None, skip: int = 0, limit: int = 100
    ) -> list[AlertAcknowledgement]:
        """Lista acknowledgements persistidos."""
        pass


class AssetRepository(ABC):
    """
    Interface de Repositório de Ativos (M3.1).
    """

    @abstractmethod
    async def save(self, asset: Asset) -> Asset:
        """Persiste ou atualiza um ativo no repositório."""
        pass

    @abstractmethod
    async def get_by_id(self, asset_id: UUID, tenant_id: UUID) -> Asset | None:
        """Obtém um ativo por asset_id e tenant_id (isolamento multi-tenant estrito)."""
        pass

    @abstractmethod
    async def resolve_active_asset(
        self, tenant_id: UUID, service_name: str, environment: str
    ) -> Asset | None:
        """Resolve um ativo ativo por tenant_id, service_name e environment."""
        pass

    @abstractmethod
    async def list(
        self, tenant_id: UUID, skip: int = 0, limit: int = 100
    ) -> list[Asset]:
        """Lista ativos de um tenant com paginação."""
        pass


class SecurityEventRepository(ABC):
    """
    Interface de Repositório de Eventos de Segurança (M3.1).
    """

    @abstractmethod
    async def save(self, event: SecurityEvent) -> tuple[SecurityEvent, bool]:
        """
        Persiste um evento de segurança com garantia de idempotência no banco de dados.
        Retorna uma tupla (event, created):
        - created=True se um novo registro foi inserido;
        - created=False se o evento foi suprimido devido a duplicidade de (tenant_id, source, idempotency_key).
        """
        pass

    @abstractmethod
    async def get_by_id(self, event_id: UUID, tenant_id: UUID) -> SecurityEvent | None:
        """Obtém um evento por event_id e tenant_id."""
        pass

    @abstractmethod
    async def get_by_idempotency_key(
        self, tenant_id: UUID, source: str, idempotency_key: str
    ) -> SecurityEvent | None:
        """Busca evento existente por chave de idempotência e tenant."""
        pass

    @abstractmethod
    async def list(
        self,
        tenant_id: UUID,
        skip: int = 0,
        limit: int = 100,
        asset_id: UUID | None = None,
    ) -> list[SecurityEvent]:
        """Lista eventos de segurança de um tenant com paginação e filtro opcional por asset_id."""
        pass


class CorrelationRuleVersionRepository(ABC):
    """
    Interface de Repositório de Versões de Regras de Correlação (M3.1).
    """

    @abstractmethod
    async def save(
        self, rule_version: CorrelationRuleVersion
    ) -> CorrelationRuleVersion:
        """Persiste uma versão de regra no repositório."""
        pass

    @abstractmethod
    async def get_by_rule_and_version(
        self, rule_id: str, version: str
    ) -> CorrelationRuleVersion | None:
        """Busca versão de regra por rule_id e versão."""
        pass

    @abstractmethod
    async def list_active(
        self, skip: int = 0, limit: int = 100
    ) -> list[CorrelationRuleVersion]:
        """Lista versões de regras ativas."""
        pass


class OutboxRepository(ABC):
    """
    Interface de Repositório para Transactional Outbox (M3.1).
    """

    @abstractmethod
    async def save(self, outbox_event: OutboxEvent) -> OutboxEvent:
        """Persiste ou atualiza uma mensagem na outbox."""
        pass

    @abstractmethod
    async def fetch_pending_and_claim(
        self, limit: int = 100, lock_for_update: bool = True
    ) -> list[OutboxEvent]:
        """
        Busca mensagens elegíveis ('pending' ou 'failed' com next_retry_at <= now)
        e atualiza o status para 'processing' com garantia concorrencial.
        """
        pass

    @abstractmethod
    async def mark_published(self, outbox_event_id: UUID) -> None:
        """Marca mensagem como 'published' e grava published_at."""
        pass

    @abstractmethod
    async def mark_failed(
        self,
        outbox_event_id: UUID,
        error_message: str,
        max_retries: int = 5,
        backoff_seconds: int = 10,
    ) -> None:
        """Marca falha, incrementa retries e registra mensagem de erro sanitizada."""
        pass
