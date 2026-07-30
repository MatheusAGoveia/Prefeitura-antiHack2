"""
Domínio Core do GovSec Shield.
GovSec Shield — Domain Package
"""

from src.core.domain.correlation import CorrelationKey, CorrelationRule, CorrelationRuleVersion
from src.core.domain.entities import AlertAcknowledgement, AuditLog, Tenant, TenantStatus
from src.core.domain.events import (
    AlertAcknowledgedEvent,
    DomainEvent,
    LogIngestedEvent,
    SecurityEventReceivedEvent,
    TenantCreatedEvent,
)
from src.core.domain.exceptions import (
    AuthenticationProviderUnavailableError,
    CrossTenantAccessDeniedError,
    DomainError,
    InvalidCredentialsError,
    RedisRevocationUnavailableError,
)
from src.core.domain.incidents import (
    Asset,
    Incident,
    IncidentEvidence,
    IncidentStatus,
    IncidentStatusChange,
    InvalidStatusTransitionError,
    SecurityEvent,
    SecurityEventSeverity,
    UnresolvedAssetEvent,
    sanitize_payload,
)
from src.core.domain.m4_contracts import Engagement, ScopeTarget, SecurityJob, ToolAdapter
from src.core.domain.repositories import (
    AlertAcknowledgementRepository,
    AssetRepository,
    CorrelationRuleVersionRepository,
    LogRepository,
    SecurityEventRepository,
    TenantRepository,
)

__all__ = [
    "AlertAcknowledgement",
    "AlertAcknowledgementRepository",
    "AlertAcknowledgedEvent",
    "Asset",
    "AssetRepository",
    "AuthenticationProviderUnavailableError",
    "AuditLog",
    "CorrelationKey",
    "CorrelationRule",
    "CorrelationRuleVersion",
    "CorrelationRuleVersionRepository",
    "CrossTenantAccessDeniedError",
    "DomainError",
    "DomainEvent",
    "Engagement",
    "Incident",
    "IncidentEvidence",
    "IncidentStatus",
    "IncidentStatusChange",
    "InvalidCredentialsError",
    "InvalidStatusTransitionError",
    "LogIngestedEvent",
    "LogRepository",
    "RedisRevocationUnavailableError",
    "ScopeTarget",
    "SecurityEvent",
    "SecurityEventReceivedEvent",
    "SecurityEventRepository",
    "SecurityEventSeverity",
    "SecurityJob",
    "Tenant",
    "TenantCreatedEvent",
    "TenantRepository",
    "TenantStatus",
    "ToolAdapter",
    "UnresolvedAssetEvent",
    "sanitize_payload",
]
