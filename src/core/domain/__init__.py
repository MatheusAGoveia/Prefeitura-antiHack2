"""
Domínio Core do GovSec Shield.
GovSec Shield — Domain Package
"""

from src.core.domain.correlation import CorrelationKey, CorrelationRule
from src.core.domain.entities import AlertAcknowledgement, AuditLog, Tenant, TenantStatus
from src.core.domain.events import (
    AlertAcknowledgedEvent,
    DomainEvent,
    LogIngestedEvent,
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
    LogRepository,
    TenantRepository,
)

__all__ = [
    "AlertAcknowledgement",
    "AlertAcknowledgementRepository",
    "AlertAcknowledgedEvent",
    "Asset",
    "AuthenticationProviderUnavailableError",
    "AuditLog",
    "CorrelationKey",
    "CorrelationRule",
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
