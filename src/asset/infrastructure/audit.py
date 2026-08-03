"""
Utilitário de Trilha de Auditoria Administrativa para o Módulo de Ativos e Scanners.
GovSec Shield — Infrastructure Layer (M3.4)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.infrastructure.db.models import AuditLogModel

# Chaves sensíveis que devem ser estritamente removidas/mascaradas dos logs de auditoria
SENSITIVE_KEYS = {
    "token",
    "password",
    "secret",
    "credential_reference",
    "authorization_reference",
    "auth_header",
    "file_content",
    "file_bytes",
    "raw_paste",
    "api_key",
}


def sanitize_audit_details(details: dict[str, Any]) -> dict[str, Any]:
    """Sanitiza os detalhes da alteração removendo credenciais e segredos."""
    sanitized: dict[str, Any] = {}
    for key, value in details.items():
        key_lower = key.lower()
        if any(s in key_lower for s in SENSITIVE_KEYS):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_audit_details(value)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_audit_details(item) if isinstance(item, dict) else (str(item.value) if hasattr(item, "value") else str(item))
                for item in value
            ]
        elif isinstance(value, UUID):
            sanitized[key] = str(value)
        elif isinstance(value, datetime):
            sanitized[key] = value.isoformat()
        elif hasattr(value, "value"):
            sanitized[key] = str(value.value)
        else:
            sanitized[key] = value
    return sanitized


logger = logging.getLogger(__name__)


async def record_asset_audit_log(
    db: AsyncSession,
    tenant_id: UUID | str,
    user_id: UUID | str | None,
    action: str,
    resource_type: str,
    resource_id: UUID | str,
    details: dict[str, Any],
    correlation_id: str | None = None,
) -> None:
    """Registra uma entrada de auditoria operacional sanitizada no PostgreSQL."""
    try:
        sanitized = sanitize_audit_details(details)
        raw_payload = {
            "action": action,
            "resource_type": resource_type,
            "resource_id": str(resource_id),
            "user_id": str(user_id) if user_id else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id,
            "details": sanitized,
        }

        t_uuid = tenant_id if isinstance(tenant_id, UUID) else UUID(str(tenant_id))

        model = AuditLogModel(
            id=uuid4(),
            tenant_id=t_uuid,
            source=resource_type,
            raw_data=json.dumps(raw_payload),
            timestamp=datetime.now(timezone.utc),
        )
        db.add(model)
    except Exception as err:
        logger.warning("Falha ao registrar log de auditoria operacional: %s", err)
