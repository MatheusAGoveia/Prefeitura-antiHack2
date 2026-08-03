"""
Entidades e Enums para Vulnerabilidades Descobertas (VulnerabilityFinding).
GovSec Shield — Domain Layer (M3.4)
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from src.asset.domain.exceptions import (
    AssetDomainError,
    InvalidCVSSError,
    InvalidStatusTransitionError,
)
from src.core.domain.validation import validate_utc_datetime
from src.shared.observability.sanitizer import data_masker

_CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


class VulnerabilitySeverity(StrEnum):
    """Níveis de severidade para achados de vulnerabilidade."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityStatus(StrEnum):
    """Estados do ciclo de vida de uma vulnerabilidade."""

    OPEN = "open"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    REOPENED = "reopened"


ALLOWED_VULNERABILITY_TRANSITIONS: dict[VulnerabilityStatus, set[VulnerabilityStatus]] = {
    VulnerabilityStatus.OPEN: {VulnerabilityStatus.ACCEPTED, VulnerabilityStatus.FALSE_POSITIVE, VulnerabilityStatus.RESOLVED},
    VulnerabilityStatus.REOPENED: {VulnerabilityStatus.ACCEPTED, VulnerabilityStatus.FALSE_POSITIVE, VulnerabilityStatus.RESOLVED},
    VulnerabilityStatus.ACCEPTED: {VulnerabilityStatus.OPEN, VulnerabilityStatus.RESOLVED},
    VulnerabilityStatus.FALSE_POSITIVE: {VulnerabilityStatus.OPEN, VulnerabilityStatus.RESOLVED},
    VulnerabilityStatus.RESOLVED: {VulnerabilityStatus.REOPENED, VulnerabilityStatus.OPEN},
}


@dataclass
class VulnerabilityStatusHistory:
    """Registro auditável de mudança de status de uma vulnerabilidade."""

    id: UUID
    tenant_id: UUID
    finding_id: UUID
    from_status: VulnerabilityStatus
    to_status: VulnerabilityStatus
    justification: str | None
    changed_by: UUID
    changed_at: datetime

    def __post_init__(self) -> None:
        validate_utc_datetime(self.changed_at, "changed_at")


@dataclass
class VulnerabilityFinding:
    """Representa um achado de vulnerabilidade em um ativo ou serviço."""

    id: UUID
    tenant_id: UUID
    asset_id: UUID
    scan_execution_id: UUID
    title: str
    severity: VulnerabilitySeverity
    status: VulnerabilityStatus
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    deduplication_hash: str
    asset_service_id: UUID | None = None
    external_id: str | None = None
    cve_id: str | None = None
    description: str | None = None
    cvss_score: Decimal | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None
    resolved_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.title or not self.title.strip():
            raise AssetDomainError("O título da vulnerabilidade é obrigatório.")
        self.title = self.title.strip()

        if self.cve_id:
            cve_clean = self.cve_id.strip().upper()
            if not _CVE_REGEX.match(cve_clean):
                raise AssetDomainError(f"Identificador CVE inválido: '{self.cve_id}'. Exemplo válido: 'CVE-2026-1234'.")
            self.cve_id = cve_clean

        if self.cvss_score is not None and not (Decimal("0.0") <= self.cvss_score <= Decimal("10.0")):
            raise InvalidCVSSError(f"Pontuação CVSS inválida: {self.cvss_score}. Deve estar entre 0.0 e 10.0.")

        validate_utc_datetime(self.first_seen_at, "first_seen_at")
        validate_utc_datetime(self.last_seen_at, "last_seen_at")
        validate_utc_datetime(self.created_at, "created_at")
        validate_utc_datetime(self.updated_at, "updated_at")
        if self.resolved_at is not None:
            validate_utc_datetime(self.resolved_at, "resolved_at")

        # Sanitizar evidências contra dados sensíveis
        if self.evidence:
            self.evidence = data_masker.mask_dict(self.evidence)

    @classmethod
    def compute_deduplication_hash(
        cls,
        tenant_id: UUID,
        asset_id: UUID,
        cve_id: str | None,
        external_id: str | None,
        title: str,
        asset_service_id: UUID | None = None,
    ) -> str:
        """Gera uma chave SHA-256 estável para deduplicação de achados repetidos."""
        key_parts = [
            str(tenant_id),
            str(asset_id),
            str(asset_service_id) if asset_service_id else "",
            cve_id.upper() if cve_id else "",
            external_id if external_id else "",
            title.strip().lower(),
        ]
        raw_key = "|".join(key_parts)
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        tenant_id: UUID,
        asset_id: UUID,
        scan_execution_id: UUID,
        title: str,
        severity: VulnerabilitySeverity,
        asset_service_id: UUID | None = None,
        external_id: str | None = None,
        cve_id: str | None = None,
        description: str | None = None,
        cvss_score: Decimal | float | None = None,
        evidence: dict[str, Any] | None = None,
        remediation: str | None = None,
    ) -> "VulnerabilityFinding":
        now = datetime.now(timezone.utc)
        cvss_dec = Decimal(str(cvss_score)) if cvss_score is not None else None
        dedup = cls.compute_deduplication_hash(
            tenant_id=tenant_id,
            asset_id=asset_id,
            cve_id=cve_id,
            external_id=external_id,
            title=title,
            asset_service_id=asset_service_id,
        )

        return cls(
            id=uuid4(),
            tenant_id=tenant_id,
            asset_id=asset_id,
            asset_service_id=asset_service_id,
            scan_execution_id=scan_execution_id,
            external_id=external_id,
            cve_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_dec,
            status=VulnerabilityStatus.OPEN,
            evidence=evidence or {},
            remediation=remediation,
            first_seen_at=now,
            last_seen_at=now,
            resolved_at=None,
            created_at=now,
            updated_at=now,
            deduplication_hash=dedup,
        )

    def change_status(
        self,
        new_status: VulnerabilityStatus,
        changed_by: UUID,
        justification: str | None = None,
    ) -> VulnerabilityStatusHistory:
        """Altera o status da vulnerabilidade registrando histórico e validações."""
        allowed = ALLOWED_VULNERABILITY_TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            raise InvalidStatusTransitionError(
                f"Transição de status de vulnerabilidade inválida de '{self.status}' para '{new_status}'."
            )

        if new_status in (VulnerabilityStatus.ACCEPTED, VulnerabilityStatus.FALSE_POSITIVE) and (not justification or not justification.strip()):
            raise InvalidStatusTransitionError(
                f"Justificativa técnica é obrigatória para transição para o status '{new_status}'."
            )

        old_status = self.status
        self.status = new_status
        now = datetime.now(timezone.utc)
        self.updated_at = now

        if new_status == VulnerabilityStatus.RESOLVED:
            self.resolved_at = now
        elif old_status == VulnerabilityStatus.RESOLVED and new_status != VulnerabilityStatus.RESOLVED:  # type: ignore[comparison-overlap]
            self.resolved_at = None

        return VulnerabilityStatusHistory(
            id=uuid4(),
            tenant_id=self.tenant_id,
            finding_id=self.id,
            from_status=old_status,
            to_status=new_status,
            justification=justification.strip() if justification else None,
            changed_by=changed_by,
            changed_at=now,
        )
