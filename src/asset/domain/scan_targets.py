"""
Entidades, Enums e Validações para Alvos de Scanner (ScanTarget).
GovSec Shield — Domain Layer (M3.4)
"""

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from src.asset.domain.exceptions import (
    AssetDomainError,
    InvalidTargetError,
    UnauthorizedPublicTargetError,
)
from src.core.domain.validation import validate_utc_datetime

# Pattern para hostname RFC 1123
_HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


class TargetType(StrEnum):
    """Tipos aceitos para alvos de scanner."""

    SINGLE_IP = "single_ip"
    CIDR = "cidr"
    IP_RANGE = "ip_range"
    HOSTNAME = "hostname"


@dataclass(frozen=True)
class TargetValidationResult:
    """Resultado detalhado da validação de um alvo de rede."""

    is_valid: bool
    target_type: TargetType
    normalized_value: str
    first_ip: str | None
    last_ip: str | None
    estimated_addresses: int
    security_warnings: list[str]
    error_message: str | None = None


class IPTargetValidator:
    """Validador defensivo de alvos de scanner (IP, CIDR, Intervalo, Hostname)."""

    MAX_ESTIMATED_ADDRESSES_PER_TARGET = 65536  # Limite de segurança para 1 alvo (/16 IPv4)

    @classmethod
    def validate_and_normalize(
        cls,
        target_type: TargetType | str,
        target_value: str,
        allow_public_targets: bool = False,
    ) -> TargetValidationResult:
        if not target_value or not target_value.strip():
            return TargetValidationResult(
                is_valid=False,
                target_type=TargetType(target_type),
                normalized_value="",
                first_ip=None,
                last_ip=None,
                estimated_addresses=0,
                security_warnings=[],
                error_message="O valor do alvo de scanner não pode ser vazio.",
            )

        raw_value = target_value.strip()
        t_type = TargetType(target_type) if isinstance(target_type, str) else target_type
        warnings: list[str] = []

        try:
            if t_type == TargetType.SINGLE_IP:
                ip_obj = ipaddress.ip_address(raw_value)
                cls._check_public_ip(ip_obj, allow_public_targets, warnings)
                norm = str(ip_obj)
                return TargetValidationResult(
                    is_valid=True,
                    target_type=t_type,
                    normalized_value=norm,
                    first_ip=norm,
                    last_ip=norm,
                    estimated_addresses=1,
                    security_warnings=warnings,
                )

            elif t_type == TargetType.CIDR:
                net_obj = ipaddress.ip_network(raw_value, strict=False)
                # Verifica IP da rede
                cls._check_public_ip(net_obj.network_address, allow_public_targets, warnings)
                total_ips = net_obj.num_addresses
                if total_ips > cls.MAX_ESTIMATED_ADDRESSES_PER_TARGET:
                    raise InvalidTargetError(
                        f"Bloco CIDR possui {total_ips} endereços, o que excede o limite máximo permitido ({cls.MAX_ESTIMATED_ADDRESSES_PER_TARGET})."
                    )

                norm = str(net_obj)
                return TargetValidationResult(
                    is_valid=True,
                    target_type=t_type,
                    normalized_value=norm,
                    first_ip=str(net_obj.network_address),
                    last_ip=str(net_obj.broadcast_address),
                    estimated_addresses=total_ips,
                    security_warnings=warnings,
                )

            elif t_type == TargetType.IP_RANGE:
                parts = [p.strip() for p in raw_value.split("-") if p.strip()]
                if len(parts) != 2:
                    raise InvalidTargetError(
                        "Intervalo de IP deve seguir o formato 'IP_INICIAL-IP_FINAL' (ex: 10.10.1.10-10.10.1.50)."
                    )
                start_ip = ipaddress.ip_address(parts[0])
                end_ip = ipaddress.ip_address(parts[1])

                if start_ip.version != end_ip.version:
                    raise InvalidTargetError(
                        "IP inicial e IP final de um intervalo devem pertencer à mesma versão do protocolo (IPv4 ou IPv6)."
                    )

                if int(end_ip) < int(start_ip):
                    raise InvalidTargetError(
                        f"IP final ({end_ip}) é menor que o IP inicial ({start_ip})."
                    )

                cls._check_public_ip(start_ip, allow_public_targets, warnings)
                cls._check_public_ip(end_ip, allow_public_targets, warnings)

                total_ips = int(end_ip) - int(start_ip) + 1
                if total_ips > cls.MAX_ESTIMATED_ADDRESSES_PER_TARGET:
                    raise InvalidTargetError(
                        f"Intervalo de IP possui {total_ips} endereços, excedendo o limite de segurança ({cls.MAX_ESTIMATED_ADDRESSES_PER_TARGET})."
                    )

                norm = f"{start_ip}-{end_ip}"
                return TargetValidationResult(
                    is_valid=True,
                    target_type=t_type,
                    normalized_value=norm,
                    first_ip=str(start_ip),
                    last_ip=str(end_ip),
                    estimated_addresses=total_ips,
                    security_warnings=warnings,
                )

            elif t_type == TargetType.HOSTNAME:
                if len(raw_value) > 253 or not _HOSTNAME_REGEX.match(raw_value):
                    raise InvalidTargetError(f"Hostname inválido: '{raw_value}'.")

                norm = raw_value.lower()
                return TargetValidationResult(
                    is_valid=True,
                    target_type=t_type,
                    normalized_value=norm,
                    first_ip=None,
                    last_ip=None,
                    estimated_addresses=1,
                    security_warnings=warnings,
                )

            else:
                raise InvalidTargetError(f"Tipo de alvo não suportado: {t_type}")

        except (ValueError, InvalidTargetError, UnauthorizedPublicTargetError) as exc:
            return TargetValidationResult(
                is_valid=False,
                target_type=t_type,
                normalized_value=raw_value,
                first_ip=None,
                last_ip=None,
                estimated_addresses=0,
                security_warnings=warnings,
                error_message=str(exc),
            )

    @classmethod
    def validate_target(
        cls, raw_value: str, allow_public_targets: bool = False
    ) -> TargetValidationResult:
        v = raw_value.strip()
        if "/" in v:
            t_type = TargetType.CIDR
        elif "-" in v:
            t_type = TargetType.IP_RANGE
        else:
            try:
                ipaddress.ip_address(v)
                t_type = TargetType.SINGLE_IP
            except ValueError:
                t_type = TargetType.HOSTNAME

        return cls.validate_and_normalize(
            target_type=t_type,
            target_value=v,
            allow_public_targets=allow_public_targets,
        )

    @classmethod
    def _check_public_ip(
        cls,
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
        allow_public: bool,
        warnings: list[str],
    ) -> None:
        is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        if not is_private:
            if not allow_public:
                raise UnauthorizedPublicTargetError(
                    f"O IP '{ip_obj}' é público e alvos públicos não são autorizados por padrão."
                )
            warnings.append(f"Atenção: O IP '{ip_obj}' é público. Certifique-se de possuir autorização prévia.")


@dataclass
class ScanTarget:
    """Entidade que representa um alvo autorizado para scanners."""

    id: UUID
    tenant_id: UUID
    asset_group_id: UUID
    name: str
    target_type: TargetType
    target_value: str
    description: str | None
    enabled: bool
    authorization_reference: str | None
    last_discovered_at: datetime | None
    created_at: datetime
    updated_at: datetime
    created_by: UUID
    updated_by: UUID | None = None

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise AssetDomainError("O nome do alvo de scanner é obrigatório.")
        self.name = self.name.strip()
        validate_utc_datetime(self.created_at, "created_at")
        validate_utc_datetime(self.updated_at, "updated_at")
        if self.last_discovered_at is not None:
            validate_utc_datetime(self.last_discovered_at, "last_discovered_at")

        # Validação do valor e tipo
        res = IPTargetValidator.validate_and_normalize(self.target_type, self.target_value)
        if not res.is_valid:
            raise InvalidTargetError(res.error_message or "Alvo de scanner inválido.")
        self.target_value = res.normalized_value

    @classmethod
    def create(
        cls,
        tenant_id: UUID,
        asset_group_id: UUID,
        name: str,
        target_type: TargetType,
        target_value: str,
        created_by: UUID,
        description: str | None = None,
        authorization_reference: str | None = None,
        enabled: bool = True,
        allow_public_targets: bool = False,
    ) -> "ScanTarget":
        val_res = IPTargetValidator.validate_and_normalize(
            target_type=target_type,
            target_value=target_value,
            allow_public_targets=allow_public_targets,
        )
        if not val_res.is_valid:
            raise InvalidTargetError(val_res.error_message or "Alvo de scanner inválido.")

        now = datetime.now(timezone.utc)
        return cls(
            id=uuid4(),
            tenant_id=tenant_id,
            asset_group_id=asset_group_id,
            name=name,
            target_type=val_res.target_type,
            target_value=val_res.normalized_value,
            description=description,
            enabled=enabled,
            authorization_reference=authorization_reference,
            last_discovered_at=None,
            created_at=now,
            updated_at=now,
            created_by=created_by,
            updated_by=None,
        )

    def update(
        self,
        name: str | None = None,
        target_type: TargetType | None = None,
        target_value: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        authorization_reference: str | None = None,
        asset_group_id: UUID | None = None,
        updated_by: UUID | None = None,
        allow_public_targets: bool = False,
    ) -> None:
        if name is not None:
            if not name or not name.strip():
                raise AssetDomainError("O nome do alvo de scanner é obrigatório.")
            self.name = name.strip()

        if description is not None:
            self.description = description

        if enabled is not None:
            self.enabled = enabled

        if authorization_reference is not None:
            self.authorization_reference = authorization_reference

        if asset_group_id is not None:
            self.asset_group_id = asset_group_id

        if target_value is not None or target_type is not None:
            new_type = target_type or self.target_type
            new_val = target_value if target_value is not None else self.target_value
            res = IPTargetValidator.validate_and_normalize(
                target_type=new_type,
                target_value=new_val,
                allow_public_targets=allow_public_targets,
            )
            if not res.is_valid:
                raise InvalidTargetError(res.error_message or "Alvo de scanner inválido.")
            self.target_type = res.target_type
            self.target_value = res.normalized_value

        self.updated_at = datetime.now(timezone.utc)
        if updated_by is not None:
            self.updated_by = updated_by
