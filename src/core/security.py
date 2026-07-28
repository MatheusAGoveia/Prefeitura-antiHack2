"""
Módulo de Validação de Escopo de Segurança (Scope Safety)
GovSec Shield — Core Security Policy
"""

import ipaddress

from pydantic import BaseModel, Field, ValidationInfo, field_validator


class ScopeSafetyConfig(BaseModel):
    """
    Configuração e validação estrita de escopo (Whitelist de Sub-redes CIDR).
    Garante que o scanner se recuse a executar se o IP alvo não estiver dentro das
    sub-redes autorizadas da prefeitura.
    """

    allowed_cidrs: list[str] = Field(
        default=[
            "189.14.0.0/16",  # Faixa pública da Prefeitura (Exemplo)
            "10.200.0.0/15",  # Rede interna de servidores
            "172.16.0.0/12",  # Rede corporativa
            "127.0.0.1/32",  # Loopback para testes locais
        ],
        description="Lista de blocos CIDR autorizados para escaneamento e auditoria.",
    )

    @classmethod
    @field_validator("allowed_cidrs")
    def validate_cidrs(cls, v: list[str]) -> list[str]:
        validated = []
        for cidr in v:
            try:
                ipaddress.ip_network(cidr, strict=False)
                validated.append(cidr)
            except ValueError as err:
                raise ValueError(f"Bloco CIDR inválido na Whitelist de Escopo: {cidr}") from err
        return validated

    def is_target_allowed(self, target_ip: str) -> bool:
        """
        Valida se um IP alvo individual ou bloco está estritamente dentro da whitelist autorizada.
        """
        try:
            target_net = ipaddress.ip_network(target_ip, strict=False)
        except ValueError:
            return False

        for allowed_cidr in self.allowed_cidrs:
            allowed_net = ipaddress.ip_network(allowed_cidr, strict=False)
            if target_net.version == allowed_net.version:
                if (
                    isinstance(target_net, ipaddress.IPv4Network)
                    and isinstance(allowed_net, ipaddress.IPv4Network)
                    and target_net.subnet_of(allowed_net)
                ):
                    return True
                if (
                    isinstance(target_net, ipaddress.IPv6Network)
                    and isinstance(allowed_net, ipaddress.IPv6Network)
                    and target_net.subnet_of(allowed_net)
                ):
                    return True
        return False


class TargetScopeRequest(BaseModel):
    """
    DTO para requisição de target com Scope Safety integrado.
    """

    target_ip: str = Field(..., description="IP ou CIDR alvo para varredura")
    tenant_id: str = Field(..., description="Identificador único do Tenant")

    @classmethod
    @field_validator("target_ip")
    def check_target_safety(cls, v: str, info: ValidationInfo) -> str:
        config = ScopeSafetyConfig()
        if not config.is_target_allowed(v):
            raise ValueError(
                f"[SCOPE SAFETY VIOLATION] O IP/CIDR '{v}' NÃO pertence às sub-redes autorizadas da Prefeitura. Execução abortada."
            )
        return v
