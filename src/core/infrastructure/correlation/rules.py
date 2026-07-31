"""
Regras de Correlação Determinísticas Concretas.
GovSec Shield — Infrastructure Correlation Rules (M3.2)

Implementações concretas de CorrelationRule (ABC do domínio).
Cada regra é:
  - Tipada e versionada (SemVer)
  - Explicável: critérios documentados como docstring
  - Sem efeitos colaterais (evaluate é puro — recebe eventos, retorna chaves)
  - Sem dependência de SQLAlchemy, FastAPI, Redis ou Kafka
"""

from collections.abc import Sequence
from uuid import UUID

from src.core.domain.correlation import CorrelationKey, CorrelationRule
from src.core.domain.incidents import SecurityEvent, SecurityEventSeverity


class InfraAvailabilityRule(CorrelationRule):
    """
    Regra R-INFRA-001: Disponibilidade de Infraestrutura.

    Critério de elegibilidade:
      - event_type contém 'down', 'unreachable', 'timeout', 'failure' ou 'unavailable'
      - OU severity >= HIGH

    Todos os eventos elegíveis dentro da mesma janela temporal, do mesmo tenant
    e do mesmo asset (ou source:event_type quando sem asset) são agrupados no
    mesmo incidente.

    Versão: 1.0.0
    Categoria: availability
    """

    @property
    def rule_id(self) -> str:
        return "R-INFRA-001"

    @property
    def rule_name(self) -> str:
        return "Disponibilidade de Infraestrutura"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "availability"

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[CorrelationKey]:
        """
        Avalia os eventos e retorna as chaves de correlação para os eventos elegíveis.
        A janela temporal e o asset_key são definidos externamente pelo handler.
        Este método apenas determina elegibilidade — não computa o bucket temporal
        (responsabilidade do CorrelationHandler que constrói a CorrelationKey).
        """
        eligible_keywords = {"down", "unreachable", "timeout", "failure", "unavailable"}
        high_severities = {SecurityEventSeverity.HIGH, SecurityEventSeverity.CRITICAL}

        keys = []
        for event in events:
            event_type_lower = event.event_type.lower()
            is_type_eligible = any(kw in event_type_lower for kw in eligible_keywords)
            is_severity_eligible = event.severity in high_severities

            if is_type_eligible or is_severity_eligible:
                asset_key = (
                    str(event.asset_id)
                    if event.asset_id is not None
                    else f"{event.source}:{event.event_type}"
                )
                # time_window é preenchido pelo handler com o bucket correto
                keys.append(
                    CorrelationKey(
                        tenant_id=event.tenant_id,
                        rule_id=self.rule_id,
                        rule_version=self.version,
                        asset_key=asset_key,
                        category=self.category,
                        time_window="placeholder",  # sobrescrito pelo handler
                    )
                )
        return keys

    def is_eligible(self, event: SecurityEvent) -> bool:
        """Verifica se um único evento é elegível para esta regra."""
        eligible_keywords = {"down", "unreachable", "timeout", "failure", "unavailable"}
        high_severities = {SecurityEventSeverity.HIGH, SecurityEventSeverity.CRITICAL}
        event_type_lower = event.event_type.lower()
        return (
            any(kw in event_type_lower for kw in eligible_keywords)
            or event.severity in high_severities
        )


class AuthBruteForceRule(CorrelationRule):
    """
    Regra R-AUTH-001: Força Bruta de Autenticação.

    Critério de elegibilidade:
      - event_type contém 'login_failed', 'auth_failure', 'brute_force' ou 'invalid_credentials'

    Agrupa tentativas de login falhas do mesmo ativo dentro da janela temporal.

    Versão: 1.0.0
    Categoria: authentication
    """

    @property
    def rule_id(self) -> str:
        return "R-AUTH-001"

    @property
    def rule_name(self) -> str:
        return "Força Bruta de Autenticação"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def category(self) -> str:
        return "authentication"

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[CorrelationKey]:
        eligible_keywords = {"login_failed", "auth_failure", "brute_force", "invalid_credentials"}
        keys = []
        for event in events:
            event_type_lower = event.event_type.lower()
            if any(kw in event_type_lower for kw in eligible_keywords):
                asset_key = (
                    str(event.asset_id)
                    if event.asset_id is not None
                    else f"{event.source}:{event.event_type}"
                )
                keys.append(
                    CorrelationKey(
                        tenant_id=event.tenant_id,
                        rule_id=self.rule_id,
                        rule_version=self.version,
                        asset_key=asset_key,
                        category=self.category,
                        time_window="placeholder",
                    )
                )
        return keys

    def is_eligible(self, event: SecurityEvent) -> bool:
        eligible_keywords = {"login_failed", "auth_failure", "brute_force", "invalid_credentials"}
        return any(kw in event.event_type.lower() for kw in eligible_keywords)


# Registro das regras disponíveis por rule_id
AVAILABLE_RULES: dict[str, CorrelationRule] = {
    "R-INFRA-001": InfraAvailabilityRule(),
    "R-AUTH-001": AuthBruteForceRule(),
}


def get_rules_for_tenant(tenant_id: UUID) -> list[CorrelationRule]:
    """
    Retorna as regras de correlação disponíveis para um tenant.
    Nesta versão, todas as regras são globais (sem configuração por-tenant).
    Em M3.3, esta função deve consultar um repositório de configuração por-tenant.
    """
    return list(AVAILABLE_RULES.values())
