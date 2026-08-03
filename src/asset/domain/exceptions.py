"""
Exceções de Domínio para o Módulo de Gestão de Ativos e Scanners (M3.4).
GovSec Shield — Domain Layer
"""

from src.core.domain.exceptions import DomainError


class AssetDomainError(DomainError):
    """Exceção base para erros do domínio de ativos e scanners."""

    pass


class InvalidTargetError(AssetDomainError):
    """Lançada quando um alvo de scanner possui formato ou faixa inválida."""

    pass


class InvalidStatusTransitionError(AssetDomainError):
    """Lançada quando uma transição de estado de execução ou vulnerabilidade é inválida."""

    pass


class TargetNotFoundError(AssetDomainError):
    """Lançada quando um alvo ou entidade não é encontrada."""

    pass


class ScheduleOverlapError(AssetDomainError):
    """Lançada quando um agendamento viola a política de sobreposição."""

    pass


class UnauthorizedPublicTargetError(AssetDomainError):
    """Lançada quando um alvo público é cadastrado sem autorização configurada."""

    pass


class InvalidPortError(AssetDomainError):
    """Lançada quando uma porta de rede informada é inválida."""

    pass


class InvalidCVSSError(AssetDomainError):
    """Lançada quando a pontuação CVSS está fora do intervalo 0.0 a 10.0."""

    pass
