"""
Módulo de Validações Puras do Domínio Core
GovSec Shield — Domain Validation Helpers

Este módulo contém funções puras de validação de domínio sem qualquer dependência
de infraestrutura ou frameworks externos.
"""

from datetime import datetime, timedelta
from typing import Any

from src.core.domain.exceptions import DomainError


def validate_utc_datetime(dt: Any, field_name: str) -> None:
    """
    Valida estritamente se um valor é um datetime timezone-aware com fuso horário UTC (+00:00).
    Rejeita valores não-datetime, datetimes ingênuos (naive) e datetimes com offset diferente de UTC.
    """
    if not isinstance(dt, datetime):
        raise DomainError(f"'{field_name}' deve ser um datetime, recebido: '{type(dt).__name__}'")
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise DomainError(f"'{field_name}' deve possuir fuso horário explícito (timezone-aware).")
    if dt.utcoffset() != timedelta(0):
        raise DomainError(f"'{field_name}' deve possuir fuso horário estritamente UTC (+00:00).")
