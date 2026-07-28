"""
Mascaramento de Dados Sensíveis (Data Sanitizer)
GovSec Shield — Shared Observability

Responsável por garantir que nenhum dado sensível (PII, credenciais, tokens)
seja exposto em texto plano nos logs estruturados do sistema.

Padrões cobertos:
- Tokens JWT / Bearer (Authorization header)
- Senhas em payloads JSON
- CPF brasileiro
- Números de cartão de crédito (PAN)
- E-mails
- Chaves de API / Secret Keys
"""

import re
from typing import Any


class DataMasker:
    """
    Mascarador de dados sensíveis para campos de log e payloads.

    Utiliza expressões regulares para identificar e substituir dados PII
    e credenciais por valores redacted, preservando a estrutura dos dados.

    Arquitetura:
        - Segue o padrão Strategy com lista extensível de (pattern, replacement)
        - Operação é stateless: sem efeitos colaterais em objetos externos
        - Aplicado pelo GovSecJSONFormatter antes da serialização JSON
    """

    # Campos de dicionário/JSON que sempre devem ser mascarados pelo nome
    _SENSITIVE_KEYS: frozenset[str] = frozenset(
        {
            "password",
            "senha",
            "secret",
            "token",
            "access_token",
            "refresh_token",
            "api_key",
            "apikey",
            "private_key",
            "client_secret",
            "authorization",
            "credential",
            "credentials",
        }
    )

    # Padrões regex para mascaramento em strings de texto livre
    _TEXT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
        # Bearer / JWT Token (Authorization: Bearer <token>)
        (
            re.compile(r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", re.IGNORECASE),
            "Bearer [REDACTED_JWT]",
        ),
        # JWT standalone (header.payload.signature)
        (
            re.compile(r"\b[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b"),
            "[REDACTED_JWT]",
        ),
        # CPF Brasileiro (XXX.XXX.XXX-XX ou XXXXXXXXXXX)
        (
            re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
            "[REDACTED_CPF]",
        ),
        # Número de Cartão de Crédito (PAN — 13-19 dígitos com espaços/hífens opcionais)
        (
            re.compile(r"\b(?:\d[\s\-]?){13,19}\b"),
            "[REDACTED_PAN]",
        ),
        # E-mail
        (
            re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
            "[REDACTED_EMAIL]",
        ),
        # Senha em query string / JSON (?password=xxx ou "password": "xxx")
        (
            re.compile(r"(password|senha|secret|token|api_key)[=:\s\"\']+[^\s&\"\']{4,}", re.IGNORECASE),
            r"\1=[REDACTED]",
        ),
    ]

    def mask_text(self, text: str) -> str:
        """
        Aplica todos os padrões de mascaramento em uma string de texto livre.

        Args:
            text: String de texto livre (ex: mensagem de log, URL, payload serializado).

        Returns:
            String com todos os padrões sensíveis substituídos por placeholders.
        """
        for pattern, replacement in self._TEXT_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def mask_dict(self, data: dict[str, Any], depth: int = 0) -> dict[str, Any]:
        """
        Mascara recursivamente valores sensíveis em um dicionário.

        Chaves presentes em `_SENSITIVE_KEYS` têm seus valores substituídos
        por `[REDACTED]`. Valores string são inspecionados via `mask_text`.
        Dicionários aninhados são processados recursivamente (limite de 10 níveis).

        Args:
            data: Dicionário de entrada (ex: payload de log, corpo de request).
            depth: Profundidade atual da recursão (proteção anti-loop).

        Returns:
            Novo dicionário com dados sensíveis mascarados.
        """
        if depth > 10:
            return data

        masked: dict[str, Any] = {}
        for key, value in data.items():
            if key.lower() in self._SENSITIVE_KEYS:
                masked[key] = "[REDACTED]"
            elif isinstance(value, dict):
                masked[key] = self.mask_dict(value, depth=depth + 1)
            elif isinstance(value, list):
                masked[key] = self._mask_list(value, depth=depth + 1)
            elif isinstance(value, str):
                masked[key] = self.mask_text(value)
            else:
                masked[key] = value
        return masked

    def _mask_list(self, items: list[Any], depth: int) -> list[Any]:
        """Mascara recursivamente elementos de uma lista."""
        masked_items: list[Any] = []
        for item in items:
            if isinstance(item, dict):
                masked_items.append(self.mask_dict(item, depth=depth + 1))
            elif isinstance(item, str):
                masked_items.append(self.mask_text(item))
            else:
                masked_items.append(item)
        return masked_items

    def mask(self, data: dict[str, Any] | str) -> dict[str, Any] | str:
        """
        Ponto de entrada principal do mascaramento.

        Despacha para `mask_text` ou `mask_dict` com base no tipo de entrada.

        Args:
            data: String ou dicionário a ser mascarado.

        Returns:
            Dado mascarado no mesmo tipo que a entrada.
        """
        if isinstance(data, str):
            return self.mask_text(data)
        if isinstance(data, dict):
            return self.mask_dict(data)
        return data


# Instância singleton global para reuso eficiente em todo o sistema
data_masker: DataMasker = DataMasker()
