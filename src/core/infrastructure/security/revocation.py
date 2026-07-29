"""
Persistência e Validação de Revogação de JWT (Token Revocation / Blacklist)
GovSec Shield — Infrastructure Security
"""

import hashlib
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from src.core.infrastructure.config import settings

logger = logging.getLogger("govsec.security.revocation")


def _get_token_identifier(token: str, payload: dict[str, Any] | None = None) -> str:
    """Extrai o JTI do payload se existente; caso contrário, computa o hash SHA-256 do token."""
    if payload and "jti" in payload and payload["jti"]:
        return str(payload["jti"])
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class BaseTokenRevocationStore(ABC):
    @abstractmethod
    def revoke(self, token: str, payload: dict[str, Any] | None = None) -> None:
        """Revoga um token registrando seu JTI ou Hash."""
        pass

    @abstractmethod
    def is_revoked(self, token: str, payload: dict[str, Any] | None = None) -> bool:
        """Verifica se o token está revogado."""
        pass


class InMemoryTokenRevocationStore(BaseTokenRevocationStore):
    def __init__(self) -> None:
        self._revoked: dict[str, float] = {}

    def revoke(self, token: str, payload: dict[str, Any] | None = None) -> None:
        ident = _get_token_identifier(token, payload)
        exp = payload.get("exp") if payload else None
        if isinstance(exp, int | float):
            exp_ts = float(exp)
        else:
            exp_ts = datetime.now(timezone.utc).timestamp() + 28800.0

        self._revoked[ident] = exp_ts
        logger.info("TOKEN_REVOKED_IN_MEMORY | ident=%s exp=%s", ident, exp_ts)

    def is_revoked(self, token: str, payload: dict[str, Any] | None = None) -> bool:
        ident = _get_token_identifier(token, payload)
        exp_ts = self._revoked.get(ident)
        if exp_ts is None:
            return False

        now_ts = datetime.now(timezone.utc).timestamp()
        if now_ts > exp_ts:
            # Token expirado limpo da memória
            self._revoked.pop(ident, None)
            return False
        return True


class RedisTokenRevocationStore(BaseTokenRevocationStore):
    def __init__(self, redis_url: str | None = None) -> None:
        self._redis_url = redis_url or settings.GOVSEC_REDIS_URL
        self._client: Any = None

    def _get_client(self) -> Any:

        if self._client is None:
            try:
                import redis

                self._client = redis.Redis.from_url(self._redis_url, decode_responses=True, socket_timeout=3.0)
            except Exception as e:
                logger.error("REDIS_CONNECTION_FAILED | url=%s error=%s", self._redis_url, e)
                if settings.GOVSEC_ENV in ("staging", "production"):
                    raise RuntimeError(
                        f"🚨 [FAIL-CLOSED] Erro ao conectar ao Redis de revogação ({self._redis_url}) em ambiente '{settings.GOVSEC_ENV}': {e}"
                    ) from e
                return None
        return self._client

    def revoke(self, token: str, payload: dict[str, Any] | None = None) -> None:
        client = self._get_client()
        if client is None:
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RuntimeError(
                    f"🚨 [FAIL-CLOSED] Redis de revogação indisponível em '{settings.GOVSEC_ENV}'."
                )
            return

        ident = _get_token_identifier(token, payload)
        key = f"govsec:jwt:revoked:{ident}"

        now_ts = datetime.now(timezone.utc).timestamp()
        exp = payload.get("exp") if payload else None
        ttl = int(float(exp) - now_ts) if isinstance(exp, int | float) else 28800

        if ttl <= 0:
            ttl = 60  # Mínimo de expiração

        try:
            client.setex(key, ttl, "1")
            logger.info("TOKEN_REVOKED_REDIS | key=%s ttl=%ss", key, ttl)
        except Exception as e:
            logger.error("REDIS_REVOKE_ERROR | key=%s error=%s", key, e)
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RuntimeError(
                    f"🚨 [FAIL-CLOSED] Falha ao gravar revogação no Redis em '{settings.GOVSEC_ENV}': {e}"
                ) from e

    def is_revoked(self, token: str, payload: dict[str, Any] | None = None) -> bool:
        client = self._get_client()
        if client is None:
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RuntimeError(
                    f"🚨 [FAIL-CLOSED] Redis de revogação indisponível em '{settings.GOVSEC_ENV}'."
                )
            return False

        ident = _get_token_identifier(token, payload)
        key = f"govsec:jwt:revoked:{ident}"
        try:
            exists = client.exists(key)
            return bool(exists)
        except Exception as e:
            logger.error("REDIS_CHECK_ERROR | key=%s error=%s", key, e)
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RuntimeError(
                    f"🚨 [FAIL-CLOSED] Falha ao verificar revogação no Redis em '{settings.GOVSEC_ENV}': {e}"
                ) from e
            return False


def get_token_revocation_store() -> BaseTokenRevocationStore:
    if settings.GOVSEC_ENV in ("staging", "production"):
        return RedisTokenRevocationStore()
    return InMemoryTokenRevocationStore()


# Singleton padrão de revogação de tokens
revocation_store: BaseTokenRevocationStore = get_token_revocation_store()
