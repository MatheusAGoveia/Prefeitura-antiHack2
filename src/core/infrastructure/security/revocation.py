"""
Persistência e Validação de Revogação de JWT Não-Bloqueante (redis.asyncio)
GovSec Shield — Infrastructure Security
"""

import hashlib
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from src.core.domain.exceptions import RedisRevocationUnavailableError
from src.core.infrastructure.config import settings

logger = logging.getLogger("govsec.security.revocation")


def _get_token_identifier(token: str, payload: dict[str, Any] | None = None) -> str:
    """Extrai o JTI do payload se existente; caso contrário, computa o hash SHA-256 do token."""
    if payload and "jti" in payload and payload["jti"]:
        return str(payload["jti"])
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class BaseTokenRevocationStore(ABC):
    @abstractmethod
    def revoke_sync(self, token: str, payload: dict[str, Any] | None = None) -> None:
        pass

    @abstractmethod
    def is_revoked_sync(self, token: str, payload: dict[str, Any] | None = None) -> bool:
        pass

    @abstractmethod
    async def revoke(self, token: str, payload: dict[str, Any] | None = None) -> None:
        pass

    @abstractmethod
    async def is_revoked(self, token: str, payload: dict[str, Any] | None = None) -> bool:
        pass


class InMemoryTokenRevocationStore(BaseTokenRevocationStore):
    def __init__(self) -> None:
        self._revoked: dict[str, float] = {}

    def revoke_sync(self, token: str, payload: dict[str, Any] | None = None) -> None:
        ident = _get_token_identifier(token, payload)
        exp = payload.get("exp") if payload else None
        exp_ts = float(exp) if isinstance(exp, int | float) else (datetime.now(timezone.utc).timestamp() + 28800.0)

        self._revoked[ident] = exp_ts
        logger.info("TOKEN_REVOKED_IN_MEMORY | ident=%s exp=%s", ident, exp_ts)

    def is_revoked_sync(self, token: str, payload: dict[str, Any] | None = None) -> bool:
        ident = _get_token_identifier(token, payload)
        exp_ts = self._revoked.get(ident)
        if exp_ts is None:
            return False

        now_ts = datetime.now(timezone.utc).timestamp()
        if now_ts > exp_ts:
            self._revoked.pop(ident, None)
            return False
        return True

    async def revoke(self, token: str, payload: dict[str, Any] | None = None) -> None:
        self.revoke_sync(token, payload)

    async def is_revoked(self, token: str, payload: dict[str, Any] | None = None) -> bool:
        return self.is_revoked_sync(token, payload)


class RedisTokenRevocationStore(BaseTokenRevocationStore):
    def __init__(self, redis_url: str | None = None) -> None:
        self._redis_url = redis_url

    def _get_redis_url(self) -> str:
        return self._redis_url or settings.GOVSEC_REDIS_URL

    async def _get_async_client(self) -> Any:
        try:
            import redis.asyncio as aioredis

            url = self._get_redis_url()
            if not url:
                if settings.GOVSEC_ENV in ("staging", "production"):
                    raise RedisRevocationUnavailableError(
                        f"🚨 [FAIL-CLOSED] URL do Redis ausente em ambiente '{settings.GOVSEC_ENV}'."
                    )
                return None
            return aioredis.from_url(  # type: ignore[no-untyped-call]
                url,
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
            )
        except Exception as e:
            logger.error("REDIS_CONNECTION_FAILED | error=%s", e)
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RedisRevocationUnavailableError(
                    f"🚨 [FAIL-CLOSED] Erro ao conectar ao Redis de revogação em ambiente '{settings.GOVSEC_ENV}'."
                ) from e
            return None

    def _get_sync_client(self) -> Any:
        try:
            import redis

            url = self._get_redis_url()
            if not url:
                if settings.GOVSEC_ENV in ("staging", "production"):
                    raise RedisRevocationUnavailableError(
                        f"🚨 [FAIL-CLOSED] URL do Redis ausente em ambiente '{settings.GOVSEC_ENV}'."
                    )
                return None
            return redis.Redis.from_url(
                url,
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
            )
        except Exception as e:
            logger.error("REDIS_CONNECTION_FAILED | error=%s", e)
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RedisRevocationUnavailableError(
                    f"🚨 [FAIL-CLOSED] Erro ao conectar ao Redis de revogação em ambiente '{settings.GOVSEC_ENV}'."
                ) from e
            return None

    def revoke_sync(self, token: str, payload: dict[str, Any] | None = None) -> None:
        client = self._get_sync_client()
        if client is None:
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RedisRevocationUnavailableError(
                    f"🚨 [FAIL-CLOSED] Redis de revogação indisponível em '{settings.GOVSEC_ENV}'."
                )
            return

        ident = _get_token_identifier(token, payload)
        key = f"govsec:jwt:revoked:{ident}"

        now_ts = datetime.now(timezone.utc).timestamp()
        exp = payload.get("exp") if payload else None
        ttl = int(float(exp) - now_ts) if isinstance(exp, int | float) else 28800
        if ttl <= 0:
            ttl = 60

        try:
            client.setex(key, ttl, "1")
            logger.info("TOKEN_REVOKED_REDIS | key=%s ttl=%ss", key, ttl)
        except Exception as e:
            logger.error("REDIS_REVOKE_ERROR | key=%s error=%s", key, e)
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RedisRevocationUnavailableError(
                    f"🚨 [FAIL-CLOSED] Falha ao gravar revogação no Redis em '{settings.GOVSEC_ENV}': {e}"
                ) from e

    def is_revoked_sync(self, token: str, payload: dict[str, Any] | None = None) -> bool:
        client = self._get_sync_client()
        if client is None:
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RedisRevocationUnavailableError(
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
                raise RedisRevocationUnavailableError(
                    f"🚨 [FAIL-CLOSED] Falha ao verificar revogação no Redis em '{settings.GOVSEC_ENV}': {e}"
                ) from e
            return False

    async def revoke(self, token: str, payload: dict[str, Any] | None = None) -> None:
        client = await self._get_async_client()
        if client is None:
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RedisRevocationUnavailableError(
                    f"🚨 [FAIL-CLOSED] Redis de revogação indisponível em '{settings.GOVSEC_ENV}'."
                )
            return

        ident = _get_token_identifier(token, payload)
        key = f"govsec:jwt:revoked:{ident}"

        now_ts = datetime.now(timezone.utc).timestamp()
        exp = payload.get("exp") if payload else None
        ttl = int(float(exp) - now_ts) if isinstance(exp, int | float) else 28800
        if ttl <= 0:
            ttl = 60

        try:
            async with client:
                await client.setex(key, ttl, "1")
            logger.info("TOKEN_REVOKED_REDIS | key=%s ttl=%ss", key, ttl)
        except Exception as e:
            logger.error("REDIS_REVOKE_ERROR | key=%s error=%s", key, e)
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RedisRevocationUnavailableError(
                    f"🚨 [FAIL-CLOSED] Falha ao gravar revogação no Redis em '{settings.GOVSEC_ENV}': {e}"
                ) from e

    async def is_revoked(self, token: str, payload: dict[str, Any] | None = None) -> bool:
        client = await self._get_async_client()
        if client is None:
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RedisRevocationUnavailableError(
                    f"🚨 [FAIL-CLOSED] Redis de revogação indisponível em '{settings.GOVSEC_ENV}'."
                )
            return False

        ident = _get_token_identifier(token, payload)
        key = f"govsec:jwt:revoked:{ident}"
        try:
            async with client:
                exists = await client.exists(key)
            return bool(exists)
        except Exception as e:
            logger.error("REDIS_CHECK_ERROR | key=%s error=%s", key, e)
            if settings.GOVSEC_ENV in ("staging", "production"):
                raise RedisRevocationUnavailableError(
                    f"🚨 [FAIL-CLOSED] Falha ao verificar revogação no Redis em '{settings.GOVSEC_ENV}'."
                ) from e
            return False


_in_memory_store_instance: InMemoryTokenRevocationStore | None = None
_redis_store_instance: RedisTokenRevocationStore | None = None


def get_token_revocation_store() -> BaseTokenRevocationStore:
    """Factory com avaliação dinâmica de ambiente para ciclo de vida do store."""
    global _in_memory_store_instance, _redis_store_instance
    if settings.GOVSEC_ENV in ("staging", "production"):
        if _redis_store_instance is None:
            _redis_store_instance = RedisTokenRevocationStore(settings.GOVSEC_REDIS_URL)
        return _redis_store_instance

    if settings.GOVSEC_REDIS_URL:
        if _redis_store_instance is None:
            _redis_store_instance = RedisTokenRevocationStore(settings.GOVSEC_REDIS_URL)
        return _redis_store_instance

    if _in_memory_store_instance is None:
        _in_memory_store_instance = InMemoryTokenRevocationStore()
    return _in_memory_store_instance
