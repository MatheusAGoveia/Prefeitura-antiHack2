"""
Manipulador de JSON Web Tokens (JWT)
GovSec Shield — Security Infrastructure
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import jwt

from src.core.infrastructure.config import settings
from src.core.infrastructure.security.revocation import (
    BaseTokenRevocationStore,
    get_token_revocation_store,
)

logger = logging.getLogger("govsec.security.jwt")


class JWTHandler:
    """
    Gerencia emissão, decodificação e revogação assíncrona de tokens JWT.
    """

    _revocation_store: BaseTokenRevocationStore | None = None

    @classmethod
    def get_revocation_store(cls) -> BaseTokenRevocationStore:
        if cls._revocation_store is None:
            cls._revocation_store = get_token_revocation_store()
        return cls._revocation_store

    @classmethod
    def set_revocation_store(cls, store: BaseTokenRevocationStore) -> None:
        cls._revocation_store = store

    @staticmethod
    def _validate_tenant_uuid(tenant_id: str | UUID) -> str:
        if isinstance(tenant_id, UUID):
            return str(tenant_id)
        try:
            return str(UUID(str(tenant_id)))
        except (ValueError, TypeError) as err:
            raise ValueError(f"tenant_id deve ser um UUID válido, recebido: '{tenant_id}'") from err

    @classmethod
    def generate_token(
        cls, user_id: str, tenant_id: str | UUID, roles: list[str], expires_in: int = 28800
    ) -> str:
        now = datetime.now(timezone.utc)
        expire = now + timedelta(seconds=expires_in)
        t_str = cls._validate_tenant_uuid(tenant_id)
        to_encode = {
            "jti": str(uuid.uuid4()),
            "sub": user_id,
            "tenant_id": t_str,
            "roles": roles,
            "token_type": "access",
            "exp": expire,
            "iat": now,
        }
        return jwt.encode(
            to_encode, settings.GOVSEC_JWT_SECRET, algorithm=settings.GOVSEC_JWT_ALGORITHM
        )

    @classmethod
    def generate_refresh_token(
        cls, user_id: str, tenant_id: str | UUID, roles: list[str], expires_in: int = 604800
    ) -> str:
        now = datetime.now(timezone.utc)
        expire = now + timedelta(seconds=expires_in)
        t_str = cls._validate_tenant_uuid(tenant_id)
        to_encode = {
            "jti": str(uuid.uuid4()),
            "sub": user_id,
            "tenant_id": t_str,
            "roles": roles,
            "token_type": "refresh",
            "exp": expire,
            "iat": now,
        }
        return jwt.encode(
            to_encode, settings.GOVSEC_JWT_SECRET, algorithm=settings.GOVSEC_JWT_ALGORITHM
        )

    @classmethod
    async def verify_token_async(cls, token: str) -> dict[str, Any] | None:
        try:
            payload: dict[str, Any] = jwt.decode(
                token, settings.GOVSEC_JWT_SECRET, algorithms=[settings.GOVSEC_JWT_ALGORITHM]
            )
            raw_tenant = payload.get("tenant_id")
            if not raw_tenant:
                return None
            try:
                UUID(str(raw_tenant))
            except (ValueError, TypeError):
                return None

            store = cls.get_revocation_store()
            if await store.is_revoked(token, payload):
                return None
            return payload
        except jwt.PyJWTError:
            return None

    @classmethod
    def verify_token(cls, token: str) -> dict[str, Any] | None:
        try:
            payload: dict[str, Any] = jwt.decode(
                token, settings.GOVSEC_JWT_SECRET, algorithms=[settings.GOVSEC_JWT_ALGORITHM]
            )
            raw_tenant = payload.get("tenant_id")
            if not raw_tenant:
                return None
            try:
                UUID(str(raw_tenant))
            except (ValueError, TypeError):
                return None

            store = cls.get_revocation_store()
            if store.is_revoked_sync(token, payload):
                return None
            return payload
        except jwt.PyJWTError:
            return None

    @classmethod
    async def refresh_token_async(cls, refresh_token: str) -> str:
        payload = await cls.verify_token_async(refresh_token)
        if not payload or payload.get("token_type") != "refresh":
            raise ValueError("Refresh Token inválido ou expirado.")

        user_id = payload["sub"]
        raw_tenant = payload.get("tenant_id")
        if not raw_tenant:
            raise ValueError("Refresh token inválido: tenant_id não encontrado.")
        try:
            tenant_uuid = UUID(str(raw_tenant))
        except (ValueError, TypeError) as err:
            raise ValueError("Refresh token inválido: tenant_id não é um UUID válido.") from err

        roles = payload.get("roles", ["viewer"])
        return cls.generate_token(user_id=user_id, tenant_id=tenant_uuid, roles=roles)

    @classmethod
    def refresh_token(cls, refresh_token: str) -> str:
        payload = cls.verify_token(refresh_token)
        if not payload or payload.get("token_type") != "refresh":
            raise ValueError("Refresh Token inválido ou expirado.")

        user_id = payload["sub"]
        raw_tenant = payload.get("tenant_id")
        if not raw_tenant:
            raise ValueError("Refresh token inválido: tenant_id não encontrado.")
        try:
            tenant_uuid = UUID(str(raw_tenant))
        except (ValueError, TypeError) as err:
            raise ValueError("Refresh token inválido: tenant_id não é um UUID válido.") from err

        roles = payload.get("roles", ["viewer"])
        return cls.generate_token(user_id=user_id, tenant_id=tenant_uuid, roles=roles)

    @classmethod
    async def blacklist_token_async(cls, token: str) -> None:
        payload = await cls.verify_token_async(token)
        store = cls.get_revocation_store()
        await store.revoke(token, payload)

    @classmethod
    def blacklist_token(cls, token: str) -> None:
        payload = cls.verify_token(token)
        store = cls.get_revocation_store()
        store.revoke_sync(token, payload)


class JWTUtils(JWTHandler):
    @staticmethod
    def create_access_token(
        user_id: str, tenant_id: str | UUID, roles: list[str], expires_delta: timedelta | None = None
    ) -> str:
        expires_in = int(expires_delta.total_seconds()) if expires_delta else settings.GOVSEC_JWT_EXPIRE_MINUTES * 60
        return JWTHandler.generate_token(user_id=user_id, tenant_id=tenant_id, roles=roles, expires_in=expires_in)

    @classmethod
    async def decode_token_async(cls, token: str) -> dict[str, Any]:
        verified = await JWTHandler.verify_token_async(token)
        if verified is None:
            raise jwt.PyJWTError("Token inválido ou revogado.")
        return verified

    @staticmethod
    def decode_token(token: str) -> dict[str, Any]:
        verified = JWTHandler.verify_token(token)
        if verified is None:
            raise jwt.PyJWTError("Token inválido ou revogado.")
        return verified
