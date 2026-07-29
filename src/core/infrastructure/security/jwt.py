"""
Utilitários para Geração e Validação de JWT
GovSec Shield — Infrastructure Security
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from src.core.infrastructure.config import settings
from src.core.infrastructure.security.revocation import (
    BaseTokenRevocationStore,
)
from src.core.infrastructure.security.revocation import (
    revocation_store as _global_revocation_store,
)


class JWTHandler:
    _revocation_store: BaseTokenRevocationStore = _global_revocation_store

    @classmethod
    def set_revocation_store(cls, store: BaseTokenRevocationStore) -> None:
        """Permite a injeção/mocking do token revocation store em testes."""
        cls._revocation_store = store

    @classmethod
    def get_revocation_store(cls) -> BaseTokenRevocationStore:
        return cls._revocation_store

    @staticmethod
    def generate_token(
        user_id: str, tenant_id: str, roles: list[str], expires_in: int = 28800
    ) -> str:
        now = datetime.now(timezone.utc)
        expire = now + timedelta(seconds=expires_in)
        to_encode = {
            "jti": str(uuid.uuid4()),
            "sub": user_id,
            "tenant_id": tenant_id,
            "tenant": tenant_id,
            "roles": roles,
            "token_type": "access",
            "exp": expire,
            "iat": now,
        }
        return jwt.encode(
            to_encode, settings.GOVSEC_JWT_SECRET, algorithm=settings.GOVSEC_JWT_ALGORITHM
        )

    @staticmethod
    def generate_refresh_token(
        user_id: str, tenant_id: str, roles: list[str], expires_in: int = 604800
    ) -> str:
        now = datetime.now(timezone.utc)
        expire = now + timedelta(seconds=expires_in)
        to_encode = {
            "jti": str(uuid.uuid4()),
            "sub": user_id,
            "tenant_id": tenant_id,
            "tenant": tenant_id,
            "roles": roles,
            "token_type": "refresh",
            "exp": expire,
            "iat": now,
        }
        return jwt.encode(
            to_encode, settings.GOVSEC_JWT_SECRET, algorithm=settings.GOVSEC_JWT_ALGORITHM
        )

    @classmethod
    def verify_token(cls, token: str) -> dict[str, Any] | None:
        try:
            payload: dict[str, Any] = jwt.decode(
                token, settings.GOVSEC_JWT_SECRET, algorithms=[settings.GOVSEC_JWT_ALGORITHM]
            )
            if cls._revocation_store.is_revoked(token, payload):
                return None
            return payload
        except jwt.PyJWTError:
            return None

    @classmethod
    def refresh_token(cls, refresh_token: str) -> str:
        payload = cls.verify_token(refresh_token)
        if not payload or payload.get("token_type") != "refresh":
            raise ValueError("Refresh Token inválido ou expirado.")

        user_id = payload["sub"]
        tenant_id = payload.get("tenant_id") or payload.get("tenant", "betim")
        roles = payload.get("roles", ["viewer"])
        return cls.generate_token(user_id=user_id, tenant_id=tenant_id, roles=roles)

    @classmethod
    def blacklist_token(cls, token: str) -> None:
        payload = cls.verify_token(token)
        cls._revocation_store.revoke(token, payload)


class JWTUtils(JWTHandler):
    @staticmethod
    def create_access_token(
        user_id: str, tenant: str, roles: list[str], expires_delta: timedelta | None = None
    ) -> str:
        expires_in = int(expires_delta.total_seconds()) if expires_delta else settings.GOVSEC_JWT_EXPIRE_MINUTES * 60
        return JWTHandler.generate_token(user_id=user_id, tenant_id=tenant, roles=roles, expires_in=expires_in)

    @staticmethod
    def decode_token(token: str) -> dict[str, Any]:
        verified = JWTHandler.verify_token(token)
        if verified is None:
            raise jwt.PyJWTError("Token inválido ou revogado.")
        return verified


