"""
Utilitários para Geração e Validação de JWT
GovSec Shield — Infrastructure Security
"""

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from src.core.infrastructure.config import settings

_TOKEN_BLACKLIST: set[str] = set()


class JWTHandler:
    @staticmethod
    def generate_token(
        user_id: str, tenant_id: str, roles: list[str], expires_in: int = 28800
    ) -> str:
        now = datetime.now(timezone.utc)
        expire = now + timedelta(seconds=expires_in)
        to_encode = {
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

    @staticmethod
    def verify_token(token: str) -> dict[str, Any] | None:
        if token in _TOKEN_BLACKLIST:
            return None
        try:
            payload: dict[str, Any] = jwt.decode(
                token, settings.GOVSEC_JWT_SECRET, algorithms=[settings.GOVSEC_JWT_ALGORITHM]
            )
            return payload
        except jwt.PyJWTError:
            return None

    @staticmethod
    def refresh_token(refresh_token: str) -> str:
        payload = JWTHandler.verify_token(refresh_token)
        if not payload or payload.get("token_type") != "refresh":
            raise ValueError("Refresh Token inválido ou expirado.")

        user_id = payload["sub"]
        tenant_id = payload.get("tenant_id") or payload.get("tenant", "betim")
        roles = payload.get("roles", ["viewer"])
        return JWTHandler.generate_token(user_id=user_id, tenant_id=tenant_id, roles=roles)

    @staticmethod
    def blacklist_token(token: str) -> None:
        _TOKEN_BLACKLIST.add(token)


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

