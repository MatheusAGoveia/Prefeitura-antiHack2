"""
Utilitários para Geração e Validação de JWT
GovSec Shield — Infrastructure Security
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import jwt
from src.core.infrastructure.config import settings

class JWTUtils:
    @staticmethod
    def create_access_token(
        user_id: str,
        tenant: str,
        roles: List[str],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.GOVSEC_JWT_EXPIRE_MINUTES)

        to_encode = {
            "sub": user_id,
            "tenant": tenant,
            "roles": roles,
            "exp": expire,
            "iat": datetime.utcnow()
        }
        return jwt.encode(to_encode, settings.GOVSEC_JWT_SECRET, algorithm=settings.GOVSEC_JWT_ALGORITHM)

    @staticmethod
    def decode_token(token: str) -> Dict[str, Any]:
        return jwt.decode(token, settings.GOVSEC_JWT_SECRET, algorithms=[settings.GOVSEC_JWT_ALGORITHM])
