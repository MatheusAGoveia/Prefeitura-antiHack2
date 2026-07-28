"""
Configurações da Plataforma
GovSec Shield — Infrastructure Config
"""

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    GOVSEC_ENV: str = "dev"
    GOVSEC_DB_URL: str = "postgresql+asyncpg://govsec:govsec@localhost:5432/govsec"
    GOVSEC_REDIS_URL: str = "redis://localhost:6379/0"
    GOVSEC_KAFKA_BOOTSTRAP: str = "localhost:19092"
    GOVSEC_KAFKA_TOPIC_PREFIX: str = "govsec"
    GOVSEC_JWT_SECRET: str = "super-secret-govsec-key-change-in-production"
    GOVSEC_JWT_ALGORITHM: str = "HS256"
    GOVSEC_JWT_EXPIRE_MINUTES: int = 60
    GOVSEC_OPA_URL: str = "http://localhost:8181/v1/data/govsec/allow"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
