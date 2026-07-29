"""
Configurações da Plataforma
GovSec Shield — Infrastructure Config
"""

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    GOVSEC_ENV: str = "dev"
    GOVSEC_DB_URL: str = "postgresql+asyncpg://govsec:govsec@localhost:5432/govsec"
    GOVSEC_REDIS_URL: str = "redis://localhost:6379/0"
    GOVSEC_KAFKA_BOOTSTRAP: str = "localhost:19092"
    GOVSEC_KAFKA_TOPIC_PREFIX: str = "govsec"
    GOVSEC_USE_KAFKA: bool = False
    GOVSEC_JWT_SECRET: str = "super-secret-govsec-key-change-in-production"
    GOVSEC_JWT_ALGORITHM: str = "HS256"
    GOVSEC_JWT_EXPIRE_MINUTES: int = 60
    GOVSEC_OPA_URL: str = "http://localhost:8181/v1/data/govsec/allow"
    GOVSEC_ALERTMANAGER_URL: str = "http://localhost:9093"
    GOVSEC_SLACK_WEBHOOK_URL: str = ""
    GOVSEC_PAGERDUTY_SERVICE_KEY: str = ""


    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @model_validator(mode="after")
    def validate_environment_and_secrets(self) -> "Settings":
        valid_envs = ("dev", "test", "staging", "production")
        if self.GOVSEC_ENV not in valid_envs:
            raise ValueError(f"GOVSEC_ENV inválido ('{self.GOVSEC_ENV}'). Escolha entre {valid_envs}.")

        if self.GOVSEC_ENV in ("staging", "production"):
            default_secret = "super-secret-govsec-key-change-in-production"
            if default_secret == self.GOVSEC_JWT_SECRET or len(self.GOVSEC_JWT_SECRET) < 32:
                raise ValueError(
                    f"Em ambiente '{self.GOVSEC_ENV}', GOVSEC_JWT_SECRET não pode usar o valor padrão ou ter menos de 32 caracteres."
                )
        return self


settings = Settings()

