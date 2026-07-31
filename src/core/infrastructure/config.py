"""
Configurações da Plataforma
GovSec Shield — Infrastructure Config
"""

from typing import Any

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    GOVSEC_ENV: str = "dev"
    GOVSEC_DB_URL: str = "postgresql+asyncpg://govsec:govsec@localhost:5432/govsec"
    GOVSEC_REDIS_URL: str = "redis://localhost:6379/0"
    GOVSEC_KAFKA_BOOTSTRAP: str = "localhost:19092"
    GOVSEC_KAFKA_TOPIC_PREFIX: str = "govsec"
    GOVSEC_KAFKA_CORRELATION_GROUP_ID: str = "govsec-correlation-group"
    GOVSEC_USE_KAFKA: bool = False
    GOVSEC_JWT_SECRET: str = "super-secret-govsec-key-change-in-production"
    GOVSEC_JWT_ALGORITHM: str = "HS256"
    GOVSEC_JWT_EXPIRE_MINUTES: int = 60
    GOVSEC_OPA_URL: str = "http://localhost:8181/v1/data/govsec/allow"
    GOVSEC_ALERTMANAGER_URL: str = "http://localhost:9093"
    GOVSEC_ALERTMANAGER_CONFIG: str = "deploy/alertmanager/alertmanager.yml"
    GOVSEC_SLACK_WEBHOOK_URL: str = ""
    GOVSEC_SLACK_WEBHOOK_FILE: str = ""
    GOVSEC_PAGERDUTY_SERVICE_KEY: str = ""
    GOVSEC_PAGERDUTY_SERVICE_FILE: str = ""
    GOVSEC_CORS_ALLOWED_ORIGINS: list[str] | str = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @model_validator(mode="before")
    @classmethod
    def parse_cors_origins(cls, data: Any) -> Any:
        if isinstance(data, dict):
            origins = data.get("GOVSEC_CORS_ALLOWED_ORIGINS")
            if isinstance(origins, str):
                origins_str = origins.strip()
                if origins_str.startswith("[") and origins_str.endswith("]"):
                    import json

                    try:
                        parsed = json.loads(origins_str)
                        if isinstance(parsed, list):
                            data["GOVSEC_CORS_ALLOWED_ORIGINS"] = [str(o).strip() for o in parsed if str(o).strip()]
                    except Exception:
                        data["GOVSEC_CORS_ALLOWED_ORIGINS"] = [o.strip() for o in origins_str.split(",") if o.strip()]
                else:
                    data["GOVSEC_CORS_ALLOWED_ORIGINS"] = [
                        o.strip() for o in origins_str.split(",") if o.strip()
                    ]
        return data

    @model_validator(mode="after")
    def validate_environment_and_secrets(self) -> "Settings":
        valid_envs = ("dev", "test", "staging", "production")
        if self.GOVSEC_ENV not in valid_envs:
            raise ValueError(f"GOVSEC_ENV inválido ('{self.GOVSEC_ENV}'). Escolha entre {valid_envs}.")

        # Garantir lista de strings para CORS
        if isinstance(self.GOVSEC_CORS_ALLOWED_ORIGINS, str):
            cors_origins = [o.strip() for o in self.GOVSEC_CORS_ALLOWED_ORIGINS.split(",") if o.strip()]
            self.GOVSEC_CORS_ALLOWED_ORIGINS = cors_origins
        else:
            cors_origins = [o.strip() for o in self.GOVSEC_CORS_ALLOWED_ORIGINS]

        # Validação Global de CORS
        if "*" in cors_origins:
            raise ValueError(
                "CORS Proibido: Wildcard '*' não é permitido em GOVSEC_CORS_ALLOWED_ORIGINS quando credenciais estão ativas."
            )

        for origin in cors_origins:
            if not origin.startswith(("http://", "https://")):
                raise ValueError(
                    f"Origem CORS inválida ('{origin}'). Deve iniciar obrigatoriamente com 'http://' ou 'https://'."
                )

        if self.GOVSEC_ENV in ("staging", "production"):
            if not cors_origins:
                raise ValueError(
                    f"Em ambiente '{self.GOVSEC_ENV}', GOVSEC_CORS_ALLOWED_ORIGINS deve ser configurado com origens explícitas."
                )

            for origin in cors_origins:
                if "localhost" in origin or "127.0.0.1" in origin:
                    raise ValueError(
                        f"Em ambiente '{self.GOVSEC_ENV}', a origem local '{origin}' é estritamente proibida em GOVSEC_CORS_ALLOWED_ORIGINS."
                    )

            insecure_default_key = "super-secret-govsec-key-change-in-production"
            if insecure_default_key == self.GOVSEC_JWT_SECRET or len(self.GOVSEC_JWT_SECRET) < 32:
                raise ValueError(
                    f"Em ambiente '{self.GOVSEC_ENV}', GOVSEC_JWT_SECRET não pode usar o valor padrão ou ter menos de 32 caracteres."
                )

            # 1. Impedir uso do arquivo local alertmanager.yml em staging/production
            config_path = self.GOVSEC_ALERTMANAGER_CONFIG.strip()
            if not config_path or (config_path.endswith("alertmanager.yml") and not config_path.endswith(".rendered.yml")):
                raise ValueError(
                    f"Em ambiente '{self.GOVSEC_ENV}', GOVSEC_ALERTMANAGER_CONFIG não pode utilizar o arquivo local 'alertmanager.yml'. Deve apontar para o arquivo renderizado (ex: deploy/alertmanager/alertmanager.rendered.yml)."
                )

            # 2. Exigir existência do arquivo renderizado

            import os

            if not os.path.exists(config_path):
                raise FileNotFoundError(
                    f"Em ambiente '{self.GOVSEC_ENV}', o arquivo de configuração do Alertmanager em '{config_path}' não foi encontrado."
                )

            # 3. Proibir test-receiver e host.docker.internal na configuração renderizada
            with open(config_path, encoding="utf-8") as f:
                content = f.read()

            if "test-receiver" in content or "host.docker.internal" in content:
                raise ValueError(
                    f"Em ambiente '{self.GOVSEC_ENV}', a configuração do Alertmanager em '{config_path}' contém 'test-receiver' ou 'host.docker.internal' proibidoss."
                )

            # 4. Validar segredos do Slack e PagerDuty obrigatoriamente
            slack_url = self.GOVSEC_SLACK_WEBHOOK_URL.strip()
            if not slack_url and self.GOVSEC_SLACK_WEBHOOK_FILE and os.path.exists(self.GOVSEC_SLACK_WEBHOOK_FILE):
                with open(self.GOVSEC_SLACK_WEBHOOK_FILE, encoding="utf-8") as sf:
                    slack_url = sf.read().strip()

            pagerduty_key = self.GOVSEC_PAGERDUTY_SERVICE_KEY.strip()
            if (
                not pagerduty_key
                and self.GOVSEC_PAGERDUTY_SERVICE_FILE
                and os.path.exists(self.GOVSEC_PAGERDUTY_SERVICE_FILE)
            ):
                with open(self.GOVSEC_PAGERDUTY_SERVICE_FILE, encoding="utf-8") as pf:
                    pagerduty_key = pf.read().strip()

            if not slack_url or not pagerduty_key:
                raise ValueError(
                    f"Em ambiente '{self.GOVSEC_ENV}', Slack e PagerDuty devem estar obrigatoriamente configurados via variáveis de ambiente ou arquivos de segredo."
                )
        return self


settings = Settings()
