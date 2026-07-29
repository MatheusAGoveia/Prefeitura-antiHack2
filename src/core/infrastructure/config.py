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
    GOVSEC_ALERTMANAGER_CONFIG: str = "deploy/alertmanager/alertmanager.yml"
    GOVSEC_SLACK_WEBHOOK_URL: str = ""
    GOVSEC_SLACK_WEBHOOK_FILE: str = ""
    GOVSEC_PAGERDUTY_SERVICE_KEY: str = ""
    GOVSEC_PAGERDUTY_SERVICE_FILE: str = ""


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

            # 1. Impedir uso do arquivo local alertmanager.yml em staging/production
            config_path = self.GOVSEC_ALERTMANAGER_CONFIG.strip()
            if not config_path or config_path.endswith("alertmanager.yml"):
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
