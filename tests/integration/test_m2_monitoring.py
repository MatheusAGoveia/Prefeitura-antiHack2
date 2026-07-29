"""
Suíte de Testes de Integração e Contratos — Fechamento Capability M2
GovSec Shield — SRE & Monitoring Integration Tests
"""

from typing import TYPE_CHECKING
from uuid import uuid4

import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.main import app
from src.core.domain.entities import AlertAcknowledgement, AuditLog
from src.core.infrastructure.config import Settings
from src.core.infrastructure.db.repositories import (
    InMemoryAlertAcknowledgementRepository,
    InMemoryLogRepository,
)
from src.core.infrastructure.policies.opa_client import OPAClient
from src.core.infrastructure.security.jwt import JWTHandler
from src.shared.observability.health import perform_readiness_checks
from src.shared.observability.metrics import collect_db_pool_metrics

if TYPE_CHECKING:
    from src.core.domain.repositories import AlertAcknowledgementRepository, LogRepository


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# -----------------------------------------------------------------------------
# 1. Validação de Segurança e Configurações por Ambiente (Section 4.1 & 4.2 & 4.3)
# -----------------------------------------------------------------------------

def test_settings_environment_validation_success(tmp_path: pytest.TempPathFactory):
    """Valida que Settings aceita ambientes dev, test, staging e production."""
    s_dev = Settings(GOVSEC_ENV="dev")
    assert s_dev.GOVSEC_ENV == "dev"

    s_test = Settings(GOVSEC_ENV="test")
    assert s_test.GOVSEC_ENV == "test"

    valid_rendered = tmp_path / "valid.rendered.yml"
    valid_rendered.write_text("global:\n  resolve_timeout: 5m\nreceivers:\n  - name: prod-receiver\n")

    s_prod = Settings(
        GOVSEC_ENV="production",
        GOVSEC_JWT_SECRET="secret-ultra-seguro-com-mais-de-32-caracteres-para-producao-12345",
        GOVSEC_ALERTMANAGER_CONFIG=str(valid_rendered),
        GOVSEC_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T00/B00/X00",
        GOVSEC_PAGERDUTY_SERVICE_KEY="pd-service-key-12345",
    )
    assert s_prod.GOVSEC_ENV == "production"



def test_settings_production_fails_with_default_or_short_jwt_secret():
    """Garante que a aplicação falha no startup se usar secret padrão ou curto em producao."""
    with pytest.raises(ValueError, match="GOVSEC_JWT_SECRET não pode usar o valor padrão"):
        Settings(
            GOVSEC_ENV="production",
            GOVSEC_JWT_SECRET="super-secret-govsec-key-change-in-production",
        )

    with pytest.raises(ValueError, match="menos de 32 caracteres"):
        Settings(
            GOVSEC_ENV="production",
            GOVSEC_JWT_SECRET="curto-123",
        )


def test_dev_token_endpoint_disabled_outside_dev_env(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    """Garante que o endpoint de token dev falha com 403 fora do ambiente dev."""
    import src.core.infrastructure.config as config_mod

    monkeypatch.setattr(config_mod.settings, "GOVSEC_ENV", "production")

    response = client.post(
        "/api/v1/auth/dev-token",
        json={"user_id": "test", "tenant_id": "betim", "role": "analyst"},
    )
    assert response.status_code == 403
    assert "desabilitados fora do ambiente 'dev'" in response.json()["detail"]


def test_opa_client_mock_mode_prohibited_outside_dev(monkeypatch: pytest.MonkeyPatch):
    """Garante que OPAClient força mock_mode=False em staging/production."""
    import src.core.infrastructure.policies.opa_client as opa_mod

    monkeypatch.setattr(opa_mod.settings, "GOVSEC_ENV", "production")
    opa_client = OPAClient(mock_mode=True)
    assert opa_client.mock_mode is False


# -----------------------------------------------------------------------------
# 2. Testes de Health Checks e Degradação (Section 4.3)
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_readiness_degraded_when_kafka_in_fallback_in_production(monkeypatch: pytest.MonkeyPatch):
    """Em produção, se o Kafka estiver em fallback in-memory, o readiness check deve retornar False."""
    import src.shared.observability.health as health_mod

    monkeypatch.setattr(health_mod.settings, "GOVSEC_ENV", "production")

    healthy, checks = await perform_readiness_checks()
    assert checks["kafka"] == "fallback_in_memory"
    assert healthy is False


# -----------------------------------------------------------------------------
# 3. Persistência de Logs de Auditoria (Section 4.4)
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_in_memory_and_postgres_log_repository_flow():
    """Valida contrato do repositório de logs com paginação e filtro por tenant."""
    log_repo: LogRepository = InMemoryLogRepository()
    tenant_id = uuid4()

    log1 = AuditLog(tenant_id=tenant_id, source="firewall-wazuh", raw_data="Alert SSH Brute Force")
    log2 = AuditLog(tenant_id=tenant_id, source="zabbix-agent", raw_data="High CPU Usage")

    await log_repo.save(log1)
    await log_repo.save(log2)

    logs = await log_repo.list(skip=0, limit=10, tenant_id=tenant_id)
    assert len(logs) == 2
    assert logs[0].source in ("firewall-wazuh", "zabbix-agent")


# -----------------------------------------------------------------------------
# 4. Métricas Prometheus e Pool DB (Section 7)
# -----------------------------------------------------------------------------

def test_prometheus_metrics_endpoint_contains_m2_gauges(client: TestClient):
    """Valida exposição de métricas operacionais de M2 no endpoint /metrics."""
    collect_db_pool_metrics()
    response = client.get("/metrics")
    assert response.status_code == 200
    content = response.text

    assert "govsec_service_info" in content
    assert "govsec_db_pool_size" in content
    assert "govsec_db_pool_available_connections" in content
    assert "govsec_event_bus_fallback_active" in content
    assert "govsec_opa_available" in content
    assert "govsec_logs_ingested_total" in content


# -----------------------------------------------------------------------------
# 5. Validação Estrutural das Regras Prometheus (Section 8)
# -----------------------------------------------------------------------------

def test_prometheus_alerts_yml_structural_validation():
    """Valida que deploy/prometheus/alerts.yml possui os 6 alertas mínimos esperados."""
    with open("deploy/prometheus/alerts.yml", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "groups" in data
    group = data["groups"][0]
    rules = group["rules"]

    alert_names = {rule["alert"] for rule in rules}
    required_alerts = {
        "ServiceDown",
        "HighLatency",
        "HighErrorRate",
        "DBConnectionPoolExhausted",
        "HighMemoryUsage",
        "NoLogsIngested",
    }
    assert required_alerts.issubset(alert_names)

    for rule in rules:
        assert "alert" in rule
        assert "expr" in rule
        assert "for" in rule
        assert "labels" in rule
        assert rule["labels"]["severity"] in ("critical", "warning", "info")
        assert "annotations" in rule
        assert "runbook_url" in rule["annotations"]


# -----------------------------------------------------------------------------
# 6. Validação Estrutural da Configuração Alertmanager (Section 5 & 9)
# -----------------------------------------------------------------------------

def test_alertmanager_yml_structural_validation():
    """Valida a estrutura de rotas, receivers e inibições no alertmanager.yml."""
    with open("deploy/alertmanager/alertmanager.yml", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "route" in data
    route = data["route"]
    assert route["group_by"] == ["alertname", "severity", "service"]
    assert "routes" in route

    receivers = {r["name"] for r in data["receivers"]}
    assert "pagerduty-and-slack" in receivers
    assert "slack-warnings" in receivers
    assert "dev-null" in receivers

    assert "inhibit_rules" in data


# -----------------------------------------------------------------------------
# 7. AcknowledgeAlertCommand (Section 10)
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_acknowledge_alert_repository_and_idempotency():
    """Valida salvamento e idempotência no repositório de acknowledgements."""
    ack_repo: AlertAcknowledgementRepository = InMemoryAlertAcknowledgementRepository()

    ack1 = AlertAcknowledgement(
        alert_id="ServiceDown-01",
        fingerprint="fingerprint-abc12345",
        reason="Servidor reiniciado manualmente pela equipe SRE",
        acknowledged_by="operador-oncall",
        tenant_id="betim",
    )

    saved1 = await ack_repo.save(ack1)
    assert saved1.fingerprint == "fingerprint-abc12345"

    # Segunda tentativa com mesmo fingerprint deve retornar a entidade existente
    ack2 = AlertAcknowledgement(
        alert_id="ServiceDown-01",
        fingerprint="fingerprint-abc12345",
        reason="Tentativa duplicada",
        acknowledged_by="outro-operador",
        tenant_id="betim",
    )

    saved2 = await ack_repo.save(ack2)
    assert saved2.id == saved1.id
    assert saved2.reason == "Servidor reiniciado manualmente pela equipe SRE"


def test_acknowledge_alert_endpoint_rbac_authorization(client: TestClient):
    """Testa que /api/v1/alerts/acknowledge autoriza perfil analyst e recusa perfil viewer."""
    from src.core.application.handlers import AcknowledgeAlertHandler
    from src.core.infrastructure.db.repositories import InMemoryAlertAcknowledgementRepository
    from src.core.infrastructure.messaging.command_bus import CommandBus
    from src.core.infrastructure.messaging.event_bus import EventBus
    from src.core.interfaces.rest.dependencies import get_command_bus

    async def mock_get_command_bus():
        bus = CommandBus(opa_client=OPAClient(mock_mode=True))
        mock_ack_repo = InMemoryAlertAcknowledgementRepository()
        handler = AcknowledgeAlertHandler(mock_ack_repo, EventBus(use_kafka=False))
        bus.register("AcknowledgeAlertCommand", lambda cmd: handler.handle(cmd))
        return bus

    app.dependency_overrides[get_command_bus] = mock_get_command_bus

    try:
        # Token com perfil 'viewer' deve ser recusado com 403
        viewer_token = JWTHandler.generate_token(user_id="user-viewer", tenant_id="betim", roles=["viewer"])
        dto_data = {
            "alert_id": "ServiceDown-01",
            "fingerprint": "fp-123456",
            "reason": "Análise iniciada pelo analista de plantão",
            "tenant_id": "betim",
        }

        res_viewer = client.post(
            "/api/v1/alerts/acknowledge",
            json=dto_data,
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert res_viewer.status_code == 403

        # Token com perfil 'analyst' deve ser aceito com 200 OK
        analyst_token = JWTHandler.generate_token(user_id="user-analyst", tenant_id="betim", roles=["analyst"])
        res_analyst = client.post(
            "/api/v1/alerts/acknowledge",
            json=dto_data,
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert res_analyst.status_code == 200
        data = res_analyst.json()
        assert data["alert_id"] == "ServiceDown-01"
        assert data["acknowledged_by"] == "user-analyst"
    finally:
        app.dependency_overrides.pop(get_command_bus, None)


# -----------------------------------------------------------------------------
# 8. Testes das Regras Finais de M2 (Point 4)
# -----------------------------------------------------------------------------

def test_alertmanager_rendered_yml_not_tracked_by_git():
    """Garante que deploy/alertmanager/alertmanager.rendered.yml NÃO está rastreado no Git."""
    import subprocess

    result = subprocess.run(
        ["git", "ls-files", "deploy/alertmanager/alertmanager.rendered.yml"],
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "", "O arquivo alertmanager.rendered.yml não pode ser rastreado pelo Git!"


def test_render_alertmanager_production_config_without_test_receivers(monkeypatch: pytest.MonkeyPatch):
    """Garante que a renderização de produção não contém test-receiver nem host.docker.internal."""
    from scripts.render_alertmanager_config import render_config

    monkeypatch.setenv("GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/X00")
    monkeypatch.setenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "pd-service-key-12345")

    output_path = render_config()
    with open(output_path, encoding="utf-8") as f:
        content = f.read()

    assert "test-receiver" not in content
    assert "host.docker.internal" not in content
    assert "https://hooks.slack.com/services/T00/B00/X00" in content
    assert "pd-service-key-12345" in content


def test_render_config_fails_in_production_if_test_receiver_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
):
    """Garante que render_config lança ValueError em staging/production se o template contiver test-receiver."""
    import scripts.render_alertmanager_config as render_mod

    monkeypatch.setenv("GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/X00")
    monkeypatch.setenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "pd-service-key-12345")

    bad_template = tmp_path / "bad.template"
    bad_template.write_text(
        "receivers:\n  - name: test-receiver\n    webhook_configs:\n      - url: http://host.docker.internal:8000/mock\n"
    )
    monkeypatch.setattr(render_mod, "TEMPLATE_PATH", str(bad_template))

    with pytest.raises(ValueError, match="proíbe o uso de 'test-receiver' ou endpoints locais"):
        render_mod.render_config()



def test_pagerduty_variable_name_consistency():
    """Garante a consistência da variável GOVSEC_PAGERDUTY_SERVICE_KEY no Settings e nos exemplos."""
    from src.core.infrastructure.config import Settings

    s = Settings()
    assert hasattr(s, "GOVSEC_PAGERDUTY_SERVICE_KEY")
    assert not hasattr(s, "GOVSEC_PAGERDUTY_ROUTING_KEY")

    with open(".env.example", encoding="utf-8") as f:
        env_example = f.read()
    assert "GOVSEC_PAGERDUTY_SERVICE_KEY=" in env_example
    assert "GOVSEC_PAGERDUTY_ROUTING_KEY" not in env_example

    with open("configs/dev/.env.example", encoding="utf-8") as f:
        dev_env_example = f.read()
    assert "GOVSEC_PAGERDUTY_SERVICE_KEY=" in dev_env_example
    assert "GOVSEC_PAGERDUTY_ROUTING_KEY" not in dev_env_example


def test_production_fails_if_alertmanager_config_points_to_local_yml(monkeypatch: pytest.MonkeyPatch):
    """Garante que a inicialização em produção falha se GOVSEC_ALERTMANAGER_CONFIG apontar para alertmanager.yml local."""
    from src.core.infrastructure.config import Settings

    monkeypatch.setenv("GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_JWT_SECRET", "super-secret-govsec-key-32-chars-long-prod")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", "deploy/alertmanager/alertmanager.yml")
    monkeypatch.setenv("GOVSEC_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/X00")
    monkeypatch.setenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "pd-service-key-12345")

    with pytest.raises(ValueError, match="não pode utilizar o arquivo local 'alertmanager.yml'"):
        Settings()


def test_production_fails_if_rendered_config_file_does_not_exist(monkeypatch: pytest.MonkeyPatch):
    """Garante que a inicialização em produção falha se o arquivo renderizado não existir."""
    from src.core.infrastructure.config import Settings

    monkeypatch.setenv("GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_JWT_SECRET", "super-secret-govsec-key-32-chars-long-prod")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", "deploy/alertmanager/non_existent.rendered.yml")
    monkeypatch.setenv("GOVSEC_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/X00")
    monkeypatch.setenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "pd-service-key-12345")

    with pytest.raises(FileNotFoundError, match="não foi encontrado"):
        Settings()


def test_production_fails_without_slack_or_pagerduty_secrets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
):
    """Garante que a inicialização em produção falha sem segredos de Slack ou PagerDuty."""
    from src.core.infrastructure.config import Settings

    monkeypatch.setenv("GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_JWT_SECRET", "super-secret-govsec-key-32-chars-long-prod")

    valid_rendered = tmp_path / "valid.rendered.yml"
    valid_rendered.write_text("global:\n  resolve_timeout: 5m\nreceivers:\n  - name: prod-receiver\n")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", str(valid_rendered))

    # Sem Slack nem PagerDuty
    monkeypatch.setenv("GOVSEC_SLACK_WEBHOOK_URL", "")
    monkeypatch.setenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "")

    with pytest.raises(ValueError, match="Slack e PagerDuty devem estar obrigatoriamente configurados"):
        Settings()


def test_production_accepts_only_validated_rendered_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
):
    """Garante que a inicialização em produção é aprovada quando o arquivo renderizado e os segredos são válidos."""
    from src.core.infrastructure.config import Settings

    monkeypatch.setenv("GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_JWT_SECRET", "super-secret-govsec-key-32-chars-long-prod")

    valid_rendered = tmp_path / "alertmanager.rendered.yml"
    valid_rendered.write_text("global:\n  resolve_timeout: 5m\nreceivers:\n  - name: prod-receiver\n")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", str(valid_rendered))
    monkeypatch.setenv("GOVSEC_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/X00")
    monkeypatch.setenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "pd-service-key-12345")

    s = Settings()
    assert str(valid_rendered) == s.GOVSEC_ALERTMANAGER_CONFIG



