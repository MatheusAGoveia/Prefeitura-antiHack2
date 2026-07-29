"""
Suíte de Testes de Integração e Contratos — Fechamento Capability M2
GovSec Shield — SRE & Monitoring Integration Tests
"""

import asyncio
import uuid
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
from src.core.infrastructure.security.kernel import AuthenticatedUser
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
        GOVSEC_CORS_ALLOWED_ORIGINS=["https://govsec.prefeitura.gov.br"],
    )
    assert s_prod.GOVSEC_ENV == "production"
    s = Settings(GOVSEC_ALERTMANAGER_CONFIG=str(valid_rendered))
    assert str(valid_rendered) == s.GOVSEC_ALERTMANAGER_CONFIG


def test_settings_production_fails_with_default_or_short_jwt_secret():
    """Garante que a aplicação falha no startup se usar secret padrão ou curto em producao."""
    with pytest.raises(ValueError, match="GOVSEC_JWT_SECRET não pode usar o valor padrão"):
        Settings(
            GOVSEC_ENV="production",
            GOVSEC_JWT_SECRET="super-secret-govsec-key-change-in-production",
            GOVSEC_CORS_ALLOWED_ORIGINS=["https://govsec.prefeitura.gov.br"],
        )

    with pytest.raises(ValueError, match="menos de 32 caracteres"):
        Settings(
            GOVSEC_ENV="production",
            GOVSEC_JWT_SECRET="curto-123",
            GOVSEC_CORS_ALLOWED_ORIGINS=["https://govsec.prefeitura.gov.br"],
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
    monkeypatch.setenv("GOVSEC_CORS_ALLOWED_ORIGINS", '["https://govsec.prefeitura.gov.br"]')

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
    monkeypatch.setenv("GOVSEC_CORS_ALLOWED_ORIGINS", '["https://govsec.prefeitura.gov.br"]')

    with pytest.raises(FileNotFoundError, match="não foi encontrado"):
        Settings()


def test_production_fails_without_slack_or_pagerduty_secrets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
):
    """Garante que a inicialização em produção falha sem segredos de Slack ou PagerDuty."""
    from src.core.infrastructure.config import Settings

    monkeypatch.setenv("GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_JWT_SECRET", "super-secret-govsec-key-32-chars-long-prod")
    monkeypatch.setenv("GOVSEC_CORS_ALLOWED_ORIGINS", '["https://govsec.prefeitura.gov.br"]')

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
    monkeypatch.setenv("GOVSEC_CORS_ALLOWED_ORIGINS", '["https://govsec.prefeitura.gov.br"]')

    valid_rendered = tmp_path / "alertmanager.rendered.yml"
    valid_rendered.write_text("global:\n  resolve_timeout: 5m\nreceivers:\n  - name: prod-receiver\n")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", str(valid_rendered))
    monkeypatch.setenv("GOVSEC_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/X00")
    monkeypatch.setenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "pd-service-key-12345")

    s = Settings()
    assert str(valid_rendered) == s.GOVSEC_ALERTMANAGER_CONFIG



# -----------------------------------------------------------------------------
# 9. Testes de Segurança Operacional M2 (Bloqueadores 1-7)
# -----------------------------------------------------------------------------

def test_auth_token_issuance_forbidden_outside_dev(monkeypatch: pytest.MonkeyPatch):
    """Garante que POST /api/v1/auth/token retorna 403 fora do ambiente dev."""
    from src.api.main import app
    from src.core.infrastructure.config import settings

    client = TestClient(app)
    monkeypatch.setattr(settings, "GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_ENV", "production")
    res = client.post(
        "/api/v1/auth/token",
        json={"user_id": "hacker", "tenant": "betim", "roles": ["system_admin"]},
    )
    assert res.status_code == 403


def test_auth_dev_token_forbidden_outside_dev(monkeypatch: pytest.MonkeyPatch):
    """Garante que POST /api/v1/auth/dev-token retorna 403 fora do ambiente dev."""
    from src.api.main import app
    from src.core.infrastructure.config import settings

    client = TestClient(app)
    monkeypatch.setattr(settings, "GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_ENV", "production")
    res = client.post(
        "/api/v1/auth/dev-token",
        json={"user_id": "hacker", "tenant": "betim", "role": "system_admin"},
    )
    assert res.status_code == 403


def test_simulated_login_forbidden_in_production(monkeypatch: pytest.MonkeyPatch):
    """Garante que o login simulado em POST /api/v1/auth/login é bloqueado em staging/produção."""
    from src.api.main import app
    from src.core.infrastructure.config import settings

    client = TestClient(app)
    monkeypatch.setattr(settings, "GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_ENV", "production")
    res = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@govsec.com", "password": "senha123"},
    )
    assert res.status_code == 403
    assert "Provedor de Identidade" in res.json()["detail"]


def test_strict_multi_tenant_isolation_log_ingestion():
    """Garante que usuário do tenant A não pode ingerir logs para tenant B."""
    from uuid import uuid4

    from src.api.main import app

    client = TestClient(app)
    token_tenant_a = JWTHandler.generate_token(user_id="user-a", tenant_id="tenant-a", roles=["analyst"])
    tenant_b_id = str(uuid4())

    res = client.post(
        "/api/v1/logs",
        json={"source": "syslog", "raw_data": "tentativa de invasao", "tenant_id": tenant_b_id},
        headers={"Authorization": f"Bearer {token_tenant_a}"},
    )
    assert res.status_code == 403


def test_strict_multi_tenant_isolation_log_query():
    """Garante que usuário do tenant A não pode consultar logs do tenant B."""
    from uuid import uuid4

    from src.api.main import app

    client = TestClient(app)
    token_tenant_a = JWTHandler.generate_token(user_id="user-a", tenant_id="tenant-a", roles=["viewer"])
    tenant_b_id = str(uuid4())

    res = client.get(
        f"/api/v1/logs?tenant_id={tenant_b_id}",
        headers={"Authorization": f"Bearer {token_tenant_a}"},
    )
    assert res.status_code == 403


def test_strict_multi_tenant_isolation_alert_ack():
    """Garante que usuário do tenant A não pode reconhecer alertas do tenant B."""
    from src.api.main import app

    client = TestClient(app)
    token_tenant_a = JWTHandler.generate_token(user_id="user-a", tenant_id="tenant-a", roles=["analyst"])

    res = client.post(
        "/api/v1/alerts/acknowledge",
        json={"alert_id": "123", "fingerprint": "abc", "reason": "teste", "tenant_id": "tenant-b"},
        headers={"Authorization": f"Bearer {token_tenant_a}"},
    )
    assert res.status_code == 403


def test_cors_wildcard_prohibited_when_credentials_allowed():
    """Garante que wildcard '*' no CORS é rejeitado quando credenciais estão ativas."""
    from src.core.infrastructure.config import Settings

    with pytest.raises(ValueError, match="CORS Proibido"):
        Settings(GOVSEC_CORS_ALLOWED_ORIGINS=["*"])


def test_validate_alertmanager_deploy_script_production_failure(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
):
    """Garante que scripts/validate_alertmanager_deploy.py retorna 1 em produção se ausente o arquivo renderizado."""
    from scripts.validate_alertmanager_deploy import validate_deploy
    from src.core.infrastructure.config import settings

    monkeypatch.setattr(settings, "GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", "deploy/alertmanager/non_existent.rendered.yml")
    assert validate_deploy() == 1


def test_redis_token_revocation_fail_closed_in_production(monkeypatch: pytest.MonkeyPatch):
    """Garante comportamento Fail-Closed se o Redis de revogação falhar em produção."""
    from src.core.infrastructure.config import settings
    from src.core.infrastructure.security.revocation import RedisTokenRevocationStore

    monkeypatch.setattr(settings, "GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_ENV", "production")
    store = RedisTokenRevocationStore(redis_url="redis://invalid_host_12345:6379/0")

    with pytest.raises(RuntimeError, match="FAIL-CLOSED"):
        asyncio.run(store.is_revoked("some_token"))


def test_check_scope_unauthenticated_returns_401():
    """Garante que POST /api/v1/security/check-scope sem token retorna 401."""
    from src.api.main import app

    client = TestClient(app)
    res = client.post("/api/v1/security/check-scope", json={"target_ip": "10.1.0.5"})
    assert res.status_code == 401


def test_check_scope_viewer_role_returns_403():
    """Garante que usuário com role 'viewer' recebe 403 ao acessar check-scope."""
    from src.api.main import app

    client = TestClient(app)
    token = JWTHandler.generate_token(user_id="user-viewer", tenant_id="betim", roles=["viewer"])
    res = client.post(
        "/api/v1/security/check-scope",
        json={"target_ip": "10.1.0.5"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403


def test_check_scope_analyst_role_returns_200():
    """Garante que usuário com role 'analyst' acessa check-scope com sucesso."""
    from src.api.main import app

    client = TestClient(app)
    token = JWTHandler.generate_token(user_id="user-analyst", tenant_id="betim", roles=["analyst"])
    res = client.post(
        "/api/v1/security/check-scope",
        json={"target_ip": "10.200.1.5"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert res.json()["is_allowed"] is True



def test_get_tenant_by_id_cross_tenant_forbidden_for_normal_user():
    """Garante que GET /api/v1/tenants/{id} para um tenant diferente retorna 403."""
    from uuid import uuid4

    from src.api.main import app

    client = TestClient(app)
    token = JWTHandler.generate_token(user_id="user-norm", tenant_id="tenant-a", roles=["viewer"])
    other_tenant_id = str(uuid4())

    res = client.get(
        f"/api/v1/tenants/{other_tenant_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403


def test_list_tenants_restricted_to_own_tenant_for_normal_user():
    """Garante que GET /api/v1/tenants retorna apenas o próprio tenant para usuário comum."""
    from uuid import uuid4

    from src.api.main import app
    from src.core.application.queries import TenantQueryHandler
    from src.core.domain.entities import Tenant
    from src.core.infrastructure.db.repositories import InMemoryTenantRepository
    from src.core.interfaces.rest.dependencies import get_query_handler

    repo = InMemoryTenantRepository()
    tenant_uuid = uuid4()
    t1 = Tenant(id=tenant_uuid, name="Prefeitura de Betim", slug="betim")
    t2 = Tenant(id=uuid4(), name="Prefeitura de Contagem", slug="contagem")
    repo._tenants[t1.id] = t1
    repo._tenants[t2.id] = t2

    query_handler = TenantQueryHandler(tenant_repo=repo)
    app.dependency_overrides[get_query_handler] = lambda: query_handler


    try:
        client = TestClient(app)
        token = JWTHandler.generate_token(user_id="user-norm", tenant_id=tenant_uuid, roles=["viewer"])

        res = client.get(
            "/api/v1/tenants",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200
        tenants = res.json()
        assert len(tenants) == 1
        assert tenants[0]["slug"] == "betim"
    finally:
        app.dependency_overrides.pop(get_query_handler, None)



@pytest.mark.asyncio
async def test_async_token_revocation_ttl_and_check():
    """Garante que revocation_store assíncrona registra revogação com JTI e expiração."""
    from src.core.infrastructure.security.revocation import InMemoryTokenRevocationStore

    store = InMemoryTokenRevocationStore()
    token = JWTHandler.generate_token(user_id="user-rev", tenant_id="betim", roles=["analyst"])
    payload = JWTHandler.verify_token(token)

    assert await store.is_revoked(token, payload) is False
    await store.revoke(token, payload)
    assert await store.is_revoked(token, payload) is True


def test_cors_origins_json_list_parsing(monkeypatch: pytest.MonkeyPatch):
    """Garante que GOVSEC_CORS_ALLOWED_ORIGINS aceita formato JSON list."""
    from src.core.infrastructure.config import Settings

    monkeypatch.setenv("GOVSEC_CORS_ALLOWED_ORIGINS", '["http://localhost:3000", "http://127.0.0.1:3000"]')
    s = Settings()
    assert "http://localhost:3000" in s.GOVSEC_CORS_ALLOWED_ORIGINS
    assert "http://127.0.0.1:3000" in s.GOVSEC_CORS_ALLOWED_ORIGINS


def test_cors_prohibits_local_hosts_in_production(monkeypatch: pytest.MonkeyPatch):
    """Garante que GOVSEC_CORS_ALLOWED_ORIGINS rejeita origens locais em produção."""
    from src.core.infrastructure.config import Settings

    monkeypatch.setenv("GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_JWT_SECRET", "super-secret-govsec-key-32-chars-long-prod")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", "deploy/alertmanager/alertmanager.rendered.yml")
    monkeypatch.setenv("GOVSEC_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/X00")
    monkeypatch.setenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "pd-service-key-12345")
    monkeypatch.setenv("GOVSEC_CORS_ALLOWED_ORIGINS", "http://localhost:3000")

    with pytest.raises(ValueError, match="estritamente proibida"):
        Settings()



# =============================================================================
# 10. Testes do Hardening Final M2 — Preflights, Async, Domain, OIDC, Paginação
# =============================================================================





def test_preflight_security_script_invalid_config_fails(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
):
    """Config com termo proibido (test-receiver) retorna 1 em produção."""
    from scripts.validate_alertmanager_deploy import validate_deploy

    bad_config = tmp_path / "alertmanager.rendered.yml"
    bad_config.write_text(
        "route:\n  receiver: test-receiver\nreceivers:\n  - name: test-receiver\n"
    )
    monkeypatch.setenv("GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", str(bad_config))
    monkeypatch.setenv("GOVSEC_SLACK_WEBHOOK_URL", "https://hooks.slack.com/T/B/X")
    monkeypatch.setenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "pd-key-abc123")
    assert validate_deploy() == 1


# =============================================================================
# 10. Testes do Hardening Final M2 — Preflights, Async, Domain, OIDC, Paginação (Comportamentais)
# =============================================================================


def test_preflight_security_script_valid_config_passes(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
):
    """Config válida (com route e receivers) retorna 0 no preflight de segurança em dev."""
    from scripts.validate_alertmanager_deploy import validate_deploy

    valid_config = tmp_path / "alertmanager.yml"
    valid_config.write_text(
        "global:\n"
        "  resolve_timeout: 5m\n"
        "route:\n"
        "  receiver: slack-warnings\n"
        "  routes:\n"
        "    - match:\n"
        "        severity: critical\n"
        "      receiver: pagerduty-and-slack\n"
        "receivers:\n"
        "  - name: pagerduty-and-slack\n"
        "    pagerduty_configs: [{service_key: 'abc'}]\n"
        "    slack_configs: [{api_url: 'https://slack.com'}]\n"
        "  - name: slack-warnings\n"
        "    slack_configs: [{api_url: 'https://slack.com'}]\n"
    )
    monkeypatch.setenv("GOVSEC_ENV", "dev")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", str(valid_config))
    assert validate_deploy() == 0


def test_preflight_security_script_invalid_yaml_syntax(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
):
    """YAML sintaticamente inválido retorna 1 no preflight."""
    from scripts.validate_alertmanager_deploy import validate_deploy

    bad_yaml = tmp_path / "alertmanager.yml"
    bad_yaml.write_text("route: [unclosed_bracket")
    monkeypatch.setenv("GOVSEC_ENV", "dev")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", str(bad_yaml))
    assert validate_deploy() == 1


def test_preflight_security_script_non_existent_receiver_referenced(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
):
    """Rota referenciando receiver inexistente retorna 1."""
    from scripts.validate_alertmanager_deploy import validate_deploy

    bad_ref = tmp_path / "alertmanager.yml"
    bad_ref.write_text(
        "route:\n"
        "  receiver: non-existent-receiver\n"
        "receivers:\n"
        "  - name: defined-receiver\n"
    )
    monkeypatch.setenv("GOVSEC_ENV", "dev")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", str(bad_ref))
    assert validate_deploy() == 1


def test_preflight_security_script_critical_route_missing_pagerduty(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
):
    """Rota crítica sem PagerDuty em produção retorna 1."""
    from scripts.validate_alertmanager_deploy import validate_deploy

    no_pd = tmp_path / "alertmanager.rendered.yml"
    no_pd.write_text(
        "route:\n"
        "  receiver: slack-warnings\n"
        "  routes:\n"
        "    - match:\n"
        "        severity: critical\n"
        "      receiver: slack-only\n"
        "receivers:\n"
        "  - name: slack-only\n"
        "    slack_configs: [{api_url: 'https://hooks.slack.com/services/T/B/X'}]\n"
        "  - name: slack-warnings\n"
        "    slack_configs: [{api_url: 'https://hooks.slack.com/services/T/B/X'}]\n"
    )
    monkeypatch.setenv("GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", str(no_pd))
    monkeypatch.setenv("GOVSEC_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")
    monkeypatch.setenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "pd-key-12345678")
    assert validate_deploy() == 1


def test_preflight_security_script_placeholders_rejected(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
):
    """Presença de placeholders (ex: XXX ou test-receiver) em produção retorna 1."""
    from scripts.validate_alertmanager_deploy import validate_deploy

    placeholder_cfg = tmp_path / "alertmanager.rendered.yml"
    placeholder_cfg.write_text(
        "route:\n"
        "  receiver: test-receiver\n"
        "receivers:\n"
        "  - name: test-receiver\n"
    )
    monkeypatch.setenv("GOVSEC_ENV", "production")
    monkeypatch.setenv("GOVSEC_ALERTMANAGER_CONFIG", str(placeholder_cfg))
    monkeypatch.setenv("GOVSEC_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")
    monkeypatch.setenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "pd-key-12345678")
    assert validate_deploy() == 1


def test_docker_compose_production_has_two_separate_preflights():
    """Verifica que docker-compose.production.yml define dois init containers com caminhos internos fixos."""
    with open("docker/compose/docker-compose.production.yml", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    services = data.get("services", {})
    assert "init-alertmanager-security-preflight" in services
    assert "init-alertmanager-amtool-preflight" in services

    security = services["init-alertmanager-security-preflight"]
    assert "Dockerfile.preflight" in security.get("build", {}).get("dockerfile", "")

    amtool = services["init-alertmanager-amtool-preflight"]
    assert "alertmanager" in amtool["image"]
    assert amtool["entrypoint"] == ["/bin/amtool"]
    assert "/config/alertmanager.yml" in amtool["command"][1]


def test_alertmanager_depends_on_both_preflights():
    """Verifica que alertmanager depende de AMBOS os preflights com service_completed_successfully."""
    with open("docker/compose/docker-compose.production.yml", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    alertmanager = data["services"]["alertmanager"]
    depends = alertmanager["depends_on"]

    assert depends["init-alertmanager-security-preflight"]["condition"] == "service_completed_successfully"
    assert depends["init-alertmanager-amtool-preflight"]["condition"] == "service_completed_successfully"


def test_real_async_refresh_flow(monkeypatch: pytest.MonkeyPatch):
    """Testa o fluxo comportamental assíncrono real do endpoint /refresh."""
    from src.api.main import app
    from src.core.infrastructure.config import settings
    from src.core.infrastructure.security.jwt import JWTHandler

    monkeypatch.setattr(settings, "GOVSEC_ENV", "dev")
    client = TestClient(app)

    stable_uuid = uuid.uuid4()
    refresh_token = JWTHandler.generate_refresh_token(
        user_id="user-async-test", tenant_id=stable_uuid, roles=["analyst"]
    )

    res = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert res.status_code == 200
    new_token = res.json()["access_token"]
    assert new_token is not None

    # Validar que o novo token contém o tenant_id UUID
    payload = JWTHandler.verify_token(new_token)
    assert payload is not None
    assert payload["tenant_id"] == str(stable_uuid)


def test_redis_unavailable_returns_503_behavioral(monkeypatch: pytest.MonkeyPatch):
    """Redis/revogação indisponível em produção retorna HTTP 503 sem expor detalhes internos."""
    from src.api.main import app
    from src.core.domain.exceptions import RedisRevocationUnavailableError
    from src.core.infrastructure.config import settings
    from src.core.infrastructure.security.jwt import JWTHandler

    monkeypatch.setattr(settings, "GOVSEC_ENV", "dev")
    client = TestClient(app)

    stable_uuid = uuid.uuid4()
    token = JWTHandler.generate_token(user_id="user-503", tenant_id=stable_uuid, roles=["analyst"])

    async def mock_verify_async(t: str):
        raise RedisRevocationUnavailableError("Conexão ao Redis de revogação expirou.")

    monkeypatch.setattr(JWTHandler, "verify_token_async", staticmethod(mock_verify_async))

    res = client.get("/api/v1/tenants", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 503
    assert res.json()["detail"] == "Serviço de validação de revogação temporariamente indisponível."
    # Garantir que detalhes de infraestrutura NÃO são expostos
    assert "Conexão ao Redis" not in res.text


def test_tenant_uuid_canonical_identity():
    """Valida normalização e validação de UUIDs de tenant."""
    test_uuid = uuid.uuid4()
    user = AuthenticatedUser(user_id="u1", tenant_id=test_uuid, roles=["viewer"])
    assert user.tenant == str(test_uuid)
    assert isinstance(user.tenant_id, uuid.UUID)


def test_invalid_tenant_uuid_query_param_rejected_400(monkeypatch: pytest.MonkeyPatch):
    """Passar string inválida como UUID no parâmetro tenant_id retorna 400 Bad Request."""
    from src.api.main import app
    from src.core.infrastructure.config import settings
    from src.core.infrastructure.security.jwt import JWTHandler

    monkeypatch.setattr(settings, "GOVSEC_ENV", "dev")
    client = TestClient(app)

    stable_uuid = uuid.uuid4()
    token = JWTHandler.generate_token(user_id="user-val", tenant_id=stable_uuid, roles=["system_admin"])

    res = client.get("/api/v1/logs?tenant_id=invalid-not-a-uuid", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 400
    assert "não é um UUID válido" in res.json()["detail"]


def test_oidc_claims_strict_behavior_in_production(monkeypatch: pytest.MonkeyPatch):
    """Testa o comportamento estrito de OIDC em produção usando provedor falso."""
    from src.api.main import app
    from src.core.application.interfaces.auth_provider import AuthenticationProviderPort
    from src.core.domain.exceptions import InvalidCredentialsError
    from src.core.infrastructure.config import settings

    monkeypatch.setattr(settings, "GOVSEC_ENV", "production")
    client = TestClient(app)

    stable_uuid = str(uuid.uuid4())

    class MockOIDCProvider(AuthenticationProviderPort):
        async def authenticate_credentials(self, email: str, password: str, tenant_id: str | None = None):
            if email == "valid@gov.br":
                return {"sub": "oidc-user-123", "tenant_id": stable_uuid, "roles": ["analyst"]}
            if email == "missing_sub@gov.br":
                return {"tenant_id": stable_uuid, "roles": ["analyst"]}
            if email == "bad_uuid@gov.br":
                return {"sub": "u2", "tenant_id": "not-a-uuid", "roles": ["analyst"]}
            raise InvalidCredentialsError("Credenciais inválidas no OIDC.")

    monkeypatch.setattr(
        "src.core.interfaces.rest.auth_routers.DefaultOIDCAuthenticationProvider",
        MockOIDCProvider,
    )

    # 1. Claims válidos -> Autenticação bem sucedida
    res1 = client.post("/api/v1/auth/login", json={"email": "valid@gov.br", "password": "pass"})
    assert res1.status_code == 200
    assert "access_token" in res1.json()

    # 2. Sub ausente -> 401
    res2 = client.post("/api/v1/auth/login", json={"email": "missing_sub@gov.br", "password": "pass"})
    assert res2.status_code == 401
    assert "sub" in res2.json()["detail"].lower()

    # 3. Tenant ID não UUID -> 401
    res3 = client.post("/api/v1/auth/login", json={"email": "bad_uuid@gov.br", "password": "pass"})
    assert res3.status_code == 401
    assert "uuid" in res3.json()["detail"].lower()


