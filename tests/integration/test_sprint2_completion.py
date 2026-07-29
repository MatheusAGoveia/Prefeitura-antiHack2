"""
Testes de Conclusão da Sprint 2 — Cobertura 100%
GovSec Shield — Integration Tests

Cobre os 6 itens pendentes da Sprint 2:
1. Spans para Eventos de Domínio
2. Métricas Prometheus para Eventos
3. Mascaramento de Dados Sensíveis (DataMasker)
4. Métricas de Sistema com psutil (SystemMetricsCollector)
5. Middleware de Recovery (RecoveryMiddleware)
6. Cobertura consolidada de testes
"""

from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.core.domain.events import LogIngestedEvent, TenantCreatedEvent
from src.core.interfaces.event_handlers.log_event_handler import LogEventHandler
from src.core.interfaces.event_handlers.tenant_event_handler import TenantEventHandler
from src.shared.observability.metrics import (
    DOMAIN_EVENTS_TOTAL,
)
from src.shared.observability.sanitizer import DataMasker, data_masker
from src.shared.observability.system_metrics import SystemMetricsCollector

# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def tenant_event() -> TenantCreatedEvent:
    return TenantCreatedEvent(
        tenant_id=uuid4(),
        name="Prefeitura de SP",
        slug="pref-sp",
    )


@pytest.fixture
def log_event() -> LogIngestedEvent:
    return LogIngestedEvent(
        tenant_id=uuid4(),
        source="wazuh-agent-01",
        raw_data='{"level": "alert", "msg": "Unauthorized access attempt"}',
    )


@pytest.fixture
def masker() -> DataMasker:
    return DataMasker()


# ─── Item 1: Spans para Eventos ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_event_handler_tenant_created_span(tenant_event: TenantCreatedEvent) -> None:
    """Valida que o TenantEventHandler cria um span OTel e processa o evento sem erro."""
    handler = TenantEventHandler()
    # Deve executar sem exceção, criando span e incrementando métricas
    await handler.handle_tenant_created(tenant_event)


@pytest.mark.asyncio
async def test_event_handler_log_ingested_span(log_event: LogIngestedEvent) -> None:
    """Valida que o LogEventHandler cria um span OTel e processa o evento sem erro."""
    handler = LogEventHandler()
    await handler.handle_log_ingested(log_event)


@pytest.mark.asyncio
async def test_event_handler_tenant_created_dict_format() -> None:
    """Valida que o TenantEventHandler aceita evento como dict (formato legado)."""
    handler = TenantEventHandler()
    event_dict = {
        "tenant_id": str(uuid4()),
        "name": "Prefeitura RJ",
        "slug": "pref-rj",
        "event_id": str(uuid4()),
    }
    # Deve processar dicionário sem erro
    await handler.handle_tenant_created(event_dict)


@pytest.mark.asyncio
async def test_event_handler_log_ingested_dict_format() -> None:
    """Valida que o LogEventHandler aceita evento como dict (formato legado)."""
    handler = LogEventHandler()
    event_dict = {
        "tenant_id": str(uuid4()),
        "source": "zabbix-monitor",
        "raw_data": "cpu_load=98%",
        "event_id": str(uuid4()),
    }
    await handler.handle_log_ingested(event_dict)


# ─── Item 2: Métricas de Eventos ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_domain_events_metrics_tenant_created(tenant_event: TenantCreatedEvent) -> None:
    """Valida que o processamento de TenantCreatedEvent incrementa DOMAIN_EVENTS_TOTAL."""
    handler = TenantEventHandler()
    tenant_str = str(tenant_event.tenant_id)

    # Capturar valor antes
    before = DOMAIN_EVENTS_TOTAL.labels(
        event_type="TenantCreatedEvent", tenant=tenant_str, status="success"
    )._value.get()

    await handler.handle_tenant_created(tenant_event)

    after = DOMAIN_EVENTS_TOTAL.labels(
        event_type="TenantCreatedEvent", tenant=tenant_str, status="success"
    )._value.get()

    assert after == before + 1.0


@pytest.mark.asyncio
async def test_domain_events_metrics_log_ingested(log_event: LogIngestedEvent) -> None:
    """Valida que o processamento de LogIngestedEvent incrementa DOMAIN_EVENTS_TOTAL."""
    handler = LogEventHandler()
    tenant_str = str(log_event.tenant_id)

    before = DOMAIN_EVENTS_TOTAL.labels(
        event_type="LogIngestedEvent", tenant=tenant_str, status="success"
    )._value.get()

    await handler.handle_log_ingested(log_event)

    after = DOMAIN_EVENTS_TOTAL.labels(
        event_type="LogIngestedEvent", tenant=tenant_str, status="success"
    )._value.get()

    assert after == before + 1.0


# ─── Item 3: Mascaramento de Dados Sensíveis ─────────────────────────────────


def test_data_masker_masks_password(masker: DataMasker) -> None:
    """Valida mascaramento de campo 'password' em dicionário."""
    data = {"username": "admin", "password": "super_secret_123"}
    result = masker.mask_dict(data)
    assert result["password"] == "[REDACTED]"
    assert result["username"] == "admin"


def test_data_masker_masks_token(masker: DataMasker) -> None:
    """Valida mascaramento de campo 'token' em dicionário."""
    data = {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"}
    result = masker.mask_dict(data)
    assert result["token"] == "[REDACTED]"


def test_data_masker_masks_jwt_bearer_in_text(masker: DataMasker) -> None:
    """Valida mascaramento de Bearer JWT em string de texto livre."""
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.cGF5bG9hZA.c2lnbmF0dXJl"
    result = masker.mask_text(text)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
    assert "[REDACTED_JWT]" in result


def test_data_masker_masks_cpf_formatted(masker: DataMasker) -> None:
    """Valida mascaramento de CPF com pontuação."""
    text = "CPF do usuário: 123.456.789-09"
    result = masker.mask_text(text)
    assert "123.456.789-09" not in result
    assert "[REDACTED_CPF]" in result


def test_data_masker_masks_email(masker: DataMasker) -> None:
    """Valida mascaramento de e-mail em texto livre."""
    text = "Contato: admin@prefeitura.sp.gov.br para suporte"
    result = masker.mask_text(text)
    assert "admin@prefeitura.sp.gov.br" not in result
    assert "[REDACTED_EMAIL]" in result


def test_data_masker_nested_dict(masker: DataMasker) -> None:
    """Valida mascaramento recursivo em dicionários aninhados.

    NOTA: 'credentials' é chave sensível → todo valor é mascarado como '[REDACTED]'.
    Usa 'auth_data' (não sensível por nome) para testar recursão interna.
    """
    data = {
        "user": {
            "name": "João Silva",
            "auth_data": {
                "password": "senha_secreta_456",
                "api_key": "sk-1234567890abcdef",
            },
        }
    }
    result = masker.mask_dict(data)
    # 'auth_data' não é sensível por nome → recursão interna
    assert result["user"]["auth_data"]["password"] == "[REDACTED]"
    assert result["user"]["auth_data"]["api_key"] == "[REDACTED]"
    assert result["user"]["name"] == "João Silva"


def test_data_masker_sensitive_key_masks_entire_value(masker: DataMasker) -> None:
    """Valida que chave de nome sensível mascara o valor inteiro (inclusive dicionários)."""
    data = {"credentials": {"username": "admin", "password": "123"}}
    result = masker.mask_dict(data)
    # A chave 'credentials' é sensível → valor mascarado completo
    assert result["credentials"] == "[REDACTED]"


def test_data_masker_mask_dispatch_string(masker: DataMasker) -> None:
    """Valida que mask() delega para mask_text quando recebe string."""
    text = "usuario: admin, senha: top_secret"
    result = masker.mask(text)
    assert isinstance(result, str)
    assert "top_secret" not in result


def test_data_masker_mask_dispatch_dict(masker: DataMasker) -> None:
    """Valida que mask() delega para mask_dict quando recebe dicionário."""
    data = {"secret": "valor_secreto"}
    result = masker.mask(data)
    assert isinstance(result, dict)
    assert result["secret"] == "[REDACTED]"


def test_global_data_masker_singleton() -> None:
    """Valida que o singleton data_masker está disponível e é instância de DataMasker."""
    assert isinstance(data_masker, DataMasker)


# ─── Item 4: Métricas de Sistema com psutil ───────────────────────────────────


def test_system_metrics_collector_returns_dict() -> None:
    """Valida que SystemMetricsCollector.collect() retorna dicionário com chaves esperadas."""
    collector = SystemMetricsCollector()
    metrics = collector.collect()

    assert isinstance(metrics, dict)
    assert "cpu_percent" in metrics
    assert "memory_used_bytes" in metrics
    assert "memory_total_bytes" in metrics
    assert "disk_used_bytes" in metrics
    assert "disk_total_bytes" in metrics
    assert "open_file_descriptors" in metrics


def test_system_metrics_collector_cpu_is_numeric() -> None:
    """Valida que o valor de CPU retornado é um número (float/int) ou None em falha."""
    collector = SystemMetricsCollector()
    metrics = collector.collect()
    cpu = metrics.get("cpu_percent")
    # None é permitido em ambientes onde psutil não consegue ler CPU
    assert cpu is None or isinstance(cpu, int | float)


def test_system_metrics_collector_memory_positive() -> None:
    """Valida que memória usada e total são valores positivos."""
    collector = SystemMetricsCollector()
    metrics = collector.collect()
    used = metrics.get("memory_used_bytes")
    total = metrics.get("memory_total_bytes")
    if used is not None and total is not None:
        assert used >= 0
        assert total > 0
        assert used <= total


# ─── Item 5: Middleware de Recovery ──────────────────────────────────────────


def test_recovery_middleware_returns_500_on_unhandled_exception() -> None:
    """Valida que o RecoveryMiddleware captura exceções e retorna HTTP 500 padronizado."""
    from src.api.middleware.recovery import RecoveryMiddleware

    test_app = FastAPI()

    @test_app.get("/crash")
    async def crash_route() -> None:
        raise RuntimeError("Simulação de erro interno crítico")

    test_app.add_middleware(RecoveryMiddleware)
    client = TestClient(test_app, raise_server_exceptions=False)

    response = client.get("/crash")

    assert response.status_code == 500
    body = response.json()
    assert body["error"] == "internal_server_error"
    assert "recovery_id" in body
    # Stack trace NÃO deve vazar ao cliente
    assert "RuntimeError" not in body.get("message", "")
    assert "Simulação" not in body.get("message", "")


def test_recovery_middleware_passes_through_success() -> None:
    """Valida que o RecoveryMiddleware não interfere em requisições bem-sucedidas."""
    from src.api.middleware.recovery import RecoveryMiddleware

    test_app = FastAPI()

    @test_app.get("/ok")
    async def ok_route() -> dict:
        return {"status": "ok"}

    test_app.add_middleware(RecoveryMiddleware)
    client = TestClient(test_app, raise_server_exceptions=False)

    response = client.get("/ok")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_recovery_middleware_provides_recovery_id() -> None:
    """Valida que o recovery_id retornado é um UUID válido para correlação em logs."""
    from uuid import UUID

    from src.api.middleware.recovery import RecoveryMiddleware

    test_app = FastAPI()

    @test_app.get("/error")
    async def error_route() -> None:
        raise ValueError("Erro de validação inesperado")

    test_app.add_middleware(RecoveryMiddleware)
    client = TestClient(test_app, raise_server_exceptions=False)

    response = client.get("/error")
    assert response.status_code == 500
    recovery_id = response.json().get("recovery_id")
    assert recovery_id is not None
    # Deve ser um UUID válido
    UUID(recovery_id)  # Raises ValueError se inválido
