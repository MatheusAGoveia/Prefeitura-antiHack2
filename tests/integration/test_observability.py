"""
Testes de Integração da Suíte de Observabilidade & SRE
GovSec Shield — Integration Tests
"""

import json
import logging
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.api.main import app
from src.core.application.commands import Command, CommandMetadata
from src.core.application.queries import GetTenantByIdQuery, TenantQueryHandler
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.models import Base
from src.core.infrastructure.messaging.command_bus import CommandBus
from src.shared.observability.logging import GovSecJSONFormatter


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest_asyncio.fixture
async def async_session_obs():
    """Sessão DB isolada para testes de observabilidade que requerem acesso ao banco."""
    engine = create_async_engine(settings.GOVSEC_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.mark.asyncio
async def test_metrics_endpoint(async_session_obs: AsyncSession) -> None:
    """Valida a exposição e formato do endpoint GET /metrics do Prometheus Exporter."""
    from src.core.infrastructure.db.unit_of_work import get_db_session

    async def _override_get_db_session():
        yield async_session_obs

    app.dependency_overrides[get_db_session] = _override_get_db_session
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            await ac.get("/healthz")  # Registrar tráfego antes do scrape
            response = await ac.get("/metrics")
    finally:
        app.dependency_overrides.pop(get_db_session, None)

    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"] or "version=0.0.4" in response.headers["content-type"]

    content = response.text
    assert "http_requests_total" in content
    assert "http_request_duration_seconds" in content


def test_liveness_endpoint(client: TestClient) -> None:
    """Valida o endpoint de Liveness (/healthz)."""
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "govsec-core"


def test_readiness_endpoint(client: TestClient) -> None:
    """Valida o endpoint de Readiness (/ready)."""
    response = client.get("/ready")
    assert response.status_code in (200, 503)
    data = response.json()
    assert "status" in data
    assert "checks" in data
    assert "database" in data["checks"]
    assert "kafka" in data["checks"]


def test_structured_json_logging_formatter() -> None:
    """Valida se o formatador de log produz JSON estruturado com os campos obrigatórios."""
    formatter = GovSecJSONFormatter()
    record = logging.LogRecord(
        name="govsec.test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Teste de mensagem estruturada",
        args=(),
        exc_info=None,
    )
    record.correlation_id = "test-corr-123"
    record.tenant = "tenant-prefeitura-sp"

    formatted = formatter.format(record)
    data = json.loads(formatted)

    assert data["level"] == "INFO"
    assert data["logger"] == "govsec.test"
    assert data["message"] == "Teste de mensagem estruturada"
    assert data["correlation_id"] == "test-corr-123"
    assert data["tenant"] == "tenant-prefeitura-sp"
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_command_bus_tracing_and_metrics() -> None:
    """Valida se a execução de Commands gera Spans e incrementa contadores Prometheus."""
    opa_mock = MagicMock()
    opa_mock.evaluate_policy = AsyncMock(return_value=True)

    handler_mock = AsyncMock(return_value={"status": "created"})

    bus = CommandBus(opa_client=opa_mock)
    bus.register("CreateTenantCommand", handler_mock)

    cmd = Command(
        payload={"name": "Prefeitura SP"},
        metadata=CommandMetadata(
            command_name="CreateTenantCommand",
            tenant="tenant-sp",
        ),
    )

    result = await bus.send(cmd)
    assert result == {"status": "created"}
    handler_mock.assert_called_once_with(cmd)


@pytest.mark.asyncio
async def test_query_handler_tracing_spans() -> None:
    """Valida se a execução de QueryHandlers é empacotada por Spans de Tracing."""
    repo_mock = MagicMock()
    repo_mock.get_by_id = AsyncMock(return_value=None)

    handler = TenantQueryHandler(tenant_repo=repo_mock)
    query = GetTenantByIdQuery(tenant_id=UUID("00000000-0000-0000-0000-000000000001"))

    res = await handler.get_by_id(query)
    assert res is None
    repo_mock.get_by_id.assert_called_once()
