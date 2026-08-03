"""
Testes de Integração para Endpoints, RBAC e Multi-Tenancy do Módulo de Ativos e Scanners (M3.4).
GovSec Shield — Integration Test Suite
"""

from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import src.asset.infrastructure.db.models  # noqa: F401
from src.api.main import app
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.models import Base
from src.core.infrastructure.db.unit_of_work import get_db_session
from src.core.infrastructure.security.jwt import JWTHandler, JWTUtils
from src.core.infrastructure.security.revocation import InMemoryTokenRevocationStore


def create_auth_headers(tenant_id: str, role: str = "engineer") -> dict[str, str]:
    """Gera token JWT autêntico para os testes de integração de API."""
    token = JWTUtils.create_access_token(user_id=str(uuid4()), tenant_id=tenant_id, roles=[role])
    return {
        "Authorization": "Bearer " + token,
    }


@pytest_asyncio.fixture
async def async_session():
    """Sessão isolada com engine dedicado por teste."""
    engine = create_async_engine(settings.GOVSEC_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def async_client(async_session: AsyncSession):
    """Cliente HTTP com override de get_db_session para a sessão de teste."""
    JWTHandler.set_revocation_store(InMemoryTokenRevocationStore())

    async def _override_get_db_session():
        yield async_session

    app.dependency_overrides[get_db_session] = _override_get_db_session
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        yield client
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_validate_scan_target_endpoint(async_client: AsyncClient):
    headers = create_auth_headers(str(uuid4()))

    # 1. IP Único Válido
    resp = await async_client.post(
        "/api/v1/scan-targets/validate",
        headers=headers,
        json={"target_type": "single_ip", "target_value": "10.10.1.15"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is True
    assert data["normalized_value"] == "10.10.1.15"
    assert data["estimated_addresses"] == 1

    # 2. Bloco CIDR Válido
    resp_cidr = await async_client.post(
        "/api/v1/scan-targets/validate",
        headers=headers,
        json={"target_type": "cidr", "target_value": "172.16.0.0/24"},
    )
    assert resp_cidr.status_code == 200
    data_cidr = resp_cidr.json()
    assert data_cidr["is_valid"] is True
    assert data_cidr["estimated_addresses"] == 256
    assert data_cidr["first_ip"] == "172.16.0.0"
    assert data_cidr["last_ip"] == "172.16.0.255"

    # 3. Intervalo de IP Invertido (Deve indicar is_valid = False)
    resp_inv = await async_client.post(
        "/api/v1/scan-targets/validate",
        headers=headers,
        json={"target_type": "ip_range", "target_value": "10.0.0.50-10.0.0.10"},
    )
    assert resp_inv.status_code == 200
    data_inv = resp_inv.json()
    assert data_inv["is_valid"] is False
    assert "é menor que o IP inicial" in data_inv["error_message"]


@pytest.mark.asyncio
async def test_asset_group_crud_and_cross_tenant_isolation(async_client: AsyncClient):
    tenant_a = str(uuid4())
    tenant_b = str(uuid4())

    headers_a = create_auth_headers(tenant_a, role="engineer")
    headers_b = create_auth_headers(tenant_b, role="engineer")

    # 1. Tenant A cria um grupo de ativos
    resp = await async_client.post(
        "/api/v1/asset-groups",
        headers=headers_a,
        json={
            "name": "Rede Datacenter " + uuid4().hex[:6],
            "environment": "production",
            "criticality": "high",
        },
    )
    assert resp.status_code == 201
    group_a = resp.json()
    group_id = group_a["id"]
    assert group_a["tenant_id"] == tenant_a

    # 2. Tenant A consulta o próprio grupo (200 OK)
    resp_get_a = await async_client.get("/api/v1/asset-groups/" + str(group_id), headers=headers_a)
    assert resp_get_a.status_code == 200

    # 3. Tenant B tenta consultar o grupo do Tenant A (Cross-Tenant -> 404 NOT FOUND)
    resp_get_b = await async_client.get("/api/v1/asset-groups/" + str(group_id), headers=headers_b)
    assert resp_get_b.status_code == 404

    # 4. Tenant B tenta deletar o grupo do Tenant A (Cross-Tenant -> 404 NOT FOUND)
    resp_del_b = await async_client.delete("/api/v1/asset-groups/" + str(group_id), headers=headers_b)
    assert resp_del_b.status_code == 404


@pytest.mark.asyncio
async def test_scan_execution_manual_dispatch_returns_202(async_client: AsyncClient):
    tenant_id = str(uuid4())
    headers = create_auth_headers(tenant_id, role="engineer")

    # 1. Criar Grupo
    res_g = await async_client.post(
        "/api/v1/asset-groups",
        headers=headers,
        json={"name": "Rede para Scanner " + uuid4().hex[:6], "environment": "production", "criticality": "high"},
    )
    assert res_g.status_code == 201
    group_id = res_g.json()["id"]

    # 2. Criar Alvo
    res_t = await async_client.post(
        "/api/v1/scan-targets",
        headers=headers,
        json={
            "asset_group_id": group_id,
            "name": "Servidor Alvo",
            "target_type": "single_ip",
            "target_value": "10.0.10.5",
        },
    )
    assert res_t.status_code == 201
    target_id = res_t.json()["id"]

    # 3. Criar Perfil de Scanner
    res_p = await async_client.post(
        "/api/v1/scanner-profiles",
        headers=headers,
        json={
            "name": "Perfil Descoberta Rápida " + uuid4().hex[:6],
            "scanner_type": "network_discovery",
            "port_strategy": "top_100",
        },
    )
    assert res_p.status_code == 201
    profile_id = res_p.json()["id"]

    # 4. Disparar Execução Manual (DEVE RETORNAR 202 ACCEPTED)
    res_exec = await async_client.post(
        "/api/v1/scan-executions",
        headers=headers,
        json={"scanner_profile_id": profile_id, "target_ids": [target_id]},
    )
    assert res_exec.status_code == 202
    exec_data = res_exec.json()
    assert exec_data["status"] == "queued"
    assert exec_data["targets_total"] == 1
    execution_id = exec_data["execution_id"]

    # 5. Consultar Detalhes da Execução
    res_get_exec = await async_client.get("/api/v1/scan-executions/" + str(execution_id), headers=headers)
    assert res_get_exec.status_code == 200
    assert res_get_exec.json()["status"] == "queued"

    # 6. Cancelar Execução Enfileirada
    res_cancel = await async_client.post("/api/v1/scan-executions/" + str(execution_id) + "/cancel", headers=headers)
    assert res_cancel.status_code == 200
    assert res_cancel.json()["status"] == "cancelled"


@pytest.mark.asyncio
async def test_monitoring_zabbix_integration_endpoints(async_client: AsyncClient):
    tenant_id = str(uuid4())
    headers = create_auth_headers(tenant_id, role="security_admin")

    # 1. Cadastrar Integração Zabbix
    res_create = await async_client.post(
        "/api/v1/monitoring-integrations",
        headers=headers,
        json={
            "name": "Zabbix Servidores " + uuid4().hex[:6],
            "base_url": "https://zabbix.prefeitura.gov.br/api_jsonrpc.php",
            "credential_reference": "vault://zabbix/api_token",
            "provider": "zabbix",
        },
    )
    assert res_create.status_code == 201
    integration_id = res_create.json()["id"]

    # 2. Testar Conectividade (sem retornar senhas/tokens)
    res_test = await async_client.post("/api/v1/monitoring-integrations/" + str(integration_id) + "/test", headers=headers)
    assert res_test.status_code == 200
    assert res_test.json()["status"] == "success"
    assert "token" not in str(res_test.json()).lower()

    # 3. Disparar Sincronização Assíncrona (DEVE RETORNAR 202 ACCEPTED)
    res_sync = await async_client.post("/api/v1/monitoring-integrations/" + str(integration_id) + "/sync", headers=headers)
    assert res_sync.status_code == 202
    assert res_sync.json()["status"] == "queued"
