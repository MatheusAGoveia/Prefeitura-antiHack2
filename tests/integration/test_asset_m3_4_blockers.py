"""
Testes de Integração para Correção dos Bloqueadores da M3.4 (Backend de Scanners).
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
async def test_scan_target_delete_and_cross_tenant_isolation(async_client: AsyncClient):
    tenant_a = str(uuid4())
    tenant_b = str(uuid4())
    headers_a = create_auth_headers(tenant_a, role="engineer")
    headers_b = create_auth_headers(tenant_b, role="engineer")

    # 1. Criar Grupo e Alvo no Tenant A
    res_g = await async_client.post(
        "/api/v1/asset-groups",
        headers=headers_a,
        json={"name": "Grupo Alvo " + uuid4().hex[:6], "environment": "production", "criticality": "high"},
    )
    assert res_g.status_code == 201
    group_id = res_g.json()["id"]

    res_t = await async_client.post(
        "/api/v1/scan-targets",
        headers=headers_a,
        json={"asset_group_id": group_id, "name": "Servidor Teste", "target_type": "single_ip", "target_value": "192.168.1.100"},
    )
    assert res_t.status_code == 201
    target_id = res_t.json()["id"]

    # 2. Tenant B tenta deletar alvo do Tenant A (Cross-Tenant -> 404 NOT FOUND)
    res_del_b = await async_client.delete(f"/api/v1/scan-targets/{target_id}", headers=headers_b)
    assert res_del_b.status_code == 404

    # 3. Tenant A deleta o próprio alvo (204 NO CONTENT)
    res_del_a = await async_client.delete(f"/api/v1/scan-targets/{target_id}", headers=headers_a)
    assert res_del_a.status_code == 204


@pytest.mark.asyncio
async def test_scanner_profile_patch_and_delete(async_client: AsyncClient):
    tenant_id = str(uuid4())
    headers = create_auth_headers(tenant_id, role="engineer")

    # 1. Criar Perfil
    res_p = await async_client.post(
        "/api/v1/scanner-profiles",
        headers=headers,
        json={"name": "Perfil Teste " + uuid4().hex[:6], "scanner_type": "network_discovery", "port_strategy": "top_100"},
    )
    assert res_p.status_code == 201
    profile_id = res_p.json()["id"]

    # 2. PATCH perfil
    res_patch = await async_client.patch(
        f"/api/v1/scanner-profiles/{profile_id}",
        headers=headers,
        json={"name": "Perfil Atualizado", "port_strategy": "top_1000"},
    )
    assert res_patch.status_code == 200
    assert res_patch.json()["name"] == "Perfil Atualizado"
    assert res_patch.json()["port_strategy"] == "top_1000"

    # 3. DELETE perfil
    res_del = await async_client.delete(f"/api/v1/scanner-profiles/{profile_id}", headers=headers)
    assert res_del.status_code == 204


@pytest.mark.asyncio
async def test_scan_schedule_patch_and_delete(async_client: AsyncClient):
    tenant_id = str(uuid4())
    headers = create_auth_headers(tenant_id, role="engineer")

    # 1. Criar Perfil, Grupo e Alvo
    res_g = await async_client.post("/api/v1/asset-groups", headers=headers, json={"name": "Grupo " + uuid4().hex[:6]})
    group_id = res_g.json()["id"]
    res_t = await async_client.post("/api/v1/scan-targets", headers=headers, json={"asset_group_id": group_id, "name": "Alvo 1", "target_type": "single_ip", "target_value": "10.0.0.1"})
    target_id = res_t.json()["id"]
    res_p = await async_client.post("/api/v1/scanner-profiles", headers=headers, json={"name": "Perfil " + uuid4().hex[:6], "scanner_type": "network_discovery"})
    profile_id = res_p.json()["id"]

    # 2. Criar Agendamento
    res_s = await async_client.post(
        "/api/v1/scan-schedules",
        headers=headers,
        json={"name": "Agendamento " + uuid4().hex[:6], "scanner_profile_id": profile_id, "target_ids": [target_id], "frequency_type": "weekly"},
    )
    assert res_s.status_code == 201
    schedule_id = res_s.json()["id"]

    # 3. PATCH agendamento
    res_patch = await async_client.patch(
        f"/api/v1/scan-schedules/{schedule_id}",
        headers=headers,
        json={"name": "Agendamento Alterado", "frequency_type": "daily"},
    )
    assert res_patch.status_code == 200
    assert res_patch.json()["name"] == "Agendamento Alterado"
    assert res_patch.json()["frequency_type"] == "daily"

    # 4. DELETE agendamento
    res_del = await async_client.delete(f"/api/v1/scan-schedules/{schedule_id}", headers=headers)
    assert res_del.status_code == 204


@pytest.mark.asyncio
async def test_monitoring_integration_credential_masking_and_patch(async_client: AsyncClient):
    tenant_id = str(uuid4())
    headers = create_auth_headers(tenant_id, role="security_admin")

    # 1. Cadastrar Integração Zabbix com secret
    res_c = await async_client.post(
        "/api/v1/monitoring-integrations",
        headers=headers,
        json={
            "name": "Zabbix Pref " + uuid4().hex[:6],
            "base_url": "https://zabbix.prefeitura.gov.br/api_jsonrpc.php",
            "credential_reference": "vault://zabbix/super_secret_token",
            "provider": "zabbix",
        },
    )
    assert res_c.status_code == 201
    data = res_c.json()
    integration_id = data["id"]

    # GARANTIA ABSOLUTA: credential_reference NÃO PODE APARECER NA RESPOSTA HTTP
    assert "credential_reference" not in data
    assert data["credentials_configured"] is True

    # 2. Consultar Detalhes (GET)
    res_get = await async_client.get(f"/api/v1/monitoring-integrations/{integration_id}", headers=headers)
    assert res_get.status_code == 200
    assert "credential_reference" not in res_get.json()
    assert res_get.json()["credentials_configured"] is True

    # 3. PATCH sem enviar credential_reference -> Deve preservar a credencial anterior
    res_patch = await async_client.patch(
        f"/api/v1/monitoring-integrations/{integration_id}",
        headers=headers,
        json={"name": "Zabbix Atualizado", "base_url": "https://zabbix2.prefeitura.gov.br/api_jsonrpc.php"},
    )
    assert res_patch.status_code == 200
    assert res_patch.json()["name"] == "Zabbix Atualizado"
    assert "credential_reference" not in res_patch.json()
    assert res_patch.json()["credentials_configured"] is True

    # 4. DELETE integração
    res_del = await async_client.delete(f"/api/v1/monitoring-integrations/{integration_id}", headers=headers)
    assert res_del.status_code == 204


@pytest.mark.asyncio
async def test_detail_screen_endpoints_pagination(async_client: AsyncClient):
    tenant_id = str(uuid4())
    headers = create_auth_headers(tenant_id, role="security_admin")

    # 1. Criar Grupo, Alvo e Perfil
    res_g = await async_client.post("/api/v1/asset-groups", headers=headers, json={"name": "Grupo " + uuid4().hex[:6]})
    group_id = res_g.json()["id"]
    res_t = await async_client.post("/api/v1/scan-targets", headers=headers, json={"asset_group_id": group_id, "name": "Alvo A", "target_type": "single_ip", "target_value": "10.10.10.1"})
    target_id = res_t.json()["id"]
    res_p = await async_client.post("/api/v1/scanner-profiles", headers=headers, json={"name": "Perfil " + uuid4().hex[:6], "scanner_type": "network_discovery"})
    profile_id = res_p.json()["id"]

    # 2. Disparar Execução
    res_e = await async_client.post("/api/v1/scan-executions", headers=headers, json={"scanner_profile_id": profile_id, "target_ids": [target_id]})
    assert res_e.status_code == 202
    exec_id = res_e.json()["execution_id"]

    # 3. GET /scan-executions/{exec_id}/targets
    res_targets = await async_client.get(f"/api/v1/scan-executions/{exec_id}/targets", headers=headers)
    assert res_targets.status_code == 200
    assert "items" in res_targets.json()
    assert "pages" in res_targets.json()

    # 4. GET /scan-executions/{exec_id}/findings
    res_findings = await async_client.get(f"/api/v1/scan-executions/{exec_id}/findings", headers=headers)
    assert res_findings.status_code == 200
    assert "items" in res_findings.json()

    # 5. GET /monitoring-integrations/{integration_id}/sync-history
    res_integ = await async_client.post(
        "/api/v1/monitoring-integrations",
        headers=headers,
        json={"name": "Zabbix Sync " + uuid4().hex[:6], "base_url": "https://zabbix.gov.br", "credential_reference": "token123"},
    )
    integ_id = res_integ.json()["id"]

    res_history = await async_client.get(f"/api/v1/monitoring-integrations/{integ_id}/sync-history", headers=headers)
    assert res_history.status_code == 200
    assert "items" in res_history.json()


@pytest.mark.asyncio
async def test_bulk_target_import_preview_and_execution(async_client: AsyncClient):
    tenant_id = str(uuid4())
    headers = create_auth_headers(tenant_id, role="engineer")

    # 1. Criar Grupo
    res_g = await async_client.post("/api/v1/asset-groups", headers=headers, json={"name": "Grupo Import " + uuid4().hex[:6]})
    group_id = res_g.json()["id"]

    # 2. Preview sem Persistência (POST /import/preview)
    raw_csv = "10.0.0.1\n172.16.0.0/24\n=SUM(A1:A10)\ninvalid_ip"
    res_prev = await async_client.post(
        "/api/v1/scan-targets/import/preview",
        headers=headers,
        data={"asset_group_id": group_id, "raw_paste": raw_csv},
    )
    assert res_prev.status_code == 200
    prev_data = res_prev.json()
    assert prev_data["total_received"] == 4
    assert prev_data["valid"] == 2
    assert prev_data["invalid"] == 2

    # Verifica que a linha com fórmula foi rejeitada
    formula_item = next(item for item in prev_data["items"] if "=SUM" in item["original_value"])
    assert formula_item["valid"] is False
    assert any("fórmula" in err for err in formula_item["errors"])

    # 3. Importação em Massa via JSON Bulk (POST /bulk)
    res_bulk = await async_client.post(
        "/api/v1/scan-targets/bulk",
        headers=headers,
        json={
            "asset_group_id": group_id,
            "authorization_reference": "DOC-AUTH-2026-999",
            "items": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        },
    )
    assert res_bulk.status_code == 201
    bulk_data = res_bulk.json()
    assert bulk_data["created_count"] == 3

    # 4. Importação Duplicada (deve pular os já cadastrados)
    res_bulk_dup = await async_client.post(
        "/api/v1/scan-targets/bulk",
        headers=headers,
        json={
            "asset_group_id": group_id,
            "authorization_reference": "DOC-AUTH-2026-999",
            "items": ["10.0.0.1", "10.0.0.4"],
        },
    )
    assert res_bulk_dup.status_code == 201
    dup_data = res_bulk_dup.json()
    assert dup_data["created_count"] == 1
    assert dup_data["skipped_duplicates"] == 1

    # 5. Teste de PDF sem camada de texto (deve retornar erro claro de OCR)
    fake_scanned_pdf = b"%PDF-1.4 %fake scanned pdf with no text layer"
    files = {"file": ("scanned.pdf", fake_scanned_pdf, "application/pdf")}
    res_pdf = await async_client.post(
        "/api/v1/scan-targets/import/preview",
        headers=headers,
        data={"asset_group_id": group_id},
        files=files,
    )
    assert res_pdf.status_code == 400
    assert "OCR ainda não é suportado" in res_pdf.json()["detail"]
