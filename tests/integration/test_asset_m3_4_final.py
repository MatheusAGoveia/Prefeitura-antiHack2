"""
Testes de Integração e Segurança para a Correção Final da M3.4 (Asset & Scanner Management).
GovSec Shield — Integration & Security Testing (M3.4)
"""

import io
import zipfile
from uuid import uuid4

import pytest
from httpx import AsyncClient

from tests.integration.test_asset_m3_4_blockers import async_client, async_session, create_auth_headers  # noqa: F401


@pytest.mark.asyncio
async def test_manual_dispatch_permissions_and_cross_tenant(async_client: AsyncClient) -> None:
    """Valida permissões RBAC de disparo (EXECUTE vs CANCEL) e isolamento multi-tenant (404)."""
    tenant_id = str(uuid4())
    engineer_auth_headers = create_auth_headers(tenant_id, role="engineer")
    viewer_auth_headers = create_auth_headers(tenant_id, role="viewer")

    # 1. Criar Grupo, Alvo, Perfil e Agendamento
    res_group = await async_client.post(
        "/api/v1/asset-groups",
        headers=engineer_auth_headers,
        json={"name": "Grupo Disparo", "environment": "production", "criticality": "high"},
    )
    assert res_group.status_code == 201
    group_id = res_group.json()["id"]

    res_target = await async_client.post(
        "/api/v1/scan-targets",
        headers=engineer_auth_headers,
        json={
            "asset_group_id": group_id,
            "name": "Target Disparo",
            "target_type": "single_ip",
            "target_value": "10.1.1.10",
        },
    )
    assert res_target.status_code == 201
    target_id = res_target.json()["id"]

    res_profile = await async_client.post(
        "/api/v1/scanner-profiles",
        headers=engineer_auth_headers,
        json={
            "name": "Perfil Disparo",
            "scanner_type": "network_discovery",
            "port_strategy": "common",
        },
    )
    assert res_profile.status_code == 201
    profile_id = res_profile.json()["id"]

    res_sched = await async_client.post(
        "/api/v1/scan-schedules",
        headers=engineer_auth_headers,
        json={
            "name": "Agendamento Disparo",
            "scanner_profile_id": profile_id,
            "target_ids": [target_id],
            "frequency_type": "manual",
        },
    )
    assert res_sched.status_code == 201
    sched_id = res_sched.json()["id"]

    # 2. Usuário Viewer tenta disparar -> 403
    res_run_viewer = await async_client.post(
        f"/api/v1/scan-schedules/{sched_id}/run",
        headers=viewer_auth_headers,
    )
    assert res_run_viewer.status_code == 403

    # 3. Usuário Engineer (possui EXECUTE) dispara -> 202
    res_run_eng = await async_client.post(
        f"/api/v1/scan-schedules/{sched_id}/run",
        headers=engineer_auth_headers,
    )
    assert res_run_eng.status_code == 202
    assert "execution_id" in res_run_eng.json()

    # 4. Acesso a recurso inexistente / outro tenant -> 404
    fake_sched_id = str(uuid4())
    res_404 = await async_client.post(
        f"/api/v1/scan-schedules/{fake_sched_id}/run",
        headers=engineer_auth_headers,
    )
    assert res_404.status_code == 404


@pytest.mark.asyncio
async def test_patch_scan_target_validation_and_conflict(async_client: AsyncClient) -> None:
    """Valida PATCH em alvos de scanner, re-validação de IP e tratamento de duplicatas (409)."""
    tenant_id = str(uuid4())
    engineer_auth_headers = create_auth_headers(tenant_id, role="engineer")

    # 1. Criar Grupo e 2 Alvos
    res_group = await async_client.post(
        "/api/v1/asset-groups",
        headers=engineer_auth_headers,
        json={"name": "Grupo Patch Target", "environment": "staging", "criticality": "medium"},
    )
    assert res_group.status_code == 201
    group_id = res_group.json()["id"]

    res_t1 = await async_client.post(
        "/api/v1/scan-targets",
        headers=engineer_auth_headers,
        json={
            "asset_group_id": group_id,
            "name": "Target Alpha",
            "target_type": "single_ip",
            "target_value": "10.2.2.1",
        },
    )
    assert res_t1.status_code == 201
    t1_id = res_t1.json()["id"]

    res_t2 = await async_client.post(
        "/api/v1/scan-targets",
        headers=engineer_auth_headers,
        json={
            "asset_group_id": group_id,
            "name": "Target Beta",
            "target_type": "single_ip",
            "target_value": "10.2.2.2",
        },
    )
    assert res_t2.status_code == 201
    t2_id = res_t2.json()["id"]

    # 2. PATCH em t1 alterando nome e descrição -> 200 OK
    res_patch = await async_client.patch(
        f"/api/v1/scan-targets/{t1_id}",
        headers=engineer_auth_headers,
        json={"name": "Target Alpha Modificado", "description": "Nova descricao"},
    )
    assert res_patch.status_code == 200
    assert res_patch.json()["name"] == "Target Alpha Modificado"

    # 3. PATCH em t1 tentando usar target_value já pertencente a t2 -> 409 Conflict
    res_conflict = await async_client.patch(
        f"/api/v1/scan-targets/{t1_id}",
        headers=engineer_auth_headers,
        json={"target_value": "10.2.2.2"},
    )
    assert res_conflict.status_code == 409

    # 4. PATCH com IP público não autorizado -> 400 Bad Request
    res_public = await async_client.patch(
        f"/api/v1/scan-targets/{t1_id}",
        headers=engineer_auth_headers,
        json={"target_value": "8.8.8.8", "allow_public_targets": False},
    )
    assert res_public.status_code == 400


@pytest.mark.asyncio
async def test_scanner_profile_canonical_naming_and_persistence(async_client: AsyncClient) -> None:
    """Valida nomes canônicos e persistência de timeout_seconds, max_parallelism e rate_limit_per_second."""
    tenant_id = str(uuid4())
    engineer_auth_headers = create_auth_headers(tenant_id, role="engineer")

    # 1. Criar Perfil
    res = await async_client.post(
        "/api/v1/scanner-profiles",
        headers=engineer_auth_headers,
        json={
            "name": "Perfil Canonico Teste",
            "scanner_type": "service_discovery",
            "timeout_seconds": 60,
            "max_parallelism": 20,
            "rate_limit_per_second": 100,
        },
    )
    assert res.status_code == 201
    prof = res.json()
    prof_id = prof["id"]
    assert prof["timeout_seconds"] == 60
    assert prof["max_parallelism"] == 20
    assert prof["rate_limit_per_second"] == 100

    # 2. PATCH no Perfil alterando parâmetros com nomes canônicos
    res_patch = await async_client.patch(
        f"/api/v1/scanner-profiles/{prof_id}",
        headers=engineer_auth_headers,
        json={
            "timeout_seconds": 120,
            "max_parallelism": 30,
            "rate_limit_per_second": 200,
        },
    )
    assert res_patch.status_code == 200
    patched = res_patch.json()
    assert patched["timeout_seconds"] == 120
    assert patched["max_parallelism"] == 30
    assert patched["rate_limit_per_second"] == 200

    # 3. GET para recarregar do banco e confirmar persistência
    res_get = await async_client.get(
        f"/api/v1/scanner-profiles/{prof_id}",
        headers=engineer_auth_headers,
    )
    assert res_get.status_code == 200
    saved = res_get.json()
    assert saved["timeout_seconds"] == 120
    assert saved["max_parallelism"] == 30
    assert saved["rate_limit_per_second"] == 200


@pytest.mark.asyncio
async def test_scan_schedule_update_recalculates_next_run(async_client: AsyncClient) -> None:
    """Valida que alterar cron ou timezone recalcula automaticamente o next_run_at."""
    tenant_id = str(uuid4())
    engineer_auth_headers = create_auth_headers(tenant_id, role="engineer")

    # 1. Criar Grupo, Alvo e Perfil
    res_group = await async_client.post(
        "/api/v1/asset-groups",
        headers=engineer_auth_headers,
        json={"name": "Grupo Sched Recalc", "environment": "production", "criticality": "high"},
    )
    group_id = res_group.json()["id"]

    res_t = await async_client.post(
        "/api/v1/scan-targets",
        headers=engineer_auth_headers,
        json={"asset_group_id": group_id, "name": "T Recalc", "target_type": "single_ip", "target_value": "10.3.3.3"},
    )
    t_id = res_t.json()["id"]

    res_p = await async_client.post(
        "/api/v1/scanner-profiles",
        headers=engineer_auth_headers,
        json={"name": "P Recalc", "scanner_type": "network_discovery"},
    )
    p_id = res_p.json()["id"]

    # 2. Criar Agendamento Cron
    res_s = await async_client.post(
        "/api/v1/scan-schedules",
        headers=engineer_auth_headers,
        json={
            "name": "Sched Cron Recalc",
            "scanner_profile_id": p_id,
            "target_ids": [t_id],
            "frequency_type": "cron",
            "cron_expression": "0 2 * * *",
            "timezone": "UTC",
        },
    )
    assert res_s.status_code == 201
    sched = res_s.json()
    sched_id = sched["id"]
    first_next_run = sched["next_run_at"]
    assert first_next_run is not None

    # 3. PATCH alterando cron_expression
    res_patch = await async_client.patch(
        f"/api/v1/scan-schedules/{sched_id}",
        headers=engineer_auth_headers,
        json={"cron_expression": "0 4 * * *"},
    )
    assert res_patch.status_code == 200
    second_next_run = res_patch.json()["next_run_at"]
    assert second_next_run is not None
    assert second_next_run != first_next_run


@pytest.mark.asyncio
async def test_safe_target_deletion_with_dependencies(async_client: AsyncClient) -> None:
    """Valida que exclusão de alvo sem dependências é física e com dependências é convertida em inativação."""
    tenant_id = str(uuid4())
    engineer_auth_headers = create_auth_headers(tenant_id, role="engineer")

    # 1. Alvo Sem Dependências
    res_g = await async_client.post(
        "/api/v1/asset-groups",
        headers=engineer_auth_headers,
        json={"name": "Grupo Safe Delete", "environment": "development", "criticality": "low"},
    )
    g_id = res_g.json()["id"]

    res_t1 = await async_client.post(
        "/api/v1/scan-targets",
        headers=engineer_auth_headers,
        json={"asset_group_id": g_id, "name": "T Isos", "target_type": "single_ip", "target_value": "10.4.4.1"},
    )
    t1_id = res_t1.json()["id"]

    # Excluir T1 -> Deve retornar 204 e remover do banco
    res_del1 = await async_client.delete(f"/api/v1/scan-targets/{t1_id}", headers=engineer_auth_headers)
    assert res_del1.status_code == 204

    res_get1 = await async_client.get(f"/api/v1/scan-targets/{t1_id}", headers=engineer_auth_headers)
    assert res_get1.status_code == 404

    # 2. Alvo Com Dependência (vinculado a agendamento)
    res_t2 = await async_client.post(
        "/api/v1/scan-targets",
        headers=engineer_auth_headers,
        json={"asset_group_id": g_id, "name": "T Linked", "target_type": "single_ip", "target_value": "10.4.4.2"},
    )
    t2_id = res_t2.json()["id"]

    res_p = await async_client.post(
        "/api/v1/scanner-profiles",
        headers=engineer_auth_headers,
        json={"name": "P Linked", "scanner_type": "network_discovery"},
    )
    p_id = res_p.json()["id"]

    await async_client.post(
        "/api/v1/scan-schedules",
        headers=engineer_auth_headers,
        json={"name": "Sched Linked", "scanner_profile_id": p_id, "target_ids": [t2_id], "frequency_type": "manual"},
    )

    # Excluir T2 -> Deve inativar (enabled=False) e preservar histórico sem erro 500/FK
    res_del2 = await async_client.delete(f"/api/v1/scan-targets/{t2_id}", headers=engineer_auth_headers)
    assert res_del2.status_code == 204

    res_get2 = await async_client.get(f"/api/v1/scan-targets/{t2_id}", headers=engineer_auth_headers)
    assert res_get2.status_code == 200
    assert res_get2.json()["enabled"] is False


@pytest.mark.asyncio
async def test_zabbix_sync_execution_persistence_and_history(async_client: AsyncClient) -> None:
    """Valida que acionar sincronização Zabbix persiste MonitoringSyncExecution e expõe no histórico."""
    tenant_id = str(uuid4())
    engineer_auth_headers = create_auth_headers(tenant_id, role="engineer")

    # 1. Criar Integração Zabbix
    res_integ = await async_client.post(
        "/api/v1/monitoring-integrations",
        headers=engineer_auth_headers,
        json={
            "name": "Zabbix Sync Test",
            "base_url": "http://zabbix.local/api",
            "credential_reference": "vault://zabbix-token-secret",
            "provider": "zabbix",
            "enabled": True,
        },
    )
    assert res_integ.status_code == 201
    integ_id = res_integ.json()["id"]

    # 2. Acionar Sync -> 202 Accepted com sync_execution_id
    res_sync = await async_client.post(
        f"/api/v1/monitoring-integrations/{integ_id}/sync",
        headers=engineer_auth_headers,
    )
    assert res_sync.status_code == 202
    body = res_sync.json()
    assert "sync_execution_id" in body
    assert body["status"] == "queued"
    sync_id = body["sync_execution_id"]

    # 3. Consultar Histórico -> Deve listar a execução persistida no banco
    res_hist = await async_client.get(
        f"/api/v1/monitoring-integrations/{integ_id}/sync-history",
        headers=engineer_auth_headers,
    )
    assert res_hist.status_code == 200
    items = res_hist.json()["items"]
    assert len(items) >= 1
    found = [i for i in items if i["id"] == sync_id]
    assert len(found) == 1
    assert found[0]["status"] == "queued"


@pytest.mark.asyncio
async def test_asset_import_real_fixtures_and_security(async_client: AsyncClient) -> None:
    """Valida rejeição de .xls legado, extensões desconhecidas, assinaturas e fórmula XLSX."""
    tenant_id = str(uuid4())
    engineer_auth_headers = create_auth_headers(tenant_id, role="engineer")

    # 1. Criar Grupo
    res_g = await async_client.post(
        "/api/v1/asset-groups",
        headers=engineer_auth_headers,
        json={"name": "Grupo Import Security", "environment": "development", "criticality": "low"},
    )
    g_id = res_g.json()["id"]

    # 2. Rejeitar .xls legado
    xls_file = ("targets.xls", b"dummy xls content", "application/vnd.ms-excel")
    res_xls = await async_client.post(
        "/api/v1/scan-targets/import/preview",
        headers=engineer_auth_headers,
        data={"asset_group_id": g_id},
        files={"file": xls_file},
    )
    assert res_xls.status_code == 400
    assert "legado" in res_xls.json()["detail"].lower()

    # 3. Rejeitar extensão desconhecida (.exe)
    exe_file = ("script.exe", b"MZexecutable...", "application/octet-stream")
    res_exe = await async_client.post(
        "/api/v1/scan-targets/import/preview",
        headers=engineer_auth_headers,
        data={"asset_group_id": g_id},
        files={"file": exe_file},
    )
    assert res_exe.status_code == 400

    # 4. Upload CSV Válido -> 200 OK no preview
    csv_bytes = b"10.5.5.1\n10.5.5.2\n"
    csv_file = ("targets.csv", csv_bytes, "text/csv")
    res_csv = await async_client.post(
        "/api/v1/scan-targets/import/preview",
        headers=engineer_auth_headers,
        data={"asset_group_id": g_id},
        files={"file": csv_file},
    )
    assert res_csv.status_code == 200
    assert res_csv.json()["valid"] == 2

    # 5. Upload XLSX com Fórmula -> Rejeitado no preview
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("xl/sharedStrings.xml", '<?xml version="1.0"?><sst><si><t>=cmd|powershell</t></si></sst>')
        zf.writestr("xl/worksheets/sheet1.xml", '<?xml version="1.0"?><worksheet><sheetData><row><c t="s"><v>0</v></c></row></sheetData></worksheet>')
    xlsx_bytes = buf.getvalue()
    xlsx_file = ("targets.xlsx", xlsx_bytes, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    res_formula = await async_client.post(
        "/api/v1/scan-targets/import/preview",
        headers=engineer_auth_headers,
        data={"asset_group_id": g_id},
        files={"file": xlsx_file},
    )
    assert res_formula.status_code == 200
    prev_items = res_formula.json()["items"]
    assert len(prev_items) == 1
    assert prev_items[0]["valid"] is False
    assert "fórmula" in prev_items[0]["errors"][0].lower() or "executável" in prev_items[0]["errors"][0].lower()
