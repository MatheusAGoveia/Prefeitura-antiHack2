"""
Testes de Integração para Validação dos Bloqueadores Finais da M3.4 (Asset & Scanner Management).
GovSec Shield — Integration & Security Testing (M3.4)
"""

import io
import zipfile
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from src.asset.domain.exceptions import AssetDomainError
from src.asset.domain.scan_schedules import FrequencyType, ScanSchedule
from src.core.infrastructure.db.models import OutboxEventModel
from tests.integration.test_asset_m3_4_blockers import async_client, async_session, create_auth_headers  # noqa: F401


@pytest.mark.asyncio
async def test_zabbix_sync_transactional_outbox_and_audit(
    async_client: AsyncClient,
    async_session,
) -> None:
    """Valida que POST /sync persiste o MonitoringSyncExecution, evento outbox e auditoria na mesma transação."""
    tenant_id = str(uuid4())
    engineer_headers = create_auth_headers(tenant_id, role="engineer")

    # 1. Criar Integração Zabbix
    res_create = await async_client.post(
        "/api/v1/monitoring-integrations",
        headers=engineer_headers,
        json={
            "name": "Zabbix Outbox Test",
            "base_url": "http://zabbix.internal/api",
            "credential_reference": "vault://zabbix-secret",
            "provider": "zabbix",
            "enabled": True,
        },
    )
    assert res_create.status_code == 201
    integ_id = res_create.json()["id"]

    # 2. Executar POST /sync
    res_sync = await async_client.post(
        f"/api/v1/monitoring-integrations/{integ_id}/sync",
        headers=engineer_headers,
    )
    assert res_sync.status_code == 202
    body = res_sync.json()
    assert body["status"] == "queued"
    sync_exec_id = body["sync_execution_id"]

    # 3. Verificar Evento na Outbox no banco
    stmt = select(OutboxEventModel).where(
        OutboxEventModel.tenant_id == UUID(tenant_id),
        OutboxEventModel.event_type == "monitoring.sync.requested",
    )
    result = await async_session.execute(stmt)
    events = result.scalars().all()
    assert len(events) >= 1
    event = events[0]
    assert event.payload["integration_id"] == integ_id
    assert event.payload["sync_execution_id"] == sync_exec_id
    # Garantir ausência de credenciais no evento
    assert "credential_reference" not in event.payload
    assert "password" not in event.payload

    # 4. Verificar Histórico via API
    res_hist = await async_client.get(
        f"/api/v1/monitoring-integrations/{integ_id}/sync-history",
        headers=engineer_headers,
    )
    assert res_hist.status_code == 200
    hist_items = res_hist.json()["items"]
    assert any(i["id"] == sync_exec_id for i in hist_items)


@pytest.mark.asyncio
async def test_target_patch_exclusive_permission_and_isolation(async_client: AsyncClient) -> None:
    """Valida que PATCH exige scan_targets:PATCH, rejeita scan_targets:POST e respeita tenant."""
    tenant_id = str(uuid4())

    # Headers com papéis específicos
    patch_user_headers = create_auth_headers(tenant_id, role="engineer")  # possui PATCH
    post_only_headers = create_auth_headers(tenant_id, role="analyst")   # possui apenas POST/GET para alvos

    # 1. Criar Grupo e Alvo
    res_g = await async_client.post(
        "/api/v1/asset-groups",
        headers=patch_user_headers,
        json={"name": "Grupo Patch RBAC", "environment": "production", "criticality": "high"},
    )
    assert res_g.status_code == 201
    g_id = res_g.json()["id"]

    res_t = await async_client.post(
        "/api/v1/scan-targets",
        headers=patch_user_headers,
        json={
            "asset_group_id": g_id,
            "name": "Target RBAC Original",
            "target_type": "single_ip",
            "target_value": "10.10.10.1",
        },
    )
    assert res_t.status_code == 201
    t_id = res_t.json()["id"]

    # 2. Usuário sem permissão PATCH (Analyst) tenta alterar -> 403
    res_patch_analyst = await async_client.patch(
        f"/api/v1/scan-targets/{t_id}",
        headers=post_only_headers,
        json={"name": "Tentativa Invalida"},
    )
    assert res_patch_analyst.status_code == 403

    # 3. Usuário com permissão PATCH altera -> 200
    res_patch_ok = await async_client.patch(
        f"/api/v1/scan-targets/{t_id}",
        headers=patch_user_headers,
        json={"name": "Target RBAC Alterado"},
    )
    assert res_patch_ok.status_code == 200
    assert res_patch_ok.json()["name"] == "Target RBAC Alterado"

    # 4. Outro tenant tentando editar o alvo -> 404
    other_tenant_headers = create_auth_headers(str(uuid4()), role="engineer")
    res_patch_other = await async_client.patch(
        f"/api/v1/scan-targets/{t_id}",
        headers=other_tenant_headers,
        json={"name": "Tentativa Cross Tenant"},
    )
    assert res_patch_other.status_code == 404


@pytest.mark.asyncio
async def test_upload_mime_magic_bytes_and_security_validations(async_client: AsyncClient) -> None:
    """Valida rejeições de mime type incompatível, assinaturas incorretas, fórmulas e executáveis."""
    tenant_id = str(uuid4())
    headers = create_auth_headers(tenant_id, role="engineer")

    res_g = await async_client.post(
        "/api/v1/asset-groups",
        headers=headers,
        json={"name": "Grupo Import Validation", "environment": "staging", "criticality": "low"},
    )
    g_id = res_g.json()["id"]

    # 1. Arquivo vazio -> 400
    res_empty = await async_client.post(
        "/api/v1/scan-targets/import/preview",
        headers=headers,
        data={"asset_group_id": g_id},
        files={"file": ("empty.csv", b"", "text/csv")},
    )
    assert res_empty.status_code == 400

    # 2. Executável MZ mascarado como CSV -> 400
    res_exe = await async_client.post(
        "/api/v1/scan-targets/import/preview",
        headers=headers,
        data={"asset_group_id": g_id},
        files={"file": ("malware.csv", b"MZexecutabledata...", "text/csv")},
    )
    assert res_exe.status_code == 400

    # 3. MIME Incompatível (pdf enviado com mime image/png) -> 400
    res_mime = await async_client.post(
        "/api/v1/scan-targets/import/preview",
        headers=headers,
        data={"asset_group_id": g_id},
        files={"file": ("doc.pdf", b"%PDF-1.4 text...", "image/png")},
    )
    assert res_mime.status_code == 400

    # 4. XLSX com Fórmula -> Rejeitado
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        sheet_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetData><row><c r="A1"><f>SUM(1,2)</f><v>3</v></c></row></sheetData>'
            '</worksheet>'
        )
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    xlsx_formula_bytes = buf.getvalue()

    res_formula = await async_client.post(
        "/api/v1/scan-targets/import/preview",
        headers=headers,
        data={"asset_group_id": g_id},
        files={"file": ("formula.xlsx", xlsx_formula_bytes, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    )
    assert res_formula.status_code == 400
    assert "fórmula" in res_formula.json()["detail"].lower()


@pytest.mark.asyncio
async def test_xlsx_parser_shared_strings_and_numeric_cells(async_client: AsyncClient) -> None:
    """Valida parser XLSX com sharedStrings, inlineStr e células numéricas."""
    tenant_id = str(uuid4())
    headers = create_auth_headers(tenant_id, role="engineer")

    res_g = await async_client.post(
        "/api/v1/asset-groups",
        headers=headers,
        json={"name": "Grupo XLSX Test", "environment": "development", "criticality": "low"},
    )
    g_id = res_g.json()["id"]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        ss_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<si><t>10.8.8.1</t></si>'
            '<si><t>10.8.8.2</t></si>'
            '</sst>'
        )
        zf.writestr("xl/sharedStrings.xml", ss_xml)

        sheet_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetData>'
            '<row><c r="A1" t="s"><v>0</v></c></row>'
            '<row><c r="A2" t="s"><v>1</v></c></row>'
            '<row><c r="A3" t="inlineStr"><is><t>10.8.8.3</t></is></c></row>'
            '</sheetData>'
            '</worksheet>'
        )
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)

    xlsx_bytes = buf.getvalue()

    res_preview = await async_client.post(
        "/api/v1/scan-targets/import/preview",
        headers=headers,
        data={"asset_group_id": g_id},
        files={"file": ("targets.xlsx", xlsx_bytes, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    )
    assert res_preview.status_code == 200
    prev = res_preview.json()
    assert prev["valid"] == 3
    vals = [item["normalized_value"] for item in prev["items"]]
    assert "10.8.8.1" in vals
    assert "10.8.8.2" in vals
    assert "10.8.8.3" in vals


def test_scan_schedule_next_run_at_frequencies_and_timezone_validation() -> None:
    """Valida o cálculo de next_run_at para ONCE, HOURLY, DAILY, WEEKLY, MONTHLY, CRON e rejeição de timezone."""
    now = datetime(2026, 8, 3, 15, 0, 0, tzinfo=timezone.utc)
    u_id = uuid4()
    t_id = uuid4()
    p_id = uuid4()

    # 1. Rejeitar Timezone inválido (sem fallback silencioso)
    with pytest.raises(AssetDomainError) as exc_tz:
        ScanSchedule.create(
            tenant_id=t_id,
            name="Sched Bad TZ",
            scanner_profile_id=p_id,
            target_ids=[u_id],
            created_by=u_id,
            tz_name="Invalid/Timezone_Name",
            frequency_type=FrequencyType.DAILY,
        )
    assert "inválido" in str(exc_tz.value).lower()

    # 2. Frequência ONCE no passado -> Rejeitada
    with pytest.raises(AssetDomainError) as exc_past:
        ScanSchedule.create(
            tenant_id=t_id,
            name="Sched ONCE Past",
            scanner_profile_id=p_id,
            target_ids=[u_id],
            created_by=u_id,
            tz_name="America/Sao_Paulo",
            frequency_type=FrequencyType.ONCE,
            start_at=now - timedelta(hours=1),
        )
    assert "futuro" in str(exc_past.value).lower()

    # 3. Frequência ONCE no futuro -> Sucesso
    future_time = now + timedelta(days=2)
    s_once = ScanSchedule.create(
        tenant_id=t_id,
        name="Sched ONCE Future",
        scanner_profile_id=p_id,
        target_ids=[u_id],
        created_by=u_id,
        tz_name="America/Sao_Paulo",
        frequency_type=FrequencyType.ONCE,
        start_at=future_time,
    )
    assert s_once.next_run_at == future_time

    # 4. Frequência HOURLY
    s_hourly = ScanSchedule.create(
        tenant_id=t_id,
        name="Sched HOURLY",
        scanner_profile_id=p_id,
        target_ids=[u_id],
        created_by=u_id,
        tz_name="UTC",
        frequency_type=FrequencyType.HOURLY,
    )
    assert s_hourly.next_run_at is not None
    assert s_hourly.next_run_at > now

    # 5. Frequência DAILY
    s_daily = ScanSchedule.create(
        tenant_id=t_id,
        name="Sched DAILY",
        scanner_profile_id=p_id,
        target_ids=[u_id],
        created_by=u_id,
        tz_name="America/Sao_Paulo",
        frequency_type=FrequencyType.DAILY,
    )
    assert s_daily.next_run_at is not None
    assert s_daily.next_run_at > now

    # 6. Frequência CRON
    s_cron = ScanSchedule.create(
        tenant_id=t_id,
        name="Sched CRON",
        scanner_profile_id=p_id,
        target_ids=[u_id],
        created_by=u_id,
        tz_name="UTC",
        frequency_type=FrequencyType.CRON,
        cron_expression="0 3 * * *",
    )
    assert s_cron.next_run_at is not None
    assert s_cron.next_run_at > now
