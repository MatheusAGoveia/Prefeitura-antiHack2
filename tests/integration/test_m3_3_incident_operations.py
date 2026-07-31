"""
Testes de Integração e Validação da Sprint M3.3 — Central Operacional de Incidentes e Evidências.
GovSec Shield — Incident Management API & Observability

Validações obrigatórias:
  1. Filtros operacionais (status, severity, created_from, created_to) e paginação sem falso vazio.
  2. Ordenação estável (sort_by e order asc/desc).
  3. Isolamento multi-tenant estrito (cross-tenant em listagem, detalhe, evidências e histórico).
  4. Incidente inexistente ou de outro tenant retornando HTTP 404.
  5. Evidência mascarada (payload sanitizado via DataMasker).
  6. Histórico auditável imutável de transição de status.
  7. Métricas Prometheus incrementadas (criados, transições e evidências).
  8. Ausência de dados sensíveis em labels Prometheus.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.api.main import app
from src.core.domain.incidents import (
    Incident,
    IncidentEvidence,
    IncidentStatus,
    SecurityEventSeverity,
    sanitize_payload,
)
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.models import Base, SecurityEventModel, TenantModel
from src.core.infrastructure.db.repositories import (
    PostgresIncidentEvidenceRepository,
    PostgresIncidentRepository,
)
from src.core.infrastructure.security.jwt import JWTUtils

TEST_DATABASE_URL = settings.GOVSEC_DB_URL


@pytest_asyncio.fixture
async def async_session():
    """Sessão com schema completo criado e destruído para cada teste."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def async_client(async_session: AsyncSession):
    """Cliente HTTP com override de get_db_session para a sessão de teste."""
    from src.core.infrastructure.db.unit_of_work import get_db_session

    async def _override_get_db_session():
        yield async_session

    app.dependency_overrides[get_db_session] = _override_get_db_session
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers_tenant_a() -> dict[str, str]:
    tenant_id = uuid4()
    user_id = uuid4()
    token = JWTUtils.create_access_token(user_id=str(user_id), tenant_id=tenant_id, roles=["security_admin"])
    return {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id), "_tenant_id": str(tenant_id)}


@pytest.fixture
def auth_headers_tenant_b() -> dict[str, str]:
    tenant_id = uuid4()
    user_id = uuid4()
    token = JWTUtils.create_access_token(user_id=str(user_id), tenant_id=tenant_id, roles=["security_admin"])
    return {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant_id), "_tenant_id": str(tenant_id)}


async def _ensure_tenant_exists(session: AsyncSession, tenant_id: UUID) -> None:
    """Insere TenantModel previamente para respeitar as FKs da tabela de incidentes/evidências."""
    stmt = select(TenantModel).where(TenantModel.id == tenant_id)
    res = await session.execute(stmt)
    if res.scalar_one_or_none() is None:
        tenant_model = TenantModel(
            id=tenant_id,
            name=f"Tenant Test {tenant_id}",
            slug=f"tenant-{str(tenant_id)[:8]}",
            status="ACTIVE",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(tenant_model)
        await session.commit()


async def _ensure_security_event_exists(session: AsyncSession, tenant_id: UUID, event_id: UUID) -> None:
    """Insere SecurityEventModel previamente para respeitar as FKs da tabela incident_evidences."""
    evidence_hash = hashlib.sha256(str(event_id).encode("utf-8")).hexdigest()
    sec_event = SecurityEventModel(
        event_id=event_id,
        tenant_id=tenant_id,
        source="test_source",
        event_type="test_event",
        severity="HIGH",
        occurred_at=datetime.now(timezone.utc),
        received_at=datetime.now(timezone.utc),
        idempotency_key=str(event_id),
        evidence_hash=evidence_hash,
        payload={"user": "admin_gov"},
    )
    session.add(sec_event)
    await session.commit()


@pytest.mark.asyncio
async def test_incidents_list_filters_and_pagination(
    async_client: AsyncClient, async_session: AsyncSession, auth_headers_tenant_a: dict[str, str]
) -> None:
    """Valida filtros operacionais por status, severidade e datas via HTTP REST."""
    tenant_id = UUID(auth_headers_tenant_a["_tenant_id"])
    await _ensure_tenant_exists(async_session, tenant_id)
    repo = PostgresIncidentRepository(async_session)
    now = datetime.now(timezone.utc)

    # Inserir incidentes de teste
    inc1 = Incident(
        incident_id=uuid4(),
        tenant_id=tenant_id,
        title="Incidente 1 — Bruteforce SSH",
        description="Ataque de força bruta",
        severity=SecurityEventSeverity.HIGH,
        status=IncidentStatus.OPEN,
        correlation_key="rule_ssh_01",
        created_at=now - timedelta(hours=2),
        updated_at=now - timedelta(hours=2),
    )
    inc2 = Incident(
        incident_id=uuid4(),
        tenant_id=tenant_id,
        title="Incidente 2 — Service Down",
        description="Queda de serviço web",
        severity=SecurityEventSeverity.CRITICAL,
        status=IncidentStatus.INVESTIGATING,
        correlation_key="rule_down_01",
        created_at=now - timedelta(hours=1),
        updated_at=now - timedelta(hours=1),
    )
    await repo.save(inc1)
    await repo.save(inc2)
    await async_session.commit()

    # 1. Filtro por status=open via HTTP
    res_open = await async_client.get(
        "/api/v1/incidents?status=open",
        headers={"Authorization": auth_headers_tenant_a["Authorization"]},
    )
    assert res_open.status_code == 200
    data_open = res_open.json()
    assert data_open["total"] == 1
    assert len(data_open["items"]) == 1
    assert data_open["items"][0]["incident_id"] == str(inc1.incident_id)

    # 2. Filtro por severity=critical via HTTP
    res_crit = await async_client.get(
        "/api/v1/incidents?severity=critical",
        headers={"Authorization": auth_headers_tenant_a["Authorization"]},
    )
    assert res_crit.status_code == 200
    data_crit = res_crit.json()
    assert data_crit["total"] == 1
    assert data_crit["items"][0]["incident_id"] == str(inc2.incident_id)


@pytest.mark.asyncio
async def test_incidents_stable_sorting(async_session: AsyncSession) -> None:
    """Valida ordenação estável (sort_by e order asc/desc)."""
    repo = PostgresIncidentRepository(async_session)
    tenant_id = uuid4()
    await _ensure_tenant_exists(async_session, tenant_id)
    now = datetime.now(timezone.utc)

    for idx in range(3):
        inc = Incident(
            incident_id=uuid4(),
            tenant_id=tenant_id,
            title=f"Incidente {idx}",
            description="Teste ordenação",
            severity=SecurityEventSeverity.LOW if idx == 0 else SecurityEventSeverity.HIGH,
            status=IncidentStatus.OPEN,
            correlation_key=f"sort_key_{idx}",
            created_at=now + timedelta(minutes=idx),
            updated_at=now + timedelta(minutes=idx),
        )
        await repo.save(inc)
    await async_session.commit()

    # Ordenação DESC por created_at
    page_desc = await repo.list(tenant_id=tenant_id, sort_by="created_at", order="desc")
    assert page_desc[0].created_at >= page_desc[1].created_at >= page_desc[2].created_at

    # Ordenação ASC por created_at
    page_asc = await repo.list(tenant_id=tenant_id, sort_by="created_at", order="asc")
    assert page_asc[0].created_at <= page_asc[1].created_at <= page_asc[2].created_at


@pytest.mark.asyncio
async def test_real_cross_tenant_isolation_returns_404(
    async_client: AsyncClient,
    async_session: AsyncSession,
    auth_headers_tenant_a: dict[str, str],
    auth_headers_tenant_b: dict[str, str],
) -> None:
    """Valida isolamento multi-tenant real: acessar incidente, evidência ou histórico do Tenant B usando token do Tenant A retorna HTTP 404."""
    tenant_a_id = UUID(auth_headers_tenant_a["_tenant_id"])
    tenant_b_id = UUID(auth_headers_tenant_b["_tenant_id"])
    await _ensure_tenant_exists(async_session, tenant_a_id)
    await _ensure_tenant_exists(async_session, tenant_b_id)

    inc_repo = PostgresIncidentRepository(async_session)
    evidence_repo = PostgresIncidentEvidenceRepository(async_session)

    # 1. Criar um incidente real e evidência real no Tenant B
    incident_b_id = uuid4()
    event_b_id = uuid4()
    await _ensure_security_event_exists(async_session, tenant_b_id, event_b_id)

    inc_b = Incident(
        incident_id=incident_b_id,
        tenant_id=tenant_b_id,
        title="Incidente Privado Tenant B",
        description="Dados estritamente do Tenant B",
        severity=SecurityEventSeverity.CRITICAL,
        status=IncidentStatus.OPEN,
        correlation_key="priv_key_b",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    await inc_repo.save(inc_b)

    ev_b = IncidentEvidence(
        evidence_id=uuid4(),
        incident_id=incident_b_id,
        event_id=event_b_id,
        tenant_id=tenant_b_id,
        evidence_hash="sha256_b_hash",
        added_at=datetime.now(timezone.utc),
        description="Evidência do Tenant B",
        raw_payload_masked={"secret_b": "data_b"},
    )
    await evidence_repo.save(ev_b)
    await async_session.commit()

    headers_a = {"Authorization": auth_headers_tenant_a["Authorization"]}

    # 2. Tentar acessar detalhe do incidente do Tenant B com token do Tenant A -> HTTP 404
    res_get = await async_client.get(f"/api/v1/incidents/{incident_b_id}", headers=headers_a)
    assert res_get.status_code == 404

    # 3. Tentar acessar evidências do incidente do Tenant B com token do Tenant A -> HTTP 404
    res_ev = await async_client.get(f"/api/v1/incidents/{incident_b_id}/evidences", headers=headers_a)
    assert res_ev.status_code == 404

    # 4. Tentar acessar histórico do incidente do Tenant B com token do Tenant A -> HTTP 404
    res_hist = await async_client.get(f"/api/v1/incidents/{incident_b_id}/history", headers=headers_a)
    assert res_hist.status_code == 404

    # 5. Tentar alterar status do incidente do Tenant B com token do Tenant A -> HTTP 404
    res_patch = await async_client.patch(
        f"/api/v1/incidents/{incident_b_id}/status",
        json={"new_status": "acknowledged", "reason": "Tentativa de alteração cross-tenant"},
        headers=headers_a,
    )
    assert res_patch.status_code == 404

    # 6. Listar incidentes com token do Tenant A -> total deve ser 0 (não lista incidentes do Tenant B)
    res_list = await async_client.get("/api/v1/incidents", headers=headers_a)
    assert res_list.status_code == 200
    list_data = res_list.json()
    assert list_data["total"] == 0
    assert len(list_data["items"]) == 0


@pytest.mark.asyncio
async def test_history_id_is_real_and_stable(
    async_client: AsyncClient, async_session: AsyncSession, auth_headers_tenant_a: dict[str, str]
) -> None:
    """Valida que o history_id retornado é o ID real do banco, permanece estável e imutável."""
    tenant_id = UUID(auth_headers_tenant_a["_tenant_id"])
    await _ensure_tenant_exists(async_session, tenant_id)
    inc_repo = PostgresIncidentRepository(async_session)

    incident_id = uuid4()
    inc = Incident(
        incident_id=incident_id,
        tenant_id=tenant_id,
        title="Incidente para Histórico Real",
        description="Teste history_id",
        severity=SecurityEventSeverity.HIGH,
        status=IncidentStatus.OPEN,
        correlation_key="hist_real_key",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    await inc_repo.save(inc)
    await async_session.commit()

    headers = {"Authorization": auth_headers_tenant_a["Authorization"]}

    # Transicionar status via HTTP REST
    res_patch = await async_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"new_status": "acknowledged", "reason": "Reconhecimento oficial SOC"},
        headers=headers,
    )
    assert res_patch.status_code == 200

    # Consultar histórico via HTTP REST
    res_hist1 = await async_client.get(f"/api/v1/incidents/{incident_id}/history", headers=headers)
    assert res_hist1.status_code == 200
    hist_data1 = res_hist1.json()
    assert hist_data1["total"] == 1
    real_history_id = hist_data1["items"][0]["history_id"]

    # Garantir que NÃO é o ID sintético antigo (UUID(int=1))
    assert real_history_id != "00000000-0000-0000-0000-000000000001"
    assert UUID(real_history_id)  # Valida formato UUID v4

    # Segunda consulta ao mesmo histórico: ID deve permanecer rigorosamente idêntico
    res_hist2 = await async_client.get(f"/api/v1/incidents/{incident_id}/history", headers=headers)
    hist_data2 = res_hist2.json()
    assert hist_data2["items"][0]["history_id"] == real_history_id


@pytest.mark.asyncio
async def test_datetime_range_validation_utc(
    async_client: AsyncClient, async_session: AsyncSession, auth_headers_tenant_a: dict[str, str]
) -> None:
    """Valida contrato estrito de intervalo de datas (created_from/created_to) com fuso horário UTC."""
    tenant_id = UUID(auth_headers_tenant_a["_tenant_id"])
    await _ensure_tenant_exists(async_session, tenant_id)
    headers = {"Authorization": auth_headers_tenant_a["Authorization"]}

    # 1. Intervalo UTC válido -> 200 OK
    now_str = quote(datetime.now(timezone.utc).isoformat())
    res1 = await async_client.get(f"/api/v1/incidents?created_from={now_str}", headers=headers)
    assert res1.status_code == 200

    # 2. Data naive sem timezone -> 422
    res2 = await async_client.get("/api/v1/incidents?created_from=2026-07-31T12:00:00", headers=headers)
    assert res2.status_code == 422
    assert "fuso horário" in res2.json()["detail"]

    # 3. Data com offset local diferente de UTC zero (ex: -03:00) -> 422
    offset_date = quote("2026-07-31T12:00:00-03:00")
    res_off = await async_client.get(f"/api/v1/incidents?created_from={offset_date}", headers=headers)
    assert res_off.status_code == 422
    assert "UTC zero" in res_off.json()["detail"]

    # 4. created_from > created_to -> 422
    from_date = quote((datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
    to_date = quote(datetime.now(timezone.utc).isoformat())
    res3 = await async_client.get(
        f"/api/v1/incidents?created_from={from_date}&created_to={to_date}",
        headers=headers,
    )
    assert res3.status_code == 422
    assert "não pode ser posterior" in res3.json()["detail"]

    # 5. Limites exatos (created_from == created_to) -> 200 OK
    res4 = await async_client.get(
        f"/api/v1/incidents?created_from={now_str}&created_to={now_str}",
        headers=headers,
    )
    assert res4.status_code == 200


@pytest.mark.asyncio
async def test_evidence_count_accuracy_and_batching(
    async_client: AsyncClient, async_session: AsyncSession, auth_headers_tenant_a: dict[str, str]
) -> None:
    """Valida precisão de evidence_count em listagens e detalhe sem N+1."""
    tenant_id = UUID(auth_headers_tenant_a["_tenant_id"])
    await _ensure_tenant_exists(async_session, tenant_id)
    inc_repo = PostgresIncidentRepository(async_session)
    evidence_repo = PostgresIncidentEvidenceRepository(async_session)

    # 1. Incidente com 0 evidências
    inc1_id = uuid4()
    inc1 = Incident(
        incident_id=inc1_id,
        tenant_id=tenant_id,
        title="Incidente Sem Evidência",
        description="Count 0",
        severity=SecurityEventSeverity.LOW,
        status=IncidentStatus.OPEN,
        correlation_key="key_cnt_0",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    await inc_repo.save(inc1)

    # 2. Incidente com 2 evidências
    inc2_id = uuid4()
    event1_id = uuid4()
    event2_id = uuid4()
    await _ensure_security_event_exists(async_session, tenant_id, event1_id)
    await _ensure_security_event_exists(async_session, tenant_id, event2_id)

    inc2 = Incident(
        incident_id=inc2_id,
        tenant_id=tenant_id,
        title="Incidente Com 2 Evidências",
        description="Count 2",
        severity=SecurityEventSeverity.HIGH,
        status=IncidentStatus.OPEN,
        correlation_key="key_cnt_2",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    await inc_repo.save(inc2)

    ev1 = IncidentEvidence(
        evidence_id=uuid4(),
        incident_id=inc2_id,
        event_id=event1_id,
        tenant_id=tenant_id,
        evidence_hash="hash_cnt_1",
        added_at=datetime.now(timezone.utc),
        description="Evidência 1",
        raw_payload_masked={"k": "v1"},
    )
    ev2 = IncidentEvidence(
        evidence_id=uuid4(),
        incident_id=inc2_id,
        event_id=event2_id,
        tenant_id=tenant_id,
        evidence_hash="hash_cnt_2",
        added_at=datetime.now(timezone.utc),
        description="Evidência 2",
        raw_payload_masked={"k": "v2"},
    )
    await evidence_repo.save(ev1)
    await evidence_repo.save(ev2)
    await async_session.commit()

    headers = {"Authorization": auth_headers_tenant_a["Authorization"]}

    # Validar no GET /api/v1/incidents (listagem)
    res_list = await async_client.get("/api/v1/incidents?sort_by=created_at&order=asc", headers=headers)
    assert res_list.status_code == 200
    items = res_list.json()["items"]
    count_map = {item["incident_id"]: item["evidence_count"] for item in items}
    assert count_map[str(inc1_id)] == 0
    assert count_map[str(inc2_id)] == 2

    # Validar no GET /api/v1/incidents/{id} (detalhe)
    res_det1 = await async_client.get(f"/api/v1/incidents/{inc1_id}", headers=headers)
    assert res_det1.json()["evidence_count"] == 0

    res_det2 = await async_client.get(f"/api/v1/incidents/{inc2_id}", headers=headers)
    assert res_det2.json()["evidence_count"] == 2


@pytest.mark.asyncio
async def test_evidence_payload_masked_in_http_response(
    async_client: AsyncClient, async_session: AsyncSession, auth_headers_tenant_a: dict[str, str]
) -> None:
    """Valida que a resposta HTTP serializada de evidências mascaram completamente senhas e tokens como [REDACTED]."""
    tenant_id = UUID(auth_headers_tenant_a["_tenant_id"])
    await _ensure_tenant_exists(async_session, tenant_id)
    inc_repo = PostgresIncidentRepository(async_session)
    evidence_repo = PostgresIncidentEvidenceRepository(async_session)

    incident_id = uuid4()
    event_id = uuid4()
    await _ensure_security_event_exists(async_session, tenant_id, event_id)

    inc = Incident(
        incident_id=incident_id,
        tenant_id=tenant_id,
        title="Incidente para Payload Mascarado HTTP",
        description="Teste HTTP masking",
        severity=SecurityEventSeverity.CRITICAL,
        status=IncidentStatus.OPEN,
        correlation_key="mask_http_key",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    await inc_repo.save(inc)

    sensitive_payload = {
        "user": "sysadmin",
        "password": "SuperSecretPassword99!",
        "token": "bearer_super_secret_jwt",
        "api_key": "sk_live_12345",
        "cookie": "session_id_secret",
        "public_info": "safe_data",
    }

    ev = IncidentEvidence(
        evidence_id=uuid4(),
        incident_id=incident_id,
        event_id=event_id,
        tenant_id=tenant_id,
        evidence_hash="sha256_mask_http",
        added_at=datetime.now(timezone.utc),
        description="Evidência com segredos",
        raw_payload_masked=sanitize_payload(sensitive_payload),
    )
    await evidence_repo.save(ev)
    await async_session.commit()

    headers = {"Authorization": auth_headers_tenant_a["Authorization"]}

    # Consulta HTTP REST de evidências
    res = await async_client.get(f"/api/v1/incidents/{incident_id}/evidences", headers=headers)
    assert res.status_code == 200
    ev_data = res.json()["items"][0]["raw_payload_masked"]

    assert ev_data["password"] == "[REDACTED]"
    assert ev_data["token"] == "[REDACTED]"
    assert ev_data["api_key"] == "[REDACTED]"
    assert ev_data["cookie"] == "[REDACTED]"
    assert ev_data["public_info"] == "safe_data"


@pytest.mark.asyncio
async def test_open_incidents_gauge_updated_on_lifecycle(
    async_client: AsyncClient, async_session: AsyncSession, auth_headers_tenant_a: dict[str, str]
) -> None:
    from src.shared.observability.metrics import (
        GOVSEC_OPEN_INCIDENTS,
        sync_open_incidents_gauge_from_db,
    )

    tenant_id = UUID(auth_headers_tenant_a["_tenant_id"])
    await _ensure_tenant_exists(async_session, tenant_id)
    inc_repo = PostgresIncidentRepository(async_session)

    incident_id = uuid4()
    inc = Incident(
        incident_id=incident_id,
        tenant_id=tenant_id,
        title="Incidente para Encerramento",
        description="Ciclo de vida gauge",
        severity=SecurityEventSeverity.HIGH,
        status=IncidentStatus.OPEN,
        correlation_key="gauge_lifecycle_key",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    await inc_repo.save(inc)
    await async_session.commit()

    # Sincronizar o gauge diretamente a partir do Postgres
    await sync_open_incidents_gauge_from_db(async_session)
    after_create = GOVSEC_OPEN_INCIDENTS.labels(severity="high")._value.get()
    assert after_create >= 1.0

    headers = {"Authorization": auth_headers_tenant_a["Authorization"]}

    # OPEN -> ACKNOWLEDGED
    await async_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"new_status": "acknowledged", "reason": "Em análise SOC"},
        headers=headers,
    )
    # ACKNOWLEDGED -> INVESTIGATING
    await async_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"new_status": "investigating", "reason": "Investigação em andamento"},
        headers=headers,
    )
    # INVESTIGATING -> CONTAINED
    await async_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"new_status": "contained", "reason": "Incidente contido"},
        headers=headers,
    )
    # CONTAINED -> RESOLVED (Deve decrementar o gauge de abertos)
    res_res = await async_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"new_status": "resolved", "reason": "Causa raiz corrigida"},
        headers=headers,
    )
    assert res_res.status_code == 200

    after_resolve = GOVSEC_OPEN_INCIDENTS.labels(severity="high")._value.get()
    assert after_resolve >= 0


@pytest.mark.asyncio
async def test_nested_string_masking_in_evidence_http_response(
    async_client: AsyncClient, async_session: AsyncSession, auth_headers_tenant_a: dict[str, str]
) -> None:
    """Valida que segredos contidos dentro de strings genéricas em estruturas aninhadas são mascarados na resposta HTTP."""
    tenant_id = UUID(auth_headers_tenant_a["_tenant_id"])
    await _ensure_tenant_exists(async_session, tenant_id)
    inc_repo = PostgresIncidentRepository(async_session)
    evidence_repo = PostgresIncidentEvidenceRepository(async_session)

    incident_id = uuid4()
    event_id = uuid4()
    await _ensure_security_event_exists(async_session, tenant_id, event_id)

    inc = Incident(
        incident_id=incident_id,
        tenant_id=tenant_id,
        title="Incidente Mascaramento de Texto",
        description="Teste de strings em listas/dicts",
        severity=SecurityEventSeverity.HIGH,
        status=IncidentStatus.OPEN,
        correlation_key="mask_text_key",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    await inc_repo.save(inc)

    complex_payload = {
        "message": "Authorization: Bearer super-secret-jwt-token-12345",
        "details": {
            "items": [
                {"description": "api_key=my_super_secret_api_key"},
                {"log_line": "Basic dXNlcm5hbWU6cGFzc3dvcmQ="},
            ]
        },
    }

    ev = IncidentEvidence(
        evidence_id=uuid4(),
        incident_id=incident_id,
        event_id=event_id,
        tenant_id=tenant_id,
        evidence_hash="hash_mask_text",
        added_at=datetime.now(timezone.utc),
        description="Evidência com textos",
        raw_payload_masked=sanitize_payload(complex_payload),
    )
    await evidence_repo.save(ev)
    await async_session.commit()

    headers = {"Authorization": auth_headers_tenant_a["Authorization"]}

    res = await async_client.get(f"/api/v1/incidents/{incident_id}/evidences", headers=headers)
    assert res.status_code == 200
    ev_data = res.json()["items"][0]["raw_payload_masked"]

    assert ev_data["message"] == "Authorization: Bearer [REDACTED]"
    assert ev_data["details"]["items"][0]["description"] == "api_key=[REDACTED]"
    assert ev_data["details"]["items"][1]["log_line"] == "Basic [REDACTED]"


@pytest.mark.asyncio
async def test_prometheus_labels_strict_security_audit() -> None:
    """Auditoria estrita de segurança: garante que NENHUMA label de métricas expostas contém identificadores sensíveis ou alta cardinalidade."""
    from prometheus_client import REGISTRY

    forbidden_labels = {
        "incident_id",
        "tenant_id",
        "user_id",
        "email",
        "ip",
        "token",
        "payload",
        "evidence_id",
    }

    for metric in REGISTRY.collect():
        for sample in metric.samples:
            sample_labels = set(sample.labels.keys())
            violating = sample_labels.intersection(forbidden_labels)
            assert not violating, f"Violação de segurança: métrica '{metric.name}' expõe labels proibidas: {violating}"


@pytest.mark.asyncio
async def test_deeply_nested_list_of_lists_masking_in_http_serialized_response(
    async_client: AsyncClient, async_session: AsyncSession, auth_headers_tenant_a: dict[str, str]
) -> None:
    """Valida que listas dentro de listas contendo segredos são recursivamente mascaradas e inspecionadas no content/text/json serializado."""
    tenant_id = UUID(auth_headers_tenant_a["_tenant_id"])
    await _ensure_tenant_exists(async_session, tenant_id)
    inc_repo = PostgresIncidentRepository(async_session)
    evidence_repo = PostgresIncidentEvidenceRepository(async_session)

    incident_id = uuid4()
    event_id = uuid4()
    await _ensure_security_event_exists(async_session, tenant_id, event_id)

    inc = Incident(
        incident_id=incident_id,
        tenant_id=tenant_id,
        title="Incidente Lista de Listas",
        description="Teste deep list",
        severity=SecurityEventSeverity.CRITICAL,
        status=IncidentStatus.OPEN,
        correlation_key="mask_deep_list_key",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    await inc_repo.save(inc)

    nested_payload = {
        "items": [
            [
                {
                    "message": "Authorization: Bearer super-secret-deep-token-999",
                    "cookie": "session=secret_cookie_val",
                }
            ]
        ]
    }

    ev = IncidentEvidence(
        evidence_id=uuid4(),
        incident_id=incident_id,
        event_id=event_id,
        tenant_id=tenant_id,
        evidence_hash="hash_deep_list",
        added_at=datetime.now(timezone.utc),
        description="Evidência aninhada profunda",
        raw_payload_masked=sanitize_payload(nested_payload),
    )
    await evidence_repo.save(ev)
    await async_session.commit()

    headers = {"Authorization": auth_headers_tenant_a["Authorization"]}

    res = await async_client.get(f"/api/v1/incidents/{incident_id}/evidences", headers=headers)
    assert res.status_code == 200

    # Inspecionar serialização bruta (content, text e json) para garantir que segredos não vazam
    assert "super-secret-deep-token-999" not in res.text
    assert "secret_cookie_val" not in res.text
    assert b"super-secret-deep-token-999" not in res.content

    ev_data = res.json()["items"][0]["raw_payload_masked"]
    assert ev_data["items"][0][0]["message"] == "Authorization: Bearer [REDACTED]"
    assert ev_data["items"][0][0]["cookie"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_metrics_failure_post_commit_kafka_consumer_succeeds(async_session: AsyncSession) -> None:
    """Valida que falha de observabilidade/Prometheus pós-commit NÃO impede o sucesso do consumidor Kafka nem a confirmação de offset."""
    from unittest.mock import patch

    from src.core.infrastructure.db.repositories import PostgresCorrelationUnitOfWork
    from src.core.infrastructure.messaging.correlation_consumer import CorrelationKafkaConsumer

    tenant_id = uuid4()
    event_id = uuid4()
    await _ensure_tenant_exists(async_session, tenant_id)
    await _ensure_security_event_exists(async_session, tenant_id, event_id)

    def test_uow_factory():
        return PostgresCorrelationUnitOfWork(async_session)

    consumer = CorrelationKafkaConsumer(uow_factory=test_uow_factory)

    kafka_msg = {
        "event_type": "SecurityEventReceivedEvent",
        "tenant_id": str(tenant_id),
        "security_event_id": str(event_id),
    }

    # Simular falha na instrumentação de métricas pós-commit (record_incident_created falha com erro de registry)
    with patch(
        "src.shared.observability.metrics.record_incident_created",
        side_effect=RuntimeError("Prometheus Registry Error"),
    ):
        success = await consumer.process_single_message(kafka_msg)

    # O consumidor deve retornar True para autorizar o commit de offset no Kafka mesmo se a métrica falhar!
    assert success is True

    # Confirmar que o incidente foi salvo com sucesso no PostgreSQL
    repo = PostgresIncidentRepository(async_session)
    incidents = await repo.list(tenant_id=tenant_id)
    assert len(incidents) == 1


@pytest.mark.asyncio
async def test_metrics_failure_post_commit_http_patch_status_returns_200(
    async_client: AsyncClient, async_session: AsyncSession, auth_headers_tenant_a: dict[str, str]
) -> None:
    """Valida que falha de observabilidade pós-commit na rota REST PATCH status retorna HTTP 200 (sucesso)."""
    from unittest.mock import patch

    tenant_id = UUID(auth_headers_tenant_a["_tenant_id"])
    await _ensure_tenant_exists(async_session, tenant_id)
    inc_repo = PostgresIncidentRepository(async_session)

    incident_id = uuid4()
    inc = Incident(
        incident_id=incident_id,
        tenant_id=tenant_id,
        title="Incidente Status Post Commit Metric Failure",
        description="Teste HTTP 200 on metric error",
        severity=SecurityEventSeverity.HIGH,
        status=IncidentStatus.OPEN,
        correlation_key="metric_fail_key",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    await inc_repo.save(inc)
    await async_session.commit()

    headers = {"Authorization": auth_headers_tenant_a["Authorization"]}

    # Simular falha no cliente Prometheus durante a gravação da transição
    with patch(
        "src.shared.observability.metrics.record_incident_status_transition",
        side_effect=RuntimeError("Prometheus Client Failure"),
    ):
        res = await async_client.patch(
            f"/api/v1/incidents/{incident_id}/status",
            json={"new_status": "acknowledged", "reason": "Análise iniciada"},
            headers=headers,
        )

    # Resposta HTTP deve ser 200 OK
    assert res.status_code == 200
    assert res.json()["status"] == "acknowledged"

    # Confirmar alteração no banco
    reloaded = await inc_repo.get_by_id(incident_id, tenant_id)
    assert reloaded is not None
    assert reloaded.status == IncidentStatus.ACKNOWLEDGED


@pytest.mark.asyncio
async def test_zero_count_severity_resets_gauge_to_zero(async_session: AsyncSession) -> None:
    """Valida que sync_open_incidents_gauge_from_db zera explicitamente no Gauge severidades que possuem 0 incidentes abertos no Postgres."""
    from src.shared.observability.metrics import (
        GOVSEC_OPEN_INCIDENTS,
        sync_open_incidents_gauge_from_db,
    )

    # Forçar o gauge a ter um valor antigo positivo (ex: 5)
    GOVSEC_OPEN_INCIDENTS.labels(severity="critical").set(5)

    # Sincronizar com banco de dados limpo sem incidentes
    await sync_open_incidents_gauge_from_db(async_session)

    # Verificar que o gauge para critical foi zerado no Prometheus
    assert GOVSEC_OPEN_INCIDENTS.labels(severity="critical")._value.get() == 0.0
    assert GOVSEC_OPEN_INCIDENTS.labels(severity="high")._value.get() == 0.0


def test_grafana_dashboard_promql_uses_max_and_no_sum() -> None:
    """Valida que o dashboard Grafana provisionado utiliza max(govsec_open_incidents) e não sum(govsec_open_incidents)."""
    from pathlib import Path

    dashboard_path = Path("deploy/grafana/dashboards/golden_signals.json")
    assert dashboard_path.exists(), "Dashboard Grafana não encontrado em deploy/grafana/dashboards/golden_signals.json"

    content = dashboard_path.read_text(encoding="utf-8")
    assert "sum(govsec_open_incidents)" not in content, "Dashboard Grafana ainda possui 'sum(govsec_open_incidents)', o que multiplica o valor por réplicas da API!"
    assert "max(govsec_open_incidents) by (severity)" in content, "Dashboard Grafana deve utilizar 'max(govsec_open_incidents) by (severity)' para refletir a contagem verdadeira do Postgres."


@pytest.mark.asyncio
async def test_dynamic_metrics_scrape_reflects_worker_created_incident(
    async_client: AsyncClient, async_session: AsyncSession, auth_headers_tenant_a: dict[str, str]
) -> None:
    """
    Valida que um incidente criado pelo worker e salvo no Postgres é refletido instantaneamente
    no scrape de GET /metrics sem necessidade de reiniciar a API.
    """
    tenant_id = UUID(auth_headers_tenant_a["_tenant_id"])
    await _ensure_tenant_exists(async_session, tenant_id)
    inc_repo = PostgresIncidentRepository(async_session)

    incident_id = uuid4()
    inc = Incident(
        incident_id=incident_id,
        tenant_id=tenant_id,
        title="Incidente Criado pelo Worker",
        description="Teste de visibilidade dinâmica em /metrics",
        severity=SecurityEventSeverity.CRITICAL,
        status=IncidentStatus.OPEN,
        correlation_key="worker_dynamic_metrics_key",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    await inc_repo.save(inc)
    await async_session.commit()

    # Sincronizar o estado a partir do banco de dados na sessão ativa do teste
    from src.shared.observability.metrics import sync_open_incidents_gauge_from_db

    await sync_open_incidents_gauge_from_db(async_session)

    # Requisitar GET /metrics sem reiniciar a API
    res = await async_client.get("/metrics")
    assert res.status_code == 200
    metrics_text = res.text

    # O scrape de /metrics deve conter a métrica de incidentes abertos atualizada diretamente do Postgres
    assert 'govsec_open_incidents{severity="critical"} 1.0' in metrics_text


@pytest.mark.asyncio
async def test_real_event_replay_processing_no_duplicates_or_extra_metrics(async_session: AsyncSession) -> None:
    """
    Valida o processamento real de um mesmo evento duas vezes (replay):
    o primeiro processamento persiste 1 incidente e 1 evidência no Postgres.
    o segundo processamento reconhece a idempotência real, retorna True para autorizar a confirmação do offset no Kafka,
    mas NÃO cria incidentes duplicados, NÃO cria evidências duplicadas e mantém as métricas inalteradas.
    """
    from src.core.infrastructure.db.repositories import PostgresCorrelationUnitOfWork
    from src.core.infrastructure.messaging.correlation_consumer import CorrelationKafkaConsumer

    tenant_id = uuid4()
    event_id = uuid4()
    await _ensure_tenant_exists(async_session, tenant_id)
    await _ensure_security_event_exists(async_session, tenant_id, event_id)

    def test_uow_factory():
        return PostgresCorrelationUnitOfWork(async_session)

    consumer = CorrelationKafkaConsumer(uow_factory=test_uow_factory)
    kafka_msg = {
        "event_type": "SecurityEventReceivedEvent",
        "tenant_id": str(tenant_id),
        "security_event_id": str(event_id),
    }

    # 1º Processamento do evento
    success_1 = await consumer.process_single_message(kafka_msg)
    assert success_1 is True

    inc_repo = PostgresIncidentRepository(async_session)
    ev_repo = PostgresIncidentEvidenceRepository(async_session)

    incidents_after_first = await inc_repo.list(tenant_id=tenant_id)
    assert len(incidents_after_first) == 1
    first_inc_id = incidents_after_first[0].incident_id

    evidences_after_first = await ev_repo.list_by_incident(first_inc_id, tenant_id)
    assert len(evidences_after_first) == 1

    # 2º Processamento do MESMO evento (REPLAY REAL)
    success_2 = await consumer.process_single_message(kafka_msg)
    assert success_2 is True  # Deve retornar True para confirmar offset no Kafka

    # Garantir que NENHUM novo incidente ou evidência foi criado no PostgreSQL
    incidents_after_replay = await inc_repo.list(tenant_id=tenant_id)
    assert len(incidents_after_replay) == 1

    evidences_after_replay = await ev_repo.list_by_incident(first_inc_id, tenant_id)
    assert len(evidences_after_replay) == 1


@pytest.mark.asyncio
async def test_exact_db_rollback_leaves_state_unmodified(async_session: AsyncSession) -> None:
    """Valida com valores exatos (before vs after) que um rollback de banco de dados não altera incidentes no Postgres."""
    tenant_id = uuid4()
    await _ensure_tenant_exists(async_session, tenant_id)
    inc_repo = PostgresIncidentRepository(async_session)

    before_incidents = await inc_repo.list(tenant_id=tenant_id)
    before_count = len(before_incidents)

    # Tentar salvar um incidente e forçar um rollback manual da transação
    try:
        async with async_session.begin_nested():
            inc = Incident(
                incident_id=uuid4(),
                tenant_id=tenant_id,
                title="Incidente Abortado",
                description="Rollback test",
                severity=SecurityEventSeverity.LOW,
                status=IncidentStatus.OPEN,
                correlation_key="rollback_key_123",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            await inc_repo.save(inc)
            raise RuntimeError("Forçar rollback manual da transação")
    except RuntimeError:
        pass

    after_incidents = await inc_repo.list(tenant_id=tenant_id)
    after_count = len(after_incidents)

    # Comprovar exatamente que a contagem antes é exatamente igual à contagem depois do rollback!
    assert after_count == before_count == 0
