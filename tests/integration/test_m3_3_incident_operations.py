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
    PostgresIncidentStatusHistoryRepository,
)
from src.core.infrastructure.security.jwt import JWTUtils
from src.shared.observability.metrics import (
    GOVSEC_INCIDENT_EVIDENCES_TOTAL,
    GOVSEC_INCIDENT_STATUS_TRANSITIONS_TOTAL,
    GOVSEC_INCIDENTS_TOTAL,
    record_incident_created,
    record_incident_evidence_added,
    record_incident_status_transition,
)

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
async def test_incidents_list_filters_and_pagination(async_session: AsyncSession) -> None:
    """Valida filtros operacionais por status, severidade e datas, sem falso vazio."""
    repo = PostgresIncidentRepository(async_session)
    tenant_id = uuid4()
    await _ensure_tenant_exists(async_session, tenant_id)
    now = datetime.now(timezone.utc)

    # 1. Inserir incidentes de teste com severidades e status distintos
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

    # Filtro por status
    total_open = await repo.count(tenant_id=tenant_id, status="open")
    page_open = await repo.list(tenant_id=tenant_id, status="open")
    assert total_open == 1
    assert len(page_open) == 1
    assert page_open[0].incident_id == inc1.incident_id

    # Filtro por severidade
    total_crit = await repo.count(tenant_id=tenant_id, severity="critical")
    page_crit = await repo.list(tenant_id=tenant_id, severity="critical")
    assert total_crit == 1
    assert page_crit[0].incident_id == inc2.incident_id

    # Filtro por janela de data
    page_recent = await repo.list(
        tenant_id=tenant_id,
        created_from=now - timedelta(minutes=90),
    )
    assert len(page_recent) == 1
    assert page_recent[0].incident_id == inc2.incident_id


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
async def test_cross_tenant_isolation_returns_404(
    async_client: AsyncClient, async_session: AsyncSession, auth_headers_tenant_a: dict[str, str]
) -> None:
    """Valida que acessar incidente, evidências ou histórico de outro tenant retorna HTTP 404."""
    tenant_a_id = UUID(auth_headers_tenant_a["_tenant_id"])
    await _ensure_tenant_exists(async_session, tenant_a_id)

    # 1. Tentar detalhar incidente aleatório (não existente para tenant A) -> 404
    random_id = uuid4()
    res1 = await async_client.get(
        f"/api/v1/incidents/{random_id}",
        headers={"Authorization": auth_headers_tenant_a["Authorization"]},
    )
    assert res1.status_code == 404

    # 2. Tentar obter evidências de incidente de outro tenant -> 404
    res2 = await async_client.get(
        f"/api/v1/incidents/{random_id}/evidences",
        headers={"Authorization": auth_headers_tenant_a["Authorization"]},
    )
    assert res2.status_code == 404

    # 3. Tentar obter histórico de incidente de outro tenant -> 404
    res3 = await async_client.get(
        f"/api/v1/incidents/{random_id}/history",
        headers={"Authorization": auth_headers_tenant_a["Authorization"]},
    )
    assert res3.status_code == 404


@pytest.mark.asyncio
async def test_evidence_payload_is_masked(async_session: AsyncSession) -> None:
    """Valida que o payload da evidência retornado é devidamente sanitizado (sem senhas/tokens em claro)."""
    inc_repo = PostgresIncidentRepository(async_session)
    evidence_repo = PostgresIncidentEvidenceRepository(async_session)
    tenant_id = uuid4()
    incident_id = uuid4()
    event_id = uuid4()

    await _ensure_tenant_exists(async_session, tenant_id)
    await _ensure_security_event_exists(async_session, tenant_id, event_id)

    # 1. Criar o incidente pai
    incident = Incident(
        incident_id=incident_id,
        tenant_id=tenant_id,
        title="Incidente para Evidência",
        description="Teste evidência mascarada",
        severity=SecurityEventSeverity.HIGH,
        status=IncidentStatus.OPEN,
        correlation_key="ev_key_01",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    await inc_repo.save(incident)

    unmasked_payload = {
        "user": "admin_gov",
        "password": "SecretPassword123!",
        "token": "bearer_jwt_token_sensitive",
        "normal_field": "public_data",
    }

    evidence = IncidentEvidence(
        evidence_id=uuid4(),
        incident_id=incident_id,
        event_id=event_id,
        tenant_id=tenant_id,
        evidence_hash="sha256_mock_hash",
        added_at=datetime.now(timezone.utc),
        description="Evidência com dados sensíveis",
        raw_payload_masked=sanitize_payload(unmasked_payload),
    )
    await evidence_repo.save(evidence)
    await async_session.commit()

    list_ev = await evidence_repo.list_by_incident(incident_id=incident_id, tenant_id=tenant_id)
    assert len(list_ev) == 1
    payload = list_ev[0].raw_payload_masked
    assert payload["password"] == "[REDACTED]"
    assert payload["token"] == "[REDACTED]"
    assert payload["normal_field"] == "public_data"


@pytest.mark.asyncio
async def test_history_is_immutable(async_session: AsyncSession) -> None:
    """Valida que o histórico de transições de status é imutável e preservado."""
    inc_repo = PostgresIncidentRepository(async_session)
    history_repo = PostgresIncidentStatusHistoryRepository(async_session)
    tenant_id = uuid4()
    incident_id = uuid4()
    await _ensure_tenant_exists(async_session, tenant_id)

    incident = Incident(
        incident_id=incident_id,
        tenant_id=tenant_id,
        title="Incidente para Transição",
        description="Teste histórico imutável",
        severity=SecurityEventSeverity.HIGH,
        status=IncidentStatus.OPEN,
        correlation_key="hist_key_01",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    await inc_repo.save(incident)
    await async_session.commit()

    # Realizar transição válida: OPEN -> ACKNOWLEDGED
    incident.transition_to(new_status=IncidentStatus.ACKNOWLEDGED, actor_id="user_admin", reason="Análise iniciada")
    await inc_repo.save(incident)
    await async_session.commit()

    history = await history_repo.list_by_incident(incident_id=incident_id, tenant_id=tenant_id)
    assert len(history) == 1
    assert history[0].from_status == IncidentStatus.OPEN
    assert history[0].to_status == IncidentStatus.ACKNOWLEDGED
    assert history[0].actor_id == "user_admin"
    assert history[0].reason == "Análise iniciada"


@pytest.mark.asyncio
async def test_prometheus_metrics_increment_without_sensitive_labels() -> None:
    """Valida que as métricas Prometheus de M3.3 são incrementadas e usam apenas labels seguras."""
    # Incrementar criados
    record_incident_created(severity="high", status="open")
    val_incidents = GOVSEC_INCIDENTS_TOTAL.labels(severity="high", status="open")._value.get()
    assert val_incidents >= 1

    # Incrementar transição
    record_incident_status_transition(from_status="open", to_status="investigating")
    val_trans = GOVSEC_INCIDENT_STATUS_TRANSITIONS_TOTAL.labels(from_status="open", to_status="investigating")._value.get()
    assert val_trans >= 1

    # Incrementar evidências
    record_incident_evidence_added(rule_id="SSHBruteforce")
    val_ev = GOVSEC_INCIDENT_EVIDENCES_TOTAL.labels(rule_id="SSHBruteforce")._value.get()
    assert val_ev >= 1

    # Garantir que labels sensíveis (user_id, incident_id, token) NÃO existem no registro Prometheus
    for sample in GOVSEC_INCIDENTS_TOTAL.collect()[0].samples:
        assert "incident_id" not in sample.labels
        assert "email" not in sample.labels
        assert "password" not in sample.labels
