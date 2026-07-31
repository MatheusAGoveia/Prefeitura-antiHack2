"""
Endpoints REST de Incidentes (M3.2).
GovSec Shield — Incident Management API

Contratos:
  GET   /api/v1/incidents          — listagem paginada por tenant (filtro obrigatório via JWT)
  GET   /api/v1/incidents/{id}     — detalhe de um incidente com contagem de evidências
  PATCH /api/v1/incidents/{id}/status — mudança auditada de status (tenant e actor do JWT)

Regras de segurança & arquitetura:
  - tenant_id NUNCA aceito do cliente; extraído exclusivamente do JWT.
  - actor_id para auditoria de status = user_id do JWT autenticado.
  - count(*) executado diretamente no banco de dados.
  - Ordenação estável: created_at DESC, incident_id DESC.
  - Sem import de modelos ORM dentro das rotas REST (encapsulamento total via repositório/UoW).
  - Transição inválida → HTTP 422 com mensagem explícita.
  - Incidente de outro tenant → HTTP 404 (não vaza existência).
"""

import logging
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.application.dto import (
    VALID_INCIDENT_STATUSES,
    ChangeIncidentStatusDTO,
    EvidenceListResponseDTO,
    EvidenceResponseDTO,
    IncidentHistoryListResponseDTO,
    IncidentHistoryResponseDTO,
    IncidentListResponseDTO,
    IncidentResponseDTO,
)
from src.core.domain.exceptions import DomainError
from src.core.domain.incidents import IncidentStatus, InvalidStatusTransitionError, sanitize_payload
from src.core.infrastructure.db.repositories import (
    PostgresCorrelationUnitOfWork,
    PostgresIncidentEvidenceRepository,
    PostgresIncidentRepository,
    PostgresIncidentStatusHistoryRepository,
)
from src.core.infrastructure.db.unit_of_work import get_db_session
from src.core.infrastructure.security.kernel import AuthenticatedUser
from src.core.interfaces.rest.dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])

VALID_SEVERITIES = frozenset(["low", "medium", "high", "critical"])
ALLOWED_SORT_FIELDS = frozenset(["created_at", "updated_at", "severity", "status"])


# ---------------------------------------------------------------------------
# GET /api/v1/incidents
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=IncidentListResponseDTO,
    summary="Listar incidentes do tenant autenticado",
    description=(
        "Retorna incidentes paginados e filtrados por tenant_id extraído do JWT. "
        "Permite filtros por status, severidade e janela de criação (UTC). "
        "O cliente NUNCA informa o tenant_id."
    ),
)
async def list_incidents(
    skip: int = Query(default=0, ge=0, description="Número de registros a pular."),
    limit: int = Query(default=50, ge=1, le=200, description="Número máximo de registros."),
    incident_status: str | None = Query(
        default=None,
        alias="status",
        description=f"Filtro opcional por status. Valores válidos: {sorted(VALID_INCIDENT_STATUSES)}",
    ),
    severity: str | None = Query(
        default=None,
        description=f"Filtro opcional por severidade. Valores válidos: {sorted(VALID_SEVERITIES)}",
    ),
    created_from: datetime | None = Query(
        default=None,
        description="Filtro de data/hora inicial de criação (UTC).",
    ),
    created_to: datetime | None = Query(
        default=None,
        description="Filtro de data/hora final de criação (UTC).",
    ),
    sort_by: str = Query(
        default="created_at",
        description=f"Campo para ordenação. Permitidos: {sorted(ALLOWED_SORT_FIELDS)}",
    ),
    order: str = Query(
        default="desc",
        description="Direção da ordenação: asc ou desc.",
    ),
    current_user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> IncidentListResponseDTO:
    """
    Lista incidentes do tenant do usuário autenticado.
    tenant_id é extraído do JWT — nunca do cliente.
    Contagem total executada via COUNT(*) no banco.
    """
    if incident_status is not None:
        normalized_status = incident_status.strip().lower()
        if normalized_status not in VALID_INCIDENT_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Status inválido: '{incident_status}'. Valores aceitos: {sorted(VALID_INCIDENT_STATUSES)}",
            )
        incident_status = normalized_status

    if severity is not None:
        normalized_severity = severity.strip().lower()
        if normalized_severity not in VALID_SEVERITIES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Severidade inválida: '{severity}'. Valores aceitos: {sorted(VALID_SEVERITIES)}",
            )
        severity = normalized_severity

    if sort_by not in ALLOWED_SORT_FIELDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Campo de ordenação inválido: '{sort_by}'. Permitidos: {sorted(ALLOWED_SORT_FIELDS)}",
        )

    order_norm = order.strip().lower()
    if order_norm not in ("asc", "desc"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Direção de ordenação inválida: '{order}'. Permitidas: 'asc', 'desc'",
        )

    if created_from is not None:
        if created_from.tzinfo is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="created_from deve conter fuso horário UTC estrito (ex: 'Z' ou '+00:00').",
            )
        if created_from.utcoffset() != timedelta(0):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="created_from deve utilizar o fuso horário UTC zero (+00:00/Z). Offsets locais não são permitidos.",
            )

    if created_to is not None:
        if created_to.tzinfo is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="created_to deve conter fuso horário UTC estrito (ex: 'Z' ou '+00:00').",
            )
        if created_to.utcoffset() != timedelta(0):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="created_to deve utilizar o fuso horário UTC zero (+00:00/Z). Offsets locais não são permitidos.",
            )

    if created_from is not None and created_to is not None and created_from > created_to:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="created_from não pode ser posterior a created_to.",
        )

    tenant_id = current_user.tenant_id
    repo = PostgresIncidentRepository(session)

    # Contar total usando COUNT(*) no banco com filtros aplicados
    total = await repo.count(
        tenant_id=tenant_id,
        status=incident_status,
        severity=severity,
        created_from=created_from,
        created_to=created_to,
    )

    # Aplicar paginação com ordenação segura e determinística
    page = await repo.list(
        tenant_id=tenant_id,
        skip=skip,
        limit=limit,
        status=incident_status,
        severity=severity,
        created_from=created_from,
        created_to=created_to,
        sort_by=sort_by,
        order=order_norm,
    )

    # Obter contagem de evidências em lote para a página (sem N+1)
    incident_ids = [inc.incident_id for inc in page]
    counts_map = await repo.get_evidence_counts_batch(tenant_id=tenant_id, incident_ids=incident_ids)

    items = [
        IncidentResponseDTO(
            incident_id=inc.incident_id,
            tenant_id=inc.tenant_id,
            title=inc.title,
            description=inc.description,
            severity=inc.severity.value,
            status=inc.status.value,
            correlation_key=inc.correlation_key,
            created_at=inc.created_at,
            updated_at=inc.updated_at,
            evidence_count=counts_map.get(inc.incident_id, 0),
        )
        for inc in page
    ]
    return IncidentListResponseDTO(items=items, total=total, skip=skip, limit=limit)


# ---------------------------------------------------------------------------
# GET /api/v1/incidents/{incident_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{incident_id}",
    response_model=IncidentResponseDTO,
    summary="Detalhar um incidente",
    description="Retorna o incidente com contagem de evidências. Incidente de outro tenant retorna 404.",
)
async def get_incident(
    incident_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> IncidentResponseDTO:
    tenant_id = current_user.tenant_id
    repo = PostgresIncidentRepository(session)
    evidence_repo = PostgresIncidentEvidenceRepository(session)

    incident = await repo.get_by_id(incident_id=incident_id, tenant_id=tenant_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incidente não encontrado.",
        )

    evidence_count = await evidence_repo.count_by_incident(
        incident_id=incident_id, tenant_id=tenant_id
    )

    return IncidentResponseDTO(
        incident_id=incident.incident_id,
        tenant_id=incident.tenant_id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity.value,
        status=incident.status.value,
        correlation_key=incident.correlation_key,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        evidence_count=evidence_count,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/incidents/{incident_id}/evidences
# ---------------------------------------------------------------------------


@router.get(
    "/{incident_id}/evidences",
    response_model=EvidenceListResponseDTO,
    summary="Listar evidências de um incidente",
    description=(
        "Retorna as evidências de um incidente do tenant autenticado, com payload devidamente sanitizado. "
        "Incidente inexistente ou de outro tenant retorna HTTP 404."
    ),
)
async def list_incident_evidences(
    incident_id: UUID,
    skip: int = Query(default=0, ge=0, description="Número de registros a pular."),
    limit: int = Query(default=50, ge=1, le=200, description="Número máximo de registros."),
    current_user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> EvidenceListResponseDTO:
    tenant_id = current_user.tenant_id
    incident_repo = PostgresIncidentRepository(session)
    evidence_repo = PostgresIncidentEvidenceRepository(session)

    # 1. Validar se o incidente existe para este tenant (isolamento estrito multi-tenant)
    incident = await incident_repo.get_by_id(incident_id=incident_id, tenant_id=tenant_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incidente não encontrado.",
        )

    # 2. Buscar total e lista paginada
    total = await evidence_repo.count_by_incident(incident_id=incident_id, tenant_id=tenant_id)
    evidences = await evidence_repo.list_by_incident(
        incident_id=incident_id, tenant_id=tenant_id, skip=skip, limit=limit
    )

    items = [
        EvidenceResponseDTO(
            evidence_id=ev.evidence_id,
            incident_id=ev.incident_id,
            event_id=ev.event_id,
            tenant_id=ev.tenant_id,
            evidence_hash=ev.evidence_hash,
            description=ev.description,
            raw_payload_masked=sanitize_payload(ev.raw_payload_masked),
            added_at=ev.added_at,
        )
        for ev in evidences
    ]
    return EvidenceListResponseDTO(items=items, total=total, skip=skip, limit=limit)


# ---------------------------------------------------------------------------
# GET /api/v1/incidents/{incident_id}/history
# ---------------------------------------------------------------------------


@router.get(
    "/{incident_id}/history",
    response_model=IncidentHistoryListResponseDTO,
    summary="Listar histórico auditável de alterações de status",
    description=(
        "Retorna o histórico auditável imutável de transições de status do incidente. "
        "Incidente inexistente ou de outro tenant retorna HTTP 404."
    ),
)
async def list_incident_history(
    incident_id: UUID,
    skip: int = Query(default=0, ge=0, description="Número de registros a pular."),
    limit: int = Query(default=50, ge=1, le=200, description="Número máximo de registros."),
    current_user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> IncidentHistoryListResponseDTO:
    tenant_id = current_user.tenant_id
    incident_repo = PostgresIncidentRepository(session)
    history_repo = PostgresIncidentStatusHistoryRepository(session)

    # 1. Validar isolamento por tenant_id
    incident = await incident_repo.get_by_id(incident_id=incident_id, tenant_id=tenant_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incidente não encontrado.",
        )

    # 2. Obter total e registros paginados
    total = await history_repo.count_by_incident(incident_id=incident_id, tenant_id=tenant_id)
    history_changes = await history_repo.list_by_incident(
        incident_id=incident_id, tenant_id=tenant_id, skip=skip, limit=limit
    )

    items = [
        IncidentHistoryResponseDTO(
            history_id=change.history_id,
            incident_id=incident_id,
            tenant_id=tenant_id,
            from_status=change.from_status.value,
            to_status=change.to_status.value,
            actor_id=change.actor_id,
            reason=change.reason,
            timestamp=change.timestamp,
        )
        for change in history_changes
    ]
    return IncidentHistoryListResponseDTO(items=items, total=total, skip=skip, limit=limit)


# ---------------------------------------------------------------------------
# PATCH /api/v1/incidents/{incident_id}/status
# ---------------------------------------------------------------------------


@router.patch(
    "/{incident_id}/status",
    response_model=IncidentResponseDTO,
    summary="Alterar status de um incidente",
    description=(
        "Transiciona o status do incidente validando a máquina de estados. "
        "tenant_id e actor_id extraídos do JWT — nunca do payload. "
        "Exige motivo. Registra histórico na mesma transação. "
        "Transição inválida → HTTP 422."
    ),
)
async def change_incident_status(
    incident_id: UUID,
    dto: ChangeIncidentStatusDTO,
    current_user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> IncidentResponseDTO:
    """
    Altera o status de um incidente com auditoria.
    - tenant_id: do JWT (obrigatório, nunca do cliente)
    - actor_id: user_id do JWT autenticado
    - reason: do payload (obrigatório, min 5 chars)
    - transição inválida: HTTP 422
    - incidente de outro tenant: HTTP 404
    """
    tenant_id = current_user.tenant_id
    actor_id = str(current_user.user_id)

    async with PostgresCorrelationUnitOfWork(session) as uow:
        incident = await uow.incidents.get_by_id(incident_id=incident_id, tenant_id=tenant_id)
        if incident is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incidente não encontrado.",
            )

        old_status = incident.status.value
        try:
            new_status = IncidentStatus(dto.new_status)
            incident.transition_to(
                new_status=new_status,
                actor_id=actor_id,
                reason=dto.reason,
            )
        except InvalidStatusTransitionError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        except DomainError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        # Persistir incidente atualizado e histórico de auditoria na mesma transação/UoW
        saved = await uow.incidents.save(incident)
        await uow.commit()

        # Contar evidências para resposta completa do DTO
        evidence_count = await uow.evidences.count_by_incident(
            incident_id=saved.incident_id, tenant_id=tenant_id
        )

        # Incrementar métrica Prometheus de transição auditada (M3.3) PÓS-COMMIT (com adaptador seguro de infraestrutura)
        from src.shared.observability.metrics import (
            safe_record_incident_status_transition,
            sync_open_incidents_gauge_from_db,
        )

        safe_record_incident_status_transition(
            from_status=old_status,
            to_status=new_status,
            severity=saved.severity.value,
        )
        try:
            await sync_open_incidents_gauge_from_db(session)
        except Exception as exc:
            # Justificativa Técnica: Isolamento de falha de observabilidade pós-commit HTTP.
            logger.warning("Falha ao sincronizar gauge no pós-commit HTTP status: %s", exc)

    return IncidentResponseDTO(
        incident_id=saved.incident_id,
        tenant_id=saved.tenant_id,
        title=saved.title,
        description=saved.description,
        severity=saved.severity.value,
        status=saved.status.value,
        correlation_key=saved.correlation_key,
        created_at=saved.created_at,
        updated_at=saved.updated_at,
        evidence_count=evidence_count,
    )
