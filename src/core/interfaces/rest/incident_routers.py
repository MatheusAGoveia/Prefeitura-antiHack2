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

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.application.dto import (
    VALID_INCIDENT_STATUSES,
    ChangeIncidentStatusDTO,
    IncidentListResponseDTO,
    IncidentResponseDTO,
)
from src.core.domain.exceptions import DomainError
from src.core.domain.incidents import IncidentStatus, InvalidStatusTransitionError
from src.core.infrastructure.db.repositories import (
    PostgresCorrelationUnitOfWork,
    PostgresIncidentEvidenceRepository,
    PostgresIncidentRepository,
)
from src.core.infrastructure.db.unit_of_work import get_db_session
from src.core.infrastructure.security.kernel import AuthenticatedUser
from src.core.interfaces.rest.dependencies import get_current_user

router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])


# ---------------------------------------------------------------------------
# GET /api/v1/incidents
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=IncidentListResponseDTO,
    summary="Listar incidentes do tenant autenticado",
    description=(
        "Retorna incidentes paginados e filtrados por tenant_id extraído do JWT. "
        "O cliente NUNCA informa o tenant_id. "
        "Ordenação estável por created_at DESC, incident_id DESC."
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
    current_user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> IncidentListResponseDTO:
    """
    Lista incidentes do tenant do usuário autenticado.
    tenant_id é extraído do JWT — nunca do cliente.
    Contagem total executada via COUNT(*) no banco.
    """
    if incident_status is not None:
        normalized = incident_status.strip().lower()
        if normalized not in VALID_INCIDENT_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Status inválido: '{incident_status}'. Valores aceitos: {sorted(VALID_INCIDENT_STATUSES)}",
            )
        incident_status = normalized

    tenant_id = current_user.tenant_id
    repo = PostgresIncidentRepository(session)

    # Contar total usando COUNT(*) no banco (alta performance)
    total = await repo.count(tenant_id=tenant_id, status=incident_status)

    # Aplicar paginação com ordenação estável (created_at DESC, incident_id DESC)
    page = await repo.list(tenant_id=tenant_id, skip=skip, limit=limit, status=incident_status)

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

    evidences = await evidence_repo.list_by_incident(
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
        evidence_count=len(evidences),
    )


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
    )
