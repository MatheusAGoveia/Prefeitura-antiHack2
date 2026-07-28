"""
Command Handlers da Aplicação
GovSec Shield — Command Handlers
"""

import re
from datetime import datetime
from uuid import UUID
from src.core.domain.entities import Tenant, TenantStatus
from src.core.domain.repositories import TenantRepository
from src.core.domain.events import TenantCreatedEvent, LogIngestedEvent
from src.core.application.commands import CreateTenantCommand, IngestLogCommand
from src.core.application.interfaces import IEventPublisher
from src.core.application.dto import TenantResponseDTO

class CreateTenantHandler:
    def __init__(self, tenant_repo: TenantRepository, event_publisher: IEventPublisher):
        self.tenant_repo = tenant_repo
        self.event_publisher = event_publisher

    async def handle(self, command: CreateTenantCommand) -> TenantResponseDTO:
        name = command.payload["name"]
        slug = command.payload.get("slug")

        if not slug:
            slug = re.sub(r"[^\w]+", "-", name.lower()).strip("-")

        existing = await self.tenant_repo.get_by_slug(slug)
        if existing:
            raise ValueError(f"Já existe um Tenant registrado com o slug '{slug}'")

        tenant = Tenant(
            name=name,
            slug=slug,
            status=TenantStatus.ACTIVE
        )

        saved = await self.tenant_repo.save(tenant)

        event = TenantCreatedEvent(
            tenant_id=saved.id,
            name=saved.name,
            slug=saved.slug
        )
        await self.event_publisher.publish(event)

        return TenantResponseDTO(
            id=saved.id,
            name=saved.name,
            slug=saved.slug,
            status=saved.status.value,
            created_at=saved.created_at,
            updated_at=saved.updated_at
        )


class IngestLogHandler:
    def __init__(self, event_publisher: IEventPublisher):
        self.event_publisher = event_publisher

    async def handle(self, command: IngestLogCommand) -> None:
        source = command.payload["source"]
        raw_data = command.payload["raw_data"]
        tenant_id_str = command.payload["tenant_id"]
        tenant_id = UUID(tenant_id_str)
        timestamp_str = command.payload.get("timestamp")
        timestamp = datetime.fromisoformat(timestamp_str) if timestamp_str else datetime.utcnow()

        event = LogIngestedEvent(
            tenant_id=tenant_id,
            source=source,
            raw_data=raw_data,
            timestamp=timestamp
        )

        await self.event_publisher.publish(event)
