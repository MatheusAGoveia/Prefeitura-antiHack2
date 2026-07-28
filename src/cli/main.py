"""
Interface de Linha de Comando (CLI) para Administração
GovSec Shield — CLI Admin
"""

import asyncio
import logging
import sys

from src.core.domain.entities import Tenant, TenantStatus
from src.core.infrastructure.db.unit_of_work import AsyncSessionLocal, UnitOfWork

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


async def create_tenant_cli(name: str, slug: str) -> None:
    async with AsyncSessionLocal() as session:
        uow = UnitOfWork(session)
        tenant = Tenant(name=name, slug=slug, status=TenantStatus.ACTIVE)
        saved = await uow.tenants.save(tenant)
        await uow.commit()
        logger.info(
            f"[CLI SUCCESS] Tenant '{saved.name}' criado com ID={saved.id} e Slug='{saved.slug}'"
        )


def cli() -> None:
    if len(sys.argv) < 4 or sys.argv[1] != "tenant" or sys.argv[2] != "create":
        logger.error("Uso correto: govsec tenant create <name> <slug>")
        sys.exit(1)

    name = sys.argv[3]
    slug = sys.argv[4] if len(sys.argv) > 4 else name.lower()
    asyncio.run(create_tenant_cli(name, slug))


if __name__ == "__main__":
    cli()
