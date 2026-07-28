"""
Interface de Linha de Comando (CLI) para Administração
GovSec Shield — CLI Admin
"""

import sys
import asyncio
from uuid import uuid4
from src.core.domain.entities import Tenant, TenantStatus
from src.core.infrastructure.db.unit_of_work import AsyncSessionLocal, UnitOfWork

async def create_tenant_cli(name: str, slug: str):
    async with AsyncSessionLocal() as session:
        uow = UnitOfWork(session)
        tenant = Tenant(name=name, slug=slug, status=TenantStatus.ACTIVE)
        saved = await uow.tenants.save(tenant)
        await uow.commit()
        print(f"[CLI SUCCESS] Tenant '{saved.name}' criado com ID={saved.id} e Slug='{saved.slug}'")

def cli():
    if len(sys.argv) < 4 or sys.argv[1] != "tenant" or sys.argv[2] != "create":
        print("Uso: govsec tenant create <name> <slug>")
        sys.exit(1)
    
    name = sys.argv[3]
    slug = sys.argv[4] if len(sys.argv) > 4 else name.lower()
    asyncio.run(create_tenant_cli(name, slug))

if __name__ == "__main__":
    cli()
