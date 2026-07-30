"""
Script de Seed Local Idempotente para Ativos (M3.1)
GovSec Shield — Dev/Test Data Seeding Script

Este script permite cadastrar idempotentemente os ativos padrão para desenvolvimento local e testes.
Proibido executar em staging ou produção.
"""

import argparse
import asyncio
import logging
import sys
from uuid import UUID

from src.core.domain.incidents import Asset
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.unit_of_work import AsyncSessionLocal, UnitOfWork

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_m3_assets")


async def seed_dev_assets(tenant_id: UUID | None = None) -> None:
    # Trava de Segurança: Proibir execução automática ou acidental em staging/production
    if settings.GOVSEC_ENV in ("staging", "production"):
        raise RuntimeError(
            f"Execução de seed cancelada (Fail-Closed): O ambiente atual é '{settings.GOVSEC_ENV}'. "
            f"Scripts de seed local de dados são estritamente proibidos fora de 'development' e 'test'."
        )

    async with AsyncSessionLocal() as session:
        uow = UnitOfWork(session)

        # Resolução explícita de tenant (sem hardcode)
        target_tenant_id = tenant_id
        if target_tenant_id is None:
            # Tentar buscar tenant dev existente no repositório
            existing_tenants = await uow.tenants.list(limit=1)
            if existing_tenants:
                target_tenant_id = existing_tenants[0].id
            else:
                raise ValueError(
                    "Nenhum tenant cadastrado encontrado. Informe o --tenant-id explicitamente "
                    "ou crie um tenant prévio no ambiente dev."
                )

        logger.info(f"Iniciando seed de ativos M3.1 para o Tenant UUID: {target_tenant_id}")

        # Resolução de ativo existente para garantir idempotência
        existing_asset = await uow.assets.resolve_active_asset(
            tenant_id=target_tenant_id,
            service_name="govsec-core-api",
            environment="development",
        )

        if existing_asset:
            logger.info(
                f"[SEED REPEAT] Ativo 'govsec-core-api' (development) já cadastrado. "
                f"AssetID={existing_asset.asset_id}"
            )
            return

        # Cadastrar novo ativo
        new_asset = Asset(
            tenant_id=target_tenant_id,
            name="GovSec Core API",
            asset_type="service",
            service_name="govsec-core-api",
            environment="development",
            criticality="HIGH",
            is_active=True,
            hostname_or_ip="api.internal.local",
        )

        saved_asset = await uow.assets.save(new_asset)
        await uow.commit()

        logger.info(
            f"[SEED SUCCESS] Ativo 'govsec-core-api' cadastrado com sucesso. "
            f"AssetID={saved_asset.asset_id}, TenantID={saved_asset.tenant_id}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed de Ativos M3.1 para Desenvolvimento Local")
    parser.add_argument(
        "--tenant-id",
        type=str,
        help="UUID do tenant de destino (opcional, utiliza primeiro tenant dev ativo se omitido)",
    )
    args = parser.parse_args()

    tenant_uuid = UUID(args.tenant_id) if args.tenant_id else None

    try:
        asyncio.run(seed_dev_assets(tenant_id=tenant_uuid))
    except Exception as exc:
        logger.error(f"Falha no seed de ativos: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
