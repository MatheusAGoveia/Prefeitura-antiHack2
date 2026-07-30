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
from typing import Any
from uuid import UUID

from src.core.domain.entities import TenantStatus
from src.core.domain.exceptions import DomainError
from src.core.domain.incidents import Asset
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.unit_of_work import AsyncSessionLocal, UnitOfWork

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_m3_assets")


async def seed_dev_assets(
    tenant_id: UUID,
    uow: Any = None,
    env_override: str | None = None,
) -> Asset:
    current_env = env_override if env_override is not None else settings.GOVSEC_ENV

    # Trava de Segurança 1: Proibir execução fora dos ambientes autorizados (dev/test)
    if current_env not in ("development", "dev", "test"):
        raise RuntimeError(
            f"Execução de seed cancelada (Fail-Closed): O ambiente atual é '{current_env}'. "
            f"Scripts de seed local de dados são estritamente proibidos fora de 'development' e 'test'."
        )

    if not isinstance(tenant_id, UUID):
        raise ValueError(f"--tenant-id deve ser um UUID válido, recebido: {tenant_id}")

    if uow is not None:
        return await _execute_seed_with_uow(tenant_id, uow)

    async with AsyncSessionLocal() as session:
        uow_impl = UnitOfWork(session)
        return await _execute_seed_with_uow(tenant_id, uow_impl)


async def _execute_seed_with_uow(tenant_id: UUID, uow: Any) -> Asset:
    # Trava de Segurança 2: Validar que o tenant informado existe e está ATIVO no banco
    tenant = await uow.tenants.get_by_id(tenant_id)
    if not tenant:
        raise ValueError(f"Tenant com ID '{tenant_id}' não foi localizado no banco de dados.")

    tenant_status_val = (
        tenant.status.value if hasattr(tenant.status, "value") else str(tenant.status)
    )
    if tenant_status_val != TenantStatus.ACTIVE.value:
        raise ValueError(
            f"Tenant '{tenant_id}' possui status '{tenant_status_val}'. "
            f"Seed é permitido apenas para tenants ativos ({TenantStatus.ACTIVE.value})."
        )

    logger.info(f"Iniciando seed de ativos M3.1 para o Tenant UUID ativo: {tenant_id}")

    # Resolução de ativo ativo existente para garantir idempotência
    existing_asset = await uow.assets.resolve_active_asset(
        tenant_id=tenant_id,
        service_name="govsec-core-api",
        environment="development",
    )

    if existing_asset:
        logger.info(
            f"[SEED REPEAT] Ativo 'govsec-core-api' (development) já cadastrado e ativo. "
            f"AssetID={existing_asset.asset_id}"
        )
        return existing_asset

    # Cadastrar novo ativo
    new_asset = Asset(
        tenant_id=tenant_id,
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
    return saved_asset


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed de Ativos M3.1 para Desenvolvimento Local")
    parser.add_argument(
        "--tenant-id",
        type=str,
        required=True,
        help="UUID do tenant de destino (obrigatorio)",
    )
    args = parser.parse_args()

    try:
        tenant_uuid = UUID(args.tenant_id)
    except (ValueError, TypeError):
        logger.error(f"Erro de parâmetro: --tenant-id deve ser um UUID válido: '{args.tenant_id}'")
        sys.exit(1)

    try:
        asyncio.run(seed_dev_assets(tenant_id=tenant_uuid))
    except (ValueError, RuntimeError, DomainError) as exc:
        logger.error(f"Falha de validação no seed de ativos: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
