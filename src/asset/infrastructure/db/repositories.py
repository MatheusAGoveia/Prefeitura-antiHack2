"""
Repositórios de Persistência Assíncrona para o Módulo de Ativos e Scanners (M3.4).
GovSec Shield — Infrastructure Layer
"""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.asset.domain.asset_groups import AssetCriticality, AssetEnvironment, AssetGroup
from src.asset.domain.discovered_assets import (
    Asset,
    AssetService,
    AssetStatus,
    ServiceProtocol,
    ServiceState,
)
from src.asset.domain.scan_targets import ScanTarget, TargetType
from src.asset.infrastructure.db.models import (
    AssetGroupModel,
    AssetServiceModel,
    DiscoveredAssetModel,
    ScanTargetModel,
)


class PostgresAssetRepository:
    """Repositório SQLAlchemy para gerenciamento de Ativos e Grupos no PostgreSQL."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # --- AssetGroup ---
    async def save_group(self, group: AssetGroup) -> None:
        stmt = select(AssetGroupModel).where(
            AssetGroupModel.id == group.id,
            AssetGroupModel.tenant_id == group.tenant_id,
        )
        res = await self._session.execute(stmt)
        model = res.scalar_one_or_none()

        if model is None:
            model = AssetGroupModel(
                id=group.id,
                tenant_id=group.tenant_id,
                name=group.name,
                description=group.description,
                environment=str(group.environment),
                unit_name=group.unit_name,
                location=group.location,
                criticality=str(group.criticality),
                active=group.active,
                created_at=group.created_at,
                updated_at=group.updated_at,
                created_by=group.created_by,
                updated_by=group.updated_by,
            )
            self._session.add(model)
        else:
            model.name = group.name
            model.description = group.description
            model.environment = str(group.environment)
            model.unit_name = group.unit_name
            model.location = group.location
            model.criticality = str(group.criticality)
            model.active = group.active
            model.updated_at = group.updated_at
            model.updated_by = group.updated_by

    async def get_group_by_id(self, group_id: UUID, tenant_id: UUID) -> AssetGroup | None:
        stmt = select(AssetGroupModel).where(
            AssetGroupModel.id == group_id,
            AssetGroupModel.tenant_id == tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()
        if not m:
            return None
        return AssetGroup(
            id=m.id,
            tenant_id=m.tenant_id,
            name=m.name,
            description=m.description,
            environment=AssetEnvironment(m.environment),
            unit_name=m.unit_name,
            location=m.location,
            criticality=AssetCriticality(m.criticality),
            active=m.active,
            created_at=m.created_at,
            updated_at=m.updated_at,
            created_by=m.created_by,
            updated_by=m.updated_by,
        )

    async def list_groups(
        self,
        tenant_id: UUID,
        environment: str | None = None,
        active_only: bool = True,
        search: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[AssetGroup], int]:
        stmt = select(AssetGroupModel).where(AssetGroupModel.tenant_id == tenant_id)
        if active_only:
            stmt = stmt.where(AssetGroupModel.active.is_(True))
        if environment:
            stmt = stmt.where(AssetGroupModel.environment == environment)
        if search:
            stmt = stmt.where(AssetGroupModel.name.ilike(f"%{search}%"))

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_res = await self._session.execute(count_stmt)
        total = total_res.scalar_one() or 0

        stmt = stmt.order_by(AssetGroupModel.name.asc()).offset((page - 1) * page_size).limit(page_size)
        res = await self._session.execute(stmt)
        rows = list(res.scalars().all())

        groups = [
            AssetGroup(
                id=m.id,
                tenant_id=m.tenant_id,
                name=m.name,
                description=m.description,
                environment=AssetEnvironment(m.environment),
                unit_name=m.unit_name,
                location=m.location,
                criticality=AssetCriticality(m.criticality),
                active=m.active,
                created_at=m.created_at,
                updated_at=m.updated_at,
                created_by=m.created_by,
                updated_by=m.updated_by,
            )
            for m in rows
        ]
        return groups, total

    # --- ScanTarget ---
    async def save_target(self, target: ScanTarget) -> None:
        stmt = select(ScanTargetModel).where(
            ScanTargetModel.id == target.id,
            ScanTargetModel.tenant_id == target.tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()

        if m is None:
            m = ScanTargetModel(
                id=target.id,
                tenant_id=target.tenant_id,
                asset_group_id=target.asset_group_id,
                name=target.name,
                target_type=str(target.target_type),
                target_value=target.target_value,
                description=target.description,
                enabled=target.enabled,
                authorization_reference=target.authorization_reference,
                last_discovered_at=target.last_discovered_at,
                created_at=target.created_at,
                updated_at=target.updated_at,
                created_by=target.created_by,
                updated_by=target.updated_by,
            )
            self._session.add(m)
        else:
            m.name = target.name
            m.target_type = str(target.target_type)
            m.target_value = target.target_value
            m.description = target.description
            m.enabled = target.enabled
            m.authorization_reference = target.authorization_reference
            m.last_discovered_at = target.last_discovered_at
            m.updated_at = target.updated_at
            m.updated_by = target.updated_by

    async def get_target_by_id(self, target_id: UUID, tenant_id: UUID) -> ScanTarget | None:
        stmt = select(ScanTargetModel).where(
            ScanTargetModel.id == target_id,
            ScanTargetModel.tenant_id == tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()
        if not m:
            return None
        return ScanTarget(
            id=m.id,
            tenant_id=m.tenant_id,
            asset_group_id=m.asset_group_id,
            name=m.name,
            target_type=TargetType(m.target_type),
            target_value=m.target_value,
            description=m.description,
            enabled=m.enabled,
            authorization_reference=m.authorization_reference,
            last_discovered_at=m.last_discovered_at,
            created_at=m.created_at,
            updated_at=m.updated_at,
            created_by=m.created_by,
            updated_by=m.updated_by,
        )

    async def list_targets(
        self,
        tenant_id: UUID,
        asset_group_id: UUID | None = None,
        target_type: str | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[ScanTarget], int]:
        stmt = select(ScanTargetModel).where(ScanTargetModel.tenant_id == tenant_id)
        if asset_group_id:
            stmt = stmt.where(ScanTargetModel.asset_group_id == asset_group_id)
        if target_type:
            stmt = stmt.where(ScanTargetModel.target_type == target_type)
        if search:
            stmt = stmt.where(ScanTargetModel.name.ilike(f"%{search}%") | ScanTargetModel.target_value.ilike(f"%{search}%"))

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_res = await self._session.execute(count_stmt)
        total = total_res.scalar_one() or 0

        stmt = stmt.order_by(ScanTargetModel.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        res = await self._session.execute(stmt)
        rows = list(res.scalars().all())

        targets = [
            ScanTarget(
                id=m.id,
                tenant_id=m.tenant_id,
                asset_group_id=m.asset_group_id,
                name=m.name,
                target_type=TargetType(m.target_type),
                target_value=m.target_value,
                description=m.description,
                enabled=m.enabled,
                authorization_reference=m.authorization_reference,
                last_discovered_at=m.last_discovered_at,
                created_at=m.created_at,
                updated_at=m.updated_at,
                created_by=m.created_by,
                updated_by=m.updated_by,
            )
            for m in rows
        ]
        return targets, total

    # --- Discovered Asset & Services ---
    async def save_asset(self, asset: Asset) -> None:
        stmt = select(DiscoveredAssetModel).where(
            DiscoveredAssetModel.id == asset.id,
            DiscoveredAssetModel.tenant_id == asset.tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()

        if m is None:
            m = DiscoveredAssetModel(
                id=asset.id,
                tenant_id=asset.tenant_id,
                asset_group_id=asset.asset_group_id,
                scan_target_id=asset.scan_target_id,
                ip_address=asset.ip_address,
                hostname=asset.hostname,
                mac_address=asset.mac_address,
                operating_system=asset.operating_system,
                device_type=asset.device_type,
                manufacturer=asset.manufacturer,
                status=str(asset.status),
                criticality=str(asset.criticality),
                first_seen_at=asset.first_seen_at,
                last_seen_at=asset.last_seen_at,
                last_scanned_at=asset.last_scanned_at,
                zabbix_host_id=asset.zabbix_host_id,
                metadata_json=asset.metadata,
                created_at=asset.created_at,
                updated_at=asset.updated_at,
            )
            self._session.add(m)
        else:
            m.status = str(asset.status)
            m.criticality = str(asset.criticality)
            m.hostname = asset.hostname or m.hostname
            m.mac_address = asset.mac_address or m.mac_address
            m.operating_system = asset.operating_system or m.operating_system
            m.device_type = asset.device_type or m.device_type
            m.manufacturer = asset.manufacturer or m.manufacturer
            m.last_seen_at = asset.last_seen_at
            m.last_scanned_at = asset.last_scanned_at or m.last_scanned_at
            m.zabbix_host_id = asset.zabbix_host_id or m.zabbix_host_id
            m.metadata_json = asset.metadata
            m.updated_at = asset.updated_at

    async def get_asset_by_id(self, asset_id: UUID, tenant_id: UUID) -> Asset | None:
        stmt = select(DiscoveredAssetModel).where(
            DiscoveredAssetModel.id == asset_id,
            DiscoveredAssetModel.tenant_id == tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()
        if not m:
            return None
        return Asset(
            id=m.id,
            tenant_id=m.tenant_id,
            asset_group_id=m.asset_group_id,
            scan_target_id=m.scan_target_id,
            ip_address=m.ip_address,
            hostname=m.hostname,
            mac_address=m.mac_address,
            operating_system=m.operating_system,
            device_type=m.device_type,
            manufacturer=m.manufacturer,
            status=AssetStatus(m.status),
            criticality=AssetCriticality(m.criticality),
            first_seen_at=m.first_seen_at,
            last_seen_at=m.last_seen_at,
            last_scanned_at=m.last_scanned_at,
            zabbix_host_id=m.zabbix_host_id,
            metadata=m.metadata_json or {},
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    async def get_asset_by_ip_and_group(
        self, tenant_id: UUID, asset_group_id: UUID, ip_address: str
    ) -> Asset | None:
        stmt = select(DiscoveredAssetModel).where(
            DiscoveredAssetModel.tenant_id == tenant_id,
            DiscoveredAssetModel.asset_group_id == asset_group_id,
            DiscoveredAssetModel.ip_address == ip_address,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()
        if not m:
            return None
        return Asset(
            id=m.id,
            tenant_id=m.tenant_id,
            asset_group_id=m.asset_group_id,
            scan_target_id=m.scan_target_id,
            ip_address=m.ip_address,
            hostname=m.hostname,
            mac_address=m.mac_address,
            operating_system=m.operating_system,
            device_type=m.device_type,
            manufacturer=m.manufacturer,
            status=AssetStatus(m.status),
            criticality=AssetCriticality(m.criticality),
            first_seen_at=m.first_seen_at,
            last_seen_at=m.last_seen_at,
            last_scanned_at=m.last_scanned_at,
            zabbix_host_id=m.zabbix_host_id,
            metadata=m.metadata_json or {},
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    async def list_assets(
        self,
        tenant_id: UUID,
        asset_group_id: UUID | None = None,
        status: str | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Asset], int]:
        stmt = select(DiscoveredAssetModel).where(DiscoveredAssetModel.tenant_id == tenant_id)
        if asset_group_id:
            stmt = stmt.where(DiscoveredAssetModel.asset_group_id == asset_group_id)
        if status:
            stmt = stmt.where(DiscoveredAssetModel.status == status)
        if search:
            stmt = stmt.where(
                DiscoveredAssetModel.ip_address.ilike(f"%{search}%")
                | DiscoveredAssetModel.hostname.ilike(f"%{search}%")
            )

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_res = await self._session.execute(count_stmt)
        total = total_res.scalar_one() or 0

        stmt = stmt.order_by(DiscoveredAssetModel.last_seen_at.desc()).offset((page - 1) * page_size).limit(page_size)
        res = await self._session.execute(stmt)
        rows = list(res.scalars().all())

        assets = [
            Asset(
                id=m.id,
                tenant_id=m.tenant_id,
                asset_group_id=m.asset_group_id,
                scan_target_id=m.scan_target_id,
                ip_address=m.ip_address,
                hostname=m.hostname,
                mac_address=m.mac_address,
                operating_system=m.operating_system,
                device_type=m.device_type,
                manufacturer=m.manufacturer,
                status=AssetStatus(m.status),
                criticality=AssetCriticality(m.criticality),
                first_seen_at=m.first_seen_at,
                last_seen_at=m.last_seen_at,
                last_scanned_at=m.last_scanned_at,
                zabbix_host_id=m.zabbix_host_id,
                metadata=m.metadata_json or {},
                created_at=m.created_at,
                updated_at=m.updated_at,
            )
            for m in rows
        ]
        return assets, total

    async def save_service(self, service: AssetService) -> None:
        stmt = select(AssetServiceModel).where(
            AssetServiceModel.id == service.id,
            AssetServiceModel.tenant_id == service.tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()

        if m is None:
            m = AssetServiceModel(
                id=service.id,
                tenant_id=service.tenant_id,
                asset_id=service.asset_id,
                port=service.port,
                protocol=str(service.protocol),
                service_name=service.service_name,
                product=service.product,
                version=service.version,
                state=str(service.state),
                banner=service.banner,
                first_seen_at=service.first_seen_at,
                last_seen_at=service.last_seen_at,
                created_at=service.created_at,
                updated_at=service.updated_at,
            )
            self._session.add(m)
        else:
            m.state = str(service.state)
            m.service_name = service.service_name or m.service_name
            m.product = service.product or m.product
            m.version = service.version or m.version
            m.banner = service.banner or m.banner
            m.last_seen_at = service.last_seen_at
            m.updated_at = service.updated_at

    async def list_services(self, asset_id: UUID, tenant_id: UUID) -> list[AssetService]:
        stmt = select(AssetServiceModel).where(
            AssetServiceModel.asset_id == asset_id,
            AssetServiceModel.tenant_id == tenant_id,
        ).order_by(AssetServiceModel.port.asc())
        res = await self._session.execute(stmt)
        s_rows = list(res.scalars().all())

        return [
            AssetService(
                id=m.id,
                tenant_id=m.tenant_id,
                asset_id=m.asset_id,
                port=m.port,
                protocol=ServiceProtocol(m.protocol),
                service_name=m.service_name,
                product=m.product,
                version=m.version,
                state=ServiceState(m.state),
                banner=m.banner,
                first_seen_at=m.first_seen_at,
                last_seen_at=m.last_seen_at,
                created_at=m.created_at,
                updated_at=m.updated_at,
            )
            for m in s_rows
        ]
