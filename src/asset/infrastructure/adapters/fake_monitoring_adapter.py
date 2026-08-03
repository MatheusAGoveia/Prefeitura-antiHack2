"""
Adaptador Fake em Memória para Integração com Zabbix (MonitoringGateway).
GovSec Shield — Infrastructure Adapter (M3.4)
"""

from typing import Any
from uuid import UUID

from src.asset.domain.discovered_assets import Asset
from src.asset.domain.monitoring import MonitoringGateway
from src.asset.domain.vulnerabilities import VulnerabilityFinding


class FakeMonitoringGateway(MonitoringGateway):
    """Adaptador de testes para simular a API do Zabbix sem requisições de rede."""

    def __init__(self) -> None:
        self.registered_hosts: dict[str, dict[str, Any]] = {}
        self.synced_vulnerabilities: dict[str, str] = {}

    async def find_host_by_ip(self, ip_address: str, tenant_id: UUID) -> dict[str, Any] | None:
        key = f"{tenant_id}:{ip_address}"
        return self.registered_hosts.get(key)

    async def register_or_update_asset(self, asset: Asset, tenant_id: UUID) -> str:
        key = f"{tenant_id}:{asset.ip_address}"
        zabbix_id = f"zabbix-host-{asset.id}"
        self.registered_hosts[key] = {
            "hostid": zabbix_id,
            "host": asset.hostname or asset.ip_address,
            "ip": asset.ip_address,
            "status": asset.status,
        }
        return zabbix_id

    async def update_vulnerability_status(
        self, finding: VulnerabilityFinding, tenant_id: UUID
    ) -> bool:
        key = f"{tenant_id}:{finding.id}"
        self.synced_vulnerabilities[key] = finding.status
        return True
