"""
Roteadores REST FastAPI do Módulo de Ativos e Scanners.
GovSec Shield — Presentation Layer (M3.4)
"""

from src.asset.interfaces.rest.asset_group_routers import router as asset_group_router
from src.asset.interfaces.rest.asset_routers import router as asset_router
from src.asset.interfaces.rest.monitoring_routers import router as monitoring_router
from src.asset.interfaces.rest.scan_execution_routers import router as scan_execution_router
from src.asset.interfaces.rest.scan_schedule_routers import router as scan_schedule_router
from src.asset.interfaces.rest.scan_target_routers import router as scan_target_router
from src.asset.interfaces.rest.scanner_profile_routers import router as scanner_profile_router
from src.asset.interfaces.rest.vulnerability_routers import router as vulnerability_router

__all__ = [
    "asset_group_router",
    "scan_target_router",
    "asset_router",
    "scanner_profile_router",
    "scan_schedule_router",
    "scan_execution_router",
    "vulnerability_router",
    "monitoring_router",
]
