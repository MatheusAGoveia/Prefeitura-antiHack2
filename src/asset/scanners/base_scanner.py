"""
Classe Abstrata Base para Scanners (BaseScanner)
GovSec Shield — Asset Discovery Module
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ScanTarget(BaseModel):
    """Modelo de dados do alvo do escaneamento."""

    target_ip: str
    ports: list[int] = Field(default_factory=lambda: [80, 443, 22, 21, 3306, 5432, 8080])
    timeout: float = Field(default=2.0, ge=0.1, le=30.0)


class ScanResult(BaseModel):
    """Resultado canônico padronizado de uma varredura."""

    scan_id: UUID = Field(default_factory=uuid4)
    target_ip: str
    port: int
    protocol: str = "TCP"
    is_open: bool
    service_name: str | None = None
    banner: str | None = None
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BaseScanner(ABC):
    """
    Classe abstrata base para todos os Scanners TCP/UDP no GovSec Shield.
    Exige Type Hints estritos e implementação síncrona/assíncrona padronizada.
    """

    def __init__(self, target: ScanTarget) -> None:
        self.target = target

    @abstractmethod
    async def execute_scan(self) -> list[ScanResult]:
        """
        Executa a varredura assíncrona contra o alvo especificado.

        Returns:
            List[ScanResult]: Lista de resultados padronizados das portas escaneadas.
        """
        pass

    @abstractmethod
    async def grab_banner(self, ip: str, port: int) -> str | None:
        """
        Realiza a coleta de banner (Banner Grabbing) na porta conectada.

        Args:
            ip (str): IP do host alvo.
            port (int): Porta conectada.

        Returns:
            Optional[str]: Banner retornado pelo serviço ou None.
        """
        pass
