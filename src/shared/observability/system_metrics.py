"""
Métricas de Sistema com psutil
GovSec Shield — Shared Observability

Coleta periódica e assíncrona de métricas de infraestrutura (CPU, memória,
disco e file descriptors) para exposição ao Prometheus e visualização no Grafana.

Arquitetura:
    - `SystemMetricsCollector`: responsável pela coleta e atualização de Gauges
    - `start_system_metrics_collector`: corrotina de loop periódico assíncrona
    - Integrado ao `lifespan` do FastAPI para inicialização limpa e cancelamento no shutdown
"""

import asyncio
import logging
import os
from typing import Any

import psutil  # type: ignore[import-untyped]
from prometheus_client import REGISTRY, Gauge

logger = logging.getLogger("govsec.observability.system_metrics")

# ─── Prometheus Gauges ────────────────────────────────────────────────────────

SYSTEM_CPU_USAGE_PERCENT = Gauge(
    "system_cpu_usage_percent",
    "Percentual de uso da CPU do host (intervalo de 1 segundo)",
    registry=REGISTRY,
)

SYSTEM_MEMORY_USED_BYTES = Gauge(
    "system_memory_used_bytes",
    "Memória RAM utilizada em bytes",
    registry=REGISTRY,
)

SYSTEM_MEMORY_TOTAL_BYTES = Gauge(
    "system_memory_total_bytes",
    "Memória RAM total disponível em bytes",
    registry=REGISTRY,
)

SYSTEM_DISK_USED_BYTES = Gauge(
    "system_disk_used_bytes",
    "Espaço em disco utilizado em bytes (partição raiz)",
    registry=REGISTRY,
)

SYSTEM_DISK_TOTAL_BYTES = Gauge(
    "system_disk_total_bytes",
    "Espaço em disco total em bytes (partição raiz)",
    registry=REGISTRY,
)

PROCESS_OPEN_FILE_DESCRIPTORS = Gauge(
    "process_open_file_descriptors",
    "Número de file descriptors abertos pelo processo atual",
    registry=REGISTRY,
)


class SystemMetricsCollector:
    """
    Coletor de métricas de infraestrutura do host e do processo.

    Utiliza `psutil` para leitura de métricas de baixo nível e atualiza os
    Gauges do Prometheus registrados globalmente.

    Design:
        - Operação stateless: cada chamada a `collect()` é independente
        - Tratamento de erros isolado por categoria de métrica (falha parcial não
          compromete coleta das demais)
        - Compatível com ambientes containerizados (leitura de `/proc` quando disponível)
    """

    def collect(self) -> dict[str, Any]:
        """
        Realiza a coleta de métricas do sistema e atualiza os Gauges do Prometheus.

        Returns:
            Dicionário com as métricas coletadas (útil para testes e healthchecks).
        """
        metrics: dict[str, Any] = {}

        # CPU
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            SYSTEM_CPU_USAGE_PERCENT.set(cpu_percent)
            metrics["cpu_percent"] = cpu_percent
        except Exception as exc:
            logger.warning("Falha ao coletar métrica CPU: %s", exc)
            metrics["cpu_percent"] = None

        # Memória RAM
        try:
            mem = psutil.virtual_memory()
            SYSTEM_MEMORY_USED_BYTES.set(mem.used)
            SYSTEM_MEMORY_TOTAL_BYTES.set(mem.total)
            metrics["memory_used_bytes"] = mem.used
            metrics["memory_total_bytes"] = mem.total
            metrics["memory_percent"] = mem.percent
        except Exception as exc:
            logger.warning("Falha ao coletar métrica de memória: %s", exc)
            metrics["memory_used_bytes"] = None

        # Disco (partição raiz)
        try:
            disk = psutil.disk_usage("/")
            SYSTEM_DISK_USED_BYTES.set(disk.used)
            SYSTEM_DISK_TOTAL_BYTES.set(disk.total)
            metrics["disk_used_bytes"] = disk.used
            metrics["disk_total_bytes"] = disk.total
            metrics["disk_percent"] = disk.percent
        except Exception as exc:
            logger.warning("Falha ao coletar métrica de disco: %s", exc)
            metrics["disk_used_bytes"] = None

        # File Descriptors do processo atual
        try:
            proc = psutil.Process(os.getpid())
            # `num_fds` não está disponível no Windows — fallback seguro
            fd_count = proc.num_fds() if hasattr(proc, "num_fds") else len(proc.open_files())
            PROCESS_OPEN_FILE_DESCRIPTORS.set(fd_count)
            metrics["open_file_descriptors"] = fd_count
        except Exception as exc:
            logger.warning("Falha ao coletar file descriptors: %s", exc)
            metrics["open_file_descriptors"] = None

        return metrics


async def start_system_metrics_collector(
    collector: SystemMetricsCollector | None = None,
    interval_seconds: int = 15,
) -> None:
    """
    Corrotina de coleta periódica de métricas de sistema.

    Deve ser executada como `asyncio.Task` dentro do `lifespan` da aplicação FastAPI.
    Captura `asyncio.CancelledError` de forma limpa para desligamento gracioso.

    Args:
        collector: Instância do `SystemMetricsCollector`. Se `None`, cria uma nova.
        interval_seconds: Intervalo em segundos entre cada coleta (padrão: 15s).
    """
    _collector = collector or SystemMetricsCollector()
    logger.info(
        "SystemMetricsCollector iniciado | interval=%ds",
        interval_seconds,
        extra={"correlation_id": "system", "tenant": "global"},
    )

    # Coleta inicial imediata antes do primeiro sleep
    _collector.collect()

    try:
        while True:
            await asyncio.sleep(interval_seconds)
            _collector.collect()
    except asyncio.CancelledError:
        logger.info(
            "SystemMetricsCollector encerrado graciosamente.",
            extra={"correlation_id": "system", "tenant": "global"},
        )
