"""
Aplicação Principal FastAPI do Core Platform
GovSec Shield — API App
"""

import asyncio
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from src.api.dashboard_api import router as dashboard_router
from src.api.middleware.auth import AuthenticationMiddleware
from src.api.middleware.recovery import RecoveryMiddleware
from src.core.infrastructure.config import settings
from src.core.infrastructure.db.models import Base
from src.core.infrastructure.db.unit_of_work import engine
from src.core.interfaces.rest.auth_routers import router as auth_router
from src.core.interfaces.rest.incident_routers import router as incident_router
from src.core.interfaces.rest.routers import router as core_router
from src.shared.observability import (
    PrometheusMetricsMiddleware,
    instrument_fastapi,
    liveness_check_handler,
    metrics_endpoint_handler,
    readiness_check_handler,
    setup_structured_logging,
    setup_tracing,
    start_system_metrics_collector,
)

# 1. Inicializar Logs Estruturados JSON (Loki Compliant)
setup_structured_logging()

# 2. Inicializar OpenTelemetry Tracing & Propagação W3C
setup_tracing()


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    """
    Gerencia o ciclo de vida da aplicação FastAPI.
    Inicia e encerra graciosamente o coletor de métricas de sistema.
    """
    # Garantir criação de tabelas se necessário
    with suppress(Exception):
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    # Startup: iniciar coleta periódica de métricas de sistema (CPU, RAM, Disco)
    metrics_task = asyncio.create_task(
        start_system_metrics_collector(interval_seconds=15),
        name="system_metrics_collector",
    )
    try:
        yield
    finally:
        # Shutdown: cancelar o task de coleta de forma limpa
        metrics_task.cancel()
        with suppress(asyncio.CancelledError):
            await metrics_task


app = FastAPI(
    title="GovSec Shield — Core Platform API",
    version="1.0.0",
    description="API do Sistema Operacional de Segurança GovSec Shield",
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    for err in exc.errors():
        loc = err.get("loc", ())
        if "tenant_id" in loc or "tenant" in loc:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": f"Parâmetro tenant_id inválido: {err.get('msg')}"},
            )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()},
    )


# 3. Middlewares em ordem (outermost → innermost):
#    RecoveryMiddleware → CORSMiddleware → PrometheusMetrics → Auth
#
# NOTA: BaseHTTPMiddleware é adicionado na ordem inversa de execução de requisições,
#       ou seja, o último `add_middleware` é o primeiro a executar na request.
app.add_middleware(AuthenticationMiddleware)
app.add_middleware(PrometheusMetricsMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.GOVSEC_CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# RecoveryMiddleware deve ser o mais externo (último a ser adicionado)
app.add_middleware(RecoveryMiddleware)

# 4. Instrumentação Automática de Tracing FastAPI (Spans para toda requisição HTTP)
instrument_fastapi(app)

# 5. Rotas de Aplicação
app.include_router(auth_router)
app.include_router(core_router)
app.include_router(incident_router)
app.include_router(dashboard_router)

# 6. Exposição de Métricas Prometheus, Health Checks e Dashboard Dev
app.add_api_route("/metrics", metrics_endpoint_handler, methods=["GET"], tags=["Observability"])
app.add_api_route("/healthz", liveness_check_handler, methods=["GET"], tags=["Health"])
app.add_api_route("/ready", readiness_check_handler, methods=["GET"], tags=["Health"])

DASHBOARD_HTML_PATH = Path("src/api/static/dashboard.html")


@app.get(
    "/dashboard", response_class=HTMLResponse, response_model=None, tags=["Dev Dashboard"]
)
async def get_dashboard() -> HTMLResponse | str:
    if DASHBOARD_HTML_PATH.exists():
        return DASHBOARD_HTML_PATH.read_text(encoding="utf-8")
    return "<h1>Dashboard HTML não encontrado</h1>"


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("GOVSEC_HOST", "127.0.0.1")
    uvicorn.run("src.api.main:app", host=host, port=8000, reload=True)
