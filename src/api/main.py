"""
Aplicação Principal FastAPI do Core Platform
GovSec Shield — API App
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from src.api.dashboard_api import router as dashboard_router
from src.api.middleware.auth import AuthenticationMiddleware
from src.core.interfaces.rest.auth_routers import router as auth_router
from src.core.interfaces.rest.routers import router as core_router
from src.shared.observability import (
    PrometheusMetricsMiddleware,
    instrument_fastapi,
    liveness_check_handler,
    metrics_endpoint_handler,
    readiness_check_handler,
    setup_structured_logging,
    setup_tracing,
)

# 1. Inicializar Logs Estruturados JSON (Loki Compliant)
setup_structured_logging()

# 2. Inicializar OpenTelemetry Tracing & Propagação W3C
setup_tracing()

app = FastAPI(
    title="GovSec Shield — Core Platform API",
    version="1.0.0",
    description="API do Sistema Operacional de Segurança GovSec Shield",
)

# 3. Middlewares: CORS, Métricas Prometheus e Autenticação
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(PrometheusMetricsMiddleware)
app.add_middleware(AuthenticationMiddleware)

# 4. Instrumentação Automática de Tracing FastAPI (Spans para toda requisição HTTP)
instrument_fastapi(app)

# 5. Rotas de Aplicação
app.include_router(auth_router)
app.include_router(core_router)
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

    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)
