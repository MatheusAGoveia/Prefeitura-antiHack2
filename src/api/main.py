"""
Aplicação Principal FastAPI do Core Platform
GovSec Shield — API App
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pathlib import Path
from src.core.interfaces.rest.routers import router as core_router
from src.api.dashboard_api import router as dashboard_router

app = FastAPI(
    title="GovSec Shield — Core Platform API",
    version="1.0.0",
    description="API do Sistema Operacional de Segurança GovSec Shield"
)

app.include_router(core_router)
app.include_router(dashboard_router)

DASHBOARD_HTML_PATH = Path("src/api/static/dashboard.html")

@app.get("/dashboard", response_class=HTMLResponse, tags=["Dev Dashboard"])
async def get_dashboard():
    if DASHBOARD_HTML_PATH.exists():
        return DASHBOARD_HTML_PATH.read_text(encoding="utf-8")
    return "<h1>Dashboard HTML não encontrado</h1>"

@app.get("/healthz", tags=["Health"])
async def healthz():
    return {"status": "ok", "service": "govsec-core"}

@app.get("/ready", tags=["Health"])
async def ready():
    return {"status": "ready", "database": "ok", "kafka": "ok"}

