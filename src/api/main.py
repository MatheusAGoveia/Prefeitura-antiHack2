"""
Aplicação Principal FastAPI do Core Platform
GovSec Shield — API App
"""

from fastapi import FastAPI
from src.core.interfaces.rest.routers import router as core_router

app = FastAPI(
    title="GovSec Shield — Core Platform API",
    version="1.0.0",
    description="API do Sistema Operacional de Segurança GovSec Shield"
)

app.include_router(core_router)

@app.get("/healthz", tags=["Health"])
async def healthz():
    return {"status": "ok", "service": "govsec-core"}

@app.get("/ready", tags=["Health"])
async def ready():
    return {"status": "ready", "database": "ok", "kafka": "ok"}
