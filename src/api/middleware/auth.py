"""
Middleware de Autenticação e Inspeção Zero Trust
GovSec Shield — Security Middleware
"""

from collections.abc import Awaitable, Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.infrastructure.security.kernel import SecurityKernel

PUBLIC_PATH_PREFIXES = (
    "/healthz",
    "/ready",
    "/metrics",
    "/dashboard",
    "/api/memoria",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/v1/auth/login",
    "/api/v1/auth/dev-token",
    "/api/v1/auth/token",
    "/api/v1/auth/refresh",
)




class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        path = request.url.path

        # Permite bypass de rotas públicas
        if any(path.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES):
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Cabeçalho Authorization com Bearer token é obrigatório."},
            )

        token = auth_header.split(" ")[1]
        try:
            user = await SecurityKernel.authenticate_async(token)
            request.state.user = user
        except PermissionError as e:

            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": str(e)},
            )

        return await call_next(request)
