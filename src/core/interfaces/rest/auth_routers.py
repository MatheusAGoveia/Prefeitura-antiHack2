"""
Rotas FastAPI para Autenticação e Gestão de Sessões
GovSec Shield — Auth Routers
"""

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from src.core.infrastructure.security.jwt import JWTHandler
from src.core.infrastructure.security.kernel import SecurityKernel

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


class LoginDTO(BaseModel):
    email: str = Field(..., examples=["admin@govsec.com"])
    password: str = Field(..., examples=["senha123"])


class LoginResponseDTO(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 28800


class RefreshTokenDTO(BaseModel):
    refresh_token: str = Field(...)


class RefreshResponseDTO(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 28800


class LogoutResponseDTO(BaseModel):
    message: str = "Logout realizado com sucesso. Token revogado."


@router.post("/login", response_model=LoginResponseDTO)
async def login(dto: LoginDTO) -> LoginResponseDTO:
    """
    Autentica usuário e retorna Access Token e Refresh Token JWT.
    """
    # Credenciais simuladas/desenvolvimento ou validação de hash
    if not dto.email or not dto.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email e senha são obrigatórios."
        )

    # Identificar tenant e papeis a partir do email de administração
    user_id = dto.email.split("@")[0]
    roles = ["system_admin", "security_admin", "engineer", "analyst", "viewer"]
    tenant_id = "betim"

    access_token = JWTHandler.generate_token(user_id=user_id, tenant_id=tenant_id, roles=roles)
    refresh_token = JWTHandler.generate_refresh_token(user_id=user_id, tenant_id=tenant_id, roles=roles)

    SecurityKernel.audit(
        user={"user_id": user_id, "tenant_id": tenant_id},
        action="LOGIN",
        resource="auth",
        success=True,
    )

    return LoginResponseDTO(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
        expires_in=28800,
    )


@router.post("/refresh", response_model=RefreshResponseDTO)
async def refresh(dto: RefreshTokenDTO) -> RefreshResponseDTO:
    """
    Emite novo Access Token a partir de um Refresh Token válido.
    """
    try:
        new_access_token = JWTHandler.refresh_token(dto.refresh_token)
        return RefreshResponseDTO(access_token=new_access_token, token_type="Bearer", expires_in=28800)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)) from e


@router.post("/logout", response_model=LogoutResponseDTO)
async def logout(authorization: str = Header(..., alias="Authorization")) -> LogoutResponseDTO:
    """
    Revoga o token atual inserindo-o na blacklist do Security Kernel.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header Authorization deve ser do tipo Bearer <token>",
        )

    token = authorization.split(" ")[1]
    JWTHandler.blacklist_token(token)

    return LogoutResponseDTO()
