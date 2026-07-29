from typing import TYPE_CHECKING

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from src.core.domain.exceptions import (
    AuthenticationProviderUnavailableError,
    InvalidCredentialsError,
)
from src.core.infrastructure.config import settings
from src.core.infrastructure.security.jwt import JWTHandler
from src.core.infrastructure.security.kernel import SecurityKernel
from src.core.infrastructure.security.oidc_provider import (
    DefaultOIDCAuthenticationProvider,
)

if TYPE_CHECKING:
    from src.core.application.interfaces.auth_provider import AuthenticationProviderPort

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


class LoginDTO(BaseModel):
    email: str = Field(..., examples=["admin@govsec.com"])
    password: str = Field(..., examples=["senha123"])
    tenant_id: str | None = Field(default="betim", examples=["betim"])


class DevTokenDTO(BaseModel):
    user_id: str = Field(default="dev_user")
    tenant_id: str = Field(default="betim")
    role: str = Field(default="analyst", description="Role única concedida para dev (viewer, analyst, engineer, security_admin, system_admin)")


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


def _resolve_roles_for_user(email: str) -> list[str]:
    """Mapeia o e-mail do usuário para roles específicas com menor privilégio em dev/test."""
    email_lower = email.lower()
    if email_lower.startswith("admin@") or email_lower.startswith("sysadmin@"):
        return ["system_admin"]
    if email_lower.startswith("security@") or email_lower.startswith("secadmin@"):
        return ["security_admin"]
    if email_lower.startswith("engineer@"):
        return ["engineer"]
    if email_lower.startswith("analyst@") or email_lower.startswith("soc@"):
        return ["analyst"]
    return ["viewer"]


@router.post("/login", response_model=LoginResponseDTO)
async def login(dto: LoginDTO) -> LoginResponseDTO:
    """
    Autentica usuário e retorna Access Token e Refresh Token JWT.
    Em staging/production, delega autenticação ao provider OIDC e utiliza claims retornados.
    """
    if not dto.email or not dto.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email e senha são obrigatórios."
        )

    if settings.GOVSEC_ENV not in ("dev", "test"):
        provider: AuthenticationProviderPort = DefaultOIDCAuthenticationProvider()
        try:
            claims = await provider.authenticate_credentials(dto.email, dto.password, dto.tenant_id)
        except AuthenticationProviderUnavailableError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=str(e)
            ) from e
        except InvalidCredentialsError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)
            ) from e

        # Utilizar claims do provider OIDC ao invés de derivação local
        user_id = claims.get("sub", dto.email.split("@")[0])
        roles = claims.get("roles", ["viewer"])
        tenant_id = claims.get("tenant_id", dto.tenant_id or "betim")
    else:
        # Ambiente dev/test: derivação local de roles a partir do email
        user_id = dto.email.split("@")[0]
        roles = _resolve_roles_for_user(dto.email)
        tenant_id = dto.tenant_id or "betim"

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



@router.post("/dev-token", response_model=LoginResponseDTO)
async def dev_token(dto: DevTokenDTO) -> LoginResponseDTO:
    """
    Endpoint exclusivo de desenvolvimento para obtenção de tokens sintéticos.
    Proibido e desabilitado fora do ambiente `dev`.
    """
    if settings.GOVSEC_ENV != "dev":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Endpoints de token de desenvolvimento estão desabilitados fora do ambiente 'dev'.",
        )

    allowed_roles = {"viewer", "analyst", "engineer", "security_admin", "system_admin"}
    if dto.role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Role '{dto.role}' inválida. Escolha entre {allowed_roles}.",
        )

    roles = [dto.role]
    access_token = JWTHandler.generate_token(user_id=dto.user_id, tenant_id=dto.tenant_id, roles=roles)
    refresh_token = JWTHandler.generate_refresh_token(user_id=dto.user_id, tenant_id=dto.tenant_id, roles=roles)

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
    Totalmente assíncrono — utiliza Redis async para verificação de revogação.
    """
    try:
        new_access_token = await JWTHandler.refresh_token_async(dto.refresh_token)
        return RefreshResponseDTO(access_token=new_access_token, token_type="Bearer", expires_in=28800)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Serviço de revogação temporariamente indisponível: {e}",
        ) from e
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)) from e


@router.post("/logout", response_model=LogoutResponseDTO)
async def logout(authorization: str = Header(..., alias="Authorization")) -> LogoutResponseDTO:
    """
    Revoga o token atual inserindo-o na blacklist do Security Kernel.
    Totalmente assíncrono — utiliza Redis async para persistência da revogação.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header Authorization deve ser do tipo Bearer <token>",
        )

    token = authorization.split(" ")[1]
    try:
        await JWTHandler.blacklist_token_async(token)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Serviço de revogação temporariamente indisponível: {e}",
        ) from e

    return LogoutResponseDTO()

