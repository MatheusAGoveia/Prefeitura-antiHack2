from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from src.core.domain.exceptions import (
    AuthenticationProviderUnavailableError,
    InvalidCredentialsError,
    RedisRevocationUnavailableError,
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

DEV_TEST_TENANT_UUID_STR = "00000000-0000-0000-0000-000000000001"
DEV_TEST_TENANT_UUID = UUID(DEV_TEST_TENANT_UUID_STR)


class LoginDTO(BaseModel):
    email: str = Field(..., examples=["admin@govsec.com"])
    password: str = Field(..., examples=["senha123"])
    tenant_id: str | None = Field(default=DEV_TEST_TENANT_UUID_STR, examples=[DEV_TEST_TENANT_UUID_STR])


class DevTokenDTO(BaseModel):
    user_id: str = Field(default="dev_user")
    tenant_id: str = Field(default=DEV_TEST_TENANT_UUID_STR)
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

        # Validação estrita de claims OIDC em staging/produção (Sem fallbacks para payload ou defaults)
        user_id = claims.get("sub")
        raw_tenant_id = claims.get("tenant_id")
        roles = claims.get("roles")

        if not user_id or not isinstance(user_id, str):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Autenticação falhou: Claim 'sub' ausente ou inválido no provedor OIDC.",
            )

        if not raw_tenant_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Autenticação falhou: Claim 'tenant_id' ausente no provedor OIDC.",
            )

        try:
            tenant_id = UUID(str(raw_tenant_id))
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Autenticação falhou: Claim 'tenant_id' retornado pelo provedor OIDC não é um UUID válido.",
            ) from e

        if not roles or not isinstance(roles, list) or len(roles) == 0:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Autenticação falhou: Claim 'roles' ausente ou vazio no provedor OIDC.",
            )
    else:
        # Ambiente dev/test: derivação local para desenvolvimento
        user_id = dto.email.split("@")[0]
        roles = _resolve_roles_for_user(dto.email)
        raw_t = dto.tenant_id
        if raw_t:
            try:
                tenant_id = UUID(raw_t)
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Parâmetro tenant_id '{raw_t}' não é um UUID válido.",
                ) from e
        else:
            tenant_id = DEV_TEST_TENANT_UUID

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

    try:
        dev_tenant_uuid = UUID(dto.tenant_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Parâmetro tenant_id '{dto.tenant_id}' não é um UUID válido.",
        ) from e

    roles = [dto.role]
    access_token = JWTHandler.generate_token(user_id=dto.user_id, tenant_id=dev_tenant_uuid, roles=roles)
    refresh_token = JWTHandler.generate_refresh_token(user_id=dto.user_id, tenant_id=dev_tenant_uuid, roles=roles)

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
    except (RuntimeError, RedisRevocationUnavailableError) as err:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Serviço de revogação temporariamente indisponível.",
        ) from err
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
    except (RuntimeError, RedisRevocationUnavailableError) as err:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Serviço de revogação temporariamente indisponível.",
        ) from err

    return LogoutResponseDTO()
