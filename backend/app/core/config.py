from pathlib import Path
from urllib.parse import quote_plus

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

from app.core.runtime_paths import RUNTIME_SECRETS_DIR
from common.project_paths import resolve_project_path

REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    app_name: str = "MCP Security Framework Backend"
    app_version: str = "0.1.0"
    environment: str = "local"
    api_prefix: str = "/api/v1"
    backend_host: str = "127.0.0.1"
    backend_port: int = 8000
    frontend_host: str = "127.0.0.1"
    frontend_port: int = Field(default=5173, ge=1, le=65535)
    mcp_gateway_host: str = "127.0.0.1"
    mcp_gateway_port: int = 9001
    agent_identity_jwks_url: str = "<configure>"

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "mcp_security"
    postgres_user: str = "mcp_user"
    postgres_password: str = "change_me"

    opa_base_url: str = "http://127.0.0.1:8181"
    opa_decision_path: str = "/v1/data/mcp/security/runtime/decision"
    opa_timeout_seconds: float = Field(default=2.0, gt=0)

    backend_assertion_jwks_path: str = str(
        RUNTIME_SECRETS_DIR / "proxy-assertion-public-jwks.json"
    )
    backend_assertion_expected_issuer: str = "mcp-security-proxy"
    backend_assertion_expected_audience: str = "mcp-security-backend"
    backend_assertion_max_ttl_seconds: int = Field(default=30, gt=0, le=300)
    backend_assertion_clock_skew_seconds: int = Field(default=5, ge=0, le=60)

    trusted_session_enabled: bool = True
    trusted_session_ttl_seconds: int = Field(default=3600, gt=0, le=86400)
    trusted_session_idle_timeout_seconds: int = Field(default=900, gt=0, le=86400)
    trusted_session_token_bytes: int = Field(default=32, ge=16, le=128)
    trusted_session_token_pepper: str = "<configure-secret-pepper>"
    trusted_session_max_active_per_agent: int = Field(default=20, gt=0, le=1000)
    trusted_session_cleanup_batch_size: int = Field(default=100, gt=0, le=10000)

    control_plane_session_cookie_name: str = "mcp_control_plane_session"
    control_plane_csrf_cookie_name: str = "mcp_control_plane_csrf"
    control_plane_csrf_header_name: str = "x-csrf-token"
    control_plane_session_ttl_seconds: int = Field(default=28800, gt=0, le=604800)
    control_plane_session_token_bytes: int = Field(default=32, ge=16, le=128)
    control_plane_cookie_secure: bool = False
    control_plane_cookie_samesite: str = "lax"

    internal_service_public_keys_path: str = str(
        RUNTIME_SECRETS_DIR / "internal-service-public-keys.json"
    )
    internal_service_timestamp_window_seconds: int = Field(default=60, gt=0, le=300)
    mcp_proxy_service_id: str = "MCP_PROXY"
    mcp_proxy_service_key_id: str = "mcp-proxy-local"
    mcp_proxy_service_private_key_path: str = str(
        RUNTIME_SECRETS_DIR / "mcp-proxy-service-ed25519.pem"
    )
    mcp_discovery_service_id: str = "MCP_DISCOVERY"
    mcp_discovery_service_key_id: str = "mcp-discovery-local"
    mcp_discovery_service_private_key_path: str = str(
        RUNTIME_SECRETS_DIR / "mcp-discovery-service-ed25519.pem"
    )
    mcp_gateway_allowed_origins: str = ""
    mcp_protocol_rediscovery_interval_seconds: int = Field(
        default=900,
        ge=60,
        le=86400,
    )
    local_runtime_start_timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    local_runtime_autostart_opa: bool = True
    local_runtime_autostart_gateway: bool = True
    local_runtime_autostart_identity_provider: bool = True
    local_runtime_managed_postgres_command_json: str = ""

    @field_validator(
        "backend_assertion_jwks_path",
        "internal_service_public_keys_path",
        "mcp_proxy_service_private_key_path",
        "mcp_discovery_service_private_key_path",
        mode="before",
    )
    @classmethod
    def resolve_project_owned_path(cls, value: object) -> object:
        if not isinstance(value, (str, Path)):
            return value
        raw = str(value).strip()
        if raw.startswith("<") and raw.endswith(">"):
            return raw
        return str(resolve_project_path(raw))

    @property
    def database_url(self) -> str:
        user = quote_plus(self.postgres_user)
        password = quote_plus(self.postgres_password)
        return (
            f"postgresql+psycopg://{user}:"
            f"{password}@{self.postgres_host}:"
            f"{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def control_center_cors_origins(self) -> list[str]:
        host = self.frontend_host.strip() or "127.0.0.1"
        aliases = [host]
        if host in {"127.0.0.1", "localhost", "0.0.0.0"}:
            aliases = ["127.0.0.1", "localhost"]
        origins: list[str] = []
        for alias in aliases:
            origin = f"http://{alias}:{self.frontend_port}"
            if origin not in origins:
                origins.append(origin)
        return origins

    class Config:
        env_file = REPO_ROOT / ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
