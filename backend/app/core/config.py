import json
import os
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
    # Lab fixture is optional in generic/production installations; opt-in
    # deployments explicitly require its health for readiness.
    readiness_require_mcp_lab: bool = False
    api_prefix: str = "/api/v1"
    backend_host: str = "127.0.0.1"
    backend_port: int = 8000
    frontend_host: str = "127.0.0.1"
    frontend_port: int = Field(default=5173, ge=1, le=65535)
    control_center_public_url: str = ""
    upstream_oauth_callback_url: str = ""
    mcp_gateway_host: str = "127.0.0.1"
    mcp_gateway_port: int = 9001
    agent_identity_jwks_url: str = "<configure>"

    postgres_host: str = "127.0.0.1"
    postgres_port: int = Field(default=55432, ge=1, le=65535)
    postgres_db: str = "mcp_security"
    postgres_user: str = "mcp_user"
    postgres_password: str = "<generate-local>"

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
    local_runtime_start_timeout_seconds: float = Field(default=20.0, gt=0, le=360)
    local_runtime_autostart_opa: bool = True
    local_runtime_autostart_gateway: bool = True
    local_runtime_autostart_identity_provider: bool = True
    local_runtime_managed_postgres_command_json: str = ""
    local_runtime_restart_attempts: int = Field(default=2, ge=0, le=10)
    local_runtime_restart_backoff_seconds: float = Field(default=1.0, ge=0, le=30)
    local_runtime_log_max_bytes: int = Field(default=5_000_000, ge=100_000, le=1_000_000_000)
    local_runtime_log_backup_count: int = Field(default=3, ge=1, le=20)

    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=200)
    database_pool_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    database_pool_recycle_seconds: int = Field(default=1800, ge=60, le=86400)

    runtime_log_retention_days: int = Field(default=30, ge=1, le=3650)
    runtime_log_max_rows: int = Field(default=250_000, ge=1_000, le=10_000_000)
    runtime_log_cleanup_batch_size: int = Field(default=5_000, ge=100, le=100_000)
    runtime_log_auto_cleanup_interval_rows: int = Field(default=1_000, ge=1, le=100_000)
    operations_metrics_window_minutes: int = Field(default=15, ge=1, le=1440)
    runtime_intent_grace_seconds: int = Field(default=120, ge=30, le=3600)

    build_scan_allowed_roots_json: str = "[]"
    build_scan_git_allowed_hosts_json: str = '["github.com","gitlab.com","bitbucket.org"]'
    build_scan_git_timeout_seconds: int = Field(default=300, ge=5, le=1800)
    build_scan_git_max_output_bytes: int = Field(
        default=1_000_000,
        ge=1024,
        le=100_000_000,
    )
    build_scan_max_files: int = Field(default=20_000, ge=1, le=1_000_000)
    build_scan_max_total_bytes: int = Field(
        default=1_000_000_000,
        ge=1_000,
        le=100_000_000_000,
    )
    build_scan_max_file_bytes: int = Field(
        default=100_000_000,
        ge=1,
        le=10_000_000_000,
    )
    build_scan_trivy_db_max_age_hours: int = Field(default=72, ge=1, le=720)

    @field_validator("build_scan_allowed_roots_json")
    @classmethod
    def validate_build_scan_allowed_roots_json(cls, value: str) -> str:
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("build_scan_allowed_roots_json must be valid JSON.") from exc
        if not isinstance(parsed, list):
            raise ValueError("build_scan_allowed_roots_json must be a JSON list.")
        if any(not isinstance(item, str) or not item.strip() for item in parsed):
            raise ValueError("build_scan_allowed_roots_json entries must be non-empty strings.")
        return value

    @field_validator("build_scan_git_allowed_hosts_json")
    @classmethod
    def validate_build_scan_git_allowed_hosts_json(cls, value: str) -> str:
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("build_scan_git_allowed_hosts_json must be valid JSON.") from exc
        if not isinstance(parsed, list) or not parsed:
            raise ValueError("build_scan_git_allowed_hosts_json must be a non-empty JSON list.")
        if any(not isinstance(item, str) or not item.strip() for item in parsed):
            raise ValueError("build_scan_git_allowed_hosts_json entries must be non-empty strings.")
        return value

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
    def build_scan_allowed_roots(self) -> list[Path]:
        values = json.loads(self.build_scan_allowed_roots_json)
        return [resolve_project_path(item) for item in values]

    @property
    def build_scan_git_allowed_hosts(self) -> list[str]:
        return [str(item).strip().lower() for item in json.loads(self.build_scan_git_allowed_hosts_json)]

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

    @property
    def control_center_url(self) -> str:
        configured = self.control_center_public_url.strip().rstrip("/")
        if configured:
            return configured
        return f"http://{self.frontend_host.strip() or '127.0.0.1'}:{self.frontend_port}"

    @property
    def upstream_oauth_callback_uri(self) -> str:
        configured = self.upstream_oauth_callback_url.strip()
        if configured:
            return configured
        host = self.backend_host.strip() or "127.0.0.1"
        return f"http://{host}:{self.backend_port}{self.api_prefix}/control-plane/upstream-oauth/callback"

    class Config:
        env_file = REPO_ROOT / ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


def _settings():
    if not os.environ.get("MCP_FRAMEWORK_QA_ROOT"):
        return Settings()
    # Validate explicit connection inputs before creating an engine, and never
    # read the operational .env in a QA subprocess.
    required = ("POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DB",
                "POSTGRES_USER", "POSTGRES_PASSWORD")
    if any(not os.environ.get(key) for key in required):
        raise ValueError("qa_explicit_database_configuration_required")
    value = Settings(_env_file=None)
    if (value.postgres_host != "127.0.0.1" or value.postgres_port == 55432
            or not value.postgres_user.startswith("tda_step6_")
            or value.postgres_db == "mcp_security"):
        raise ValueError("qa_operational_database_refused")
    return value


settings = _settings()
