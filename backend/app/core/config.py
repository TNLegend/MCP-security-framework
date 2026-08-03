from pathlib import Path
from urllib.parse import quote_plus

from pydantic import Field
from pydantic_settings import BaseSettings

REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    app_name: str = "MCP Security Framework Backend"
    app_version: str = "0.1.0"
    environment: str = "local"
    api_prefix: str = "/api/v1"

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "mcp_security"
    postgres_user: str = "mcp_user"
    postgres_password: str = "change_me"

    opa_base_url: str = "http://127.0.0.1:8181"
    opa_decision_path: str = "/v1/data/mcp/security/runtime/decision"
    opa_timeout_seconds: float = Field(default=2.0, gt=0)

    backend_assertion_jwks_path: str = "<configure-outside-repository>"
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

    @property
    def database_url(self) -> str:
        user = quote_plus(self.postgres_user)
        password = quote_plus(self.postgres_password)
        return (
            f"postgresql+psycopg://{user}:"
            f"{password}@{self.postgres_host}:"
            f"{self.postgres_port}/{self.postgres_db}"
        )

    class Config:
        env_file = REPO_ROOT / ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
