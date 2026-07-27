from pathlib import Path
from enum import Enum
from urllib.parse import quote_plus

from pydantic import Field
from pydantic_settings import BaseSettings

REPO_ROOT = Path(__file__).resolve().parents[3]


class PolicyEngineMode(str, Enum):
    LEGACY = "legacy"
    SHADOW = "shadow"
    OPA = "opa"


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

    policy_engine_mode: PolicyEngineMode = PolicyEngineMode.LEGACY
    opa_base_url: str = "http://127.0.0.1:8181"
    opa_decision_path: str = "/v1/data/mcp/security/runtime/decision"
    opa_timeout_seconds: float = Field(default=2.0, gt=0)

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
