from pathlib import Path
from urllib.parse import quote_plus

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
