from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "MCP Security Framework Backend"
    app_version: str = "0.1.0"
    environment: str = "local"
    api_prefix: str = "/api/v1"

    class Config:
        env_file = "../.env"
        env_file_encoding = "utf-8"


settings = Settings()
