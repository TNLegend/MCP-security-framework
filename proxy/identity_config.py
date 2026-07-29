import os
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _split_csv(value: str, default: tuple[str, ...]) -> tuple[str, ...]:
    items = tuple(item.strip() for item in value.split(",") if item.strip())
    return items or default


@dataclass(frozen=True)
class AgentIdentityConfig:
    provider: str
    issuer: str
    audience: str
    jwks_url: str
    allowed_algorithms: tuple[str, ...]
    accepted_types: tuple[str, ...]
    clock_skew_seconds: int
    http_timeout_seconds: float
    jwks_cache_ttl_seconds: int
    token_max_size_bytes: int = 16384
    environment: str = "local"

    @classmethod
    def from_env(cls) -> "AgentIdentityConfig":
        return cls(
            provider=os.getenv("AGENT_IDENTITY_PROVIDER", "jwt_jwks"),
            issuer=os.getenv("AGENT_IDENTITY_ISSUER", "<configure>"),
            audience=os.getenv("AGENT_IDENTITY_AUDIENCE", "mcp-security-proxy"),
            jwks_url=os.getenv("AGENT_IDENTITY_JWKS_URL", "<configure>"),
            allowed_algorithms=_split_csv(
                os.getenv("AGENT_IDENTITY_ALLOWED_ALGORITHMS", "RS256"),
                ("RS256",),
            ),
            accepted_types=_split_csv(
                os.getenv("AGENT_IDENTITY_ACCEPTED_TYPES", "at+jwt"),
                ("at+jwt",),
            ),
            clock_skew_seconds=int(
                os.getenv("AGENT_IDENTITY_CLOCK_SKEW_SECONDS", "30")
            ),
            http_timeout_seconds=float(
                os.getenv("AGENT_IDENTITY_HTTP_TIMEOUT_SECONDS", "2")
            ),
            jwks_cache_ttl_seconds=int(
                os.getenv("AGENT_IDENTITY_JWKS_CACHE_TTL_SECONDS", "300")
            ),
            token_max_size_bytes=int(
                os.getenv("AGENT_IDENTITY_TOKEN_MAX_SIZE_BYTES", "16384")
            ),
            environment=os.getenv("ENVIRONMENT", "local"),
        )


@dataclass(frozen=True)
class ProxyAssertionConfig:
    issuer: str
    audience: str
    private_key_path: Path
    key_id: str
    ttl_seconds: int = 30
    max_ttl_seconds: int | None = None

    @classmethod
    def from_env(cls) -> "ProxyAssertionConfig":
        return cls(
            issuer=os.getenv("PROXY_ASSERTION_ISSUER", "mcp-security-proxy"),
            audience=os.getenv("PROXY_ASSERTION_AUDIENCE", "mcp-security-backend"),
            private_key_path=Path(
                os.getenv(
                    "PROXY_ASSERTION_PRIVATE_KEY_PATH",
                    "<configure-outside-repository>",
                )
            ),
            key_id=os.getenv("PROXY_ASSERTION_KEY_ID", "<configure>"),
            ttl_seconds=int(
                os.getenv(
                    "PROXY_ASSERTION_TTL_SECONDS",
                    os.getenv("PROXY_ASSERTION_MAX_TTL_SECONDS", "30"),
                )
            ),
        )


@dataclass(frozen=True)
class IdentityBindingConfig:
    path: Path

    @classmethod
    def from_env(cls) -> "IdentityBindingConfig":
        return cls(
            path=Path(
                os.getenv(
                    "AGENT_IDENTITY_BINDINGS_PATH",
                    os.getenv(
                        "IDENTITY_BINDINGS_PATH",
                        str(REPO_ROOT / "policies" / "identity_bindings.yaml"),
                    ),
                )
            )
        )


@dataclass(frozen=True)
class ToolSecurityProfilesConfig:
    path: Path

    @classmethod
    def from_env(cls) -> "ToolSecurityProfilesConfig":
        return cls(
            path=Path(
                os.getenv(
                    "TOOL_SECURITY_PROFILES_PATH",
                    str(REPO_ROOT / "policies" / "tool_security_profiles.yaml"),
                )
            )
        )


@dataclass(frozen=True)
class ResourceScopesConfig:
    path: Path
    max_path_bytes: int
    max_path_segments: int
    allow_unc: bool
    allow_device_paths: bool
    allow_ntfs_ads: bool

    @classmethod
    def from_env(cls) -> "ResourceScopesConfig":
        return cls(
            path=Path(
                os.getenv(
                    "RESOURCE_SCOPES_PATH",
                    str(REPO_ROOT / "policies" / "resource_scopes.yaml"),
                )
            ),
            max_path_bytes=int(os.getenv("RESOURCE_MAX_PATH_BYTES", "4096")),
            max_path_segments=int(os.getenv("RESOURCE_MAX_PATH_SEGMENTS", "256")),
            allow_unc=_env_bool("RESOURCE_ALLOW_UNC", default=False),
            allow_device_paths=_env_bool("RESOURCE_ALLOW_DEVICE_PATHS", default=False),
            allow_ntfs_ads=_env_bool("RESOURCE_ALLOW_NTFS_ADS", default=False),
        )


def _env_bool(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
