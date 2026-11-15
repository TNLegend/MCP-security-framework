from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

from common.project_paths import PROJECT_ROOT, resolve_project_path


PROJECT_PATH_ENV_NAMES = (
    "AGENT_IDENTITY_BINDINGS_PATH",
    "AGENT_IDENTITY_PUBLIC_JWKS_PATH",
    "AGENT_IDENTITY_SIGNING_PRIVATE_KEY_PATH",
    "BACKEND_ASSERTION_JWKS_PATH",
    "IDENTITY_BINDINGS_PATH",
    "INTERNAL_SERVICE_PUBLIC_KEYS_PATH",
    "MCP_DISCOVERY_SERVICE_PRIVATE_KEY_PATH",
    "MCP_PROXY_SERVICE_PRIVATE_KEY_PATH",
    "PROXY_ASSERTION_PRIVATE_KEY_PATH",
    "RESOURCE_ROOT_LEGAL_CONTRACTS",
    "RESOURCE_ROOT_PROJECT_WORKSPACE",
    "RESOURCE_ROOT_USER_DOCUMENTS",
    "TRUSTED_ADAPTER_DIRECTORY",
)


def load_project_environment(
    env_path: Path | None = None,
    *,
    project_root: Path = PROJECT_ROOT,
    override: bool = False,
) -> bool:
    if os.environ.get("MCP_FRAMEWORK_QA_ROOT"):
        # Never load the source .env in a QA process, including Proxy entrypoints.
        if env_path is None:
            normalize_project_environment_paths(project_root=project_root)
            return False
        qa_session=Path(os.environ["MCP_FRAMEWORK_QA_ROOT"]).resolve().parent
        if not Path(env_path).resolve().is_relative_to(qa_session):
            raise ValueError("qa_env_file_outside_session_refused")
    selected_path = env_path or project_root / ".env"
    loaded = load_dotenv(dotenv_path=selected_path, override=override)
    normalize_project_environment_paths(project_root=project_root)
    return loaded


def normalize_project_environment_paths(
    *,
    project_root: Path = PROJECT_ROOT,
) -> None:
    for name in PROJECT_PATH_ENV_NAMES:
        value = os.getenv(name)
        if not value or _is_placeholder(value):
            continue
        os.environ[name] = str(resolve_project_path(value, project_root=project_root))


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith("<") and stripped.endswith(">")
