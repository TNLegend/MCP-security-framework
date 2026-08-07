from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

RUNTIME_DIR = PROJECT_ROOT / ".runtime"
RUNTIME_MODELS_DIR = RUNTIME_DIR / "models"
RUNTIME_CACHE_DIR = RUNTIME_DIR / "cache"
RUNTIME_TOOLS_DIR = RUNTIME_DIR / "tools"
RUNTIME_TMP_DIR = RUNTIME_DIR / "tmp"
RUNTIME_SECRETS_DIR = RUNTIME_DIR / "secrets"

HF_HOME_DIR = RUNTIME_CACHE_DIR / "huggingface"
MODEL_CACHE_DIR = RUNTIME_MODELS_DIR / "huggingface"
TRANSFORMERS_CACHE_DIR = RUNTIME_CACHE_DIR / "transformers"
SENTENCE_TRANSFORMERS_HOME_DIR = RUNTIME_CACHE_DIR / "sentence-transformers"
TORCH_HOME_DIR = RUNTIME_CACHE_DIR / "torch"
PIP_CACHE_DIR = RUNTIME_CACHE_DIR / "pip"
NPM_CACHE_DIR = RUNTIME_CACHE_DIR / "npm"

OPA_VERSION = "1.18.2"
OPA_SHA256 = "b9022224ee660c87cc35ce957c21c352fa57b267d71fb4e1ce779a38e107c9df"
OPA_DIR = RUNTIME_TOOLS_DIR / "opa"
OPA_EXE = OPA_DIR / "opa.exe"


def runtime_directories() -> tuple[Path, ...]:
    return (
        RUNTIME_DIR,
        RUNTIME_MODELS_DIR,
        RUNTIME_CACHE_DIR,
        HF_HOME_DIR,
        MODEL_CACHE_DIR,
        TRANSFORMERS_CACHE_DIR,
        SENTENCE_TRANSFORMERS_HOME_DIR,
        TORCH_HOME_DIR,
        PIP_CACHE_DIR,
        NPM_CACHE_DIR,
        RUNTIME_TOOLS_DIR,
        OPA_DIR,
        RUNTIME_TMP_DIR,
        RUNTIME_SECRETS_DIR,
    )


def ensure_runtime_directories() -> None:
    for path in runtime_directories():
        path.mkdir(parents=True, exist_ok=True)


def runtime_environment() -> dict[str, str]:
    return {
        "HF_HOME": str(HF_HOME_DIR),
        "HF_HUB_CACHE": str(MODEL_CACHE_DIR),
        "TRANSFORMERS_CACHE": str(TRANSFORMERS_CACHE_DIR),
        "SENTENCE_TRANSFORMERS_HOME": str(SENTENCE_TRANSFORMERS_HOME_DIR),
        "TORCH_HOME": str(TORCH_HOME_DIR),
        "PIP_CACHE_DIR": str(PIP_CACHE_DIR),
        "npm_config_cache": str(NPM_CACHE_DIR),
        "TMPDIR": str(RUNTIME_TMP_DIR),
        "TEMP": str(RUNTIME_TMP_DIR),
        "TMP": str(RUNTIME_TMP_DIR),
    }


def configure_runtime_environment() -> dict[str, str]:
    ensure_runtime_directories()
    env = runtime_environment()
    for name, value in env.items():
        os.environ[name] = value
    return env
