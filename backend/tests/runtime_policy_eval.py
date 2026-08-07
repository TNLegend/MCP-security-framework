import json
import shutil
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

from app.core.runtime_paths import OPA_EXE
from app.schemas.policy_decision import PolicyDecision

REPO_ROOT = Path(__file__).resolve().parents[2]
OPA_POLICY_DIR = REPO_ROOT / "policies" / "opa"
LOCAL_OPA = OPA_EXE


def evaluate_runtime_policy_with_opa_cli(context: dict) -> dict:
    cache_key = json.dumps(context, sort_keys=True, separators=(",", ":"))
    return _evaluate_runtime_policy_cached(cache_key)


@lru_cache(maxsize=256)
def _evaluate_runtime_policy_cached(cache_key: str) -> dict:
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        encoding="utf-8",
        delete=False,
    ) as input_file:
        input_path = Path(input_file.name)
        input_file.write(cache_key)

    try:
        completed = subprocess.run(
            [
                _opa_executable(),
                "eval",
                "--format",
                "json",
                "--data",
                str(OPA_POLICY_DIR),
                "--input",
                str(input_path),
                "data.mcp.security.runtime.decision",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        input_path.unlink(missing_ok=True)

    payload = json.loads(completed.stdout)
    decision = payload["result"][0]["expressions"][0]["value"]
    return PolicyDecision.model_validate(decision).model_dump(mode="json")


def _opa_executable() -> str:
    if LOCAL_OPA.exists():
        return str(LOCAL_OPA)
    opa = shutil.which("opa")
    if opa is not None:
        return opa
    return "opa"
