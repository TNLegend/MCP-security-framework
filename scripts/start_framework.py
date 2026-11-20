from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
VENV_PYTHON = BACKEND_DIR / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

# Bootstrap before importing FastAPI/SQLAlchemy so a new clone can start.
# The internal --ready flag does not bypass model integrity verification.
if __name__ == "__main__" and "--ready" not in sys.argv:
    setup = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "setup_local_environment.py")],
        cwd=REPO_ROOT, check=False,
    )
    if setup.returncode:
        raise SystemExit(setup.returncode)
    if not VENV_PYTHON.is_file():
        raise SystemExit("BOOTSTRAP_DID_NOT_CREATE_BACKEND_VENV")
    raise SystemExit(subprocess.call(
        [str(VENV_PYTHON), str(Path(__file__).resolve()), "--ready"],
        cwd=REPO_ROOT,
    ))

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from app.core.runtime_paths import configure_runtime_environment  # noqa: E402
from app.db.init_db import init_db  # noqa: E402
from app.services.cloud_deploy_history import local_policy_sha256  # noqa: E402
from common.project_environment import load_project_environment  # noqa: E402

load_project_environment()

from app.core.config import settings  # noqa: E402
from app.services.local_runtime_manager import LocalRuntimeManager  # noqa: E402


def _opa_remote_bundle_matches_manifest(base_url: str) -> bool:
    """Verify exact loaded Rego source bytes against the pinned local manifest.

    OPA's /v1/policies endpoint exposes the raw source for every loaded module.
    Any extra/missing module or byte-level drift rejects the deployment.
    A privileged subsequent hot update remains outside this startup check.
    """
    import hashlib

    try:
        manifest_path = REPO_ROOT / "policies" / "opa" / "deploy_bundle_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest.get("policy_sha256")
        if (manifest.get("format") != "deploy-opa-local-bundle-v1"
                or not isinstance(expected, dict)
                or set(expected) != {"runtime_policy.rego", "deploy_security.rego"}):
            return False
        with urllib.request.urlopen(
            base_url.rstrip("/") + "/v1/policies", timeout=5
        ) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            return False
        listing = json.loads(raw.decode("utf-8"))
        policies = listing.get("result") if isinstance(listing, dict) else None
        if not isinstance(policies, list) or len(policies) != len(expected):
            return False
        observed: dict[str, str] = {}
        for entry in policies:
            if not isinstance(entry, dict):
                return False
            module_id, source = entry.get("id"), entry.get("raw")
            if not isinstance(module_id, str) or not isinstance(source, str):
                return False
            filename = module_id.replace("\\", "/").split("/")[-1]
            if filename in observed or filename not in expected:
                return False
            observed[filename] = hashlib.sha256(source.encode("utf-8")).hexdigest()
        return observed == expected
    except (OSError, urllib.error.URLError, TimeoutError, ValueError,
            UnicodeError, TypeError, AttributeError):
        return False


def _opa_dual_policy_ready(base_url: str) -> bool:
    """A healthy OPA listener without Deploy policy must NOT be reused as ready."""
    endpoints = (
        ("/v1/data/mcp/security/runtime/decision", "runtime"),
        ("/v1/data/mcp/security/deploy/decision", "deploy"),
    )
    for suffix, kind in endpoints:
        try:
            request = urllib.request.Request(
                base_url.rstrip("/") + suffix,
                method="POST",
                data=b'{"input":{}}',
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=4) as response:
                raw = response.read(65537)
            if len(raw) > 65536:
                return False
            payload = json.loads(raw.decode("utf-8"))
            result = payload.get("result") if isinstance(payload, dict) else None
            if not isinstance(result, dict):
                return False
            if kind == "runtime" and (
                result.get("policy_revision") != "opa-runtime-v2"
                or result.get("decision") != "BLOCK"
                or result.get("effect") != "DENY"
                or not isinstance(result.get("rule_ids"), list)
                or not result["rule_ids"]
            ):
                return False
            if kind == "deploy" and (
                result.get("policy_revision") != "opa-deploy-security-advisory-v1"
                or result.get("classification") != "EVIDENCE_INCOMPLETE"
                or result.get("runtime_enforcement") is not False
                or result.get("effective_aws_authorization_proven") is not False
                or result.get("obligations") != ["REVIEW_EVIDENCE", "LOG"]
            ):
                return False
        except (urllib.error.URLError, OSError, TimeoutError,
                ValueError, UnicodeError, TypeError, AttributeError):
            return False
    return True


def main() -> int:
    configure_runtime_environment()
    python = VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable)
    manager = LocalRuntimeManager(python_executable=python)
    interrupted = False

    def _signal_handler(signum, frame):  # noqa: ANN001
        nonlocal interrupted
        interrupted = True
        raise KeyboardInterrupt

    previous_sigint = signal.signal(signal.SIGINT, _signal_handler)
    try:
        database = manager.ensure_database(auto_start=True)
        if database.status != "healthy":
            print(json.dumps({"ready": False, "database": database.as_dict()}, indent=2))
            return 1
        try:
            local_policy_sha256()  # Verify pinned local Runtime + Deploy policy hashes.
        except (OSError, ValueError, KeyError):
            print(json.dumps({"ready": False,
                              "error": "opa_local_policy_bundle_integrity_failed"}, indent=2))
            return 1

        opa = manager.ensure_opa(auto_start=True)
        if opa.status != "healthy":
            print(json.dumps({"ready": False, "opa": opa.as_dict()}, indent=2))
            return 1
        if not _opa_dual_policy_ready(settings.opa_base_url):
            print(json.dumps({"ready": False, "error": "opa_runtime_or_deploy_policy_missing"}, indent=2))
            return 1
        if not _opa_remote_bundle_matches_manifest(settings.opa_base_url):
            print(json.dumps({"ready": False, "error": "opa_remote_policy_bundle_mismatch"}, indent=2))
            return 1

        # Only migrate after verifying both policies. A Runtime-only reused
        # OPA must never trigger a partial Deploy rollout.
        init_db()

        identity_provider = manager.ensure_identity_provider(
            auto_start=settings.local_runtime_autostart_identity_provider
        )
        if identity_provider.status != "healthy":
            print(
                json.dumps(
                    {"ready": False, "identity_provider": identity_provider.as_dict()},
                    indent=2,
                )
            )
            return 1

        mcp_lab = manager.ensure_mcp_lab(auto_start=True)
        if mcp_lab.status != "healthy":
            print(json.dumps({"ready": False, "mcp_lab": mcp_lab.as_dict()}, indent=2))
            return 1

        backend = manager.start_backend()
        if backend.status != "healthy":
            print(json.dumps({"ready": False, "backend": backend.as_dict()}, indent=2))
            return 1

        gateway = manager.ensure_gateway(auto_start=True)
        frontend_ensure = getattr(manager, "ensure_frontend", None)
        frontend = frontend_ensure(auto_start=True) if callable(frontend_ensure) else None
        status = manager.status()
        status_payload = status.as_dict()
        status_payload["mcp_lab"] = mcp_lab.as_dict()
        if frontend is not None:
            status_payload["frontend"] = frontend.as_dict()
        frontend_ready = frontend is None or frontend.status == "healthy"
        status_payload["ready"] = (
            status.ready and mcp_lab.status == "healthy" and frontend_ready
        )
        print(json.dumps(status_payload, indent=2))
        if gateway.status != "healthy" or not status_payload["ready"]:
            return 1

        print("Framework ready. Press Ctrl+C to stop processes started by this launcher.")
        while not interrupted:
            failure = manager.required_child_failure()
            if failure is not None:
                print(
                    json.dumps(
                        {
                            "ready": False,
                            "error": "framework_owned_child_exited",
                            **failure,
                        },
                        indent=2,
                    ),
                    file=sys.stderr,
                )
                recover = getattr(manager, "recover_required_child", None)
                if callable(recover) and recover(failure):
                    print(
                        json.dumps(
                            {
                                "ready": True,
                                "recovered_component": failure.get("component"),
                                "restart_attempt": manager.restart_counts.get(
                                    str(failure.get("component") or ""),
                                    0,
                                ),
                            },
                            indent=2,
                        )
                    )
                    continue
                return 1
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        manager.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
