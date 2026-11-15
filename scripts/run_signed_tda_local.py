"""Start only an independently owner-signed M4 V19 analyzer installation.

No implicit initial activation, privilege grants or schema migrations. This
operational launcher is deliberately separate from the signed inference source
closure. Its only authority is the existing signed manifest and the current
analyzer_authority row; the API and Gateway independently verify both.

Usage:
  python scripts/run_signed_tda_local.py check
  python scripts/run_signed_tda_local.py smoke
  python scripts/run_signed_tda_local.py serve

Private signing keys and ADMIN passwords are never opened by this launcher.
This launcher never signs manifests or activates analyzer authority itself.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
for path in (str(BACKEND), str(ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from app.services.tda.configuration import ANALYZER_REVISION
EXPECTED_REVISION = ANALYZER_REVISION
EXPECTED_IDENTITY = ""

PG_CTL = ROOT / ".runtime/tools/postgresql/pgsql/bin/pg_ctl.exe"
PG_DATA = ROOT / ".runtime/postgres/data"
PG_LOG = ROOT / ".runtime/postgres/postgres.log"


class OperationalGateError(RuntimeError):
    pass


def refuse(message: str) -> None:
    raise OperationalGateError(message)


def local_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def pg_command(arguments: list[str]) -> int:
    if not PG_CTL.is_file() or not PG_DATA.is_dir():
        refuse("original_pgctl_or_cluster_unavailable")
    pgctl_log = ROOT / ".runtime/tmp/tda_signed_pgctl.log"
    pgctl_log.parent.mkdir(parents=True, exist_ok=True)
    with pgctl_log.open("ab") as f:
        result = subprocess.run(
            [str(PG_CTL), "-D", str(PG_DATA), *arguments],
            stdout=f,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=75,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    return result.returncode


def signed_environment(args: argparse.Namespace) -> dict[str, str]:
    """Load only externally owner-signed V2 identities, never V1 bindings.

    The owner-approved pipeline digest and public-key fingerprint must be
    independently pinned through the launch environment.
    """
    import re
    from app.services.tda_application.pipeline import configured_pipeline, digest

    global EXPECTED_IDENTITY
    EXPECTED_IDENTITY = os.environ.get("M4_V19_APPROVED_PIPELINE_SHA256", "").strip()
    trusted_pub_digest = os.environ.get("M4_V19_OWNER_PUBLIC_KEY_SHA256", "").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", EXPECTED_IDENTITY):
        refuse("owner_approved_v2_pipeline_identity_pin_required")
    if not re.fullmatch(r"[0-9a-f]{64}", trusted_pub_digest):
        refuse("independently_trusted_owner_public_key_pin_required")

    prep = Path(args.preparation).expanduser().resolve(strict=True)
    owner_dir = Path(args.owner_keystore).expanduser().resolve(strict=True)
    signed_dir = Path(args.signed_output).expanduser().resolve(strict=True)
    bundle = Path(args.m4_bundle).expanduser().resolve(strict=True)
    model_manifest = prep / "M4_MODEL_MANIFEST_UNSIGNED.json"
    pipeline_manifest = prep / "M4_ANALYZER_V2_MANIFEST_UNSIGNED.json"
    owner_pub = owner_dir / "tda-owner-deployment-ed25519-public.pem"
    model_sig = signed_dir / "m4-model-signature.base64"
    pipeline_sig = signed_dir / "tda-owner-signature.base64"
    approval_path = signed_dir / "tda-owner-approval.json"

    files = (model_manifest, pipeline_manifest, owner_pub, model_sig,
             pipeline_sig, approval_path)
    for path in files:
        if not path.is_file():
            refuse("required_v19_signed_artifact_unavailable:" + path.name)

    if hashlib.sha256(owner_pub.read_bytes()).hexdigest() != trusted_pub_digest:
        refuse("owner_public_key_not_independently_trusted")

    approval = json.loads(approval_path.read_text("utf8"))
    m4 = json.loads(model_manifest.read_text("utf8"))
    main = json.loads(pipeline_manifest.read_text("utf8"))
    if (
        approval.get("status") != "OWNER_SIGNED_NOT_ACTIVATED"
        or approval.get("analyzer_revision") != EXPECTED_REVISION
        or approval.get("manifest_identity") != EXPECTED_IDENTITY
        or approval.get("model_manifest_identity") != digest(m4)
        or approval.get("signer_public_key_sha256") != trusted_pub_digest
        or main.get("schema") != "verified_m4_analyzer_pipeline_v2"
        or main.get("m4_signed_identity_sha256") != digest(m4)
    ):
        refuse("owner_approval_not_bound_to_v19_model_and_analyzer")
    if digest(main) != EXPECTED_IDENTITY:
        refuse("owner_approved_digest_not_equal_to_manifest")

    def b64_signature(path):
        value=path.read_text("ascii").strip()
        try:
            if len(base64.b64decode(value,validate=True)) != 64:
                refuse("invalid_ed25519_signature_length")
        except (ValueError,base64.binascii.Error) as exc:
            raise OperationalGateError("invalid_ed25519_signature_encoding") from exc
        return value

    if os.environ.get("ANALYZER_PIPELINE_BINDINGS"):
        refuse("old_v1_model_bindings_not_supported")
    os.environ.update({
        "ANALYZER_M4_V2_ENABLED": "1",
        "M4_SEMANTICS_MODEL_ROOT": str(bundle),
        "M4_SEMANTICS_IDENTITY_MANIFEST": str(model_manifest),
        "M4_SEMANTICS_APPROVED_SHA256": digest(m4),
        "M4_SEMANTICS_TRUST_KEY": str(owner_pub),
        "M4_SEMANTICS_SIGNATURE": b64_signature(model_sig),
        "ANALYZER_PIPELINE_MANIFEST": str(pipeline_manifest),
        "ANALYZER_PIPELINE_APPROVED_SHA256": EXPECTED_IDENTITY,
        "ANALYZER_PIPELINE_TRUST_KEY": str(owner_pub),
        "ANALYZER_PIPELINE_SIGNATURE": b64_signature(pipeline_sig),
        "ANALYZER_PROCESS_ROLE": "WORKER",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
    })
    verified = configured_pipeline()
    if not verified.m4_v2 or verified.identity != EXPECTED_IDENTITY:
        refuse("signed_v19_pipeline_identity_verification_failed")
    if verified._manifest["execution"]["analyzer_revision"] != EXPECTED_REVISION:
        refuse("unexpected_v19_code_revision")
    return {
        "revision": EXPECTED_REVISION,
        "pipeline_identity": EXPECTED_IDENTITY,
        "sources": len(verified._manifest["execution"]["source_sha256"]),
        "m6_e5_verified": True,
        "m4_model_identity": digest(m4),
    }


def check_active_authority() -> int:
    from app.core.config import settings
    from app.db.database import SessionLocal
    from app.models.analyzer_authority import AnalyzerAuthority

    if (settings.postgres_host, settings.postgres_port, settings.postgres_db) != (
        "127.0.0.1",
        55432,
        "mcp_security",
    ):
        refuse("original_local_postgres_location_mismatch")
    with SessionLocal() as session:
        row = session.get(AnalyzerAuthority, 1)
        if row is None:
            refuse("tda_initial_authority_not_active")
        if row.pipeline_identity != EXPECTED_IDENTITY:
            refuse("tda_authority_identity_does_not_match_owner_signature")
        if row.generation < 1:
            refuse("tda_authority_generation_invalid")
        generation = row.generation
        session.rollback()
    os.environ["ANALYZER_AUTHORITY_GENERATION"] = str(generation)
    return generation


def http_ready(url: str, *, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=1.0) as response:
                if response.status == 200:
                    return True
        except (OSError, URLError, HTTPError):
            pass
        time.sleep(0.4)
    return False


def run_services(mode: str) -> None:
    from app.core.config import settings
    from app.core.runtime_paths import configure_runtime_environment
    from app.services.local_runtime_manager import LocalRuntimeManager

    ports = (
        settings.backend_port,
        settings.mcp_gateway_port,
        8181,
        9000,
        9100,
        settings.frontend_port,
    )
    if any(not local_available(port) for port in ports):
        refuse("a_runtime_service_port_is_already_in_use")

    initial_pg_running = pg_command(["status"]) == 0
    started_pg = False
    manager: LocalRuntimeManager | None = None
    frontend: subprocess.Popen | None = None
    frontend_log = None
    try:
        if not initial_pg_running:
            code = pg_command(
                [
                    "-l",
                    str(PG_LOG),
                    "-o",
                    "-h 127.0.0.1 -p 55432",
                    "-w",
                    "-t",
                    "45",
                    "start",
                ]
            )
            if code:
                refuse("original_postgres_failed_to_start")
            started_pg = True
        generation = check_active_authority()
        configure_runtime_environment()
        manager = LocalRuntimeManager(python_executable=Path(sys.executable))
        if manager.database_status().status != "healthy":
            refuse("original_postgres_unhealthy")
        if manager.ensure_opa(auto_start=True).status != "healthy":
            refuse("OPA_unhealthy")
        if manager.ensure_identity_provider(auto_start=True).status != "healthy":
            refuse("identity_provider_unhealthy")
        if manager.ensure_mcp_lab(auto_start=True).status != "healthy":
            refuse("mcp_lab_unhealthy")
        backend_status = manager.start_backend()
        if backend_status.status != "healthy" and not http_ready(
            f"http://127.0.0.1:{settings.backend_port}/api/v1/health",
            timeout=120,
        ):
            refuse("signed_backend_unhealthy")
        gateway_status = manager.ensure_gateway(auto_start=True)
        if gateway_status.status != "healthy" and not http_ready(
            f"http://127.0.0.1:{settings.mcp_gateway_port}/health",
            timeout=90,
        ):
            refuse("signed_gateway_unhealthy")

        node = shutil.which("node")
        vite = ROOT / "frontend/node_modules/vite/bin/vite.js"
        if node and vite.is_file():
            log_path = ROOT / ".runtime/tmp/tda_signed_frontend.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            frontend_log = log_path.open("ab")
            frontend = subprocess.Popen(
                [
                    node,
                    str(vite),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(settings.frontend_port),
                    "--strictPort",
                ],
                cwd=str(ROOT / "frontend"),
                env=os.environ.copy(),
                stdout=frontend_log,
                stderr=subprocess.STDOUT,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if not http_ready(
                f"http://127.0.0.1:{settings.frontend_port}/", timeout=20
            ):
                refuse("frontend_not_ready")
        else:
            refuse("node_or_vite_unavailable")
        backend_url = f"http://127.0.0.1:{settings.backend_port}"
        if not http_ready(backend_url + "/api/v1/readiness", timeout=15):
            refuse("full_framework_readiness_not_200")

        print(
            json.dumps(
                {
                    "status": "SIGNED_V19_RUNTIME_READY",
                    "revision": EXPECTED_REVISION,
                    "pipeline_identity": EXPECTED_IDENTITY,
                    "generation": generation,
                    "readiness": "200",
                    "frontend": f"http://127.0.0.1:{settings.frontend_port}",
                    "mode": mode,
                }
            ),
            flush=True,
        )
        if mode == "serve":
            print(
                "Running; Ctrl+C stops this launcher's owned services.",
                flush=True,
            )
            while True:
                if manager.required_child_failure() is not None:
                    refuse("managed_required_child_exited")
                if frontend is not None and frontend.poll() is not None:
                    refuse("frontend_process_exited")
                time.sleep(0.8)
    except KeyboardInterrupt:
        print("Shutdown requested.", flush=True)
    finally:
        if frontend is not None:
            if frontend.poll() is None:
                frontend.terminate()
                try:
                    frontend.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    frontend.kill()
                    frontend.wait(timeout=5)
        if frontend_log is not None:
            frontend_log.close()
        if manager is not None:
            manager.shutdown()
        if started_pg:
            if pg_command(["-m", "fast", "-w", "-t", "40", "stop"]) != 0:
                print("WARNING: failed to stop original PostgreSQL.", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify or run existing TDA owner-signed generation without approval changes"
    )
    parser.add_argument("mode", choices=["check", "smoke", "serve"])
    parser.add_argument("--preparation", type=Path, required=True)
    parser.add_argument("--owner-keystore", type=Path, required=True)
    parser.add_argument("--signed-output", type=Path, required=True)
    parser.add_argument("--m4-bundle", type=Path, required=True)
    args = parser.parse_args()
    from common.project_environment import load_project_environment

    load_project_environment(project_root=ROOT)
    if os.environ.get("MCP_FRAMEWORK_QA_ROOT"):
        refuse("QA_runtime_inherited; use isolated QA harness")
    details = signed_environment(args)
    if args.mode == "check":
        print(json.dumps({"status": "OWNER_SIGNED_RELEASE_VERIFIED", **details}))
    else:
        run_services(args.mode)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OperationalGateError as exc:
        print("SIGNED_TDA_START_REFUSED:", str(exc), file=sys.stderr)
        raise SystemExit(2) from exc