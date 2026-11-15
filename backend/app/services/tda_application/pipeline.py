"""Explicit verified pipeline. Trust anchor is supplied separately by the deployment owner.

Hashing detects accidental/untrusted artifact replacement, not a hostile local
administrator controlling code, manifest and process. Protected immutable
deployment is a prerequisite; this module does not establish Windows ACLs.
"""

from app.services.tda.configuration import (
    ANALYZER_REVISION,
)
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath


from app.services.tda_application._integrity import (
    PipelineIntegrityError, canonical, digest, file_digest,
)


def _under(path, root):
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (ValueError, OSError):
        raise PipelineIntegrityError("artifact_outside_trusted_root")
    return path.resolve(strict=True)


def inventory(snapshot, root):
    snapshot = Path(snapshot)
    root = Path(root)
    _under(snapshot, root)
    result = []
    for p in sorted(snapshot.rglob("*")):
        if p.is_dir() and (
            p.is_symlink() or getattr(p, "is_junction", lambda: False)()
        ):
            raise PipelineIntegrityError("linked_artifact_directory")
        if not p.is_file():
            if p.is_symlink():
                raise PipelineIntegrityError("broken_artifact_link")
            continue
        target = _under(p, root)
        result.append(
            {
                "path": p.relative_to(snapshot).as_posix(),
                "bytes": target.stat().st_size,
                "sha256": file_digest(target),
            }
        )
    if not result:
        raise PipelineIntegrityError("empty_snapshot")
    return result


def execution_configuration():
    """Declared decision/extraction closure, computed only at service startup.

    Standard built-in packs only. A custom pack or engine requires its own
    reviewed identity; this identity must not be reused for an injected engine.
    """
    from importlib.metadata import version

    root = Path(__file__).resolve().parents[4]
    roots = [
        root / p
        for p in (
            "backend/app",
            "proxy",
            "common",
            "agent",
            "scanners",
            "policies",
            "backend/requirements.txt",
            "scripts/check_tda_pipeline_release.py",
            "scripts/replay_tda_engineering.py",
            "scripts/migrations/20261102_step6_analyzer_authority.sql",
        )
    ]
    sources = source_inventory(roots)
    return {
        "analyzer_revision": ANALYZER_REVISION,
        "source_roots": [str(p) for p in roots],
        "source_sha256": sources,
        "dependency_artifacts": dependency_artifacts(),
        "dependencies": {
            p: version(p)
            for p in (
                "torch",
                "transformers",
                "tokenizers",
                "sentence-transformers",
                "pydantic",
                "numpy",
            )
        },
    }


def configured_pipeline():
    """No V1 MiniLM manifest or unsigned analyzer fallback."""
    import os
    if os.environ.get("ANALYZER_M4_V2_ENABLED") != "1":
        raise PipelineIntegrityError("signed_m4_v2_required")
    return configured_m4_pipeline_v2()


from threading import RLock

def source_inventory(roots):
    result = {}
    for root in map(Path, roots):
        if (
            not root.exists()
            or root.is_symlink()
            or getattr(root, "is_junction", lambda: False)()
        ):
            raise PipelineIntegrityError("source_root_unavailable_or_linked")
        if root.is_file():
            result[str(root)] = file_digest(root)
            continue
        for p in sorted(root.rglob("*")):
            if p.is_symlink() or getattr(p, "is_junction", lambda: False)():
                raise PipelineIntegrityError("linked_source_not_supported")
            if p.is_file() and p.suffix.lower() in {
                ".py",
                ".json",
                ".rego",
                ".yaml",
                ".yml",
                ".toml",
                ".txt",
            }:
                if "__pycache__" not in p.parts:
                    result[str(p)] = file_digest(p)
    return result


def verify_source_closure(execution):
    if source_inventory(execution["source_roots"]) != execution["source_sha256"]:
        raise PipelineIntegrityError("pipeline_source_closure_changed")


from functools import lru_cache


@lru_cache(maxsize=1)
def dependency_artifacts():
    """Content hashes at process startup, not merely distribution versions.

    Deployment must protect the installed environment against writes after
    verification and restart all workers on activation. A local administrator
    controlling the interpreter and trust key is outside this trust boundary.
    """
    from importlib.metadata import distribution, packages_distributions
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
    import sys
    import os

    records = {}
    pending = [
        "torch",
        "transformers",
        "tokenizers",
        "sentence-transformers",
        "pydantic",
        "numpy",
        "sqlalchemy",
        "cryptography",
        "fastapi",
        "jsonschema",
        "psycopg",
        "httpx",
        "PyJWT",
        "uvicorn",
    ]
    import ast

    owners = packages_distributions()
    root = Path(__file__).resolve().parents[3]
    for part in ("backend/app", "proxy", "common", "agent", "scanners"):
        for source in (root / part).rglob("*.py"):
            tree = ast.parse(source.read_text(encoding="utf8"))
            for node in ast.walk(tree):
                names = (
                    [a.name for a in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module]
                    if isinstance(node, ast.ImportFrom)
                    and node.level == 0
                    and node.module
                    else []
                )
                for name in names:
                    pending.extend(owners.get(name.split(".")[0], ()))
    pending.extend(owners.get("psycopg_binary", ()))
    visited = set()
    while pending:
        name = canonicalize_name(pending.pop())
        if name in visited:
            continue
        visited.add(name)
        dist = distribution(name)
        for raw in dist.requires or ():
            req = Requirement(raw)
            if req.marker is None or req.marker.evaluate({"extra": ""}):
                pending.append(req.name)
        files = {}
        for item in dist.files or ():
            p = Path(dist.locate_file(item)).resolve()
            if (
                p.is_file()
                and p.suffix.lower()
                in {
                    ".py",
                    ".pyd",
                    ".dll",
                    ".so",
                    ".json",
                    ".txt",
                    ".toml",
                    ".yaml",
                    ".yml",
                }
                and ("__pycache__" not in p.parts)
            ):
                files[str(p)] = file_digest(p)
        records[dist.metadata["Name"]] = {"version": dist.version, "files": files}
    # Windows executable paths are case-insensitive. Both the prepared
    # manifest and a worker started via a differently cased path must bind
    # the exact same executable bytes, without skipping any SHA-256 check.
    runtime = {}
    interpreter_files = (
        Path(sys.executable),
        Path(sys._base_executable),
        Path(sys.base_prefix)
        / f"python{sys.version_info.major}{sys.version_info.minor}.dll",
        Path(sys.prefix) / "pyvenv.cfg",
    )
    for p in interpreter_files:
        if p.is_file():
            key = os.path.normcase(str(p))
            fingerprint = file_digest(p)
            if key in runtime and runtime[key] != fingerprint:
                raise PipelineIntegrityError("interpreter_case_alias_collision")
            runtime[key] = fingerprint
    return {
        "interpreter": {"version": sys.version, "files": runtime},
        "distributions": records,
    }


def require_current_pipeline(analysis):
    """An explicit deployment pin applies to ADMIN and signed approvals alike."""
    pipeline = configured_pipeline()
    if pipeline is not None and analysis.model_versions != pipeline.model_versions:
        raise PipelineIntegrityError("analysis_pipeline_not_current")
    if (
        getattr(analysis, "analyzer_revision", None)
        != pipeline._manifest["execution"]["analyzer_revision"]
    ):
        raise PipelineIntegrityError("analysis_revision_not_current")
    # The caller can reuse this already fully verified identity inside the
    # same authorization decision, without a second full-file SHA256 walk.
    return pipeline


def check_revision_transition(previous, current):
    old = previous["execution"]
    new = current["execution"]
    if (
        old["source_sha256"] != new["source_sha256"]
        and old["analyzer_revision"] == new["analyzer_revision"]
    ):
        raise PipelineIntegrityError("source_change_requires_analyzer_revision_bump")
    return True

# New analyzer authority identity for an EN-only GLiNER+DeBERTa semantic M4.
# Historical V1 approvals remain persisted evidence, but have no inference
# authority or execution path in this V19 online application.
M4_V2_SCHEMA = "verified_m4_analyzer_pipeline_v2"
M4_V2_DOMAIN = b"mcp-security-framework/analyzer-deployment/v2\x00"
M4_V2_MODELS = {"GLINER": "GLINER2.5_BASE_PASS10",
                "DEBERTA": "DEBERTA_V3_SMALL_V2"}
M4_V2_DRIFT_NAME = "intfloat/multilingual-e5-small"


def execution_configuration_v2():
    """GLiNER/DeBERTa M4 semantic identity; E5 stays pinned for M6 drift."""
    from importlib.metadata import version, PackageNotFoundError
    from importlib.util import find_spec
    result = execution_configuration()
    result["m4_semantic_models"] = dict(M4_V2_MODELS)
    result["m4_behavior_authority"] = "NONE"
    result["m4_language_scope"] = "EN_ONLY"
    result["m6_drift_strategy"] = "M6_E5_DESCRIPTION_SIMILARITY_AND_STRUCTURAL_DELTA"

    # The research GLiNER2 installation is an editable, clean Git checkout
    # without distribution metadata. Hash every importable source file instead
    # of trusting a guessed package version or an unpinned import path.
    spec = find_spec("gliner2")
    if spec is None or spec.origin is None:
        raise PipelineIntegrityError("m4_v2_gliner2_package_unavailable")
    package_root = Path(spec.origin).parent.resolve(strict=True)
    if package_root.is_symlink() or not package_root.is_dir():
        raise PipelineIntegrityError("m4_v2_gliner2_invalid_package_root")
    gliner_files = {}
    for source in sorted(package_root.rglob("*")):
        if source.is_symlink() or getattr(source, "is_junction", lambda: False)():
            raise PipelineIntegrityError("m4_v2_gliner2_linked_source")
        if source.is_file() and source.suffix.lower() in {
            ".py", ".pyi", ".json", ".toml", ".yml", ".yaml", ".txt",
        }:
            gliner_files[source.relative_to(package_root).as_posix()] = file_digest(source)
    if not gliner_files:
        raise PipelineIntegrityError("m4_v2_gliner2_empty_source_inventory")
    # Metadata from an editable checkout can appear or disappear merely by
    # building a wheel. It is not an immutable version/trust anchor.
    # The Git revision is pinned by backend/requirements.txt; the exact
    # imported package bytes are validated by the SHA-256 inventory below.
    result["dependencies"]["gliner2"] = {
        "pinned_source_commit": "ca4f68235b50fe4c3ecf3876851d748fe4b15c6c",
        "package_version": "2.1.0",
        "import_root": str(package_root),
        "sha256": gliner_files,
    }
    return result


def build_m4_pipeline_v2_manifest(repo_root, model_root):
    """Unsigned owner-review proposal; creating a digest grants no authority."""
    from app.services.tda_application.m4_pipeline_integrity import configured_m4_identity
    model = configured_m4_identity(Path(repo_root), Path(model_root))
    # E5 belongs to M6, but its exact local bytes must remain part of the
    # signed pipeline closure when V2 calls M6 drift analysis.
    from app.core.runtime_paths import MODEL_CACHE_DIR
    from app.services.tda.models.artifacts import _local_snapshot_path
    from app.services.tda.configuration import EMBEDDING_MODEL_NAME
    m6_snapshot = _local_snapshot_path(MODEL_CACHE_DIR, EMBEDDING_MODEL_NAME)
    if m6_snapshot is None:
        raise PipelineIntegrityError("m6_e5_local_snapshot_required")
    m6_binding = {
        "name": EMBEDDING_MODEL_NAME,
        "root": str(MODEL_CACHE_DIR.resolve(strict=True)),
        "snapshot": str(m6_snapshot.resolve(strict=True)),
        "files": inventory(m6_snapshot, MODEL_CACHE_DIR),
    }
    return {
        "schema": M4_V2_SCHEMA,
        "purpose": "EN_ONLY_ANALYZER_SEMANTICS_ADVISORY",
        "model_names": dict(M4_V2_MODELS),
        "m4_signed_identity_sha256": model.identity,
        "policy_authority": "NONE",
        "embedding_role": M4_V2_DRIFT_NAME,
        "m6_embedding": m6_binding,
        "execution": execution_configuration_v2(),
    }


class VerifiedM4PipelineV2:
    """Signed analyzer generation; model claims remain non-authoritative.

    This authorizes a *code/model identity*, not a tool, policy or runtime call.
    A new source closure or revision requires an independently signed manifest.
    """
    m4_v2 = True

    def __init__(self, manifest, approved_sha256, m4_identity):
        if not isinstance(manifest, dict) or manifest.get("schema") != M4_V2_SCHEMA:
            raise PipelineIntegrityError("m4_v2_invalid_schema")
        if digest(manifest) != approved_sha256:
            raise PipelineIntegrityError("m4_v2_unapproved_manifest")
        if (manifest.get("purpose") != "EN_ONLY_ANALYZER_SEMANTICS_ADVISORY"
                or manifest.get("policy_authority") != "NONE"
                or manifest.get("model_names") != M4_V2_MODELS
                or manifest.get("embedding_role") != M4_V2_DRIFT_NAME
                or manifest.get("m4_signed_identity_sha256") != m4_identity.identity):
            raise PipelineIntegrityError("m4_v2_incorrect_semantic_authority")
        # Role separation: this is NOT a third M4 model. This is the
        # independently owned M6 drift model already used by the framework.
        from app.services.tda.configuration import EMBEDDING_MODEL_NAME
        m6 = manifest.get("m6_embedding")
        if not isinstance(m6, dict) or set(m6) != {
            "name", "root", "snapshot", "files"
        } or m6.get("name") != EMBEDDING_MODEL_NAME or not isinstance(
            m6.get("files"), list
        ) or not m6["files"]:
            raise PipelineIntegrityError("m4_v2_m6_e5_binding_required")
        from app.core.runtime_paths import MODEL_CACHE_DIR
        if Path(m6["root"]).resolve(strict=True) != MODEL_CACHE_DIR.resolve(strict=True):
            raise PipelineIntegrityError("m4_v2_m6_e5_root_mismatch")
        self._m6_snapshot = Path(m6["snapshot"])
        self._m6_root = Path(m6["root"])
        self._manifest = deepcopy(manifest)
        self._m4_identity = m4_identity
        self.identity = approved_sha256
        self.verify()

    @property
    def model_versions(self):
        rev = "pipeline-sha256:" + self.identity
        return {
            "semantic": {"name": "GLINER2.5_BASE_PASS10+DEBERTA_V3_SMALL_V2",
                         "version": rev},
            "m4_gliner": {"name": M4_V2_MODELS["GLINER"], "version": rev},
            "m4_deberta": {"name": M4_V2_MODELS["DEBERTA"], "version": rev},
            "embedding": {"name": M4_V2_DRIFT_NAME, "version": rev},
        }

    def assert_execution(self, expected):
        if self._manifest.get("execution") != expected:
            raise PipelineIntegrityError("m4_v2_execution_mismatch")

    def _verify_analyzer_and_m6_after_m4(self):
        """Check all signed analyzer, GLiNER source and E5 bytes.

        Caller must have just verified the signed M4 identity. This split
        avoids verifying the *same M4 files* a second time inside one
        configured_pipeline() request. execution_configuration_v2() builds
        a live source SHA inventory, so repeating verify_source_closure()
        would only hash the identical paths a second time.
        """
        execution = self._manifest.get("execution")
        if not isinstance(execution, dict):
            raise PipelineIntegrityError("m4_v2_execution_missing")
        if execution != execution_configuration_v2():
            raise PipelineIntegrityError("m4_v2_dependency_or_execution_changed")
        m6 = self._manifest["m6_embedding"]
        try:
            observed = inventory(self._m6_snapshot, self._m6_root)
        except (OSError, ValueError) as exc:
            raise PipelineIntegrityError("m6_e5_artifacts_unavailable") from exc
        if observed != m6["files"]:
            raise PipelineIntegrityError("m6_e5_artifacts_changed")
        return self.identity

    def verify(self):
        """Full direct verification: signed M4 + live analyzer + E5."""
        self._m4_identity.verify()
        return self._verify_analyzer_and_m6_after_m4()

    def model_path(self, role):
        if role != "embedding":
            raise PipelineIntegrityError("m4_v2_legacy_model_loader_refused")
        self.verify()
        return _under(self._m6_snapshot, self._m6_root)

    def load_checked(self, role, loader):
        if role != "embedding":
            raise PipelineIntegrityError("m4_v2_legacy_model_loader_refused")
        self.verify()
        result = loader(self.model_path("embedding"))
        self.verify()
        return result


_m4_v2_cache = {}
_m4_v2_lock = RLock()


def configured_m4_pipeline_v2():
    """Separate signed V2 identity; a V1 MiniLM/E5 manifest cannot activate it."""
    import os
    import base64
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from app.services.tda_application.m4_pipeline_integrity import configured_m4_identity

    if os.environ.get("ANALYZER_M4_V2_ENABLED") != "1":
        raise PipelineIntegrityError("m4_v2_neural_semantics_required")
    if os.environ.get("ANALYZER_PIPELINE_BINDINGS"):
        raise PipelineIntegrityError("m4_v2_old_minilm_bindings_refused")
    names = ("ANALYZER_PIPELINE_MANIFEST", "ANALYZER_PIPELINE_APPROVED_SHA256",
             "ANALYZER_PIPELINE_SIGNATURE", "ANALYZER_PIPELINE_TRUST_KEY")
    values = tuple(os.environ.get(k, "") for k in names)
    if not all(values):
        raise PipelineIntegrityError("m4_v2_signed_deployment_configuration_required")
    repo = Path(__file__).resolve().parents[4]
    model_root = os.environ.get("M4_SEMANTICS_MODEL_ROOT", "")
    if not model_root:
        raise PipelineIntegrityError("m4_v2_model_bundle_required")
    m4_identity = configured_m4_identity(repo, Path(model_root))
    with _m4_v2_lock:
        try:
            manifest = json.loads(Path(values[0]).read_text(encoding="utf8"))
            if digest(manifest) != values[1]:
                raise PipelineIntegrityError("m4_v2_unapproved_manifest")
            pub = load_pem_public_key(Path(values[3]).read_bytes())
            if not isinstance(pub, Ed25519PublicKey):
                raise ValueError("m4_v2_wrong_signature_key")
            pub.verify(
                base64.b64decode(values[2], validate=True),
                M4_V2_DOMAIN + canonical(manifest),
            )
        except PipelineIntegrityError:
            raise
        except Exception as exc:
            raise PipelineIntegrityError("m4_v2_deployment_signature_invalid") from exc
        key = (values, m4_identity.identity)
        if key not in _m4_v2_cache:
            # Constructor verifies the entire M4/analyzer/E5 closure. Do
            # not immediately perform that expensive verification again.
            worker = VerifiedM4PipelineV2(manifest, values[1], m4_identity)
            _m4_v2_cache[key] = worker
        else:
            # configured_m4_identity() above has already verified the
            # signature and exact on-disk SHA-256 of every M4 source/model
            # in THIS request. Recheck the live analyzer, GLiNER and M6/E5
            # closure, but do not hash M4's identical bytes twice.
            worker = _m4_v2_cache[key]
            worker._verify_analyzer_and_m6_after_m4()
        return worker
