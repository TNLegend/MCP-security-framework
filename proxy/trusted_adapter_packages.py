from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass
from hashlib import sha256
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from common.canonical_json import canonical_json_bytes
from proxy.resource_adapters_v2 import (
    AdapterManifest,
    AdapterRegistry,
    ResourceAdapter,
    TrustedAdapterRegistration,
    register_trusted_adapter,
    registered_trusted_adapters,
    verify_trusted_adapter_distribution,
)
from proxy.tool_security_v2 import SecurityModelError


ADAPTER_PACKAGE_VERSION = "1"
ADAPTER_SDK_API_VERSION = "1"
MAX_ADAPTER_ARCHIVE_BYTES = 1_000_000
MAX_ADAPTER_SOURCE_BYTES = 500_000
RUNTIME_ARCHIVE_FILES = frozenset({"adapter.py", "manifest.json", "signature.json"})
ADAPTER_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
SEMVER_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class AdapterStarter:
    starter_id: str
    title: str
    family: str
    description: str
    recommended_for: tuple[str, ...]


STARTERS = (
    AdapterStarter(
        starter_id="blank",
        title="Blank specialized adapter",
        family="custom",
        description="Fail-closed starter for a semantic family not covered by the installed SDK.",
        recommended_for=("proprietary identifiers", "domain-specific commands", "unknown semantic families"),
    ),
    AdapterStarter("sql", "SQL adapter", "database", "Starter for parsed SQL statements and database objects.", ("queries", "database objects", "row results")),
    AdapterStarter("shell", "Shell adapter", "process", "Starter for argv-only command execution without shell expansion.", ("commands", "executables", "exit results")),
    AdapterStarter("payment", "Payment adapter", "payments", "Starter for payment destinations and bounded transaction results.", ("transfers", "recipients", "payment status")),
    AdapterStarter("cloud-iam", "Cloud IAM adapter", "cloud-iam", "Starter for provider-qualified IAM resources and mutations.", ("ARNs", "roles", "policy changes")),
    AdapterStarter("git", "Git adapter", "source-control", "Starter for canonical repositories, refs, and bounded changed files.", ("repositories", "branches", "commits")),
    AdapterStarter("messaging", "Messaging adapter", "messaging", "Starter for canonical recipients, channels, and delivery receipts.", ("email", "channels", "message delivery")),
)


def adapter_starter_catalog() -> tuple[dict[str, Any], ...]:
    return tuple(asdict(starter) for starter in STARTERS)


def build_adapter_starter_archive(starter_id: str, adapter_id: str) -> bytes:
    starter = _starter(starter_id)
    normalized_id = _validate_adapter_id(adapter_id)
    manifest = _starter_manifest(starter, normalized_id)
    source = _starter_source(manifest)
    readme = _starter_readme(starter, normalized_id)
    test_source = _starter_test_source(normalized_id)
    return _zip_bytes(
        {
            "manifest.json": _pretty_json_bytes(manifest),
            "adapter.py": source.encode("utf-8"),
            "tests/test_adapter.py": test_source.encode("utf-8"),
            "README.md": readme.encode("utf-8"),
        }
    )


def create_signed_adapter_archive(
    source_directory: Path,
    *,
    private_key_pem: bytes,
) -> bytes:
    manifest_path = source_directory / "manifest.json"
    source_path = source_directory / "adapter.py"
    if not manifest_path.is_file() or not source_path.is_file():
        raise SecurityModelError("adapter_source_files_missing")
    manifest = _parse_manifest(manifest_path.read_bytes())
    source = source_path.read_bytes()
    if not source or len(source) > MAX_ADAPTER_SOURCE_BYTES:
        raise SecurityModelError("adapter_source_size_invalid")
    try:
        source.decode("utf-8")
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise SecurityModelError("adapter_signing_key_invalid") from exc
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise SecurityModelError("adapter_signing_key_type_unsupported")
    payload = _signed_payload(manifest, source)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    signature = {
        "algorithm": "Ed25519",
        "public_key_pem": public_key_pem,
        "signature_base64": base64.b64encode(private_key.sign(payload)).decode("ascii"),
    }
    return _zip_bytes(
        {
            "manifest.json": canonical_json_bytes(manifest),
            "adapter.py": source,
            "signature.json": canonical_json_bytes(signature),
        }
    )


def verify_adapter_archive(
    archive: bytes,
    *,
    trusted_signer_fingerprints: tuple[str, ...],
) -> TrustedAdapterRegistration:
    files = _read_runtime_archive(archive)
    manifest = _parse_manifest(files["manifest.json"])
    source = files["adapter.py"]
    signature_document = _parse_signature(files["signature.json"])
    fingerprint = _verified_signer(
        signature_document,
        _signed_payload(manifest, source),
    )
    trusted = {_validate_fingerprint(value) for value in trusted_signer_fingerprints}
    if not trusted or fingerprint not in trusted:
        raise SecurityModelError("adapter_signer_not_trusted")
    adapter = _load_verified_adapter(manifest, source)
    registration = verify_trusted_adapter_distribution(
        adapter,
        distribution=_signed_payload(manifest, source),
        public_key_pem=signature_document["public_key_pem"],
        signature_base64=signature_document["signature_base64"],
    )
    if registration.signer_key_fingerprint != fingerprint:
        raise SecurityModelError("adapter_signer_fingerprint_mismatch")
    return registration


def load_adapter_directory(
    directory: Path,
    *,
    trusted_signer_fingerprints: tuple[str, ...],
) -> tuple[TrustedAdapterRegistration, ...]:
    if not directory.exists():
        raise SecurityModelError("trusted_adapter_directory_missing")
    if not directory.is_dir():
        raise SecurityModelError("trusted_adapter_directory_invalid")
    registrations = tuple(
        verify_adapter_archive(
            archive_path.read_bytes(),
            trusted_signer_fingerprints=trusted_signer_fingerprints,
        )
        for archive_path in sorted(directory.glob("*.zip"))
    )
    AdapterRegistry(trusted_adapters=registrations)
    return registrations


def load_trusted_adapters_from_environment() -> tuple[TrustedAdapterRegistration, ...]:
    raw_directory = os.getenv("TRUSTED_ADAPTER_DIRECTORY", "").strip()
    if not raw_directory:
        return ()
    fingerprints = tuple(
        value.strip().lower()
        for value in os.getenv("TRUSTED_ADAPTER_SIGNER_FINGERPRINTS", "").split(",")
        if value.strip()
    )
    registrations = load_adapter_directory(
        Path(raw_directory),
        trusted_signer_fingerprints=fingerprints,
    )
    existing = {
        registration.adapter.manifest.adapter_id: registration
        for registration in registered_trusted_adapters()
    }
    for registration in registrations:
        adapter_id = registration.adapter.manifest.adapter_id
        current = existing.get(adapter_id)
        if current is not None:
            if current.distribution_sha256 != registration.distribution_sha256:
                raise SecurityModelError("adapter_id_collision")
            continue
        register_trusted_adapter(registration)
    return registrations


def install_adapter_archive(
    archive: bytes,
    *,
    destination_directory: Path,
    trusted_signer_fingerprints: tuple[str, ...],
) -> Path:
    registration = verify_adapter_archive(
        archive,
        trusted_signer_fingerprints=trusted_signer_fingerprints,
    )
    adapter_id = registration.adapter.manifest.adapter_id
    destination_directory.mkdir(parents=True, exist_ok=True)
    target = destination_directory / f"{adapter_id}.zip"
    if target.exists():
        existing = verify_adapter_archive(
            target.read_bytes(),
            trusted_signer_fingerprints=trusted_signer_fingerprints,
        )
        if existing.distribution_sha256 != registration.distribution_sha256:
            raise SecurityModelError("adapter_id_collision")
        return target
    temporary = destination_directory / f".{adapter_id}.tmp"
    temporary.write_bytes(archive)
    temporary.replace(target)
    return target


def signer_fingerprint(public_key_pem: str) -> str:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise SecurityModelError("adapter_signature_invalid") from exc
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise SecurityModelError("adapter_signature_key_type_unsupported")
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(public_der).hexdigest()


def _read_runtime_archive(archive: bytes) -> dict[str, bytes]:
    if not archive or len(archive) > MAX_ADAPTER_ARCHIVE_BYTES:
        raise SecurityModelError("adapter_archive_size_invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            names = package.namelist()
            if len(names) != len(set(names)) or set(names) != RUNTIME_ARCHIVE_FILES:
                raise SecurityModelError("adapter_archive_layout_invalid")
            if any(
                info.is_dir()
                or info.file_size > MAX_ADAPTER_SOURCE_BYTES
                or info.compress_size > MAX_ADAPTER_ARCHIVE_BYTES
                for info in package.infolist()
            ):
                raise SecurityModelError("adapter_archive_entry_invalid")
            if sum(info.file_size for info in package.infolist()) > MAX_ADAPTER_ARCHIVE_BYTES:
                raise SecurityModelError("adapter_archive_expanded_size_invalid")
            return {name: package.read(name) for name in names}
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise SecurityModelError("adapter_archive_invalid") from exc


def _parse_manifest(raw: bytes) -> dict[str, Any]:
    value = _strict_json_object(raw, "adapter_manifest_invalid")
    expected = {
        "package_version",
        "adapter_id",
        "adapter_api_version",
        "implementation_version",
        "display_name",
        "family",
        "publisher",
        "trust_level",
        "supported_capabilities",
        "supported_resource_types",
        "argument_validation",
        "result_validation",
        "entrypoint",
    }
    if set(value) != expected:
        raise SecurityModelError("adapter_manifest_fields_invalid")
    _validate_adapter_id(value["adapter_id"])
    if value["package_version"] != ADAPTER_PACKAGE_VERSION:
        raise SecurityModelError("adapter_package_version_unsupported")
    if value["adapter_api_version"] != ADAPTER_SDK_API_VERSION:
        raise SecurityModelError("adapter_api_version_unsupported")
    if not isinstance(value["implementation_version"], str) or not SEMVER_PATTERN.fullmatch(value["implementation_version"]):
        raise SecurityModelError("adapter_implementation_version_invalid")
    if value["trust_level"] != "SIGNED_REVIEWED" or value["entrypoint"] != "adapter:Adapter":
        raise SecurityModelError("adapter_manifest_trust_boundary_invalid")
    for key in ("display_name", "family", "publisher", "argument_validation", "result_validation"):
        if not isinstance(value[key], str) or not value[key].strip() or len(value[key]) > 256:
            raise SecurityModelError("adapter_manifest_metadata_invalid")
    for key in ("supported_capabilities", "supported_resource_types"):
        values = value[key]
        if not isinstance(values, list) or not values or len(values) > 128:
            raise SecurityModelError("adapter_manifest_support_invalid")
        if any(not isinstance(item, str) or not item or len(item) > 128 for item in values):
            raise SecurityModelError("adapter_manifest_support_invalid")
        if len(values) != len(set(values)):
            raise SecurityModelError("adapter_manifest_support_duplicate")
    return value


def _parse_signature(raw: bytes) -> dict[str, str]:
    value = _strict_json_object(raw, "adapter_signature_document_invalid")
    if set(value) != {"algorithm", "public_key_pem", "signature_base64"}:
        raise SecurityModelError("adapter_signature_document_invalid")
    if value.get("algorithm") != "Ed25519":
        raise SecurityModelError("adapter_signature_algorithm_unsupported")
    if not all(isinstance(value.get(key), str) for key in ("public_key_pem", "signature_base64")):
        raise SecurityModelError("adapter_signature_document_invalid")
    return value


def _verified_signer(signature_document: dict[str, str], payload: bytes) -> str:
    try:
        public_key = serialization.load_pem_public_key(signature_document["public_key_pem"].encode("ascii"))
        signature = base64.b64decode(signature_document["signature_base64"], validate=True)
    except (ValueError, TypeError, UnicodeError, binascii.Error) as exc:
        raise SecurityModelError("adapter_signature_invalid") from exc
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise SecurityModelError("adapter_signature_key_type_unsupported")
    try:
        public_key.verify(signature, payload)
    except InvalidSignature as exc:
        raise SecurityModelError("adapter_signature_invalid") from exc
    return signer_fingerprint(signature_document["public_key_pem"])


def _load_verified_adapter(manifest: dict[str, Any], source: bytes) -> ResourceAdapter:
    digest = sha256(source).hexdigest()
    module_name = f"_mcp_trusted_adapter_{manifest['adapter_id'].replace('-', '_')}_{digest[:12]}"
    with tempfile.TemporaryDirectory(prefix="mcp-trusted-adapter-") as directory:
        source_path = Path(directory) / "adapter.py"
        source_path.write_bytes(source)
        spec = importlib.util.spec_from_file_location(module_name, source_path)
        if spec is None or spec.loader is None:
            raise SecurityModelError("adapter_module_load_failed")
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
            adapter_type = getattr(module, "Adapter")
            adapter = adapter_type()
        except Exception as exc:
            raise SecurityModelError("adapter_module_load_failed") from exc
    if not isinstance(adapter, ResourceAdapter):
        raise SecurityModelError("adapter_class_invalid")
    expected_manifest = AdapterManifest(
        adapter_id=manifest["adapter_id"],
        adapter_api_version=manifest["adapter_api_version"],
        implementation_version=manifest["implementation_version"],
        supported_capabilities=tuple(manifest["supported_capabilities"]),
        supported_resource_types=tuple(manifest["supported_resource_types"]),
        display_name=manifest["display_name"],
        family=manifest["family"],
        publisher=manifest["publisher"],
        trust_level=manifest["trust_level"],
        argument_validation=manifest["argument_validation"],
        result_validation=manifest["result_validation"],
    )
    if adapter.manifest != expected_manifest:
        raise SecurityModelError("adapter_manifest_code_mismatch")
    return adapter


def _signed_payload(manifest: dict[str, Any], source: bytes) -> bytes:
    return canonical_json_bytes(
        {
            "package_version": ADAPTER_PACKAGE_VERSION,
            "manifest": manifest,
            "files": {"adapter.py": sha256(source).hexdigest()},
        }
    )


def _strict_json_object(raw: bytes, error_code: str) -> dict[str, Any]:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise SecurityModelError(error_code) from exc
    if not isinstance(value, dict):
        raise SecurityModelError(error_code)
    return value


def _starter(starter_id: str) -> AdapterStarter:
    try:
        return next(value for value in STARTERS if value.starter_id == starter_id)
    except StopIteration as exc:
        raise SecurityModelError("adapter_starter_not_found") from exc


def _validate_adapter_id(value: Any) -> str:
    if not isinstance(value, str) or not ADAPTER_ID_PATTERN.fullmatch(value):
        raise SecurityModelError("adapter_manifest_invalid_id")
    return value


def _validate_fingerprint(value: str) -> str:
    normalized = str(value).strip().lower()
    if not FINGERPRINT_PATTERN.fullmatch(normalized):
        raise SecurityModelError("adapter_signer_fingerprint_invalid")
    return normalized


def _starter_manifest(starter: AdapterStarter, adapter_id: str) -> dict[str, Any]:
    prefix = adapter_id.replace("-", "_").replace(".", "_")
    return {
        "package_version": ADAPTER_PACKAGE_VERSION,
        "adapter_id": adapter_id,
        "adapter_api_version": ADAPTER_SDK_API_VERSION,
        "implementation_version": "0.1.0",
        "display_name": starter.title,
        "family": starter.family,
        "publisher": "replace-with-reviewed-publisher",
        "trust_level": "SIGNED_REVIEWED",
        "supported_capabilities": [f"{prefix}.execute"],
        "supported_resource_types": [f"{prefix}_resource"],
        "argument_validation": "not_implemented_fail_closed",
        "result_validation": "not_implemented_fail_closed",
        "entrypoint": "adapter:Adapter",
    }


def _starter_source(manifest: dict[str, Any]) -> str:
    values = {key: repr(manifest[key]) for key in (
        "adapter_id",
        "adapter_api_version",
        "implementation_version",
        "display_name",
        "family",
        "publisher",
        "trust_level",
        "argument_validation",
        "result_validation",
    )}
    capabilities = repr(tuple(manifest["supported_capabilities"]))
    resources = repr(tuple(manifest["supported_resource_types"]))
    return f'''from proxy.resource_adapters_v2 import AdapterManifest, AdapterResultInspection, ResourceAdapter
from proxy.tool_security_v2 import SecurityModelError


class Adapter(ResourceAdapter):
    manifest = AdapterManifest(
        adapter_id={values["adapter_id"]},
        adapter_api_version={values["adapter_api_version"]},
        implementation_version={values["implementation_version"]},
        supported_capabilities={capabilities},
        supported_resource_types={resources},
        display_name={values["display_name"]},
        family={values["family"]},
        publisher={values["publisher"]},
        trust_level={values["trust_level"]},
        argument_validation={values["argument_validation"]},
        result_validation={values["result_validation"]},
    )

    def resolve(self, canonical_args, effect, adapter_resolution, trusted_authority_context):
        # Replace this fail-closed placeholder with reviewed deterministic normalization.
        raise SecurityModelError("adapter_not_implemented")

    def inspect_result(self, result):
        return AdapterResultInspection(True, ("adapter_result_not_implemented",))
'''


def _starter_test_source(adapter_id: str) -> str:
    return f'''import unittest

from adapter import Adapter
from proxy.tool_security_v2 import SecurityModelError


class AdapterTests(unittest.TestCase):
    def test_starter_fails_closed_until_implemented(self):
        adapter = Adapter()
        self.assertEqual(adapter.manifest.adapter_id, {adapter_id!r})
        with self.assertRaisesRegex(SecurityModelError, "adapter_not_implemented"):
            adapter.resolve({{}}, None, None, {{}})
        self.assertTrue(adapter.inspect_result({{}}).blocked)


if __name__ == "__main__":
    unittest.main()
'''


def _starter_readme(starter: AdapterStarter, adapter_id: str) -> str:
    return f'''# {starter.title}

Adapter ID: `{adapter_id}`
SDK API: `{ADAPTER_SDK_API_VERSION}`

The generated implementation deliberately fails closed. Implement deterministic
resource extraction/canonicalization and bounded result validation, then update the
manifest and matching `Adapter.manifest` fields together.

Before deployment:

1. Add positive, negative, ambiguity, and malformed-result tests.
2. Run the framework adapter validation command.
3. Have the code reviewed by a trusted maintainer.
4. Sign the distribution with an Ed25519 key whose public fingerprint is configured
   in `TRUSTED_ADAPTER_SIGNER_FINGERPRINTS`.
5. Install the signed archive into `TRUSTED_ADAPTER_DIRECTORY` and restart the
   backend and Gateway together.

An imported Security Pack cannot execute this code or bypass that deployment path.
'''


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, files[name])
    return output.getvalue()


def _pretty_json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
