from __future__ import annotations

import base64
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for path in (str(ROOT), str(BACKEND)):
    if path not in sys.path:
        sys.path.insert(0, path)

from app.services.security_pack_onboarding import adapter_guidance_for_tool
from proxy.resource_adapters_v2 import AdapterRegistry, inspect_adapter_result
from proxy.security_packs import PackCapability, PackResourceType, SecurityPackManifest
from proxy.tool_request_preparation import prepare_tool_request_v2
from proxy.tool_security_v2 import (
    AuthorityResourceScope,
    ReferencePrecision,
    ResourceBinding,
    ScopeMatchMode,
    SecurityModelError,
    ToolEffect,
    ToolObservationApproval,
    ToolSecurityContract,
    validate_contract_for_schema,
)
from proxy.trusted_adapter_packages import (
    adapter_starter_catalog,
    build_adapter_starter_archive,
    create_signed_adapter_archive,
    install_adapter_archive,
    load_adapter_directory,
    signer_fingerprint,
    verify_adapter_archive,
)


WIDGET_MANIFEST = {
    "package_version": "1",
    "adapter_id": "widget-adapter",
    "adapter_api_version": "1",
    "implementation_version": "1.0.0",
    "display_name": "Widget Adapter",
    "family": "widget",
    "publisher": "runtime-test",
    "trust_level": "SIGNED_REVIEWED",
    "supported_capabilities": ["widget.execute"],
    "supported_resource_types": ["widget_resource"],
    "argument_validation": "canonical_widget_identifier",
    "result_validation": "bounded_widget_result",
    "entrypoint": "adapter:Adapter",
}

WIDGET_ADAPTER_SOURCE = '''from proxy.resource_adapters_v2 import AdapterManifest, AdapterResultInspection, ResourceAdapter
from proxy.tool_security_v2 import ClaimedResourceReference, NormalizedBindingFacts, NormalizedEffectFacts, ReferencePrecision


class Adapter(ResourceAdapter):
    manifest = AdapterManifest(
        adapter_id="widget-adapter",
        adapter_api_version="1",
        implementation_version="1.0.0",
        supported_capabilities=("widget.execute",),
        supported_resource_types=("widget_resource",),
        display_name="Widget Adapter",
        family="widget",
        publisher="runtime-test",
        trust_level="SIGNED_REVIEWED",
        argument_validation="canonical_widget_identifier",
        result_validation="bounded_widget_result",
    )

    def resolve(self, canonical_args, effect, adapter_resolution, trusted_authority_context):
        binding = effect.resource_bindings[0]
        value = canonical_args.get(binding.path[0])
        valid = isinstance(value, str) and value.strip() and len(value) <= 128
        reference = ()
        if valid:
            reference = (ClaimedResourceReference(
                authority=trusted_authority_context["authority"],
                resource_type=binding.resource_type,
                canonical_value="widget:" + value.strip().lower(),
                ancestors=(),
                resource_sensitivity="internal",
            ),)
        runtime_precision = ReferencePrecision.EXPLICIT if valid else ReferencePrecision.OPAQUE
        return NormalizedEffectFacts(
            effect_id=effect.effect_id,
            capability_id=effect.capability,
            requires_resource=True,
            adapter_id=adapter_resolution.adapter_id,
            adapter_api_version=adapter_resolution.adapter_api_version,
            declared_reference_precision=effect.declared_reference_precision,
            runtime_reference_precision=runtime_precision,
            effective_reference_precision=runtime_precision,
            max_resource_cardinality=effect.max_resource_cardinality,
            bindings=(NormalizedBindingFacts(
                path=binding.path,
                status="resolved" if valid else "invalid",
                resource_type=binding.resource_type,
                role=binding.role,
                occurrence_count=len(reference),
                references=reference,
            ),),
        )

    def inspect_result(self, result):
        content = result.get("structuredContent") if isinstance(result, dict) else None
        valid = isinstance(content, dict) and isinstance(content.get("widget_id"), str)
        return AdapterResultInspection(not valid, () if valid else ("widget_result_invalid",))
'''


class TrustedAdapterPackageTests(unittest.TestCase):
    def test_unknown_tool_guidance_keeps_generic_and_specialized_paths_distinct(self):
        tool = SimpleNamespace(
            name="transmute_widget",
            title="Transmute Widget",
            description="Apply a proprietary transformation to a widget reference.",
            input_schema={
                "type": "object",
                "properties": {"widget": {"type": "string", "maxLength": 128}},
                "required": ["widget"],
                "additionalProperties": False,
            },
        )
        guidance = adapter_guidance_for_tool(tool)
        self.assertEqual(guidance["status"], "NO_COMPATIBLE_TEMPLATE")
        self.assertTrue(guidance["generic_declarative_available"])
        self.assertEqual(guidance["closest_adapters"], ())
        self.assertEqual(guidance["recommended_starter"], "blank")
        self.assertEqual(
            {item["starter_id"] for item in guidance["starters"]},
            {"blank", "sql", "shell", "payment", "cloud-iam", "git", "messaging"},
        )

    def test_all_starter_archives_are_bounded_and_fail_closed(self):
        starters = adapter_starter_catalog()
        self.assertEqual(
            {item["starter_id"] for item in starters},
            {"blank", "sql", "shell", "payment", "cloud-iam", "git", "messaging"},
        )
        for item in starters:
            starter_id = item["starter_id"]
            adapter_id = f"cert-{starter_id}-adapter"
            with self.subTest(starter_id=starter_id):
                archive = build_adapter_starter_archive(starter_id, adapter_id)
                self.assertLess(len(archive), 1_000_000)
                with zipfile.ZipFile(io.BytesIO(archive)) as package:
                    self.assertEqual(
                        set(package.namelist()),
                        {"manifest.json", "adapter.py", "tests/test_adapter.py", "README.md"},
                    )
                    manifest = json.loads(package.read("manifest.json"))
                    source = package.read("adapter.py").decode("utf-8")
                    test_source = package.read("tests/test_adapter.py").decode("utf-8")
                self.assertEqual(manifest["adapter_id"], adapter_id)
                self.assertEqual(manifest["adapter_api_version"], "1")
                self.assertEqual(manifest["trust_level"], "SIGNED_REVIEWED")
                self.assertIn('raise SecurityModelError("adapter_not_implemented")', source)
                self.assertIn(
                    'AdapterResultInspection(True, ("adapter_result_not_implemented",))',
                    source,
                )
                self.assertIn("test_starter_fails_closed_until_implemented", test_source)

    def test_signed_adapter_loads_only_for_trusted_signer_and_enters_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            self._write_widget_source(source)
            key = ed25519.Ed25519PrivateKey.generate()
            archive = create_signed_adapter_archive(
                source,
                private_key_pem=_private_key_pem(key),
            )
            fingerprint = _fingerprint(key)

            with self.assertRaisesRegex(SecurityModelError, "adapter_signer_not_trusted"):
                verify_adapter_archive(
                    archive,
                    trusted_signer_fingerprints=("0" * 64,),
                )
            with self.assertRaisesRegex(SecurityModelError, "adapter_signature_invalid"):
                verify_adapter_archive(
                    _tamper_source(archive),
                    trusted_signer_fingerprints=(fingerprint,),
                )

            registration = verify_adapter_archive(
                archive,
                trusted_signer_fingerprints=(fingerprint,),
            )
            package = _widget_pack()
            registry = AdapterRegistry(
                security_packs=(package,),
                trusted_adapters=(registration,),
            )
            resolved = registry.resolve("widget.execute", "widget_resource")
            self.assertEqual(resolved.adapter_id, "widget-adapter")
            self.assertEqual(resolved.trust_level, "SIGNED_REVIEWED")

            contract = ToolSecurityContract(
                server_ref="streamable_http:https://widgets.example/mcp",
                tool_name="transmute_widget",
                effects=(ToolEffect(
                    effect_id="widget.execute",
                    capability="widget.execute",
                    resource_bindings=(ResourceBinding(
                        path=("widget",),
                        resource_type="widget_resource",
                    ),),
                    max_resource_cardinality=1,
                ),),
            )
            schema = {
                "type": "object",
                "properties": {"widget": {"type": "string", "maxLength": 128}},
                "required": ["widget"],
                "additionalProperties": False,
            }
            resolutions = validate_contract_for_schema(
                contract,
                schema,
                capability_catalog=registry.capabilities,
                resource_type_registry=registry.resource_types,
                adapter_resolver=registry,
            )
            with patch(
                "proxy.resource_adapters_v2.registered_trusted_adapters",
                return_value=(registration,),
            ):
                prepared = prepare_tool_request_v2(
                    raw_arguments={"widget": "ALPHA-42"},
                    input_schema=schema,
                    contract=contract,
                    adapter_resolutions=resolutions,
                    approval=ToolObservationApproval(
                        tool_observation_id=1,
                        server_ref=contract.server_ref,
                        upstream_protocol_profile_id="modern-2025-11-25",
                        tool_fingerprint="a" * 64,
                        contract_hash=contract.contract_hash,
                        evidence_bundle_hash="b" * 64,
                        admin_id="admin",
                        approved_at="2026-01-01T00:00:00Z",
                        revision_id="revision-widget",
                    ),
                    authority_scopes=(AuthorityResourceScope(
                        scope_id="widget-alpha",
                        authority=contract.server_ref,
                        resource_type="widget_resource",
                        canonical_value="widget:alpha-42",
                        match_mode=ScopeMatchMode.SELF,
                    ),),
                    authority_context={},
                    client_protocol_profile_id="modern-2025-11-25",
                    upstream_protocol_profile_id="modern-2025-11-25",
                    security_packs=(package,),
                )
            self.assertTrue(prepared.arguments_valid)
            self.assertEqual(prepared.resource_adapter, "widget-adapter")
            self.assertEqual(prepared.canonical_resource, "widget:alpha-42")
            self.assertFalse(
                inspect_adapter_result(
                    {"structuredContent": {"widget_id": "alpha-42"}},
                    resolutions,
                    registry=registry,
                ).blocked
            )
            self.assertTrue(
                inspect_adapter_result({}, resolutions, registry=registry).blocked
            )

    def test_install_and_directory_load_detect_collisions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            self._write_widget_source(source)
            key = ed25519.Ed25519PrivateKey.generate()
            archive = create_signed_adapter_archive(source, private_key_pem=_private_key_pem(key))
            fingerprint = _fingerprint(key)
            installed = install_adapter_archive(
                archive,
                destination_directory=root / "installed",
                trusted_signer_fingerprints=(fingerprint,),
            )
            self.assertEqual(installed.name, "widget-adapter.zip")
            registrations = load_adapter_directory(
                installed.parent,
                trusted_signer_fingerprints=(fingerprint,),
            )
            self.assertEqual(registrations[0].adapter.manifest.adapter_id, "widget-adapter")

            other_key = ed25519.Ed25519PrivateKey.generate()
            (source / "adapter.py").write_text(
                WIDGET_ADAPTER_SOURCE + "\n# different reviewed distribution\n",
                encoding="utf-8",
            )
            other_archive = create_signed_adapter_archive(
                source,
                private_key_pem=_private_key_pem(other_key),
            )
            with self.assertRaisesRegex(SecurityModelError, "adapter_id_collision"):
                install_adapter_archive(
                    other_archive,
                    destination_directory=installed.parent,
                    trusted_signer_fingerprints=(fingerprint, _fingerprint(other_key)),
                )

    @staticmethod
    def _write_widget_source(directory: Path) -> None:
        import json

        (directory / "manifest.json").write_text(
            json.dumps(WIDGET_MANIFEST),
            encoding="utf-8",
        )
        (directory / "adapter.py").write_text(WIDGET_ADAPTER_SOURCE, encoding="utf-8")


def _widget_pack() -> SecurityPackManifest:
    return SecurityPackManifest(
        id="widget-pack",
        version="1.0.0",
        title="Widget Pack",
        description="Runtime package for a proprietary widget family.",
        origin="DECLARATIVE",
        capabilities=(PackCapability(
            id="widget.execute",
            domain="widget",
            verb="execute",
            requires_resource=True,
            allowed_resource_types=("widget_resource",),
        ),),
        resource_types=(PackResourceType(
            id="widget_resource",
            canonicalizer="hierarchical_name",
            hierarchy_support=True,
            allowed_matching_modes=("SELF", "SUBTREE"),
            adapter_id="widget-adapter",
            requires_specialized_interpretation=True,
        ),),
    )


def _private_key_pem(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _fingerprint(key: ed25519.Ed25519PrivateKey) -> str:
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return signer_fingerprint(public_pem)


def _tamper_source(archive: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(archive)) as source, zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as destination:
        for name in source.namelist():
            value = source.read(name)
            if name == "adapter.py":
                value += b"\n# tampered\n"
            destination.writestr(name, value)
    return output.getvalue()


if __name__ == "__main__":
    unittest.main()
