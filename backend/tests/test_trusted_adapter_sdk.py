import base64
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from proxy.resource_adapters_v2 import (
    AdapterManifest,
    AdapterRegistry,
    AdapterResultInspection,
    ResourceAdapter,
    TrustedAdapterRegistration,
    inspect_adapter_result,
    resolve_effect_facts,
    verify_trusted_adapter_distribution,
)
from proxy.security_packs import builtin_security_packs
from proxy.tool_security_v2 import (
    AdapterResolution,
    ReferencePrecision,
    ResourceBinding,
    SecurityModelError,
    ToolEffect,
)


SPECIALIZED_CASES = (
    (
        "database.sql.read",
        "sql_database_object",
        "query",
        "SELECT total FROM Finance.Accounts",
        "finance.accounts",
    ),
    (
        "process.shell.execute",
        "shell_executable",
        "command",
        "git status --short",
        "git",
    ),
    (
        "payment.transfer.execute",
        "payment_destination",
        "recipient",
        "merchant:acct-42",
        "merchant:acct-42",
    ),
    (
        "cloud.iam.mutate",
        "cloud_iam_resource",
        "arn",
        "arn:aws:iam::123456789012:role/Operator",
        "arn:aws:iam::123456789012:role/Operator",
    ),
    (
        "git.repository.write",
        "git_repository_ref",
        "repository",
        "github.com/OpenAI/Codex#main",
        "github.com/openai/codex:main",
    ),
    (
        "message.delivery.send",
        "message_destination",
        "recipient",
        "Admin@Example.COM",
        "email:Admin:example.com",
    ),
)


class TrustedAdapterSDKTests(unittest.TestCase):
    def test_catalog_exposes_reviewed_versioned_adapters(self):
        catalog = AdapterRegistry().catalog()
        by_id = {item["adapter_id"]: item for item in catalog}
        self.assertTrue({"sql", "shell", "payment", "cloud-iam", "git", "messaging"} <= set(by_id))
        for adapter_id in ("sql", "shell", "payment", "cloud-iam", "git", "messaging"):
            self.assertEqual(by_id[adapter_id]["adapter_api_version"], "1")
            self.assertEqual(by_id[adapter_id]["trust_level"], "BUILTIN_REVIEWED")
            self.assertNotEqual(by_id[adapter_id]["argument_validation"], "")
            self.assertNotEqual(by_id[adapter_id]["result_validation"], "")

    def test_specialized_pack_is_opt_in_and_does_not_replace_legacy_resources(self):
        packs = {pack.id: pack for pack in builtin_security_packs()}
        specialized = packs["trusted-adapter-examples"]
        self.assertEqual(len(specialized.resource_types), 6)
        self.assertTrue(all(item.requires_specialized_interpretation for item in specialized.resource_types))
        self.assertEqual(
            {item.adapter_id for item in specialized.resource_types},
            {"sql", "shell", "payment", "cloud-iam", "git", "messaging"},
        )
        database = packs["database"]
        self.assertEqual(database.resource_types[0].adapter_id, "generic-declarative")

    def test_each_specialized_adapter_extracts_a_canonical_resource(self):
        registry = AdapterRegistry()
        for capability, resource_type, field, raw_value, expected in SPECIALIZED_CASES:
            with self.subTest(adapter=resource_type):
                effect = _effect(capability, resource_type, field)
                manifest = registry.resolve(capability, resource_type)
                resolution = _resolution(effect, resource_type, manifest)
                facts = resolve_effect_facts(
                    {field: raw_value},
                    effect,
                    resolution,
                    {"authority": "qa-mcp"},
                    registry=registry,
                )
                self.assertEqual(facts.bindings[0].status, "resolved")
                reference = facts.bindings[0].references[0]
                self.assertEqual(reference.canonical_value, expected)
                scope_value, scope_ancestors = registry.resource_types.canonicalize(
                    resource_type,
                    expected,
                    {},
                )
                self.assertEqual(reference.canonical_value, scope_value)
                self.assertEqual(reference.ancestors, scope_ancestors)
                self.assertEqual(facts.effective_reference_precision, ReferencePrecision.EXPLICIT)

    def test_sql_and_shell_ambiguity_fail_closed_to_opaque(self):
        registry = AdapterRegistry()
        for capability, resource_type, field, value in (
            ("database.sql.read", "sql_database_object", "query", "SELECT * FROM a; DELETE FROM b"),
            ("database.sql.read", "sql_database_object", "query", "SELECT 1"),
            ("database.sql.read", "sql_database_object", "query", "DELETE FROM accounts"),
            ("process.shell.execute", "shell_executable", "command", "echo ok && cat /etc/passwd"),
            ("process.shell.execute", "shell_executable", "command", "echo $(whoami)"),
        ):
            with self.subTest(value=value):
                effect = _effect(capability, resource_type, field)
                manifest = registry.resolve(capability, resource_type)
                facts = resolve_effect_facts(
                    {field: value},
                    effect,
                    _resolution(effect, resource_type, manifest),
                    {"authority": "qa-mcp"},
                    registry=registry,
                )
                self.assertEqual(facts.bindings[0].status, "invalid")
                self.assertEqual(facts.effective_reference_precision, ReferencePrecision.OPAQUE)

    def test_specialized_result_validation_blocks_malformed_structured_results(self):
        registry = AdapterRegistry()
        cases = (
            ("sql", {"structuredContent": "not-an-object"}, "adapter_result_structured_content_invalid"),
            ("sql", {"structuredContent": {"rows": "not-a-list"}}, "sql_result_rows_invalid"),
            ("shell", {"structuredContent": {"exit_code": "zero"}}, "shell_result_exit_code_invalid"),
            ("payment", {"structuredContent": {"status": "invented"}}, "payment_result_status_invalid"),
            ("cloud-iam", {"structuredContent": {"changed_resources": "many"}}, "cloud_iam_result_resources_invalid"),
            ("git", {"structuredContent": {"changed_files": "many"}}, "git_result_changed_files_invalid"),
            ("messaging", {"structuredContent": {"receipts": "many"}}, "messaging_result_receipts_invalid"),
        )
        for adapter_id, result, finding in cases:
            with self.subTest(adapter=adapter_id):
                manifest = registry.get(adapter_id).manifest
                inspection = inspect_adapter_result(
                    result,
                    (AdapterResolution(
                        effect_id="qa",
                        resource_type=manifest.supported_resource_types[0],
                        adapter_id=adapter_id,
                        adapter_api_version=manifest.adapter_api_version,
                        implementation_version=manifest.implementation_version,
                    ),),
                    registry=registry,
                )
                self.assertTrue(inspection.blocked)
                self.assertIn(finding, inspection.finding_codes)

    def test_adapter_result_exception_fails_closed(self):
        resolution = AdapterResolution(
            effect_id="qa",
            resource_type="widget_resource",
            adapter_id="broken-result",
            adapter_api_version="1",
            implementation_version="1.0.0",
        )
        inspection = inspect_adapter_result(
            {"structuredContent": {"widget_id": "alpha-42"}},
            (resolution,),
            registry=BrokenResultRegistry(),
        )
        self.assertTrue(inspection.blocked)
        self.assertEqual(
            inspection.finding_codes,
            ("adapter_result_inspection_error",),
        )

    def test_unsigned_external_adapter_is_rejected(self):
        unsigned = TrustedAdapterRegistration(
            adapter=SignedExternalAdapter(),
            distribution_sha256="a" * 64,
            signer_key_fingerprint="b" * 64,
            _verification_marker=object(),
        )
        with self.assertRaisesRegex(
            SecurityModelError,
            "external_adapter_signature_required",
        ):
            AdapterRegistry(trusted_adapters=(unsigned,))

    def test_unsupported_adapter_api_version_is_rejected(self):
        incompatible = TrustedAdapterRegistration(
            adapter=UnsupportedApiAdapter(),
            distribution_sha256="a" * 64,
            signer_key_fingerprint="b" * 64,
            _verification_marker=object(),
        )
        with self.assertRaisesRegex(
            SecurityModelError,
            "adapter_api_version_unsupported",
        ):
            AdapterRegistry(trusted_adapters=(incompatible,))

    def test_stale_resolution_and_external_signature_verification_fail_closed(self):
        registry = AdapterRegistry()
        stale = AdapterResolution(
            effect_id="qa",
            resource_type="sql_database_object",
            adapter_id="sql",
            adapter_api_version="1",
            implementation_version="0.9.0",
        )
        self.assertEqual(
            inspect_adapter_result({}, (stale,), registry=registry).finding_codes,
            ("adapter_resolution_stale",),
        )
        adapter = SignedExternalAdapter()
        private = ed25519.Ed25519PrivateKey.generate()
        public_pem = private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        distribution = b"reviewed adapter distribution"
        invalid_signature = ed25519.Ed25519PrivateKey.generate().sign(distribution)
        with self.assertRaisesRegex(SecurityModelError, "adapter_signature_invalid"):
            verify_trusted_adapter_distribution(
                adapter,
                distribution=distribution,
                public_key_pem=public_pem,
                signature_base64=base64.b64encode(invalid_signature).decode("ascii"),
            )

        registration = verify_trusted_adapter_distribution(
            adapter,
            distribution=distribution,
            public_key_pem=public_pem,
            signature_base64=base64.b64encode(private.sign(distribution)).decode("ascii"),
        )
        catalog = {
            item["adapter_id"]: item
            for item in AdapterRegistry(trusted_adapters=(registration,)).catalog()
        }
        self.assertTrue(catalog["external-test"]["signature_verified"])
        self.assertEqual(len(catalog["external-test"]["distribution_sha256"]), 64)
        self.assertEqual(len(catalog["external-test"]["signer_key_fingerprint"]), 64)


class BrokenResultAdapter(ResourceAdapter):
    manifest = AdapterManifest(
        adapter_id="broken-result",
        adapter_api_version="1",
        implementation_version="1.0.0",
        supported_capabilities=("widget.execute",),
        supported_resource_types=("widget_resource",),
    )

    def resolve(self, canonical_args, effect, adapter_resolution, trusted_authority_context):
        raise AssertionError("result-only test adapter must not resolve arguments")

    def inspect_result(self, result):
        raise TypeError("simulated adapter result failure")


class BrokenResultRegistry:
    def __init__(self):
        self.adapter = BrokenResultAdapter()

    def get(self, adapter_id):
        if adapter_id != self.adapter.manifest.adapter_id:
            raise AssertionError("unexpected adapter id")
        return self.adapter


class UnsupportedApiAdapter(ResourceAdapter):
    manifest = AdapterManifest(
        adapter_id="unsupported-api-test",
        adapter_api_version="2",
        implementation_version="1.0.0",
        supported_capabilities=("*",),
        supported_resource_types=("*",),
        trust_level="SIGNED_REVIEWED",
    )

    def resolve(self, canonical_args, effect, adapter_resolution, trusted_authority_context):
        raise AssertionError("unsupported adapter API must never be called")

    def inspect_result(self, result):
        return AdapterResultInspection()


class SignedExternalAdapter(ResourceAdapter):
    manifest = AdapterManifest(
        adapter_id="external-test",
        adapter_api_version="1",
        implementation_version="1.0.0",
        supported_capabilities=("*",),
        supported_resource_types=("*",),
        trust_level="SIGNED_REVIEWED",
    )

    def resolve(self, canonical_args, effect, adapter_resolution, trusted_authority_context):
        raise AssertionError("unsigned adapter must never be called")

    def inspect_result(self, result):
        return AdapterResultInspection()


def _effect(capability, resource_type, field):
    return ToolEffect(
        effect_id=f"qa-{resource_type}",
        capability=capability,
        resource_bindings=(ResourceBinding(path=(field,), resource_type=resource_type),),
        max_resource_cardinality=64,
        declared_reference_precision=ReferencePrecision.EXPLICIT,
    )


def _resolution(effect, resource_type, manifest):
    return AdapterResolution(
        effect_id=effect.effect_id,
        resource_type=resource_type,
        adapter_id=manifest.adapter_id,
        adapter_api_version=manifest.adapter_api_version,
        implementation_version=manifest.implementation_version,
    )


if __name__ == "__main__":
    unittest.main()
