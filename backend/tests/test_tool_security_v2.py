import unittest

from pydantic import ValidationError

from proxy.resource_adapters_v2 import AdapterRegistry, resolve_effect_facts
from proxy.tool_security_v2 import (
    AuthorityResourceScope,
    ReferencePrecision,
    ResourceBinding,
    ResourceTypeRegistry,
    ScopeMatchMode,
    SecurityModelError,
    SupportedSchemaProfileV1,
    ToolEffect,
    ToolSecurityContract,
    validate_contract_for_schema,
    validate_scope,
)
from scripts.evaluate_mcp_gateway import evaluate_inventory


def send_email_schema():
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "recipient": {"type": "string", "maxLength": 254},
            "subject": {"type": "string", "maxLength": 200},
            "body": {"type": "string", "maxLength": 10000},
        },
        "required": ["recipient", "subject", "body"],
    }


def send_email_contract():
    return ToolSecurityContract(
        server_ref="streamable_http:http://127.0.0.1:9100/mcp",
        tool_name="send_email",
        effects=(
            ToolEffect(
                effect_id="send-message",
                capability="message.send",
                resource_bindings=(
                    ResourceBinding(path=("recipient",), resource_type="email_address"),
                ),
                declared_reference_precision=ReferencePrecision.EXPLICIT,
            ),
        ),
        unbound_arguments=(("subject",), ("body",)),
    )


class SupportedSchemaProfileTests(unittest.TestCase):
    def test_supported_schema_has_deterministic_accountable_paths(self):
        self.assertEqual(
            SupportedSchemaProfileV1.validate(send_email_schema()),
            (("body",), ("recipient",), ("subject",)),
        )

    def test_offline_evaluation_harness_reports_genericity_and_rejections(self):
        report = evaluate_inventory(
            {
                "server": {
                    "endpoint": "http://127.0.0.1:9100/mcp",
                    "transport": "streamable_http",
                    "supported_protocol_profiles": ["modern", "legacy"],
                },
                "tools": [
                    {
                        "name": "send_email",
                        "upstream_protocol_profile_id": "modern",
                        "input_schema": send_email_schema(),
                    },
                    {
                        "name": "unsafe_dynamic",
                        "upstream_protocol_profile_id": "legacy",
                        "input_schema": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": True,
                        },
                    },
                ],
            }
        )
        self.assertEqual(report["tools_discovered"], 2)
        self.assertEqual(report["tools_generically_onboardable"], 1)
        self.assertEqual(report["tools_rejected"], 1)
        send_email = report["tools"][0]
        self.assertEqual(send_email["tool_specific_python_authorization_loc"], 0)
        self.assertEqual(send_email["tool_specific_rego_loc"], 0)

    def test_unsupported_or_unbounded_schema_is_rejected(self):
        for schema in (
            {"type": "object", "properties": {}, "additionalProperties": True},
            {"type": "object", "properties": {}, "additionalProperties": False, "$ref": "x"},
            {
                "type": "object",
                "properties": {
                    "region": {
                        "type": "string",
                        "maxLength": 64,
                        "x-mcp-header": "Region",
                    }
                },
                "required": ["region"],
                "additionalProperties": False,
            },
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"n": {"type": "number"}},
            },
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"items": {"type": "array", "items": {"type": "string"}}},
            },
        ):
            with self.subTest(schema=schema):
                with self.assertRaises(SecurityModelError):
                    SupportedSchemaProfileV1.validate(schema)


class ContractAdmissionTests(unittest.TestCase):
    def test_generic_send_email_contract_resolves_without_tool_branch(self):
        resolutions = validate_contract_for_schema(
            send_email_contract(),
            send_email_schema(),
        )
        self.assertEqual(len(resolutions), 1)
        self.assertEqual(resolutions[0].adapter_id, "generic-declarative")

    def test_unknown_capability_is_rejected(self):
        contract = send_email_contract().model_copy(
            update={
                "effects": (
                    send_email_contract().effects[0].model_copy(
                        update={"capability": "message.unknown"}
                    ),
                )
            }
        )
        with self.assertRaisesRegex(SecurityModelError, "unknown_capability"):
            validate_contract_for_schema(contract, send_email_schema())

    def test_incompatible_type_and_missing_adapter_are_rejected(self):
        contract = send_email_contract().model_copy(
            update={
                "effects": (
                    send_email_contract().effects[0].model_copy(
                        update={
                            "resource_bindings": (
                                ResourceBinding(
                                    path=("recipient",),
                                    resource_type="filesystem_path",
                                ),
                            )
                        }
                    ),
                )
            }
        )
        with self.assertRaisesRegex(SecurityModelError, "capability_resource_type_incompatible"):
            validate_contract_for_schema(contract, send_email_schema())

    def test_total_input_accounting_is_mandatory_and_disjoint(self):
        missing = send_email_contract().model_copy(update={"unbound_arguments": (("subject",),)})
        with self.assertRaisesRegex(SecurityModelError, "unaccounted_schema_argument"):
            validate_contract_for_schema(missing, send_email_schema())

        overlap = send_email_contract().model_copy(
            update={"unbound_arguments": (("recipient",), ("subject",), ("body",))}
        )
        with self.assertRaisesRegex(SecurityModelError, "argument_bound_and_unbound"):
            validate_contract_for_schema(overlap, send_email_schema())

    def test_invalid_binding_token_and_missing_schema_path_are_rejected(self):
        with self.assertRaises(ValidationError):
            ResourceBinding(path=("$bad",), resource_type="email_address")
        contract = send_email_contract().model_copy(
            update={"unbound_arguments": (("subject",), ("missing",))}
        )
        with self.assertRaisesRegex(SecurityModelError, "contract_path_not_in_schema"):
            validate_contract_for_schema(contract, send_email_schema())


class ResourceTypeAndAdapterTests(unittest.TestCase):
    def test_authority_is_preserved_in_claimed_reference(self):
        contract = send_email_contract()
        resolution = validate_contract_for_schema(contract, send_email_schema())[0]
        facts = resolve_effect_facts(
            {"recipient": "Alice@example.COM", "subject": "Hi", "body": "Text"},
            contract.effects[0],
            resolution,
            {"authority": "demo-mail-server"},
        )
        reference = facts.bindings[0].references[0]
        self.assertEqual(reference.authority, "demo-mail-server")
        self.assertEqual(reference.canonical_value, "Alice@example.com")
        self.assertEqual(facts.effective_reference_precision, ReferencePrecision.EXPLICIT)

    def test_occurrences_are_counted_before_deduplication(self):
        schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "recipients": {
                    "type": "array",
                    "maxItems": 10,
                    "items": {"type": "string", "maxLength": 254},
                }
            },
            "required": ["recipients"],
        }
        contract = ToolSecurityContract(
            server_ref="mail-a",
            tool_name="bulk_send",
            effects=(
                ToolEffect(
                    effect_id="send-message",
                    capability="message.send",
                    resource_bindings=(
                        ResourceBinding(path=("recipients", "*"), resource_type="email_address"),
                    ),
                    max_resource_cardinality=2,
                ),
            ),
        )
        resolution = validate_contract_for_schema(contract, schema)[0]
        facts = resolve_effect_facts(
            {"recipients": ["a@example.com", "a@example.com", "a@example.com"]},
            contract.effects[0],
            resolution,
            {"authority": "mail-a"},
        )
        self.assertEqual(facts.bindings[0].occurrence_count, 3)

    def test_filesystem_ancestors_do_not_use_string_prefix_matching(self):
        canonical, ancestors = ResourceTypeRegistry().canonicalize(
            "filesystem_path",
            "/database-secret",
            {"filesystem_path_mode": "ABSOLUTE"},
        )
        self.assertEqual(canonical, "/database-secret")
        self.assertNotIn("/data", ancestors)

    def test_filesystem_relative_rooted_authority_rejects_absolute_and_ambiguous_paths(self):
        registry = ResourceTypeRegistry()
        canonical, ancestors = registry.canonicalize(
            "filesystem_path",
            "contracts/a.txt",
            {"filesystem_path_mode": "RELATIVE_ROOTED"},
        )
        self.assertEqual(canonical, "contracts/a.txt")
        self.assertEqual(ancestors, ("contracts", "contracts/a.txt"))

        for value, code in (
            ("/contracts/a.txt", "filesystem_path_absolute_unsupported"),
            ("contracts/./a.txt", "filesystem_path_dot_segment"),
            ("contracts/../secret.txt", "filesystem_path_traversal"),
            ("contracts-secret", None),
        ):
            with self.subTest(value=value):
                if code is None:
                    canonical, ancestors = registry.canonicalize(
                        "filesystem_path",
                        value,
                        {"filesystem_path_mode": "RELATIVE_ROOTED"},
                    )
                    self.assertEqual(canonical, "contracts-secret")
                    self.assertNotIn("contracts", ancestors)
                else:
                    with self.assertRaisesRegex(SecurityModelError, code):
                        registry.canonicalize(
                            "filesystem_path",
                            value,
                            {"filesystem_path_mode": "RELATIVE_ROOTED"},
                        )

    def test_filesystem_authorities_remain_isolated(self):
        registry = ResourceTypeRegistry()
        canonical, _ = registry.canonicalize(
            "filesystem_path",
            "contracts/a.txt",
            {"filesystem_path_mode": "RELATIVE_ROOTED"},
        )
        ref_a = ("authority-a", canonical)
        ref_b = ("authority-b", canonical)
        self.assertNotEqual(ref_a, ref_b)

    def test_filesystem_does_not_collapse_relative_absolute_or_dot_forms(self):
        registry = ResourceTypeRegistry()
        accepted, _ = registry.canonicalize(
            "filesystem_path",
            "contracts/a.txt",
            {"filesystem_path_mode": "RELATIVE_ROOTED"},
        )
        self.assertEqual(accepted, "contracts/a.txt")
        with self.assertRaises(SecurityModelError):
            registry.canonicalize(
                "filesystem_path",
                "/contracts/a.txt",
                {"filesystem_path_mode": "RELATIVE_ROOTED"},
            )
        with self.assertRaises(SecurityModelError):
            registry.canonicalize(
                "filesystem_path",
                "contracts/./a.txt",
                {"filesystem_path_mode": "RELATIVE_ROOTED"},
            )

    def test_email_only_supports_self_scope(self):
        scope = AuthorityResourceScope(
            scope_id="alice-mail",
            authority="mail-a",
            resource_type="email_address",
            canonical_value="alice@example.com",
            match_mode=ScopeMatchMode.SUBTREE,
        )
        with self.assertRaisesRegex(SecurityModelError, "scope_match_mode_unsupported"):
            validate_scope(scope)

    def test_root_subtree_requires_explicit_acknowledgement(self):
        scope = AuthorityResourceScope(
            scope_id="filesystem-root",
            authority="files-a",
            resource_type="filesystem_path",
            canonical_value="/",
            match_mode=ScopeMatchMode.SUBTREE,
            broad_scope_acknowledged=False,
        )
        with self.assertRaisesRegex(SecurityModelError, "root_subtree_requires_acknowledgement"):
            validate_scope(
                scope,
                authority_config={"filesystem_path_mode": "ABSOLUTE"},
            )
        accepted = validate_scope(
            scope.model_copy(update={"broad_scope_acknowledged": True}),
            authority_config={"filesystem_path_mode": "ABSOLUTE"},
        )
        self.assertEqual(accepted.canonical_value, "/")

    def test_adapter_interface_has_no_authorization_inputs(self):
        adapter = AdapterRegistry().get("generic-declarative")
        argument_names = adapter.resolve.__code__.co_varnames[: adapter.resolve.__code__.co_argcount]
        self.assertNotIn("grants", argument_names)
        self.assertNotIn("scopes", argument_names)
        self.assertNotIn("decision", argument_names)

    def test_legacy_upstream_pool_isolated_by_framework_session(self):
        from proxy.protocol_sessions import LegacyUpstreamSessionPool

        pool = LegacyUpstreamSessionPool()
        created = []

        def factory():
            value = object()
            created.append(value)
            return value

        first = pool.get_or_create(
            framework_session_id="agent-session-a",
            server_id=1,
            profile_id="legacy",
            factory=factory,
        )
        same = pool.get_or_create(
            framework_session_id="agent-session-a",
            server_id=1,
            profile_id="legacy",
            factory=factory,
        )
        second = pool.get_or_create(
            framework_session_id="agent-session-b",
            server_id=1,
            profile_id="legacy",
            factory=factory,
        )
        self.assertIs(first, same)
        self.assertIsNot(first, second)
        self.assertEqual(len(created), 2)


if __name__ == "__main__":
    unittest.main()
