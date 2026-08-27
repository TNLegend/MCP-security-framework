import unittest
from unittest.mock import patch

from pydantic import ValidationError

from proxy.resource_adapters_v2 import AdapterRegistry, resolve_effect_facts
from proxy.security_packs import PackCapability, PackResourceType, SecurityPackManifest
from proxy.tool_request_preparation import prepare_tool_request_v2
from proxy.tool_security_v2 import (
    ArgumentConstraint,
    AuthorityResourceScope,
    CapabilityCatalog,
    FixedResourceReference,
    ReferencePrecision,
    ResourceBinding,
    ResourceTypeRegistry,
    ScopeMatchMode,
    SecurityModelError,
    SupportedSchemaProfileV1,
    ToolEffect,
    ToolObservationApproval,
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


def transfer_pack():
    resource = PackResourceType(
        id="lot3_account",
        canonicalizer="hierarchical_name",
        hierarchy_support=True,
        allowed_matching_modes=("SELF", "SUBTREE"),
        adapter_id="generic-declarative",
    )
    return SecurityPackManifest(
        id="lot3-transfer",
        version="1.0.0",
        title="Lot 3 Transfer",
        description="Advanced multi-effect transfer pack",
        origin="DECLARATIVE",
        capabilities=(
            PackCapability(
                id="lot3_transfer.debit",
                domain="lot3_transfer",
                verb="debit",
                destructive=True,
                external_effect=True,
                allowed_resource_types=(resource.id,),
            ),
            PackCapability(
                id="lot3_transfer.credit",
                domain="lot3_transfer",
                verb="credit",
                external_effect=True,
                allowed_resource_types=(resource.id,),
            ),
        ),
        resource_types=(resource,),
    )


def transfer_schema():
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "source_account": {"type": "string", "maxLength": 128},
            "destination_account": {"type": "string", "maxLength": 128},
            "amount": {"type": "number", "minimum": 0, "maximum": 1000000},
        },
        "required": ["source_account", "destination_account", "amount"],
    }


def transfer_contract():
    return ToolSecurityContract(
        server_ref="transfer-a",
        tool_name="transfer_payment",
        effects=(
            ToolEffect(
                effect_id="debit",
                capability="lot3_transfer.debit",
                resource_bindings=(
                    ResourceBinding(
                        path=("source_account",),
                        resource_type="lot3_account",
                        role="SOURCE",
                    ),
                ),
            ),
            ToolEffect(
                effect_id="credit",
                capability="lot3_transfer.credit",
                resource_bindings=(
                    ResourceBinding(
                        path=("destination_account",),
                        resource_type="lot3_account",
                        role="DESTINATION",
                    ),
                ),
            ),
        ),
        argument_constraints=(
            ArgumentConstraint(
                constraint_id="amount-limit",
                path=("amount",),
                operator="LE",
                value=500,
            ),
        ),
        unbound_arguments=(("amount",),),
    )


def transfer_resolutions(contract, pack):
    return validate_contract_for_schema(
        contract,
        transfer_schema(),
        capability_catalog=CapabilityCatalog(security_packs=(pack,)),
        resource_type_registry=ResourceTypeRegistry(security_packs=(pack,)),
        adapter_resolver=AdapterRegistry(security_packs=(pack,)),
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
            {"$ref": "https://vendor.example/schema.json"},
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

    def test_conditional_action_selector_schema_is_rejected(self):
        selectors = (
            ("action", {"type": "string", "maxLength": 16, "enum": ["read", "export"]}),
            ("verb", {"type": "string", "maxLength": 16, "enum": ["read", "delete"]}),
            ("delete", {"type": "boolean"}),
        )
        for name, selector_schema in selectors:
            with self.subTest(name=name), self.assertRaisesRegex(
                SecurityModelError,
                "conditional_selector_schema_unsupported",
            ):
                SupportedSchemaProfileV1.validate(
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            name: selector_schema,
                            "path": {"type": "string", "maxLength": 4096},
                        },
                        "required": [name, "path"],
                    }
                )

    def test_ordinary_string_enum_remains_supported(self):
        schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "format": {
                    "type": "string",
                    "maxLength": 16,
                    "enum": ["json", "text"],
                }
            },
            "required": ["format"],
        }

        self.assertEqual(SupportedSchemaProfileV1.validate(schema), (("format",),))

    def test_local_defs_nullable_and_equivalent_unions_are_supported(self):
        schema = {
            "type": "object",
            "additionalProperties": False,
            "$defs": {
                "destination": {"type": ["string", "null"], "maxLength": 512},
            },
            "properties": {
                "url": {"$ref": "#/$defs/destination"},
                "identifier": {
                    "oneOf": [
                        {"type": "string", "maxLength": 64},
                        {"type": "integer", "minimum": 1, "maximum": 999999},
                    ],
                },
            },
            "required": ["url", "identifier"],
        }

        self.assertEqual(
            SupportedSchemaProfileV1.validate(schema),
            (("identifier",), ("url",)),
        )

    def test_ambiguous_union_and_recursive_ref_remain_fail_closed(self):
        cases = (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "target": {
                        "anyOf": [
                            {"type": "string", "maxLength": 64},
                            {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {"id": {"type": "string", "maxLength": 64}},
                                "required": ["id"],
                            },
                        ],
                    },
                },
                "required": ["target"],
            },
            {
                "$ref": "#/$defs/loop",
                "$defs": {"loop": {"$ref": "#/$defs/loop"}},
            },
        )
        for schema in cases:
            with self.subTest(schema=schema), self.assertRaises(SecurityModelError):
                SupportedSchemaProfileV1.validate(schema)


class ContractHashCompatibilityTests(unittest.TestCase):
    def test_lot3_neutral_defaults_preserve_historical_contract_hash(self):
        historical = {
            "contract_version": "2",
            "server_ref": "streamable_http:http://127.0.0.1:9000/mcp",
            "tool_name": "read_file",
            "effects": [
                {
                    "effect_id": "tool-1.filesystem.read",
                    "capability": "filesystem.read",
                    "resource_bindings": [
                        {
                            "path": ["path"],
                            "resource_type": "filesystem_path",
                        }
                    ],
                    "fixed_resource": None,
                    "max_resource_cardinality": 100,
                    "declared_reference_precision": "EXPLICIT",
                }
            ],
            "unbound_arguments": [],
        }
        contract = ToolSecurityContract.model_validate(historical)
        self.assertEqual(
            contract.contract_hash,
            "ef5188e981b4d5e5289a384af01ee330084279d74aff305034bb6e5baca84de0",
        )
        self.assertNotIn("argument_constraints", contract.contract_hash_payload())
        self.assertNotIn("result_control", contract.contract_hash_payload())
        self.assertNotIn(
            "role",
            contract.contract_hash_payload()["effects"][0]["resource_bindings"][0],
        )

    def test_advanced_security_semantics_change_contract_hash(self):
        base = transfer_contract()
        advanced_hash = base.contract_hash
        without_constraint = base.model_copy(update={"argument_constraints": ()})
        self.assertNotEqual(advanced_hash, without_constraint.contract_hash)


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

    def test_zero_argument_resource_tool_uses_fixed_reference(self):
        schema = {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        }
        contract = ToolSecurityContract(
            server_ref="files-a",
            tool_name="list_files",
            effects=(
                ToolEffect(
                    effect_id="list",
                    capability="filesystem.list",
                    fixed_resource=FixedResourceReference(
                        resource_type="filesystem_path",
                        canonical_value="fs.project_workspace",
                    ),
                ),
            ),
        )

        resolutions = validate_contract_for_schema(contract, schema)
        facts = resolve_effect_facts(
            {},
            contract.effects[0],
            resolutions[0],
            {
                "authority": "files-a",
                "resource_type_config": {"filesystem_path_mode": "RELATIVE_ROOTED"},
            },
        )

        self.assertEqual(resolutions[0].adapter_id, "filesystem")
        self.assertEqual(facts.bindings[0].path, ())
        self.assertEqual(facts.bindings[0].occurrence_count, 1)
        self.assertEqual(
            facts.bindings[0].references[0].canonical_value,
            "fs.project_workspace",
        )

    def test_invalid_multi_effect_request_does_not_keep_resolved_fixed_resource(self):
        schema = {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        }
        contract = ToolSecurityContract(
            server_ref="files-a",
            tool_name="mixed_files",
            effects=(
                ToolEffect(
                    effect_id="list",
                    capability="filesystem.list",
                    fixed_resource=FixedResourceReference(
                        resource_type="filesystem_path",
                        canonical_value="contracts",
                    ),
                ),
                ToolEffect(
                    effect_id="read",
                    capability="filesystem.read",
                    resource_bindings=(
                        ResourceBinding(
                            path=("path",),
                            resource_type="filesystem_path",
                        ),
                    ),
                ),
            ),
        )
        approval = ToolObservationApproval(
            tool_observation_id=1,
            server_ref="files-a",
            upstream_protocol_profile_id="modern",
            tool_fingerprint="a" * 64,
            contract_hash=contract.contract_hash,
            evidence_bundle_hash="b" * 64,
            admin_id="admin",
            approved_at="2026-01-01T00:00:00Z",
            revision_id="revision-1",
        )
        resolutions = validate_contract_for_schema(contract, schema)
        first_facts = resolve_effect_facts(
            {"path": "contracts/a.txt"},
            contract.effects[0],
            resolutions[0],
            {
                "authority": "files-a",
                "resource_type_config": {
                    "filesystem_path_mode": "RELATIVE_ROOTED",
                },
            },
        )
        with patch(
            "proxy.tool_request_preparation.resolve_effect_facts",
            side_effect=[
                first_facts,
                SecurityModelError("filesystem_path_traversal"),
            ],
        ):
            prepared = prepare_tool_request_v2(
                raw_arguments={"path": "contracts/a.txt"},
                input_schema=schema,
                contract=contract,
                adapter_resolutions=resolutions,
                approval=approval,
                authority_scopes=(),
                authority_context={"filesystem_path_mode": "RELATIVE_ROOTED"},
                client_protocol_profile_id="modern",
                upstream_protocol_profile_id="modern",
            )

        self.assertFalse(prepared.arguments_valid)
        self.assertTrue(prepared.validation_error_codes)
        self.assertIsNone(prepared.canonical_resource)
        self.assertEqual(prepared.arguments, {})
        self.assertEqual(prepared.execution_arguments, {})


class ArgumentConstraintRuntimeTests(unittest.TestCase):
    def _prepare(self, amount):
        pack = transfer_pack()
        contract = transfer_contract()
        approval = ToolObservationApproval(
            tool_observation_id=1,
            server_ref="transfer-a",
            upstream_protocol_profile_id="modern",
            tool_fingerprint="a" * 64,
            contract_hash=contract.contract_hash,
            evidence_bundle_hash="b" * 64,
            admin_id="admin",
            approved_at="2026-01-01T00:00:00Z",
            revision_id="revision-1",
        )
        return prepare_tool_request_v2(
            raw_arguments={
                "source_account": "account/source",
                "destination_account": "account/destination",
                "amount": amount,
            },
            input_schema=transfer_schema(),
            contract=contract,
            adapter_resolutions=transfer_resolutions(contract, pack),
            approval=approval,
            authority_scopes=(),
            authority_context={},
            client_protocol_profile_id="modern",
            upstream_protocol_profile_id="modern",
            security_packs=(pack,),
        )

    def test_multi_effect_request_under_limit_resolves_both_effects(self):
        prepared = self._prepare(100)
        self.assertTrue(prepared.arguments_valid)
        self.assertEqual(prepared.validation_error_codes, ())
        self.assertEqual(
            {effect["capability_id"] for effect in prepared.normalized_facts["effects"]},
            {"lot3_transfer.debit", "lot3_transfer.credit"},
        )
        roles = {
            effect["bindings"][0]["role"]
            for effect in prepared.normalized_facts["effects"]
        }
        self.assertEqual(roles, {"SOURCE", "DESTINATION"})

    def test_constraint_violation_fails_closed_before_effect_resolution(self):
        with patch(
            "proxy.tool_request_preparation.resolve_effect_facts"
        ) as resolver:
            prepared = self._prepare(1000)
        self.assertFalse(prepared.arguments_valid)
        self.assertIn(
            "argument_constraint_failed:amount-limit",
            prepared.validation_error_codes,
        )
        self.assertEqual(prepared.arguments, {})
        self.assertEqual(prepared.execution_arguments, {})
        resolver.assert_not_called()

    def test_constraint_path_outside_schema_is_rejected(self):
        contract = transfer_contract().model_copy(
            update={
                "argument_constraints": (
                    ArgumentConstraint(
                        constraint_id="unknown-field",
                        path=("missing",),
                        operator="EQ",
                        value="x",
                    ),
                )
            }
        )
        pack = transfer_pack()
        with self.assertRaisesRegex(SecurityModelError, "constraint_path_not_in_schema"):
            validate_contract_for_schema(
                contract,
                transfer_schema(),
                capability_catalog=CapabilityCatalog(security_packs=(pack,)),
                resource_type_registry=ResourceTypeRegistry(security_packs=(pack,)),
                adapter_resolver=AdapterRegistry(security_packs=(pack,)),
            )


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

    def test_legacy_upstream_pool_has_caps_and_closes_sessions(self):
        from proxy.protocol_sessions import LegacyUpstreamSessionPool

        class ClosableClient:
            closed = 0

            def close(self):
                type(self).closed += 1

        pool = LegacyUpstreamSessionPool(max_clients=1)
        pool.get_or_create(
            framework_session_id="agent-session-a",
            server_id=1,
            profile_id="legacy",
            factory=ClosableClient,
        )
        with self.assertRaisesRegex(RuntimeError, "legacy_upstream_session_capacity_exceeded"):
            pool.get_or_create(
                framework_session_id="agent-session-b",
                server_id=1,
                profile_id="legacy",
                factory=ClosableClient,
            )
        self.assertEqual(pool.close_framework_session("agent-session-a"), 1)
        self.assertEqual(ClosableClient.closed, 1)

        per_session_pool = LegacyUpstreamSessionPool(
            max_clients=10,
            max_clients_per_framework_session=1,
        )
        per_session_pool.get_or_create(
            framework_session_id="agent-session-a",
            server_id=1,
            profile_id="legacy",
            connection_context_hash="a",
            factory=ClosableClient,
        )
        with self.assertRaisesRegex(
            RuntimeError,
            "legacy_upstream_framework_session_capacity_exceeded",
        ):
            per_session_pool.get_or_create(
                framework_session_id="agent-session-a",
                server_id=2,
                profile_id="legacy",
                connection_context_hash="b",
                factory=ClosableClient,
            )

    def test_legacy_upstream_pool_closes_expired_clients(self):
        from proxy.protocol_sessions import LegacyUpstreamSessionPool

        class ClosableClient:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        pool = LegacyUpstreamSessionPool(ttl_seconds=0)
        first = pool.get_or_create(
            framework_session_id="agent-session-a",
            server_id=1,
            profile_id="legacy",
            factory=ClosableClient,
        )
        second = pool.get_or_create(
            framework_session_id="agent-session-a",
            server_id=1,
            profile_id="legacy",
            factory=ClosableClient,
        )

        self.assertTrue(first.closed)
        self.assertIsNot(first, second)


if __name__ == "__main__":
    unittest.main()
