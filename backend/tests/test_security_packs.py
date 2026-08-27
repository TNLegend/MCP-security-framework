import unittest
import sys
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.models.mcp_tool import MCPTool
from app.models.mcp_server import MCPServer
from app.db.database import Base
from app.models.control_plane import ControlPlaneState, ControlPlaneUser
from app.schemas.control_plane import empty_latest_configuration
from app.schemas.security_pack import ContractScopeInput, CreateToolContractDraftRequest
from app.services.control_plane_config import create_revision, publish_revision
from app.services.security_pack_onboarding import (
    _AIPackSuggestion,
    _build_contract,
    _contract_resource_types,
    _merge_scopes,
    _pack_manifest_from_ai_suggestion,
    _resolve_draft,
    create_tool_contract_draft,
    create_tool_security_pack_draft,
    reanalyze_tool_with_published_contract,
    suggest_templates_for_tool,
)
from app.services.published_configuration import validate_config_content
from app.services.tool_analysis import (
    HashingEmbeddingModel,
    SemanticResult,
    ToolAnalysisService as RealToolAnalysisService,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from proxy.resource_adapters_v2 import AdapterRegistry, resolve_effect_facts
from proxy.protocol_profiles import LEGACY_PROFILE_ID
from proxy.security_packs import (
    PackCapability,
    PackResourceType,
    SecurityPackError,
    SecurityPackManifest,
    SecurityPackRegistry,
    TemplateArgumentConstraint,
    TemplateBinding,
    TemplateEffect,
    TemplateResultControl,
    ToolContractTemplate,
)
from proxy.tool_security_v2 import (
    AdapterResolution,
    FixedResourceReference,
    ReferencePrecision,
    ResourceBinding,
    ToolEffect,
    ToolSecurityContract,
)


class SecurityPackRegistryTests(unittest.TestCase):
    def test_builtin_catalog_spans_multiple_domains(self):
        registry = SecurityPackRegistry()
        self.assertGreaterEqual(len(registry.packs()), 8)
        for capability in (
            "filesystem.read",
            "network.request",
            "database.write",
            "message.send",
            "cloud.object.delete",
            "calendar.write",
            "payment.initiate",
            "process.execute",
        ):
            self.assertEqual(registry.capability(capability).id, capability)

    def test_declarative_pack_extends_catalog_without_overriding_builtin_ids(self):
        pack = custom_pack()
        registry = SecurityPackRegistry((pack,))
        self.assertEqual(registry.capability("ticket.read").domain, "ticket")
        self.assertEqual(registry.template("ticket.read")[0].id, "ticketing")

        duplicate = pack.model_copy(update={"id": "filesystem"})
        with self.assertRaisesRegex(SecurityPackError, "duplicate_security_pack"):
            SecurityPackRegistry((duplicate,))

    def test_pack_rejects_template_references_outside_its_manifest(self):
        invalid = SecurityPackManifest(
                id="invalid",
                version="1.0.0",
                title="Invalid",
                description="Invalid references",
                origin="DECLARATIVE",
                capabilities=(
                    PackCapability(
                        id="invalid.read",
                        domain="invalid",
                        verb="read",
                        allowed_resource_types=("invalid_object",),
                    ),
                ),
                resource_types=(),
            )
        with self.assertRaisesRegex(SecurityPackError, "capability_resource_type_unavailable"):
            SecurityPackRegistry((invalid,))


    def test_advanced_template_projects_multiple_effects_roles_constraints_and_result_control(self):
        pack = advanced_transfer_pack()
        registry = SecurityPackRegistry((pack,))
        _, template = registry.template("lot3.transfer")
        tool = MCPTool(
            id=77,
            server_id=7,
            name="transfer_payment",
            input_schema={
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "source_account": {"type": "string", "maxLength": 128},
                    "destination_account": {"type": "string", "maxLength": 128},
                    "amount": {"type": "number", "minimum": 0, "maximum": 1000000},
                },
                "required": ["source_account", "destination_account", "amount"],
            },
        )
        server = MCPServer(
            id=7,
            name="Transfer MCP",
            server_type="third_party",
            endpoint="https://transfer.example/mcp",
            transport="streamable_http",
            status="active",
        )
        contract = _build_contract(
            tool=tool,
            server=server,
            template=template,
            mappings={
                "source": ("source_account",),
                "destination": ("destination_account",),
                "amount_limit": ("amount",),
            },
            fixed_resources={},
            schema_paths={("source_account",), ("destination_account",), ("amount",)},
        )

        self.assertEqual(
            [effect.capability for effect in contract.effects],
            ["lot3_transfer.debit", "lot3_transfer.credit"],
        )
        self.assertEqual(contract.effects[0].resource_bindings[0].role, "SOURCE")
        self.assertEqual(contract.effects[1].resource_bindings[0].role, "DESTINATION")
        self.assertEqual(contract.argument_constraints[0].operator, "LE")
        self.assertEqual(contract.argument_constraints[0].value, 500)
        self.assertEqual(contract.result_control.classification, "SENSITIVE")
        self.assertTrue(contract.result_control.track_for_exfiltration)

    def test_multi_resource_scope_requires_or_accepts_explicit_resource_type(self):
        registry = AdapterRegistry()
        with self.assertRaisesRegex(
            Exception,
            "scope_resource_type_ambiguous",
        ):
            _merge_scopes(
                existing=(),
                requested=(ContractScopeInput(
                    scope_id="ambiguous",
                    canonical_value="prod/customers",
                ),),
                authority="streamable_http:https://example.test/mcp",
                resource_types=("database_object", "url"),
                registry=registry,
            )

        scopes = _merge_scopes(
            existing=(),
            requested=(ContractScopeInput(
                scope_id="destination",
                resource_type="url",
                canonical_value="https://example.com/api",
            ),),
            authority="streamable_http:https://example.test/mcp",
            resource_types=("database_object", "url"),
            registry=registry,
        )
        self.assertEqual(scopes[0].resource_type, "url")
        self.assertEqual(scopes[0].canonical_value, "https://example.com/api")


class SecurityPackOnboardingTests(unittest.TestCase):
    def test_first_onboarding_creates_and_reuses_fail_closed_v2_draft(self):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        with Session() as db:
            admin = ControlPlaneUser(
                username="admin",
                password_hash="not-used",
                role="ADMIN",
                enabled=True,
            )
            db.add(admin)
            db.flush()
            source = empty_latest_configuration()
            published = create_revision(
                db,
                content=source,
                status="PUBLISHED",
                actor=admin,
                change_summary="published v2",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=published.id))
            payload = CreateToolContractDraftRequest(
                template_id="filesystem.read",
                change_summary="onboard first v2 tool",
            )

            first, first_content = _resolve_draft(db, payload, admin)
            second, second_content = _resolve_draft(db, payload, admin)

            self.assertEqual(first.id, second.id)
            self.assertEqual(first.schema_version, 2)
            self.assertEqual(first_content.capability_catalog_version, "2")
            self.assertEqual(first_content.identity_bindings, source.identity_bindings)
            self.assertEqual(second_content.tool_security_contracts, ())

    def test_template_suggestions_cover_non_filesystem_tools(self):
        cases = (
            ("send_email", "Send an email to a recipient", "recipient", "messaging.send"),
            ("query_database", "Read a database table", "table", "database.read"),
            ("create_event", "Create a calendar event", "event", "calendar.write"),
            ("call_api", "Fetch an HTTP API endpoint", "url", "http.request"),
        )
        for name, description, argument, expected in cases:
            with self.subTest(name=name):
                tool = MCPTool(
                    id=1,
                    server_id=1,
                    name=name,
                    title=name.replace("_", " ").title(),
                    description=description,
                    input_schema={
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {argument: {"type": "string", "maxLength": 512}},
                        "required": [argument],
                    },
                )
                suggestions = suggest_templates_for_tool(tool)
                self.assertTrue(suggestions)
                self.assertEqual(suggestions[0]["template_id"], expected)
                self.assertEqual(
                    suggestions[0]["argument_mappings"]["resource"],
                    (argument,),
                )

    def test_zero_argument_list_tool_prefers_the_list_template(self):
        tool = MCPTool(
            id=1,
            server_id=1,
            name="list_files",
            title="List Files",
            description="List files available in the workspace.",
            input_schema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        )

        suggestions = suggest_templates_for_tool(tool)

        self.assertTrue(suggestions)
        self.assertEqual(suggestions[0]["template_id"], "filesystem.list")

    def test_unknown_tool_has_no_arbitrary_template_fallback(self):
        tool = MCPTool(
            id=1,
            server_id=1,
            name="transmute_qubits",
            title="Transmute Qubits",
            description="Apply a frobnication phase to a quantum lattice.",
            input_schema={
                "type": "object",
                "properties": {"lattice": {"type": "string"}},
                "required": ["lattice"],
                "additionalProperties": False,
            },
        )

        self.assertEqual(suggest_templates_for_tool(tool), [])

    def test_read_like_unknown_domain_does_not_fall_back_to_arbitrary_read_template(self):
        tool = MCPTool(
            id=1,
            server_id=1,
            name="get_ticket",
            title="Get Ticket",
            description="Retrieve one support ticket by identifier.",
            input_schema={
                "type": "object",
                "properties": {"ticket_id": {"type": "string"}},
                "required": ["ticket_id"],
                "additionalProperties": False,
            },
        )

        self.assertEqual(suggest_templates_for_tool(tool), [])

    def test_ai_pack_suggestion_normalizes_safe_provider_shape_variations(self):
        gemini_shape = _AIPackSuggestion.model_validate({
            "pack_id": "widget-management",
            "title": "Widget Retrieval Security Pack",
            "capability_id": "inventory.read",
            "resource_type_id": "widget_object",
            "template_id": "inventory.read",
            "keywords": ["widget", "inventory", "read-only"],
            "argument_hints": {
                "widget_id": "The unique identifier for the product widget."
            },
            "destructive": False,
            "external_effect": False,
            "uncertainties": ["Administrator review required."],
        })
        self.assertEqual(gemini_shape.argument_hints, ("widget_id",))

        groq_shape = _AIPackSuggestion.model_validate({
            "pack_id": "widget-get",
            "title": "Get Widget",
            "capability_id": "widget.get",
            "resource_type_id": "widget",
            "template_id": "widget.get",
            "keywords": ["widget", "product", "retrieve"],
            "argument_hints": ["widget_id"],
            "destructive": False,
            "external_effect": "none",
            "uncertainties": "none",
        })
        self.assertFalse(groq_shape.external_effect)
        self.assertEqual(groq_shape.uncertainties, ())

        with self.assertRaises(ValueError):
            _AIPackSuggestion.model_validate({
                "pack_id": "widget-bad",
                "title": "Bad Widget",
                "capability_id": "widget.read",
                "resource_type_id": "widget",
                "template_id": "widget.read",
                "keywords": ["widget"],
                "argument_hints": ["widget_id"],
                "destructive": "maybe",
                "external_effect": False,
                "uncertainties": [],
            })

    def test_ai_pack_proposal_is_reduced_to_safe_declarative_manifest(self):
        manifest = _pack_manifest_from_ai_suggestion(_AIPackSuggestion(
            pack_id="quantum-tools",
            title="Quantum Tools",
            capability_id="quantum.transmute",
            resource_type_id="quantum_lattice",
            template_id="quantum.transmute",
            keywords=("quantum", "transmute"),
            argument_hints=("lattice",),
            external_effect=True,
        ))

        self.assertEqual(manifest.origin, "DECLARATIVE")
        self.assertEqual(manifest.resource_types[0].adapter_id, "generic-declarative")
        self.assertFalse(manifest.resource_types[0].requires_specialized_interpretation)
        self.assertEqual(manifest.templates[0].capability, "quantum.transmute")

    def test_unknown_tool_pack_and_contract_share_one_v2_draft(self):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        with Session() as db:
            admin = ControlPlaneUser(
                username="admin",
                password_hash="not-used",
                role="ADMIN",
                enabled=True,
            )
            server = MCPServer(
                name="Ticket MCP",
                server_type="third_party",
                endpoint="https://tickets.example/mcp",
                transport="streamable_http",
                status="active",
                preferred_upstream_profile=LEGACY_PROFILE_ID,
            )
            db.add_all((admin, server))
            db.flush()
            tool = MCPTool(
                server_id=server.id,
                name="get_ticket",
                title="Get Ticket",
                description="Retrieve one support ticket by identifier.",
                input_schema={
                    "type": "object",
                    "properties": {"ticket_id": {"type": "string"}},
                    "required": ["ticket_id"],
                    "additionalProperties": False,
                },
            )
            db.add(tool)
            db.flush()
            published = create_revision(
                db,
                content=empty_latest_configuration(),
                status="PUBLISHED",
                actor=admin,
                change_summary="published v2",
            )
            db.add(ControlPlaneState(id=1, active_revision_id=published.id))
            db.flush()

            pack_revision = create_tool_security_pack_draft(
                db,
                tool=tool,
                manifest=custom_pack(),
                draft_revision_id=None,
                actor=admin,
                change_summary="Create ticket pack",
            )
            class SafeSemanticModel:
                def classify(self, text, categories):
                    scores = {category: 0.01 for category in categories}
                    scores["normal_tool_description"] = 0.99
                    return SemanticResult(
                        scores=scores,
                        best_category="normal_tool_description",
                        confidence=0.99,
                        model_name="test-semantic",
                        model_version="1",
                        flagged=False,
                    )

            def analysis_service():
                return RealToolAnalysisService(
                    semantic_model=SafeSemanticModel(),
                    embedding_model=HashingEmbeddingModel(),
                )

            with patch(
                "app.services.security_pack_onboarding.ToolAnalysisService",
                analysis_service,
            ):
                result = create_tool_contract_draft(
                    db,
                    tool=tool,
                    payload=CreateToolContractDraftRequest(
                        template_id="ticket.read",
                        argument_mappings={"resource": ("ticket_id",)},
                        draft_revision_id=pack_revision.id,
                        approve_observations=True,
                        change_summary="Create ticket contract",
                    ),
                    actor=admin,
                )
            content = validate_config_content(pack_revision.content)

            self.assertEqual(result["revision_id"], pack_revision.id)
            self.assertEqual(result["observation_approvals"], 1)
            self.assertEqual(content.security_packs[0].id, "ticketing")
            self.assertEqual(content.tool_security_contracts[0].tool_name, "get_ticket")

            publish_revision(
                db,
                draft_id=pack_revision.id,
                actor=admin,
                change_summary="Publish ticket contract",
            )

            captured_profiles = []

            class FakeAnalysis:
                analysis_status = "APPROVED"

            class FakeAnalysisService:
                def observe_and_analyze(self, **kwargs):
                    captured_profiles.append(kwargs["profile_snapshot"])
                    kwargs["tool"].analysis_status = "APPROVED"
                    return FakeAnalysis()

            with patch(
                "app.services.security_pack_onboarding.ToolAnalysisService",
                FakeAnalysisService,
            ):
                reanalysis = reanalyze_tool_with_published_contract(
                    db,
                    tool=tool,
                    actor=admin,
                )

            self.assertEqual(reanalysis["analysis_statuses"], ("APPROVED",))
            self.assertEqual(captured_profiles[0]["contract_hash"], result["contract_hash"])
            self.assertEqual(captured_profiles[0]["security_pack"]["id"], "ticketing")

    def test_benign_url_is_not_a_finding_but_private_destination_is_sensitive(self):
        registry = AdapterRegistry()
        effect = ToolEffect(
            effect_id="request",
            capability="network.request",
            resource_bindings=(
                ResourceBinding(path=("url",), resource_type="url"),
            ),
            declared_reference_precision=ReferencePrecision.EXPLICIT,
        )
        resolution = AdapterResolution(
            effect_id="request",
            adapter_id="url",
            adapter_api_version="1",
            implementation_version="1.0.0",
            resource_type="url",
        )
        public = resolve_effect_facts(
            {"url": "https://EXAMPLE.com:443/api"},
            effect,
            resolution,
            {"authority": "streamable_http:https://mcp.example/mcp"},
            registry=registry,
        )
        self.assertEqual(public.bindings[0].references[0].canonical_value, "https://example.com/api")
        self.assertEqual(public.bindings[0].references[0].resource_sensitivity, "unknown")

        private = resolve_effect_facts(
            {"url": "http://127.0.0.1/admin"},
            effect,
            resolution,
            {"authority": "streamable_http:https://mcp.example/mcp"},
            registry=registry,
        )
        self.assertEqual(private.bindings[0].references[0].resource_sensitivity, "secret")
        self.assertIn(
            "private_network_destination",
            private.bindings[0].references[0].resource_flags,
        )

    def test_fixed_resource_contract_supplies_a_scope_resource_type(self):
        contract = ToolSecurityContract(
            server_ref="streamable_http:http://127.0.0.1:9000/mcp",
            tool_name="list_files",
            effects=(
                ToolEffect(
                    effect_id="list-files",
                    capability="filesystem.list",
                    fixed_resource=FixedResourceReference(
                        resource_type="filesystem_path",
                        canonical_value="contracts",
                    ),
                    max_resource_cardinality=1,
                    declared_reference_precision=ReferencePrecision.EXPLICIT,
                ),
            ),
            unbound_arguments=(),
        )

        self.assertEqual(_contract_resource_types(contract), ("filesystem_path",))


def custom_pack() -> SecurityPackManifest:
    return SecurityPackManifest(
        id="ticketing",
        version="1.0.0",
        title="Ticketing",
        description="Ticket operations",
        origin="DECLARATIVE",
        capabilities=(
            PackCapability(
                id="ticket.read",
                domain="ticket",
                verb="read",
                allowed_resource_types=("ticket_object",),
            ),
        ),
        resource_types=(
            PackResourceType(
                id="ticket_object",
                canonicalizer="hierarchical_name",
                hierarchy_support=True,
                allowed_matching_modes=("SELF", "SUBTREE"),
                adapter_id="generic-declarative",
            ),
        ),
        templates=(
            ToolContractTemplate(
                id="ticket.read",
                title="Read Ticket",
                description="Read one ticket",
                capability="ticket.read",
                keywords=("ticket", "issue"),
                bindings=(
                    TemplateBinding(
                        key="resource",
                        resource_type="ticket_object",
                        argument_hints=("ticket", "issue", "id"),
                    ),
                ),
            ),
        ),
    )


def advanced_transfer_pack() -> SecurityPackManifest:
    resource = PackResourceType(
        id="lot3_account",
        canonicalizer="hierarchical_name",
        hierarchy_support=True,
        allowed_matching_modes=("SELF", "SUBTREE"),
        adapter_id="generic-declarative",
    )
    return SecurityPackManifest(
        id="lot3-transfer-pack",
        version="1.0.0",
        title="Lot 3 Transfer Pack",
        description="Advanced declarative transfer semantics",
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
        templates=(
            ToolContractTemplate(
                id="lot3.transfer",
                title="Transfer Payment",
                description="Debit a source and credit a destination under a bounded amount.",
                keywords=("transfer", "payment"),
                effects=(
                    TemplateEffect(
                        key="debit",
                        capability="lot3_transfer.debit",
                        bindings=(TemplateBinding(
                            key="source",
                            resource_type=resource.id,
                            role="SOURCE",
                            argument_hints=("source_account", "source"),
                        ),),
                    ),
                    TemplateEffect(
                        key="credit",
                        capability="lot3_transfer.credit",
                        bindings=(TemplateBinding(
                            key="destination",
                            resource_type=resource.id,
                            role="DESTINATION",
                            argument_hints=("destination_account", "destination"),
                        ),),
                    ),
                ),
                constraints=(TemplateArgumentConstraint(
                    key="amount_limit",
                    operator="LE",
                    value=500,
                    argument_hints=("amount",),
                ),),
                result_control=TemplateResultControl(
                    classification="SENSITIVE",
                    track_for_exfiltration=True,
                ),
            ),
        ),
    )


if __name__ == "__main__":
    unittest.main()
