import atexit
import os
import shutil
import sys
import tempfile
import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from proxy.agent_identity import AgentIdentityError, VerifiedExternalIdentity
from proxy.identity_binding import ResolvedIdentityBinding
from app.schemas.policy_decision import PolicyDecision
from proxy.backend_client import BackendClientError
from proxy.mcp_proxy import (
    MCPProxy,
    _can_execute_policy_decision,
    _fail_closed_proxy_decision,
    _validate_policy_decision,
)
from proxy.resource_adapters import revalidate_resource, resolve_resource
from proxy.resource_registry import ResourceRegistry, ResolvedFilesystemScope
from proxy.tool_security_profiles import (
    ResolvedToolSecurityProfile,
    ToolResourceProfile,
)
from proxy.trusted_sessions import ProxyTrustedSession, TrustedSessionError
from runtime_policy_eval import evaluate_runtime_policy_with_opa_cli


def policy_decision(
    effect: str | None = "ALLOW",
    obligations: list[dict] | None = None,
    runtime_decision: str = "ALLOW",
    rule_id: str = "test_rule",
) -> dict:
    decision = {
        "obligations": obligations if obligations is not None else [],
        "rule_ids": [rule_id],
        "reason": "Test decision.",
        "severity": "low",
        "evidence": {},
        "recommended_action": None,
        "policy_revision": "test-policy-v1",
        "decision": runtime_decision,
        "rule_id": rule_id,
    }
    if effect is not None:
        decision["effect"] = effect
    return decision


def validated_policy_decision(
    effect: str | None = "ALLOW",
    obligations: list[dict] | None = None,
    runtime_decision: str = "ALLOW",
    rule_id: str = "test_rule",
) -> PolicyDecision:
    return PolicyDecision.model_validate(
        policy_decision(
            effect=effect,
            obligations=obligations,
            runtime_decision=runtime_decision,
            rule_id=rule_id,
        )
    )


class FakeBackendClient:
    def __init__(self, decision) -> None:
        self.decision = decision
        self.created_logs = []
        self.last_policy_context = None

    def find_server(self, server_id=None, endpoint=None):
        return {
            "id": 1,
            "endpoint": "http://127.0.0.1:9000/mcp",
            "transport": "streamable_http",
            "protocol_version": "2025-11-25",
            "trust_status": "trusted",
            "security_status": "pending_analysis",
        }

    def find_tool(self, server_id: int, tool_name: str):
        return {
            "id": 1,
            "server_id": server_id,
            "name": tool_name,
            "risk_score": 40,
            "sensitivity": "medium",
            "description_risk_score": 0,
            "input_schema": list_files_schema() if tool_name == "list_files" else read_file_schema(),
        }

    def request_policy_decision(self, context: dict, *, identity_assertion: str | None = None):
        self.last_policy_context = context
        self.last_identity_assertion = identity_assertion
        return self.decision

    def create_runtime_log(self, log_payload: dict):
        self.created_logs.append(log_payload)
        return {"id": len(self.created_logs), **log_payload}


_RESOURCE_TEMP_DIR = tempfile.TemporaryDirectory()
atexit.register(_RESOURCE_TEMP_DIR.cleanup)
TEST_RESOURCE_ROOT = Path(_RESOURCE_TEMP_DIR.name)
(TEST_RESOURCE_ROOT / "contracts").mkdir(parents=True, exist_ok=True)
(TEST_RESOURCE_ROOT / "contracts" / "contract1.txt").write_text(
    "Contract test content.",
    encoding="utf-8",
)
(TEST_RESOURCE_ROOT / "public").mkdir(parents=True, exist_ok=True)
(TEST_RESOURCE_ROOT / "public" / "readme.txt").write_text(
    "Public test content.",
    encoding="utf-8",
)
(TEST_RESOURCE_ROOT / ".ENV").write_text("test placeholder", encoding="utf-8")
(TEST_RESOURCE_ROOT / "keys").mkdir(parents=True, exist_ok=True)
(TEST_RESOURCE_ROOT / "keys" / "id_rsa.backup").write_text(
    "test placeholder",
    encoding="utf-8",
)
(TEST_RESOURCE_ROOT / "SECRETS").mkdir(parents=True, exist_ok=True)
(TEST_RESOURCE_ROOT / "SECRETS" / "api.txt").write_text(
    "test placeholder",
    encoding="utf-8",
)


class FakeTrustedSessionManager:
    def create_for_identity(
        self,
        *,
        external_identity: VerifiedExternalIdentity,
        identity_binding: ResolvedIdentityBinding,
    ) -> ProxyTrustedSession:
        return ProxyTrustedSession(
            session_reference="session-001",
            session_token="test-session-token",
            agent_id=identity_binding.agent_id,
            identity_issuer=external_identity.issuer,
            identity_subject=external_identity.subject,
            identity_binding_revision=identity_binding.revision,
            session_status="active",
        )

    def validate_token(self, session_token: str) -> ProxyTrustedSession:
        if session_token != "test-session-token":
            raise TrustedSessionError("trusted_session_invalid")
        return ProxyTrustedSession(
            session_reference="session-001",
            session_token=session_token,
            agent_id="agent-demo",
            identity_issuer="https://issuer.example/",
            identity_subject="agent-demo",
            identity_binding_revision="test-bindings-v1",
            session_status="active",
        )


class FakeToolSecurityProfileResolver:
    def resolve(
        self,
        *,
        server_ref: str,
        tool_name: str,
    ) -> ResolvedToolSecurityProfile:
        if tool_name == "read_file":
            return ResolvedToolSecurityProfile(
                revision="tool-security-profiles-test-v1",
                server_ref=server_ref,
                tool_name=tool_name,
                operation="read",
                required_capability="filesystem.read",
                resource=ToolResourceProfile(
                    adapter="filesystem",
                    argument_name="path",
                    expected_type="file",
                    relative_base_scope="fs.project_workspace",
                    allowed_scope_candidates=["fs.project_workspace", "fs.public"],
                ),
            )
        if tool_name == "list_files":
            return ResolvedToolSecurityProfile(
                revision="tool-security-profiles-test-v1",
                server_ref=server_ref,
                tool_name=tool_name,
                operation="list",
                required_capability="filesystem.list",
                resource=ToolResourceProfile(
                    adapter="filesystem",
                    argument_name="path",
                    expected_type="directory",
                    relative_base_scope="fs.project_workspace",
                    allowed_scope_candidates=["fs.project_workspace", "fs.public"],
                ),
            )
        raise RuntimeError("unknown_tool_security_profile")


class FakeResourceRegistryResolver:
    def load(self) -> ResourceRegistry:
        return ResourceRegistry(
            revision="resource-scopes-test-v1",
            filesystem_scopes={
                "fs.project_workspace": ResolvedFilesystemScope(
                    scope_id="fs.project_workspace",
                    root=TEST_RESOURCE_ROOT,
                    root_resolved=TEST_RESOURCE_ROOT.resolve(strict=True),
                    allowed_operations=("read", "list"),
                    sensitivity="internal",
                    symlink_policy="internal-only",
                    denied_patterns=(
                        "**/.env*",
                        "**/.ssh/**",
                        "**/.aws/credentials",
                        "**/id_rsa*",
                        "**/secrets/**",
                    ),
                ),
                "fs.public": ResolvedFilesystemScope(
                    scope_id="fs.public",
                    root=TEST_RESOURCE_ROOT / "public",
                    root_resolved=(TEST_RESOURCE_ROOT / "public").resolve(
                        strict=True
                    ),
                    allowed_operations=("read", "list"),
                    sensitivity="internal",
                    symlink_policy="internal-only",
                    denied_patterns=(),
                ),
            },
        )


class InventoryErrorBackendClient(FakeBackendClient):
    def find_server(self, server_id=None, endpoint=None):
        raise BackendClientError("Inventory unavailable.")


class PolicyErrorBackendClient(FakeBackendClient):
    def request_policy_decision(self, context: dict, *, identity_assertion: str | None = None):
        raise BackendClientError("Policy backend unavailable.")


class TrackingMCPClient:
    called = False
    call_count = 0
    last_tool_name = None
    last_arguments = None

    def __init__(self, endpoint: str, protocol_version: str) -> None:
        self.endpoint = endpoint
        self.protocol_version = protocol_version

    def call_tool(self, name: str, arguments: dict):
        TrackingMCPClient.called = True
        TrackingMCPClient.call_count += 1
        TrackingMCPClient.last_tool_name = name
        TrackingMCPClient.last_arguments = arguments
        return {"isError": False, "content": [{"type": "text", "text": "ok"}]}


def tool_call() -> dict:
    return {
        "agent_id": "agent-demo",
        "access_token": "token:agent-demo",
        "session_id": "session-001",
        "tool_name": "read_file",
        "arguments": {"path": "contracts/contract1.txt"},
    }


class FakeIdentityVerifier:
    def verify(self, access_token: str) -> VerifiedExternalIdentity:
        subject = "agent-demo"
        if isinstance(access_token, str) and access_token.startswith("token:"):
            subject = access_token.removeprefix("token:")
        now = datetime.now(timezone.utc)
        return VerifiedExternalIdentity(
            issuer="https://issuer.example/",
            subject=subject,
            audience=("mcp-security-proxy",),
            client_id=None,
            token_id=f"jti-{subject}",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )


class MissingTokenVerifier:
    def verify(self, access_token: str) -> VerifiedExternalIdentity:
        raise AgentIdentityError("agent_access_token_missing")


class FakeIdentityBindingResolver:
    def resolve(self, *, issuer: str, subject: str) -> ResolvedIdentityBinding:
        return ResolvedIdentityBinding(
            agent_id=subject,
            revision="test-bindings-v1",
        )


class FakeAssertionSigner:
    def __init__(self) -> None:
        self.signed_contexts = []

    def sign(self, context: dict) -> str:
        self.signed_contexts.append(context)
        return "test.assertion.value"


def reset_tracking_mcp_client() -> None:
    TrackingMCPClient.called = False
    TrackingMCPClient.call_count = 0
    TrackingMCPClient.last_tool_name = None
    TrackingMCPClient.last_arguments = None


def create_directory_link(link_path: Path, target_path: Path) -> None:
    remove_directory_link(link_path)
    try:
        link_path.symlink_to(target_path, target_is_directory=True)
        return
    except OSError:
        if os.name != "nt":
            raise
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link_path), str(target_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise OSError("directory link could not be created")


def remove_directory_link(path: Path) -> None:
    if path.is_symlink() or _is_junction(path):
        path.rmdir()
    elif path.exists():
        shutil.rmtree(path)


def _is_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    try:
        return bool(is_junction and is_junction())
    except OSError:
        return False


def read_file_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
            }
        },
        "required": ["path"],
        "additionalProperties": False,
    }


def list_files_schema() -> dict:
    return {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }


class MissingSchemaBackendClient(FakeBackendClient):
    def find_tool(self, server_id: int, tool_name: str):
        tool = super().find_tool(server_id, tool_name)
        tool["input_schema"] = None
        return tool


class InvalidSchemaBackendClient(FakeBackendClient):
    def find_tool(self, server_id: int, tool_name: str):
        tool = super().find_tool(server_id, tool_name)
        tool["input_schema"] = {"type": 123}
        return tool


class UnknownDialectSchemaBackendClient(FakeBackendClient):
    def find_tool(self, server_id: int, tool_name: str):
        tool = super().find_tool(server_id, tool_name)
        tool["input_schema"] = {
            "$schema": "https://unknown.example/custom-dialect",
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        }
        return tool


class Draft7SchemaBackendClient(FakeBackendClient):
    def find_tool(self, server_id: int, tool_name: str):
        tool = super().find_tool(server_id, tool_name)
        tool["input_schema"] = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        }
        return tool


class EvaluatingBackendClient(FakeBackendClient):
    def request_policy_decision(self, context: dict, *, identity_assertion: str | None = None):
        context = {
            **context,
            "subject": {
                **context["subject"],
                "role": "legal_agent",
                "authorization_status": "resolved",
                "authorization_revision": "test-authorization-v1",
                "grants": [
                    {
                        "capability": "filesystem.read",
                        "scopes": ["fs.project_workspace", "sensitive"],
                    },
                    {
                        "capability": "filesystem.list",
                        "scopes": ["fs.project_workspace"],
                    },
                ],
                "allowed_capabilities": ["filesystem.read", "filesystem.list"],
                "allowed_scopes": ["fs.project_workspace", "sensitive"],
            },
        }
        self.last_policy_context = context
        self.last_identity_assertion = identity_assertion
        return evaluate_runtime_policy_with_opa_cli(context)


class SubjectAwareEvaluatingBackendClient(FakeBackendClient):
    profiles = {
        "agent-demo": {
            "role": "legal_agent",
            "authorization_status": "resolved",
            "authorization_revision": "test-authorization-v1",
            "grants": [
                {"capability": "filesystem.read", "scopes": ["fs.project_workspace"]},
                {"capability": "filesystem.list", "scopes": ["fs.project_workspace"]},
            ],
            "allowed_capabilities": ["filesystem.read", "filesystem.list"],
            "allowed_scopes": ["fs.project_workspace"],
        },
        "agent-contract-reader": {
            "role": "contract_reader",
            "authorization_status": "resolved",
            "authorization_revision": "test-authorization-v1",
            "grants": [
                {"capability": "filesystem.read", "scopes": ["fs.project_workspace"]},
            ],
            "allowed_capabilities": ["filesystem.read"],
            "allowed_scopes": ["fs.project_workspace"],
        },
        "agent-list-only": {
            "role": "file_lister",
            "authorization_status": "resolved",
            "authorization_revision": "test-authorization-v1",
            "grants": [
                {"capability": "filesystem.list", "scopes": ["fs.project_workspace"]},
            ],
            "allowed_capabilities": ["filesystem.list"],
            "allowed_scopes": ["fs.project_workspace"],
        },
        "agent-no-access": {
            "role": "restricted",
            "authorization_status": "resolved",
            "authorization_revision": "test-authorization-v1",
            "grants": [],
            "allowed_capabilities": [],
            "allowed_scopes": [],
        },
    }

    def request_policy_decision(
        self,
        context: dict,
        *,
        identity_assertion: str | None = None,
    ):
        agent_id = context["subject"]["agent_id"]
        subject = self.profiles.get(
            agent_id,
            {
                "role": "unknown",
                "authorization_status": "unknown",
                "authorization_revision": "test-authorization-v1",
                "grants": [],
                "allowed_capabilities": [],
                "allowed_scopes": [],
            },
        )
        context = {**context, "subject": {**context["subject"], **subject}}
        self.last_policy_context = context
        self.last_identity_assertion = identity_assertion
        return evaluate_runtime_policy_with_opa_cli(context)


class EvaluatingUnknownDialectSchemaBackendClient(
    UnknownDialectSchemaBackendClient,
    EvaluatingBackendClient,
):
    def request_policy_decision(self, context: dict, *, identity_assertion: str | None = None):
        return EvaluatingBackendClient.request_policy_decision(
            self,
            context,
            identity_assertion=identity_assertion,
        )


class UnknownToolBackendClient(FakeBackendClient):
    def find_tool(self, server_id: int, tool_name: str):
        return None


class ProxyPolicyEnforcementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.default_identity_patches = [
            patch("proxy.mcp_proxy.JWTJWKSAgentIdentityVerifier", FakeIdentityVerifier),
            patch("proxy.mcp_proxy.IdentityBindingResolver", FakeIdentityBindingResolver),
            patch("proxy.mcp_proxy.InternalIdentityAssertionSigner", FakeAssertionSigner),
            patch("proxy.mcp_proxy.TrustedSessionManager", FakeTrustedSessionManager),
            patch(
                "proxy.mcp_proxy.ToolSecurityProfileResolver",
                FakeToolSecurityProfileResolver,
            ),
            patch(
                "proxy.mcp_proxy.ResourceRegistryResolver",
                FakeResourceRegistryResolver,
            ),
        ]
        for patcher in self.default_identity_patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.default_identity_patches):
            patcher.stop()

    def test_absolute_path_inside_registered_scope_can_execute(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["arguments"] = {
            "path": str(TEST_RESOURCE_ROOT / "contracts" / "contract1.txt")
        }

        result = proxy.handle_tool_call(call)

        self.assertTrue(result["mcp_called"])
        self.assertEqual(result["execution_status"], "success")
        self.assertEqual(
            backend.last_policy_context["request"]["resource_resolution_status"],
            "resolved",
        )
        self.assertEqual(
            TrackingMCPClient.last_arguments,
            {"path": "contracts/contract1.txt"},
        )

    def test_absolute_path_outside_registered_scope_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outside_file = Path(directory) / "outside.txt"
            outside_file.write_text("outside", encoding="utf-8")

            reset_tracking_mcp_client()
            backend = FakeBackendClient(
                policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
            )
            proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
            call = tool_call()
            call["arguments"] = {"path": str(outside_file)}

            result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertEqual(
            backend.last_policy_context["request"]["resource_resolution_status"],
            "resource_outside_registered_scope",
        )

    def test_internal_only_link_inside_scope_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contracts = root / "contracts"
            contracts.mkdir()
            (contracts / "contract1.txt").write_text("ok", encoding="utf-8")
            link = root / "contracts_link"
            create_directory_link(link, contracts)
            try:
                registry = self._resource_registry(
                    root,
                    symlink_policy="internal-only",
                )
                resolution = resolve_resource(
                    profile=self._read_profile(),
                    arguments={"path": "contracts_link/contract1.txt"},
                    registry=registry,
                )
            finally:
                remove_directory_link(link)

        self.assertEqual(resolution.resource_resolution_status, "resolved")
        self.assertEqual(
            resolution.execution_arguments,
            {"path": "contracts/contract1.txt"},
        )

    def test_internal_only_outgoing_link_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as root_directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(root_directory)
            outside = Path(outside_directory)
            (outside / "secret.txt").write_text("outside", encoding="utf-8")
            link = root / "outgoing"
            create_directory_link(link, outside)
            try:
                resolution = resolve_resource(
                    profile=self._read_profile(),
                    arguments={"path": "outgoing/secret.txt"},
                    registry=self._resource_registry(
                        root,
                        symlink_policy="internal-only",
                    ),
                )
            finally:
                remove_directory_link(link)

        self.assertEqual(
            resolution.resource_resolution_status,
            "resource_link_outside_scope",
        )

    def test_deny_link_policy_blocks_internal_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contracts = root / "contracts"
            contracts.mkdir()
            (contracts / "contract1.txt").write_text("ok", encoding="utf-8")
            link = root / "contracts_link"
            create_directory_link(link, contracts)
            try:
                resolution = resolve_resource(
                    profile=self._read_profile(),
                    arguments={"path": "contracts_link/contract1.txt"},
                    registry=self._resource_registry(root, symlink_policy="deny"),
                )
            finally:
                remove_directory_link(link)

        self.assertEqual(
            resolution.resource_resolution_status,
            "resource_link_forbidden",
        )

    def test_revalidate_detects_link_target_change_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            (first / "contract1.txt").write_text("first", encoding="utf-8")
            (second / "contract1.txt").write_text("second", encoding="utf-8")
            link = root / "current"
            create_directory_link(link, first)
            try:
                resolution = resolve_resource(
                    profile=self._read_profile(),
                    arguments={"path": "current/contract1.txt"},
                    registry=self._resource_registry(
                        root,
                        symlink_policy="internal-only",
                    ),
                )
                remove_directory_link(link)
                create_directory_link(link, second)
                is_valid, reason = revalidate_resource(resolution)
            finally:
                remove_directory_link(link)

        self.assertFalse(is_valid)
        self.assertEqual(reason, "resource_changed_before_execution")

    def _read_profile(self) -> ResolvedToolSecurityProfile:
        return ResolvedToolSecurityProfile(
            revision="tool-security-profiles-test-v1",
            server_ref="streamable_http:http://127.0.0.1:9000/mcp",
            tool_name="read_file",
            operation="read",
            required_capability="filesystem.read",
            resource=ToolResourceProfile(
                adapter="filesystem",
                argument_name="path",
                expected_type="file",
                relative_base_scope="fs.project_workspace",
                allowed_scope_candidates=["fs.project_workspace"],
            ),
        )

    def _resource_registry(
        self,
        root: Path,
        *,
        symlink_policy: str,
    ) -> ResourceRegistry:
        return ResourceRegistry(
            revision="resource-scopes-test-v1",
            filesystem_scopes={
                "fs.project_workspace": ResolvedFilesystemScope(
                    scope_id="fs.project_workspace",
                    root=root,
                    root_resolved=root.resolve(strict=True),
                    allowed_operations=("read", "list"),
                    sensitivity="internal",
                    symlink_policy=symlink_policy,
                    denied_patterns=(),
                )
            },
        )

    def test_allow_with_log_can_execute(self) -> None:
        can_execute, reason = _can_execute_policy_decision(
            validated_policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )

        self.assertTrue(can_execute)
        self.assertIsNone(reason)

    def test_allow_with_warn_and_log_can_execute(self) -> None:
        can_execute, reason = _can_execute_policy_decision(
            validated_policy_decision(
                "ALLOW",
                [
                    {"type": "WARN", "parameters": {}},
                    {"type": "LOG", "parameters": {}},
                ],
            )
        )

        self.assertTrue(can_execute)
        self.assertIsNone(reason)

    def test_deny_cannot_execute(self) -> None:
        can_execute, reason = _can_execute_policy_decision(
            validated_policy_decision(
                "DENY",
                [
                    {"type": "LOG", "parameters": {}},
                    {"type": "ALERT", "parameters": {}},
                ],
                runtime_decision="BLOCK",
            )
        )

        self.assertFalse(can_execute)
        self.assertEqual(reason, "policy_denied")

    def test_defer_cannot_execute(self) -> None:
        can_execute, reason = _can_execute_policy_decision(
            validated_policy_decision(
                "DEFER",
                [
                    {"type": "REQUIRE_APPROVAL", "parameters": {}},
                    {"type": "LOG", "parameters": {}},
                ],
                runtime_decision="ASK_APPROVAL",
            )
        )

        self.assertFalse(can_execute)
        self.assertEqual(reason, "policy_deferred")

    def test_allow_with_limit_output_cannot_execute(self) -> None:
        can_execute, reason = _can_execute_policy_decision(
            validated_policy_decision(
                "ALLOW",
                [
                    {"type": "LIMIT_OUTPUT", "parameters": {}},
                    {"type": "LOG", "parameters": {}},
                ],
                runtime_decision="LIMIT",
            )
        )

        self.assertFalse(can_execute)
        self.assertEqual(reason, "unsupported_policy_obligation")

    def test_allow_with_redact_cannot_execute(self) -> None:
        can_execute, reason = _can_execute_policy_decision(
            validated_policy_decision(
                "ALLOW",
                [
                    {"type": "REDACT", "parameters": {}},
                    {"type": "LOG", "parameters": {}},
                ],
            )
        )

        self.assertFalse(can_execute)
        self.assertEqual(reason, "unsupported_policy_obligation")

    def test_missing_effect_cannot_execute(self) -> None:
        validated, reason = _validate_policy_decision(
            policy_decision(None, [{"type": "LOG", "parameters": {}}])
        )

        self.assertIsNone(validated)
        self.assertEqual(reason, "missing_policy_effect")

    def test_invalid_effect_cannot_execute(self) -> None:
        validated, reason = _validate_policy_decision(
            policy_decision("PERMIT", [{"type": "LOG", "parameters": {}}])
        )

        self.assertIsNone(validated)
        self.assertEqual(reason, "invalid_policy_effect")

    def test_invalid_obligation_structure_cannot_execute(self) -> None:
        validated, reason = _validate_policy_decision(
            policy_decision("ALLOW", [{"parameters": {}}])
        )

        self.assertIsNone(validated)
        self.assertEqual(reason, "invalid_policy_obligation")

    def test_missing_rule_ids_cannot_execute(self) -> None:
        decision = policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        del decision["rule_ids"]

        validated, reason = _validate_policy_decision(decision)

        self.assertIsNone(validated)
        self.assertEqual(reason, "invalid_policy_decision")

    def test_incoherent_effect_and_decision_cannot_execute(self) -> None:
        decision = policy_decision(
            "ALLOW",
            [{"type": "LOG", "parameters": {}}],
            runtime_decision="BLOCK",
        )

        validated, reason = _validate_policy_decision(decision)

        self.assertIsNone(validated)
        self.assertEqual(reason, "inconsistent_policy_decision")

    def test_missing_minimal_obligation_cannot_execute(self) -> None:
        decision = policy_decision(
            "ALLOW",
            [{"type": "LOG", "parameters": {}}],
            runtime_decision="WARN",
            rule_id="warn_high_risk_tool",
        )

        validated, reason = _validate_policy_decision(decision)

        self.assertIsNone(validated)
        self.assertEqual(reason, "invalid_policy_obligation")

    def test_rule_id_not_in_rule_ids_cannot_execute(self) -> None:
        decision = policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        decision["rule_ids"] = ["another_rule"]

        validated, reason = _validate_policy_decision(decision)

        self.assertIsNone(validated)
        self.assertEqual(reason, "inconsistent_policy_decision")

    def test_duplicate_obligations_cannot_execute(self) -> None:
        decision = policy_decision(
            "ALLOW",
            [
                {"type": "LOG", "parameters": {}},
                {"type": "LOG", "parameters": {}},
            ],
        )

        validated, reason = _validate_policy_decision(decision)

        self.assertIsNone(validated)
        self.assertEqual(reason, "invalid_policy_obligation")

    def test_malformed_obligation_parameters_cannot_execute(self) -> None:
        decision = policy_decision(
            "ALLOW",
            [{"type": "LOG", "parameters": "not-an-object"}],
        )

        validated, reason = _validate_policy_decision(decision)

        self.assertIsNone(validated)
        self.assertEqual(reason, "invalid_policy_obligation")

    def test_fail_closed_proxy_decision_is_validated(self) -> None:
        decision = _fail_closed_proxy_decision(
            rule_id="policy_error",
            reason="Policy decision failed.",
        )

        validated = PolicyDecision.model_validate(decision.model_dump(mode="json"))

        self.assertEqual(validated.effect, "DENY")
        self.assertEqual(validated.decision, "BLOCK")
        self.assertEqual(validated.rule_id, "policy_error")

    def test_validate_policy_decision_returns_policy_decision(self) -> None:
        validated, error = _validate_policy_decision(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )

        self.assertIsNone(error)
        self.assertIsInstance(validated, PolicyDecision)

        can_execute, reason = _can_execute_policy_decision(validated)

        self.assertTrue(can_execute)
        self.assertIsNone(reason)

    def test_can_execute_rejects_raw_dict(self) -> None:
        with self.assertRaises(TypeError):
            _can_execute_policy_decision(
                policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
            )

    def test_warn_without_warn_is_invalid_policy_obligation(self) -> None:
        validated, reason = _validate_policy_decision(
            policy_decision(
                "ALLOW",
                [{"type": "LOG", "parameters": {}}],
                runtime_decision="WARN",
                rule_id="warn_high_risk_tool",
            )
        )

        self.assertIsNone(validated)
        self.assertEqual(reason, "invalid_policy_obligation")

    def test_limit_without_limit_output_is_invalid_policy_obligation(self) -> None:
        validated, reason = _validate_policy_decision(
            policy_decision(
                "ALLOW",
                [{"type": "LOG", "parameters": {}}],
                runtime_decision="LIMIT",
                rule_id="limit_large_outputs",
            )
        )

        self.assertIsNone(validated)
        self.assertEqual(reason, "invalid_policy_obligation")

    def test_block_without_alert_is_invalid_policy_obligation(self) -> None:
        validated, reason = _validate_policy_decision(
            policy_decision(
                "DENY",
                [{"type": "LOG", "parameters": {}}],
                runtime_decision="BLOCK",
                rule_id="deny_sensitive_paths",
            )
        )

        self.assertIsNone(validated)
        self.assertEqual(reason, "invalid_policy_obligation")

    def test_ask_approval_without_required_approval_is_invalid_policy_obligation(self) -> None:
        validated, reason = _validate_policy_decision(
            policy_decision(
                "DEFER",
                [{"type": "LOG", "parameters": {}}],
                runtime_decision="ASK_APPROVAL",
                rule_id="require_approval_for_sensitive_tool",
            )
        )

        self.assertIsNone(validated)
        self.assertEqual(reason, "invalid_policy_obligation")

    def test_allow_without_log_is_invalid_policy_obligation(self) -> None:
        validated, reason = _validate_policy_decision(
            policy_decision("ALLOW", [{"type": "WARN", "parameters": {}}])
        )

        self.assertIsNone(validated)
        self.assertEqual(reason, "invalid_policy_obligation")

    def test_effect_deny_with_decision_allow_is_inconsistent(self) -> None:
        validated, reason = _validate_policy_decision(
            policy_decision("DENY", [{"type": "LOG", "parameters": {}}])
        )

        self.assertIsNone(validated)
        self.assertEqual(reason, "inconsistent_policy_decision")

    def test_effect_allow_with_decision_ask_approval_is_inconsistent(self) -> None:
        validated, reason = _validate_policy_decision(
            policy_decision(
                "ALLOW",
                [
                    {"type": "REQUIRE_APPROVAL", "parameters": {}},
                    {"type": "LOG", "parameters": {}},
                ],
                runtime_decision="ASK_APPROVAL",
                rule_id="require_approval_for_sensitive_tool",
            )
        )

        self.assertIsNone(validated)
        self.assertEqual(reason, "inconsistent_policy_decision")

    def test_rate_limit_is_unsupported_policy_obligation(self) -> None:
        can_execute, reason = _can_execute_policy_decision(
            validated_policy_decision(
                "ALLOW",
                [
                    {"type": "RATE_LIMIT", "parameters": {}},
                    {"type": "LOG", "parameters": {}},
                ],
            )
        )

        self.assertFalse(can_execute)
        self.assertEqual(reason, "unsupported_policy_obligation")

    def test_alert_with_allow_is_unsupported_policy_obligation(self) -> None:
        can_execute, reason = _can_execute_policy_decision(
            validated_policy_decision(
                "ALLOW",
                [
                    {"type": "ALERT", "parameters": {}},
                    {"type": "LOG", "parameters": {}},
                ],
            )
        )

        self.assertFalse(can_execute)
        self.assertEqual(reason, "unsupported_policy_obligation")

    def test_inventory_error_blocks_without_calling_mcp(self) -> None:
        TrackingMCPClient.called = False
        proxy = MCPProxy(
            backend_client=InventoryErrorBackendClient({}),
            mcp_client_class=TrackingMCPClient,
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)
        self.assertEqual(result["decision"]["effect"], "DENY")
        self.assertEqual(result["decision"]["decision"], "BLOCK")
        self.assertEqual(result["decision"]["rule_id"], "inventory_error")
        self.assertEqual(result["skip_reason"], "inventory_error")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["execution_status"], "blocked")

    def test_policy_error_blocks_without_calling_mcp(self) -> None:
        TrackingMCPClient.called = False
        proxy = MCPProxy(
            backend_client=PolicyErrorBackendClient({}),
            mcp_client_class=TrackingMCPClient,
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)
        self.assertEqual(result["decision"]["effect"], "DENY")
        self.assertEqual(result["decision"]["decision"], "BLOCK")
        self.assertEqual(result["decision"]["rule_id"], "policy_error")
        self.assertEqual(result["skip_reason"], "policy_error")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["execution_status"], "blocked")

    def test_invalid_session_blocks_without_policy_or_mcp(self) -> None:
        TrackingMCPClient.called = False
        backend = FakeBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["session_token"] = "invalid-session-token"

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)
        self.assertIsNone(backend.last_policy_context)
        self.assertEqual(result["decision"]["rule_id"], "trusted_identity_required")
        self.assertEqual(
            result["decision"]["evidence"]["identity_error_code"],
            "trusted_session_invalid",
        )
        self.assertEqual(result["skip_reason"], "trusted_session_invalid")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["execution_status"], "blocked")

    def test_non_dict_policy_response_blocks_without_calling_mcp(self) -> None:
        TrackingMCPClient.called = False
        proxy = MCPProxy(
            backend_client=FakeBackendClient(["ALLOW"]),
            mcp_client_class=TrackingMCPClient,
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)
        self.assertEqual(result["decision"]["rule_id"], "invalid_policy_decision")
        self.assertEqual(result["skip_reason"], "invalid_policy_decision")
        self.assertEqual(result["execution_status"], "blocked")

    def test_partial_backend_decision_does_not_call_mcp(self) -> None:
        TrackingMCPClient.called = False
        proxy = MCPProxy(
            backend_client=FakeBackendClient(
                {
                    "effect": "ALLOW",
                    "obligations": [{"type": "LOG", "parameters": {}}],
                    "decision": "ALLOW",
                    "rule_id": "partial_rule",
                }
            ),
            mcp_client_class=TrackingMCPClient,
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)
        self.assertEqual(result["skip_reason"], "invalid_policy_decision")
        self.assertEqual(result["decision"]["effect"], "DENY")
        self.assertEqual(result["decision"]["decision"], "BLOCK")

    def test_unsupported_obligation_blocks_without_limited_status(self) -> None:
        TrackingMCPClient.called = False
        proxy = MCPProxy(
            backend_client=FakeBackendClient(
                policy_decision(
                    "ALLOW",
                    [
                        {"type": "LIMIT_OUTPUT", "parameters": {}},
                        {"type": "LOG", "parameters": {}},
                    ],
                    runtime_decision="LIMIT",
                    rule_id="limit_large_outputs",
                )
            ),
            mcp_client_class=TrackingMCPClient,
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["execution_status"], "blocked")
        self.assertEqual(result["skip_reason"], "unsupported_policy_obligation")
        self.assertEqual(
            result["runtime_log"]["error_summary"],
            "unsupported_policy_obligation",
        )

    def test_proxy_executes_opa_allow(self) -> None:
        TrackingMCPClient.called = False
        proxy = MCPProxy(
            backend_client=FakeBackendClient(
                policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
            ),
            mcp_client_class=TrackingMCPClient,
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertTrue(result["executed"])
        self.assertTrue(result["mcp_called"])
        self.assertTrue(TrackingMCPClient.called)

    def test_proxy_executes_opa_warn(self) -> None:
        TrackingMCPClient.called = False
        proxy = MCPProxy(
            backend_client=FakeBackendClient(
                policy_decision(
                    "ALLOW",
                    [
                        {"type": "WARN", "parameters": {}},
                        {"type": "LOG", "parameters": {}},
                    ],
                    runtime_decision="WARN",
                    rule_id="warn_high_risk_tool",
                )
            ),
            mcp_client_class=TrackingMCPClient,
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertTrue(result["executed"])
        self.assertTrue(result["mcp_called"])
        self.assertTrue(TrackingMCPClient.called)

    def test_proxy_blocks_opa_deny(self) -> None:
        TrackingMCPClient.called = False
        proxy = MCPProxy(
            backend_client=FakeBackendClient(
                policy_decision(
                    "DENY",
                    [
                        {"type": "LOG", "parameters": {}},
                        {"type": "ALERT", "parameters": {}},
                    ],
                    runtime_decision="BLOCK",
                    rule_id="deny_sensitive_paths",
                )
            ),
            mcp_client_class=TrackingMCPClient,
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)

    def test_proxy_blocks_opa_defer(self) -> None:
        TrackingMCPClient.called = False
        proxy = MCPProxy(
            backend_client=FakeBackendClient(
                policy_decision(
                    "DEFER",
                    [
                        {"type": "REQUIRE_APPROVAL", "parameters": {}},
                        {"type": "LOG", "parameters": {}},
                    ],
                    runtime_decision="ASK_APPROVAL",
                    rule_id="require_approval_for_sensitive_tool",
                )
            ),
            mcp_client_class=TrackingMCPClient,
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)

    def test_proxy_blocks_opa_limit(self) -> None:
        TrackingMCPClient.called = False
        proxy = MCPProxy(
            backend_client=FakeBackendClient(
                policy_decision(
                    "ALLOW",
                    [
                        {"type": "LIMIT_OUTPUT", "parameters": {}},
                        {"type": "LOG", "parameters": {}},
                    ],
                    runtime_decision="LIMIT",
                    rule_id="limit_large_outputs",
                )
            ),
            mcp_client_class=TrackingMCPClient,
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)
        self.assertEqual(result["skip_reason"], "unsupported_policy_obligation")

    def test_proxy_blocks_opa_fail_closed_unavailable(self) -> None:
        TrackingMCPClient.called = False
        proxy = MCPProxy(
            backend_client=FakeBackendClient(
                policy_decision(
                    "DENY",
                    [
                        {"type": "LOG", "parameters": {}},
                        {"type": "ALERT", "parameters": {}},
                    ],
                    runtime_decision="BLOCK",
                    rule_id="opa_unavailable",
                )
            ),
            mcp_client_class=TrackingMCPClient,
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["executed"])
        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)
        self.assertEqual(result["decision"]["rule_id"], "opa_unavailable")

    def test_valid_contract_arguments_are_prepared_and_executed(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)

        result = proxy.handle_tool_call(tool_call())

        self.assertTrue(result["executed"])
        self.assertEqual(
            backend.last_policy_context["request"]["canonical_resource"],
            "fs.project_workspace:/contracts/contract1.txt",
        )
        self.assertEqual(
            backend.last_policy_context["request"]["arguments"],
            {"path": "contracts/contract1.txt"},
        )
        self.assertEqual(TrackingMCPClient.last_arguments, {"path": "contracts/contract1.txt"})

    def test_backslash_path_is_normalized_before_policy_and_mcp(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["arguments"] = {"path": "contracts\\contract1.txt"}

        result = proxy.handle_tool_call(call)

        self.assertTrue(result["executed"])
        self.assertEqual(
            backend.last_policy_context["request"]["canonical_resource"],
            "fs.project_workspace:/contracts/contract1.txt",
        )
        self.assertEqual(TrackingMCPClient.last_arguments, {"path": "contracts/contract1.txt"})

    def test_dot_segment_path_is_normalized_before_policy_and_mcp(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["arguments"] = {"path": "contracts/./contract1.txt"}

        result = proxy.handle_tool_call(call)

        self.assertTrue(result["executed"])
        self.assertEqual(
            backend.last_policy_context["request"]["canonical_resource"],
            "fs.project_workspace:/contracts/contract1.txt",
        )
        self.assertEqual(TrackingMCPClient.last_arguments, {"path": "contracts/contract1.txt"})

    def test_integer_path_is_invalid_and_not_sent_to_mcp(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["arguments"] = {"path": 123}

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "invalid_tool_arguments_guard")
        self.assertFalse(backend.last_policy_context["request"]["arguments_valid"])
        self.assertEqual(backend.last_policy_context["request"]["arguments"], {})
        self.assertIn("invalid_type:path", backend.last_policy_context["request"]["validation_error_codes"])

    def test_array_null_missing_and_extra_arguments_are_invalid(self) -> None:
        cases = [
            ({"path": [".env"]}, "invalid_type:path"),
            ({"path": None}, "invalid_type:path"),
            ({}, "missing_required:path"),
            ({"path": "contracts/contract1.txt", "admin": True}, "unexpected_argument:admin"),
        ]
        for arguments, expected_code in cases:
            with self.subTest(arguments=arguments):
                reset_tracking_mcp_client()
                backend = FakeBackendClient(
                    policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
                )
                proxy = MCPProxy(
                    backend_client=backend,
                    mcp_client_class=TrackingMCPClient,
                )
                call = tool_call()
                call["arguments"] = arguments

                result = proxy.handle_tool_call(call)

                self.assertFalse(result["mcp_called"])
                self.assertFalse(TrackingMCPClient.called)
                self.assertIn(
                    expected_code,
                    backend.last_policy_context["request"]["validation_error_codes"],
                )

    def test_missing_schema_is_invalid_and_not_sent_to_mcp(self) -> None:
        reset_tracking_mcp_client()
        backend = MissingSchemaBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "invalid_tool_arguments_guard")
        self.assertIn("input_schema_missing", backend.last_policy_context["request"]["validation_error_codes"])

    def test_invalid_schema_is_invalid_and_not_sent_to_mcp(self) -> None:
        reset_tracking_mcp_client()
        backend = InvalidSchemaBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "invalid_tool_arguments_guard")
        self.assertIn("input_schema_invalid", backend.last_policy_context["request"]["validation_error_codes"])

    def test_traversal_outside_root_and_absolute_path_are_invalid(self) -> None:
        cases = [
            ("../../.env", "path_traversal_outside_root"),
            ("/etc/passwd", "resource_outside_registered_scope"),
        ]
        for path, expected_code in cases:
            with self.subTest(path=path):
                reset_tracking_mcp_client()
                backend = FakeBackendClient(
                    policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
                )
                proxy = MCPProxy(
                    backend_client=backend,
                    mcp_client_class=TrackingMCPClient,
                )
                call = tool_call()
                call["arguments"] = {"path": path}

                result = proxy.handle_tool_call(call)

                self.assertFalse(result["mcp_called"])
                self.assertEqual(
                    backend.last_policy_context["request"][
                        "resource_resolution_status"
                    ],
                    expected_code,
                )

    def test_contract_parent_env_uses_canonical_sensitive_path(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision(
                "DENY",
                [
                    {"type": "LOG", "parameters": {}},
                    {"type": "ALERT", "parameters": {}},
                ],
                runtime_decision="BLOCK",
                rule_id="deny_sensitive_paths",
            )
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["arguments"] = {"path": "contracts/../.env"}

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertEqual(
            backend.last_policy_context["request"]["canonical_resource"],
            "fs.project_workspace:/.ENV",
        )
        self.assertEqual(result["decision"]["rule_id"], "deny_sensitive_paths")

    def test_uppercase_env_is_sensitive_and_not_sent_to_mcp(self) -> None:
        reset_tracking_mcp_client()
        backend = EvaluatingBackendClient({})
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["arguments"] = {"path": ".ENV"}

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)
        self.assertEqual(
            backend.last_policy_context["request"]["canonical_resource"],
            "fs.project_workspace:/.ENV",
        )
        self.assertEqual(
            backend.last_policy_context["request"]["resource_scope"],
            "fs.project_workspace",
        )
        self.assertEqual(result["decision"]["rule_id"], "deny_sensitive_resource")
        self.assertEqual(result["decision"]["effect"], "DENY")

    def test_contract_parent_uppercase_env_uses_canonical_sensitive_path(self) -> None:
        reset_tracking_mcp_client()
        backend = EvaluatingBackendClient({})
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["arguments"] = {"path": "contracts/../.ENV"}

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertEqual(
            backend.last_policy_context["request"]["canonical_resource"],
            "fs.project_workspace:/.ENV",
        )
        self.assertEqual(result["decision"]["rule_id"], "deny_sensitive_resource")

    def test_uppercase_secrets_path_is_sensitive_and_not_sent_to_mcp(self) -> None:
        reset_tracking_mcp_client()
        backend = EvaluatingBackendClient({})
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["arguments"] = {"path": "SECRETS/api.txt"}

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)
        self.assertEqual(
            backend.last_policy_context["request"]["resource_scope"],
            "fs.project_workspace",
        )
        self.assertEqual(result["decision"]["rule_id"], "deny_sensitive_resource")

    def test_unknown_schema_dialect_denies_invalid_arguments(self) -> None:
        reset_tracking_mcp_client()
        backend = EvaluatingUnknownDialectSchemaBackendClient({})
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)
        self.assertFalse(backend.last_policy_context["request"]["arguments_valid"])
        self.assertEqual(backend.last_policy_context["request"]["arguments"], {})
        self.assertIn(
            "input_schema_unsupported_draft",
            backend.last_policy_context["request"]["validation_error_codes"],
        )
        self.assertEqual(result["decision"]["rule_id"], "deny_invalid_arguments")

    def test_backend_allow_with_unknown_schema_dialect_triggers_local_guard(self) -> None:
        reset_tracking_mcp_client()
        backend = UnknownDialectSchemaBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertFalse(TrackingMCPClient.called)
        self.assertEqual(result["decision"]["rule_id"], "invalid_tool_arguments_guard")
        self.assertIn(
            "input_schema_unsupported_draft",
            backend.last_policy_context["request"]["validation_error_codes"],
        )

    def test_draft7_schema_validates_normally_and_can_execute(self) -> None:
        reset_tracking_mcp_client()
        backend = Draft7SchemaBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)

        result = proxy.handle_tool_call(tool_call())

        self.assertTrue(result["executed"])
        self.assertTrue(result["mcp_called"])
        self.assertTrue(TrackingMCPClient.called)
        self.assertTrue(backend.last_policy_context["request"]["arguments_valid"])
        self.assertEqual(TrackingMCPClient.last_arguments, {"path": "contracts/contract1.txt"})

    def test_schema_without_schema_uri_uses_default_draft_and_can_execute(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)

        result = proxy.handle_tool_call(tool_call())

        self.assertTrue(result["executed"])
        self.assertTrue(result["mcp_called"])
        self.assertTrue(backend.last_policy_context["request"]["arguments_valid"])

    def test_spoofed_prepared_facts_are_ignored(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call.update(
            {
                "arguments": {"path": 123},
                "arguments_valid": True,
                "canonical_resource": "contracts/contract1.txt",
                "resource_scope": "contracts",
                "operation": "read",
            }
        )

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertFalse(backend.last_policy_context["request"]["arguments_valid"])
        self.assertIsNone(backend.last_policy_context["request"]["canonical_resource"])
        self.assertEqual(backend.last_policy_context["request"]["resource_scope"], "invalid")
        self.assertEqual(result["decision"]["rule_id"], "invalid_tool_arguments_guard")

    def test_policy_deny_is_preserved_for_invalid_arguments(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision(
                "DENY",
                [
                    {"type": "LOG", "parameters": {}},
                    {"type": "ALERT", "parameters": {}},
                ],
                runtime_decision="BLOCK",
                rule_id="deny_invalid_arguments",
            )
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["arguments"] = {"path": 123}

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "deny_invalid_arguments")
        self.assertEqual(result["skip_reason"], "policy_denied")

    def test_preparation_error_does_not_call_policy_or_mcp(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)

        with patch("proxy.mcp_proxy.prepare_tool_request", side_effect=RuntimeError):
            result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertIsNone(backend.last_policy_context)
        self.assertEqual(result["decision"]["rule_id"], "request_preparation_error")
        self.assertEqual(result["skip_reason"], "request_preparation_error")

    def test_unknown_tool_keeps_inventory_error_behavior(self) -> None:
        reset_tracking_mcp_client()
        proxy = MCPProxy(
            backend_client=UnknownToolBackendClient({}),
            mcp_client_class=TrackingMCPClient,
        )

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "inventory_error")

    def test_caller_spoofed_required_capability_is_ignored(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["required_capability"] = "filesystem.admin"

        proxy.handle_tool_call(call)

        self.assertEqual(
            backend.last_policy_context["request"]["required_capability"],
            "filesystem.read",
        )

    def test_caller_subject_entitlements_are_not_sent_as_authoritative(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call.update(
            {
                "agent_role": "admin",
                "allowed_capabilities": ["filesystem.admin"],
                "allowed_scopes": ["everything"],
                "grants": [
                    {
                        "capability": "filesystem.admin",
                        "scopes": ["everything"],
                    }
                ],
            }
        )

        proxy.handle_tool_call(call)

        subject = backend.last_policy_context["subject"]
        self.assertEqual(subject["role"], "unknown")
        self.assertEqual(subject["authorization_status"], "unknown")
        self.assertEqual(subject["allowed_capabilities"], [])
        self.assertEqual(subject["allowed_scopes"], [])
        self.assertEqual(subject["grants"], [])

    def test_list_files_produces_filesystem_list_capability(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision("ALLOW", [{"type": "LOG", "parameters": {}}])
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = {
            "agent_id": "agent-demo",
            "access_token": "token:agent-demo",
            "session_id": "session-001",
            "tool_name": "list_files",
            "arguments": {},
        }

        proxy.handle_tool_call(call)

        self.assertEqual(
            backend.last_policy_context["request"]["required_capability"],
            "filesystem.list",
        )

    def test_agent_demo_read_contract_is_executed(self) -> None:
        reset_tracking_mcp_client()
        backend = SubjectAwareEvaluatingBackendClient({})
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)

        result = proxy.handle_tool_call(tool_call())

        self.assertTrue(result["executed"])
        self.assertTrue(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "allow_contracts_read")

    def test_agent_demo_list_files_is_executed(self) -> None:
        reset_tracking_mcp_client()
        backend = SubjectAwareEvaluatingBackendClient({})
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = {
            "agent_id": "agent-demo",
            "access_token": "token:agent-demo",
            "session_id": "session-001",
            "tool_name": "list_files",
            "arguments": {},
        }

        result = proxy.handle_tool_call(call)

        self.assertTrue(result["executed"])
        self.assertTrue(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "log_normal_runtime_call")

    def test_contract_reader_list_files_is_blocked(self) -> None:
        reset_tracking_mcp_client()
        backend = SubjectAwareEvaluatingBackendClient({})
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = {
            "agent_id": "agent-contract-reader",
            "access_token": "token:agent-contract-reader",
            "session_id": "session-001",
            "tool_name": "list_files",
            "arguments": {},
        }

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "deny_capability_not_granted")

    def test_list_only_read_contract_is_blocked(self) -> None:
        reset_tracking_mcp_client()
        backend = SubjectAwareEvaluatingBackendClient({})
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["agent_id"] = "agent-list-only"
        call["access_token"] = "token:agent-list-only"

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "deny_capability_not_granted")

    def test_no_access_read_contract_is_blocked(self) -> None:
        reset_tracking_mcp_client()
        backend = SubjectAwareEvaluatingBackendClient({})
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["agent_id"] = "agent-no-access"
        call["access_token"] = "token:agent-no-access"

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "deny_capability_not_granted")

    def test_unknown_agent_with_spoofed_grants_is_blocked(self) -> None:
        reset_tracking_mcp_client()
        backend = SubjectAwareEvaluatingBackendClient({})
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call.update(
            {
                "agent_id": "unknown-agent",
                "access_token": "token:unknown-agent",
                "allowed_capabilities": ["filesystem.read"],
                "allowed_scopes": ["contracts"],
                "grants": [
                    {
                        "capability": "filesystem.read",
                        "scopes": ["contracts"],
                    }
                ],
            }
        )

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "deny_unknown_subject")

    def test_cross_product_scope_attack_is_blocked(self) -> None:
        reset_tracking_mcp_client()
        backend = SubjectAwareEvaluatingBackendClient({})
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["arguments"] = {"path": "public/readme.txt"}

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "deny_scope_not_granted")

    def test_subject_authorization_fail_closed_blocks_before_mcp(self) -> None:
        reset_tracking_mcp_client()
        backend = FakeBackendClient(
            policy_decision(
                "DENY",
                [
                    {"type": "LOG", "parameters": {}},
                    {"type": "ALERT", "parameters": {}},
                ],
                runtime_decision="BLOCK",
                rule_id="subject_authorization_unavailable",
            )
        )
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)

        result = proxy.handle_tool_call(tool_call())

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "subject_authorization_unavailable")

    def test_sensitive_path_remains_priority_for_known_subject(self) -> None:
        reset_tracking_mcp_client()
        backend = SubjectAwareEvaluatingBackendClient({})
        proxy = MCPProxy(backend_client=backend, mcp_client_class=TrackingMCPClient)
        call = tool_call()
        call["arguments"] = {"path": ".ENV"}

        result = proxy.handle_tool_call(call)

        self.assertFalse(result["mcp_called"])
        self.assertEqual(result["decision"]["rule_id"], "deny_sensitive_resource")
