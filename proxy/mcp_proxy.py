from pathlib import Path
import sys
from typing import Any
from datetime import datetime, timezone

from pydantic import ValidationError

backend_path = Path(__file__).resolve().parents[1] / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from proxy.agent_identity import (
    AgentIdentityError,
    AgentIdentityVerifier,
    JWTJWKSAgentIdentityVerifier,
    VerifiedExternalIdentity,
)
from proxy.backend_client import BackendClient, BackendClientError
from proxy.http_mcp_client import (
    MCPHttpClient,
    MCPHttpError,
    MCPProtocolError,
    SUPPORTED_PROTOCOL_VERSION,
)
from proxy.protocol_profiles import (
    LEGACY_PROFILE_ID,
    ProtocolProfileError,
    ProtocolProfileRegistry,
)
from proxy.protocol_revisions import ProtocolEra
from proxy.protocol_sessions import LegacyUpstreamSessionPool
from app.services.published_configuration import (
    PublishedConfigurationError,
    PublishedConfigurationSnapshot,
    PublishedConfigurationSnapshotResolver,
)
from proxy.identity_binding import (
    IdentityBindingError,
    IdentityBindingResolver,
    ResolvedIdentityBinding,
)
from proxy.internal_identity_assertion import (
    InternalIdentityAssertionError,
    InternalIdentityAssertionSigner,
)
from proxy.runtime_logger import (
    build_runtime_log,
    send_runtime_log,
    summarize_tool_result,
)
from proxy.tool_request_preparation import (
    PreparedToolRequest,
    prepare_tool_request_v2,
)
from proxy.resource_adapters_v2 import inspect_adapter_result
from proxy.tool_security_v2 import AdapterResolution
from proxy.tool_result_guard import ToolResultGuard, is_external_effect, should_track_result
from common.canonical_json import sha256_canonical_json
from common.mcp_endpoint import (
    MCPEndpointValidationError,
    server_ref_for_server,
    validate_mcp_endpoint,
)
from common.trust_status import is_trusted_server_status
from common.upstream_auth import (
    UpstreamAuthError,
    resolve_upstream_bearer_token,
    upstream_auth_context_hash,
    validate_upstream_auth_config,
)
from proxy.trusted_sessions import (
    ProxyTrustedSession,
    TrustedSessionError,
    TrustedSessionManager,
    direct_bearer_session,
)

try:
    from app.schemas.policy_decision import PolicyDecision, PolicyEffect
except ModuleNotFoundError:
    from app.schemas.policy_decision import PolicyDecision, PolicyEffect


SUPPORTED_RUNTIME_OBLIGATIONS = {"LOG", "WARN"}
VALID_POLICY_EFFECTS = {"ALLOW", "DENY", "DEFER"}


def _can_execute_policy_decision(decision: PolicyDecision) -> tuple[bool, str | None]:
    if not isinstance(decision, PolicyDecision):
        raise TypeError("_can_execute_policy_decision requires a PolicyDecision.")

    if decision.effect == PolicyEffect.DENY:
        return False, "policy_denied"

    if decision.effect == PolicyEffect.DEFER:
        return False, "policy_deferred"

    if decision.effect != PolicyEffect.ALLOW:
        return False, "invalid_policy_effect"

    obligation_types = {obligation.type.value for obligation in decision.obligations}

    unsupported_obligations = obligation_types - SUPPORTED_RUNTIME_OBLIGATIONS
    if unsupported_obligations:
        return False, "unsupported_policy_obligation"

    return True, None


def _validate_policy_decision(
    raw_decision: Any,
    *,
    expected_revision_id: str | None = None,
    expected_content_hash: str | None = None,
    expected_arguments_hash: str | None = None,
) -> tuple[PolicyDecision | None, str | None]:
    if not isinstance(raw_decision, dict):
        return None, "invalid_policy_decision"

    if "effect" not in raw_decision:
        return None, "missing_policy_effect"

    effect = raw_decision.get("effect")
    if effect not in VALID_POLICY_EFFECTS:
        return None, "invalid_policy_effect"

    try:
        validated = PolicyDecision.model_validate(raw_decision)
    except ValidationError as exc:
        return None, _classify_policy_validation_error(exc)

    if expected_arguments_hash is not None:
        if not validated.decision_id:
            return None, "missing_decision_id"
        if validated.control_plane_revision_id != expected_revision_id:
            return None, "policy_revision_binding_mismatch"
        if validated.control_plane_content_hash != expected_content_hash:
            return None, "policy_content_hash_binding_mismatch"
        if validated.canonical_arguments_hash != expected_arguments_hash:
            return None, "policy_arguments_hash_binding_mismatch"

    return validated, None


def _classify_policy_validation_error(exc: ValidationError) -> str:
    for error in exc.errors():
        location = tuple(str(part) for part in error.get("loc", ()))
        message = str(error.get("msg", ""))

        if any(part == "obligations" for part in location):
            return "invalid_policy_obligation"

        if "obligation" in message:
            return "invalid_policy_obligation"

        if "effect is not coherent" in message:
            return "inconsistent_policy_decision"

        if "rule_id must be present" in message:
            return "inconsistent_policy_decision"

    return "invalid_policy_decision"


class MCPProxy:
    def __init__(
        self,
        backend_client: BackendClient | None = None,
        mcp_client_class: type[MCPHttpClient] = MCPHttpClient,
        identity_verifier: AgentIdentityVerifier | None = None,
        identity_binding_resolver: IdentityBindingResolver | None = None,
        assertion_signer: InternalIdentityAssertionSigner | None = None,
        trusted_session_manager: TrustedSessionManager | None = None,
        config_snapshot_resolver: PublishedConfigurationSnapshotResolver | None = None,
        legacy_upstream_session_pool: LegacyUpstreamSessionPool | None = None,
        tool_result_guard: ToolResultGuard | None = None,
    ) -> None:
        self.backend_client = backend_client or BackendClient()
        self.mcp_client_class = mcp_client_class
        self.identity_verifier = identity_verifier or JWTJWKSAgentIdentityVerifier()
        self.identity_binding_resolver = identity_binding_resolver
        self.assertion_signer = assertion_signer or InternalIdentityAssertionSigner()
        self.trusted_session_manager = (
            trusted_session_manager or TrustedSessionManager()
        )
        self.config_snapshot_resolver = (
            config_snapshot_resolver or PublishedConfigurationSnapshotResolver()
        )
        self.legacy_upstream_session_pool = (
            legacy_upstream_session_pool or LegacyUpstreamSessionPool()
        )
        self.tool_result_guard = tool_result_guard or ToolResultGuard()
        self._requires_config_snapshot = True

    def handle_tool_call(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        claimed_agent_id = tool_call.get("agent_id")
        safe_input_tool_call = {
            key: value
            for key, value in tool_call.items()
            if key
            not in {
                "access_token",
                "authorization",
                "identity_assertion",
                "session_token",
            }
        }

        try:
            config_snapshot = self._load_config_snapshot()
        except PublishedConfigurationError as exc:
            return self._trusted_identity_error_response(
                safe_input_tool_call,
                exc.code,
            )
        except Exception:
            return self._trusted_identity_error_response(
                safe_input_tool_call,
                "published_config_unavailable",
            )

        identity_binding_resolver = self.identity_binding_resolver or config_snapshot
        if identity_binding_resolver is None:
            return self._trusted_identity_error_response(
                safe_input_tool_call,
                "published_config_unavailable",
            )

        try:
            trusted_session = self._resolve_trusted_session(
                tool_call,
                claimed_agent_id=claimed_agent_id,
                identity_binding_resolver=identity_binding_resolver,
            )
        except AgentIdentityError as exc:
            return self._trusted_identity_error_response(
                safe_input_tool_call,
                exc.code,
            )
        except IdentityBindingError as exc:
            return self._trusted_identity_error_response(
                safe_input_tool_call,
                exc.code,
            )
        except TrustedSessionError as exc:
            return self._trusted_identity_error_response(
                safe_input_tool_call,
                exc.code,
            )
        except Exception:
            return self._trusted_identity_error_response(
                safe_input_tool_call,
                "identity_verification_unexpected_error",
            )

        tool_call = {
            **safe_input_tool_call,
            "agent_id": trusted_session.agent_id,
            "identity_status": "verified",
            "identity_issuer": trusted_session.identity_issuer,
            "identity_binding_revision": trusted_session.identity_binding_revision,
            "session_status": trusted_session.session_status,
            "session_reference": trusted_session.session_reference,
            "session_id": trusted_session.session_reference,
            "control_plane_revision_id": (
                config_snapshot.revision_id if config_snapshot is not None else "unknown"
            ),
            "control_plane_revision_number": (
                config_snapshot.revision_number if config_snapshot is not None else None
            ),
            "control_plane_content_hash": (
                config_snapshot.content_hash if config_snapshot is not None else "unknown"
            ),
            "policy_settings": (
                config_snapshot.get_policy_settings()
                if config_snapshot is not None
                and callable(getattr(config_snapshot, "get_policy_settings", None))
                else {"rules": {}}
            ),
        }

        raw_arguments = tool_call.get("arguments", {})
        if raw_arguments is None:
            raw_arguments = {}

        tool_call = {
            **tool_call,
            "tool_name": tool_call.get("tool_name"),
            "arguments": raw_arguments,
        }

        try:
            server = self._resolve_server(tool_call)
        except BackendClientError as exc:
            return self._inventory_error_response(tool_call, str(exc))
        if protocol_verdict_expired(server):
            return self._inventory_error_response(
                tool_call,
                "Registered MCP protocol verdict is expired; rediscovery is required.",
            )

        upstream_protocol_profile_id = (
            server.get("preferred_upstream_profile")
            or server.get("preferred_protocol_profile")
            or LEGACY_PROFILE_ID
        )
        try:
            tool = self._resolve_tool(
                server,
                tool_call,
                str(upstream_protocol_profile_id),
            )
        except BackendClientError as exc:
            return self._inventory_error_response(tool_call, str(exc))
        tool_call = {
            **tool_call,
            "client_protocol_profile_id": (
                tool_call.get("client_protocol_profile_id") or LEGACY_PROFILE_ID
            ),
            "upstream_protocol_profile_id": upstream_protocol_profile_id,
        }
        try:
            profile_registry = ProtocolProfileRegistry()
            client_protocol_profile = profile_registry.get(
                str(tool_call["client_protocol_profile_id"])
            )
            upstream_protocol_profile = profile_registry.get(str(upstream_protocol_profile_id))
        except ProtocolProfileError as exc:
            return self._profile_error_response(
                tool_call,
                server.get("id"),
                str(exc),
            )
        tool_call = {
            **tool_call,
            "client_protocol_era": client_protocol_profile.protocol_era.value,
            "client_protocol_version": client_protocol_profile.protocol_version,
            "client_transport_kind": client_protocol_profile.transport_kind.value,
            "upstream_protocol_era": upstream_protocol_profile.protocol_era.value,
            "upstream_protocol_version": upstream_protocol_profile.protocol_version,
            "upstream_transport_kind": upstream_protocol_profile.transport_kind.value,
        }

        server_ref = server_ref_for_server(server)
        emergency_code, deny_id = self._emergency_deny_status(
            tool_call,
            server_ref=server_ref,
            tool_name=str(tool.get("name") or tool_call.get("tool_name") or ""),
        )
        if emergency_code is not None:
            return self._emergency_deny_response(
                tool_call=tool_call,
                server_id=server.get("id"),
                error_code=emergency_code,
                deny_id=deny_id,
            )
        try:
            resolved_tool_name = str(tool.get("name") or tool_call.get("tool_name") or "")
            contract = config_snapshot.get_tool_security_contract(
                server_ref=server_ref,
                tool_name=resolved_tool_name,
            )
            current_fingerprint = tool.get("current_fingerprint")
            if not isinstance(current_fingerprint, str) or not current_fingerprint:
                raise PublishedConfigurationError("tool_observation_fingerprint_missing")
            approval = config_snapshot.get_tool_observation_approval(
                server_ref=server_ref,
                upstream_protocol_profile_id=str(upstream_protocol_profile_id),
                tool_fingerprint=current_fingerprint,
            )
            if approval.contract_hash != contract.contract_hash:
                raise PublishedConfigurationError("approval_contract_hash_mismatch")
            if tool.get("analysis_status") in {
                "ANALYSIS_FAILED", "BLOCKED", "PENDING_ANALYSIS", "QUARANTINED", "STALE",
            }:
                raise PublishedConfigurationError("approved_observation_not_current")
            tool = {
                **tool,
                "analysis_status": "APPROVED",
                "review_status": "APPROVED",
                "approved_fingerprint": current_fingerprint,
                "approved_fingerprint_match": True,
            }
            adapter_resolutions = tuple(
                resolution
                for effect in contract.effects
                for resolution in config_snapshot.get_adapter_resolutions(effect_id=effect.effect_id)
            )
            prepared_request = prepare_tool_request_v2(
                raw_arguments=raw_arguments,
                input_schema=tool.get("input_schema"),
                contract=contract,
                adapter_resolutions=adapter_resolutions,
                approval=approval,
                authority_scopes=config_snapshot.get_authority_resource_scopes(),
                authority_context=config_snapshot.get_authority_context(server_ref),
                client_protocol_profile_id=str(
                    tool_call.get("client_protocol_profile_id") or LEGACY_PROFILE_ID
                ),
                upstream_protocol_profile_id=str(upstream_protocol_profile_id),
                capability_catalog_version=config_snapshot.content.capability_catalog_version,
                resource_type_registry_version=config_snapshot.content.resource_type_registry_version,
                security_packs=config_snapshot.content.security_packs,
            )
        except PublishedConfigurationError as exc:
            return self._profile_error_response(
                tool_call,
                server.get("id"),
                getattr(exc, "code", str(exc)),
            )
        except Exception:
            decision = _fail_closed_proxy_decision(
                rule_id="request_preparation_error",
                reason="Tool request could not be safely prepared.",
                severity="critical",
            )
            decision_data = decision.model_dump(mode="json")
            safe_tool_call = self._prepared_tool_call(
                tool_call,
                PreparedToolRequest(
                    arguments={},
                    canonical_arguments_hash="44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                    arguments_valid=False,
                    validation_error_codes=("request_preparation_error",),
                    operation="unknown",
                    required_capability="unclassified",
                    resource_adapter="unknown",
                    resource_type="unknown",
                    resource_scope="invalid",
                    canonical_resource=None,
                    resource_sensitivity="unknown",
                    resource_resolution_status="request_preparation_error",
                    resource_flags=(),
                    resource_registry_revision="unknown",
                    tool_profile_revision="unknown",
                    operation_allowed_on_scope=False,
                    execution_arguments={},
                ),
            )
            return self._skip_response(
                tool_call=safe_tool_call,
                server_id=server["id"],
                decision=decision_data,
                status="blocked",
                execution_status="blocked",
                message="Tool call skipped because request preparation failed.",
                error_summary="request_preparation_error",
                skip_reason="request_preparation_error",
            )

        prepared_tool_call = self._prepared_tool_call(tool_call, prepared_request)
        if not prepared_request.arguments_valid:
            decision = _fail_closed_proxy_decision(
                rule_id="invalid_tool_arguments_guard",
                reason="Tool arguments are invalid or could not be safely prepared.",
                severity="high",
                evidence={
                    "arguments_valid": False,
                    "validation_error_codes": list(
                        prepared_request.validation_error_codes
                    ),
                },
                policy_revision="proxy-safety-guard-v1",
            )
            decision_data = decision.model_dump(mode="json")
            return self._skip_response(
                tool_call=prepared_tool_call,
                server_id=server["id"],
                decision=decision_data,
                status="blocked",
                execution_status="blocked",
                message="Tool call skipped because tool arguments are invalid.",
                error_summary="invalid_tool_arguments",
                skip_reason="invalid_tool_arguments",
            )

        context = self._build_policy_context(
            prepared_tool_call,
            server,
            tool,
            prepared_request,
        )

        try:
            identity_assertion = self.assertion_signer.sign(context)
        except InternalIdentityAssertionError as exc:
            decision = _trusted_identity_fail_closed_proxy_decision(exc.code)
            decision_data = decision.model_dump(mode="json")
            return self._skip_response(
                tool_call=prepared_tool_call,
                server_id=server["id"],
                decision=decision_data,
                status="blocked",
                execution_status="blocked",
                message="Tool call skipped because internal identity assertion failed.",
                error_summary=exc.code,
                skip_reason=exc.code,
            )
        except Exception:
            decision = _trusted_identity_fail_closed_proxy_decision(
                "identity_verification_unexpected_error"
            )
            decision_data = decision.model_dump(mode="json")
            return self._skip_response(
                tool_call=prepared_tool_call,
                server_id=server["id"],
                decision=decision_data,
                status="blocked",
                execution_status="blocked",
                message="Tool call skipped because internal identity assertion failed.",
                error_summary="identity_verification_unexpected_error",
                skip_reason="identity_verification_unexpected_error",
            )

        try:
            raw_decision = self.backend_client.request_policy_decision(
                context,
                identity_assertion=identity_assertion,
            )
        except BackendClientError as exc:
            decision = _fail_closed_proxy_decision(
                rule_id="policy_error",
                reason=f"Policy decision failed: {exc}",
            )
            decision_data = decision.model_dump(mode="json")
            return self._skip_response(
                tool_call=prepared_tool_call,
                server_id=server["id"],
                decision=decision_data,
                status="blocked",
                execution_status="blocked",
                message="Tool call skipped because policy evaluation failed.",
                error_summary="policy_error",
                skip_reason="policy_error",
            )

        decision, validation_error = _validate_policy_decision(
            raw_decision,
            expected_revision_id=tool_call.get("control_plane_revision_id"),
            expected_content_hash=tool_call.get("control_plane_content_hash"),
            expected_arguments_hash=prepared_request.canonical_arguments_hash,
        )
        if validation_error is not None:
            decision = _fail_closed_proxy_decision(
                rule_id=validation_error,
                reason="Policy decision response is invalid.",
            )
            decision_data = decision.model_dump(mode="json")
            return self._skip_response(
                tool_call=prepared_tool_call,
                server_id=server["id"],
                decision=decision_data,
                status="blocked",
                execution_status="blocked",
                message=f"Tool call skipped because policy decision is invalid: {validation_error}.",
                error_summary=validation_error,
                skip_reason=validation_error,
            )

        unsafe_resource_reason = self._unsafe_resource_guard_reason(prepared_request)
        if unsafe_resource_reason is not None and decision.effect != PolicyEffect.DENY:
            decision = _fail_closed_proxy_decision(
                rule_id="unsafe_resource_guard",
                reason="Resolved resource is not safe to execute.",
                severity="critical",
                evidence={"resource_error_code": unsafe_resource_reason},
                policy_revision="proxy-resource-guard-v1",
            )
            policy_decision_data = decision.model_dump(mode="json")
            return self._skip_response(
                tool_call=prepared_tool_call,
                server_id=server["id"],
                decision=policy_decision_data,
                status="blocked",
                execution_status="blocked",
                message="Tool call skipped because resource resolution is unsafe.",
                error_summary=unsafe_resource_reason,
                skip_reason=unsafe_resource_reason,
            )

        can_execute, skip_reason = _can_execute_policy_decision(decision)
        policy_decision_data = decision.model_dump(mode="json")
        if not can_execute:
            return self._skip_response(
                tool_call=prepared_tool_call,
                server_id=server["id"],
                decision=policy_decision_data,
                status=self._status_for_skipped_policy_decision(decision),
                execution_status=self._execution_status_for_skip_reason(skip_reason),
                message=f"Tool call skipped by policy: {skip_reason}.",
                error_summary=skip_reason,
                skip_reason=skip_reason,
            )

        return self._execute_tool_call(
            prepared_tool_call,
            server,
            policy_decision_data,
            prepared_request,
        )

    def create_trusted_session(self, access_token: str) -> dict[str, Any]:
        config_snapshot = self._load_config_snapshot() if self.identity_binding_resolver is None else None
        identity_binding_resolver = self.identity_binding_resolver or config_snapshot
        if identity_binding_resolver is None:
            raise IdentityBindingError("agent_identity_binding_unavailable")
        external_identity = self.identity_verifier.verify(access_token)
        identity_binding = identity_binding_resolver.resolve(
            issuer=external_identity.issuer,
            subject=external_identity.subject,
        )
        trusted_session = self.trusted_session_manager.create_for_identity(
            external_identity=external_identity,
            identity_binding=identity_binding,
        )
        return {
            "session_reference": trusted_session.session_reference,
            "session_token": trusted_session.session_token,
            "agent_id": trusted_session.agent_id,
            "identity_binding_revision": trusted_session.identity_binding_revision,
        }

    def authenticate_framework_identity(
        self,
        identity_request: dict[str, Any],
    ) -> ProxyTrustedSession:
        config_snapshot = self._load_config_snapshot() if self.identity_binding_resolver is None else None
        identity_binding_resolver = self.identity_binding_resolver or config_snapshot
        if identity_binding_resolver is None:
            raise IdentityBindingError("agent_identity_binding_unavailable")
        return self._resolve_trusted_session(
            identity_request,
            claimed_agent_id=identity_request.get("agent_id"),
            identity_binding_resolver=identity_binding_resolver,
        )

    def _resolve_trusted_session(
        self,
        tool_call: dict[str, Any],
        *,
        claimed_agent_id: Any,
        identity_binding_resolver: IdentityBindingResolver,
    ) -> ProxyTrustedSession:
        session_token = tool_call.get("session_token")
        if session_token is not None:
            trusted_session = self.trusted_session_manager.validate_token(session_token)
            binding = identity_binding_resolver.resolve(
                issuer=trusted_session.identity_issuer,
                subject=trusted_session.identity_subject,
            )
            if (
                binding.agent_id != trusted_session.agent_id
                or binding.revision != trusted_session.identity_binding_revision
            ):
                raise TrustedSessionError("trusted_session_binding_invalid")
            self._verify_claimed_agent_id(claimed_agent_id, trusted_session.agent_id)
            return trusted_session

        external_identity = self.identity_verifier.verify(tool_call.get("access_token"))
        identity_binding = identity_binding_resolver.resolve(
            issuer=external_identity.issuer,
            subject=external_identity.subject,
        )
        self._verify_claimed_agent_id(claimed_agent_id, identity_binding.agent_id)
        return direct_bearer_session(
            external_identity=external_identity,
            identity_binding=identity_binding,
        )

    def _load_config_snapshot(self) -> PublishedConfigurationSnapshot:
        return self.config_snapshot_resolver.load_active_snapshot()

    def _verify_claimed_agent_id(
        self,
        claimed_agent_id: Any,
        resolved_agent_id: str,
    ) -> None:
        if (
            isinstance(claimed_agent_id, str)
            and claimed_agent_id
            and claimed_agent_id != resolved_agent_id
        ):
            raise TrustedSessionError("claimed_identity_mismatch")

    def _resolve_server(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        raw_server_id = tool_call.get("server_id")
        if tool_call.get("server_endpoint") not in (None, ""):
            raise BackendClientError(
                "Runtime server_endpoint override is not allowed."
            )
        for field in ("upstream_token", "authorization", "api_key", "credential"):
            if tool_call.get(field) not in (None, ""):
                raise BackendClientError(
                    "Runtime upstream credential override is not allowed."
                )
        if isinstance(raw_server_id, bool) or not isinstance(raw_server_id, int):
            raise BackendClientError(
                "Runtime tool calls must use a registered integer server_id."
            )
        if raw_server_id <= 0:
            raise BackendClientError(
                "Runtime tool calls must use a positive registered server_id."
            )

        server = self.backend_client.find_server(server_id=raw_server_id)
        if server is None:
            raise BackendClientError("No matching registered MCP server found.")

        endpoint = str(server.get("endpoint") or "")
        try:
            validate_mcp_endpoint(endpoint)
            validate_upstream_auth_config(
                server.get("auth_mode"),
                server.get("credential_ref"),
            )
            if server.get("auth_mode") == "OAUTH" and not isinstance(
                server.get("oauth_config"),
                dict,
            ):
                raise UpstreamAuthError("upstream_oauth_configuration_invalid")
        except (MCPEndpointValidationError, UpstreamAuthError) as exc:
            raise BackendClientError(
                f"Resolved MCP server configuration is invalid: {exc}"
            ) from exc

        return server

    def _resolve_tool(
        self,
        server: dict[str, Any],
        tool_call: dict[str, Any],
        upstream_protocol_profile_id: str | None = None,
    ) -> dict[str, Any]:
        tool_name = tool_call.get("tool_name")
        if not tool_name:
            raise BackendClientError("Tool call is missing tool_name.")

        tool = self.backend_client.find_tool(
            server["id"],
            str(tool_name),
            upstream_protocol_profile_id,
        )
        if tool is None:
            raise BackendClientError(
                f"Tool '{tool_name}' was not found for server id {server['id']}."
            )
        return tool

    def _build_policy_context(
        self,
        tool_call: dict[str, Any],
        server: dict[str, Any],
        tool: dict[str, Any],
        prepared_request: PreparedToolRequest,
    ) -> dict[str, Any]:
        trust_status = server.get("trust_status") or server.get("status") or "unknown"

        return {
            "subject": {
                "agent_id": tool_call["agent_id"],
                "identity_status": "verified",
                "identity_issuer": tool_call["identity_issuer"],
                "identity_binding_revision": tool_call["identity_binding_revision"],
                "session_status": tool_call["session_status"],
                "session_reference": tool_call["session_reference"],
                "role": "unknown",
                "authorization_status": "unknown",
                "authorization_revision": "unresolved",
                "grants": [],
                "allowed_capabilities": [],
                "allowed_scopes": [],
            },
            "server": {
                "id": server.get("id"),
                "endpoint": server.get("endpoint"),
                "server_ref": server_ref_for_server(server),
                "known": True,
                "trusted": is_trusted_server_status(trust_status),
                "trust_status": trust_status,
                "security_status": server.get("security_status"),
            },
            "tool": {
                "id": tool.get("id"),
                "name": tool.get("name") or tool_call.get("tool_name"),
                "profile_status": "resolved",
                "profile_revision": prepared_request.tool_profile_revision,
                "risk_score": tool.get("risk_score", 0.0),
                "sensitivity": tool.get("sensitivity") or "unknown",
                "capabilities": tool.get("capabilities") or [],
                "admission_status": tool.get("admission_status", "unknown"),
                "description_risk_score": tool.get("description_risk_score", 0.0),
                "capability_mismatch": tool.get("capability_mismatch", False),
                "drift_status": tool.get("drift_status") or "unknown",
                "analysis_status": tool.get("analysis_status") or "missing",
                "current_fingerprint": tool.get("current_fingerprint"),
                "approved_fingerprint_match": tool.get(
                    "approved_fingerprint_match",
                    False,
                ),
                "risk_level": tool.get("risk_level") or "unknown",
                "semantic_flagged": tool.get("semantic_flagged", False),
                "deterministic_critical_finding": tool.get(
                    "deterministic_critical_finding",
                    False,
                ),
                "consistency_status": tool.get("consistency_status") or "unknown",
                "review_status": tool.get("review_status") or "missing",
                "analyzer_revision": tool.get("analyzer_revision") or "unknown",
            },
            "request": {
                "operation": prepared_request.operation,
                "resource_adapter": prepared_request.resource_adapter,
                "resource_type": prepared_request.resource_type,
                "resource_scope": prepared_request.resource_scope,
                "required_capability": prepared_request.required_capability,
                "canonical_resource": prepared_request.canonical_resource,
                "arguments": prepared_request.arguments,
                "canonical_arguments_hash": prepared_request.canonical_arguments_hash,
                "arguments_valid": prepared_request.arguments_valid,
                "validation_error_codes": list(
                    prepared_request.validation_error_codes
                ),
                "resource_sensitivity": prepared_request.resource_sensitivity,
                "resource_resolution_status": prepared_request.resource_resolution_status,
                "resource_flags": list(prepared_request.resource_flags),
                "resource_registry_revision": prepared_request.resource_registry_revision,
                "tool_profile_revision": prepared_request.tool_profile_revision,
                "operation_allowed_on_scope": prepared_request.operation_allowed_on_scope,
                "estimated_output_size_mb": tool_call.get("estimated_output_size_mb", 0.001),
                "security_model_version": prepared_request.security_model_version,
                "contract_hash": prepared_request.contract_hash,
                "tool_security_contract": prepared_request.security_contract,
                "normalized_facts": prepared_request.normalized_facts,
                "tool_observation_approval": prepared_request.tool_observation_approval,
                "authority_resource_scopes": list(
                    prepared_request.authority_resource_scopes
                ),
                "capability_catalog": list(prepared_request.capability_catalog),
            },
            "runtime": {
                "environment": tool_call.get("environment", "local"),
                "session_id": tool_call["session_id"],
                "control_plane_revision_id": tool_call.get(
                    "control_plane_revision_id",
                    "unknown",
                ),
                "control_plane_revision_number": tool_call.get(
                    "control_plane_revision_number",
                ),
                "control_plane_content_hash": tool_call.get(
                    "control_plane_content_hash",
                    "unknown",
                ),
                "client_protocol_profile_id": tool_call.get(
                    "client_protocol_profile_id",
                    LEGACY_PROFILE_ID,
                ),
                "upstream_protocol_profile_id": tool_call.get(
                    "upstream_protocol_profile_id",
                    server.get("preferred_upstream_profile")
                    or server.get("preferred_protocol_profile")
                    or LEGACY_PROFILE_ID,
                ),
                "client_protocol_era": tool_call.get("client_protocol_era", "legacy"),
                "client_protocol_version": tool_call.get(
                    "client_protocol_version",
                    "2025-11-25",
                ),
                "client_transport_kind": tool_call.get(
                    "client_transport_kind",
                    "legacy_streamable_http",
                ),
                "upstream_protocol_era": tool_call.get("upstream_protocol_era", "legacy"),
                "upstream_protocol_version": tool_call.get(
                    "upstream_protocol_version",
                    "2025-11-25",
                ),
                "upstream_transport_kind": tool_call.get(
                    "upstream_transport_kind",
                    "legacy_streamable_http",
                ),
            },
            "policy_settings": tool_call.get("policy_settings") or {"rules": {}},
        }

    def _status_for_skipped_policy_decision(self, decision: PolicyDecision) -> str:
        if decision.effect == PolicyEffect.DEFER:
            return "approval_required"
        return "blocked"

    def _execution_status_for_skip_reason(self, skip_reason: str | None) -> str:
        if skip_reason == "policy_deferred":
            return "approval_required"
        return "blocked"

    def _execute_tool_call(
        self,
        tool_call: dict[str, Any],
        server: dict[str, Any],
        decision: dict[str, Any],
        prepared_request: PreparedToolRequest,
    ) -> dict[str, Any]:
        execution_hash = sha256_canonical_json(tool_call.get("arguments") or {})
        decision_hash = decision.get("canonical_arguments_hash")
        if (
            execution_hash != prepared_request.canonical_arguments_hash
            or decision_hash != execution_hash
        ):
            fail_closed = _fail_closed_proxy_decision(
                rule_id="canonical_arguments_changed_before_execution",
                reason="Authorized arguments changed before MCP execution.",
                severity="critical",
                policy_revision="proxy-complete-mediation-v2",
            ).model_dump(mode="json")
            return self._skip_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=fail_closed,
                status="blocked",
                execution_status="blocked",
                message="Tool call skipped because execution arguments changed.",
                error_summary="canonical_arguments_changed_before_execution",
                skip_reason="canonical_arguments_changed_before_execution",
            )

        session_reference = str(tool_call.get("session_reference") or "")
        if (
            is_external_effect(prepared_request)
            and self.tool_result_guard.matches_prior_result(
                session_reference,
                tool_call.get("arguments") or {},
            )
        ):
            fail_closed = _fail_closed_proxy_decision(
                rule_id="cross_call_data_exfiltration_guard",
                reason="Outgoing arguments contain data returned by a prior read operation.",
                severity="critical",
                policy_revision="proxy-result-guard-v1",
            ).model_dump(mode="json")
            return self._skip_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=fail_closed,
                status="blocked",
                execution_status="blocked",
                message="Tool call skipped by the cross-call data guard.",
                error_summary="cross_call_data_exfiltration_guard",
                skip_reason="cross_call_data_exfiltration_guard",
            )

        emergency_code, deny_id = self._emergency_deny_status(
            tool_call,
            server_ref=server_ref_for_server(server),
            tool_name=str(tool_call.get("tool_name") or ""),
        )
        if emergency_code is not None:
            return self._emergency_deny_response(
                tool_call=tool_call,
                server_id=server.get("id"),
                error_code=emergency_code,
                deny_id=deny_id,
            )

        upstream_profile_id = (
            tool_call.get("upstream_protocol_profile_id")
            or server.get("preferred_upstream_profile")
            or server.get("preferred_protocol_profile")
            or LEGACY_PROFILE_ID
        )
        try:
            upstream_profile = ProtocolProfileRegistry().get(str(upstream_profile_id))
        except ProtocolProfileError as exc:
            fail_closed = _fail_closed_proxy_decision(
                rule_id="unsupported_mcp_protocol_profile",
                reason="Resolved MCP server uses an unsupported protocol profile.",
                evidence={"profile_error_code": str(exc)},
                policy_revision="proxy-protocol-guard-v1",
            ).model_dump(mode="json")
            return self._skip_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=fail_closed,
                status="blocked",
                execution_status="blocked",
                message="Tool call skipped because the MCP protocol profile is unsupported.",
                error_summary=str(exc),
                skip_reason=str(exc),
            )
        protocol_version = upstream_profile.protocol_version

        try:
            bearer_token = resolve_upstream_bearer_token(
                server.get("auth_mode"),
                server.get("credential_ref"),
                oauth_config=server.get("oauth_config"),
            )
        except UpstreamAuthError as exc:
            return self._execution_error_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=decision,
                mcp_called=False,
                execution_status="upstream_auth_error",
                error_summary=str(exc),
            )
        auth_context_hash = upstream_auth_context_hash(
            str(server.get("auth_mode") or "NONE"),
            bearer_token,
        )

        def create_mcp_client():
            client_kwargs = {
                "endpoint": server["endpoint"],
                "protocol_version": protocol_version,
                "protocol_profile_id": str(upstream_profile_id),
            }
            if bearer_token is not None:
                client_kwargs["bearer_token"] = bearer_token
            return self.mcp_client_class(**client_kwargs)

        try:
            if upstream_profile.protocol_era == ProtocolEra.LEGACY:
                mcp_client = self.legacy_upstream_session_pool.get_or_create(
                    framework_session_id=str(tool_call.get("session_reference") or "unknown"),
                    server_id=int(server["id"]),
                    profile_id=str(upstream_profile_id),
                    connection_context_hash=auth_context_hash,
                    factory=create_mcp_client,
                )
            else:
                mcp_client = create_mcp_client()
        except Exception:
            return self._execution_error_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=decision,
                mcp_called=False,
                execution_status="client_initialization_error",
                error_summary="MCP client initialization failed.",
            )

        mcp_called = False
        try:
            mcp_called = True
            tool_result = mcp_client.call_tool(
                str(tool_call.get("tool_name")),
                tool_call.get("arguments") or {},
            )
            adapter_inspection = inspect_adapter_result(
                tool_result,
                tuple(
                    AdapterResolution.model_validate(value)
                    for value in prepared_request.adapter_resolutions
                ),
            )
            if adapter_inspection.blocked:
                return self._blocked_tool_result_response(
                    tool_call=tool_call,
                    server_id=server["id"],
                    mcp_called=mcp_called,
                    finding_codes=adapter_inspection.finding_codes,
                    rule_id="specialized_adapter_result_blocked",
                    policy_revision="trusted-adapter-sdk-v1",
                    message="Tool result failed specialized adapter validation.",
                )
            inspection = self.tool_result_guard.inspect(tool_result)
            if inspection.blocked:
                return self._blocked_tool_result_response(
                    tool_call=tool_call,
                    server_id=server["id"],
                    mcp_called=mcp_called,
                    finding_codes=inspection.finding_codes,
                    rule_id="unsafe_tool_result_blocked",
                    policy_revision="proxy-result-guard-v1",
                    message="Tool result withheld by the security framework.",
                )
            if should_track_result(prepared_request):
                self.tool_result_guard.remember_read_result(
                    session_reference,
                    tool_result,
                )
            execution_status = (
                "tool_error" if bool(tool_result.get("isError", False)) else "success"
            )
            log_payload = build_runtime_log(
                tool_call,
                decision,
                server_id=server["id"],
                executed=True,
                execution_status=execution_status,
                tool_result=tool_result,
                status="allowed",
            )
            runtime_log = self._send_runtime_log(log_payload)

            return self._response(
                status="allowed",
                decision=decision,
                executed=True,
                mcp_called=mcp_called,
                execution_status=execution_status,
                tool_result=tool_result,
                runtime_log=runtime_log,
                message="Tool call executed through the MCP HTTP server.",
            )
        except MCPHttpError as exc:
            return self._execution_error_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=decision,
                mcp_called=mcp_called,
                execution_status="http_error",
                error_summary=str(exc),
            )
        except MCPProtocolError as exc:
            return self._execution_error_response(
                tool_call=tool_call,
                server_id=server["id"],
                decision=decision,
                mcp_called=mcp_called,
                execution_status="protocol_error",
                error_summary=str(exc),
            )

    def _blocked_tool_result_response(
        self,
        *,
        tool_call: dict[str, Any],
        server_id: int,
        mcp_called: bool,
        finding_codes: tuple[str, ...],
        rule_id: str,
        policy_revision: str,
        message: str,
    ) -> dict[str, Any]:
        guarded_decision = _fail_closed_proxy_decision(
            rule_id=rule_id,
            reason=message,
            severity="critical",
            evidence={"finding_codes": list(finding_codes)},
            policy_revision=policy_revision,
        ).model_dump(mode="json")
        guarded_result = {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": "Tool result withheld by the security framework.",
                }
            ],
        }
        log_payload = build_runtime_log(
            tool_call,
            guarded_decision,
            server_id=server_id,
            executed=True,
            execution_status="result_blocked",
            tool_result=guarded_result,
            status="blocked",
        )
        runtime_log = self._send_runtime_log(log_payload)
        return self._response(
            status="blocked",
            decision=guarded_decision,
            executed=True,
            mcp_called=mcp_called,
            execution_status="result_blocked",
            tool_result=guarded_result,
            runtime_log=runtime_log,
            message=message,
            skip_reason=rule_id,
        )

    def _skip_response(
        self,
        *,
        tool_call: dict[str, Any],
        server_id: int | None,
        decision: dict[str, Any],
        status: str,
        execution_status: str,
        message: str,
        error_summary: str | None = None,
        skip_reason: str | None = None,
    ) -> dict[str, Any]:
        log_payload = build_runtime_log(
            tool_call,
            decision,
            server_id=server_id,
            executed=False,
            execution_status=execution_status,
            error_summary=error_summary,
            status=status,
        )
        runtime_log = self._send_runtime_log(log_payload)

        return self._response(
            status=status,
            decision=decision,
            executed=False,
            mcp_called=False,
            execution_status=execution_status,
            tool_result=None,
            runtime_log=runtime_log,
            message=message,
            skip_reason=skip_reason,
        )

    def _inventory_error_response(
        self,
        tool_call: dict[str, Any],
        error_summary: str,
    ) -> dict[str, Any]:
        decision = _fail_closed_proxy_decision(
            rule_id="inventory_error",
            reason=error_summary,
        )
        decision_data = decision.model_dump(mode="json")
        log_payload = build_runtime_log(
            tool_call,
            decision_data,
            server_id=None,
            executed=False,
            execution_status="blocked",
            error_summary=error_summary,
            status="blocked",
        )
        runtime_log = self._send_runtime_log(log_payload)

        return self._response(
            status="blocked",
            decision=decision_data,
            executed=False,
            mcp_called=False,
            execution_status="blocked",
            tool_result=None,
            runtime_log=runtime_log,
            message="Tool call skipped because inventory resolution failed.",
            skip_reason="inventory_error",
        )

    def _execution_error_response(
        self,
        *,
        tool_call: dict[str, Any],
        server_id: int,
        decision: dict[str, Any],
        mcp_called: bool,
        execution_status: str,
        error_summary: str,
    ) -> dict[str, Any]:
        log_payload = build_runtime_log(
            tool_call,
            decision,
            server_id=server_id,
            executed=False,
            execution_status=execution_status,
            error_summary=error_summary,
            status="allowed",
        )
        runtime_log = self._send_runtime_log(log_payload)

        return self._response(
            status="error",
            decision=decision,
            executed=False,
            mcp_called=mcp_called,
            execution_status=execution_status,
            tool_result=None,
            runtime_log=runtime_log,
            message=error_summary,
            skip_reason=None,
        )

    def _send_runtime_log(self, log_payload: dict[str, Any]) -> dict[str, Any]:
        try:
            created_log = send_runtime_log(log_payload, self.backend_client)
            return {
                "created": True,
                "id": created_log.get("id"),
                "payload": log_payload,
                "response": created_log,
            }
        except BackendClientError as exc:
            return {
                "created": False,
                "id": None,
                "payload": log_payload,
                "error": str(exc),
            }

    def _response(
        self,
        *,
        status: str,
        decision: dict[str, Any],
        executed: bool,
        mcp_called: bool,
        execution_status: str,
        tool_result: dict[str, Any] | None,
        runtime_log: dict[str, Any],
        message: str,
        skip_reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "decision": decision,
            "rule_id": decision.get("rule_id"),
            "reason": decision.get("reason"),
            "executed": executed,
            "mcp_called": mcp_called,
            "execution_status": execution_status,
            "tool_result": tool_result,
            "result_summary": summarize_tool_result(tool_result),
            "runtime_log_created": runtime_log.get("created", False),
            "runtime_log_id": runtime_log.get("id"),
            "runtime_log_error": (
                "runtime_log_persistence_failed"
                if runtime_log.get("created", False) is False
                else None
            ),
            "runtime_log": runtime_log.get("payload"),
            "message": message,
            "skip_reason": skip_reason,
        }

    def _prepared_tool_call(
        self,
        tool_call: dict[str, Any],
        prepared_request: PreparedToolRequest,
    ) -> dict[str, Any]:
        prepared_tool_call = dict(tool_call)
        prepared_tool_call.pop("access_token", None)
        prepared_tool_call.pop("authorization", None)
        prepared_tool_call.pop("identity_assertion", None)
        prepared_tool_call["arguments"] = prepared_request.execution_arguments
        prepared_tool_call["canonical_arguments_hash"] = (
            prepared_request.canonical_arguments_hash
        )
        prepared_tool_call["arguments_valid"] = prepared_request.arguments_valid
        prepared_tool_call["validation_error_codes"] = list(
            prepared_request.validation_error_codes
        )
        prepared_tool_call["operation"] = prepared_request.operation
        prepared_tool_call["resource_adapter"] = prepared_request.resource_adapter
        prepared_tool_call["resource_type"] = prepared_request.resource_type
        prepared_tool_call["resource_scope"] = prepared_request.resource_scope
        prepared_tool_call["required_capability"] = prepared_request.required_capability
        prepared_tool_call["canonical_resource"] = prepared_request.canonical_resource
        prepared_tool_call["resource_sensitivity"] = prepared_request.resource_sensitivity
        prepared_tool_call["resource_resolution_status"] = (
            prepared_request.resource_resolution_status
        )
        prepared_tool_call["resource_flags"] = list(prepared_request.resource_flags)
        prepared_tool_call["resource_registry_revision"] = (
            prepared_request.resource_registry_revision
        )
        prepared_tool_call["tool_profile_revision"] = prepared_request.tool_profile_revision
        prepared_tool_call["operation_allowed_on_scope"] = (
            prepared_request.operation_allowed_on_scope
        )
        return prepared_tool_call

    def _profile_error_response(
        self,
        tool_call: dict[str, Any],
        server_id: int | None,
        error_code: str,
    ) -> dict[str, Any]:
        reason = {
            "approved_observation_not_current": (
                "The current tool analysis is not eligible for the published observation approval."
            ),
            "tool_observation_fingerprint_missing": (
                "The current tool observation fingerprint is unavailable."
            ),
            "approval_contract_hash_mismatch": (
                "The published observation approval does not match the active tool contract."
            ),
        }.get(error_code, "Trusted runtime metadata could not be resolved.")
        decision = _fail_closed_proxy_decision(
            rule_id=error_code,
            reason=reason,
        )
        decision_data = decision.model_dump(mode="json")
        return self._skip_response(
            tool_call=tool_call,
            server_id=server_id,
            decision=decision_data,
            status="blocked",
            execution_status="blocked",
            message="Tool call skipped because trusted runtime metadata is unavailable.",
            error_summary=error_code,
            skip_reason=error_code,
        )

    def _emergency_deny_status(
        self,
        tool_call: dict[str, Any],
        *,
        server_ref: str,
        tool_name: str,
    ) -> tuple[str | None, str | None]:
        checker = getattr(self.backend_client, "check_emergency_deny", None)
        if not callable(checker):
            return "emergency_deny_store_unavailable", None
        try:
            result = checker(
                {
                    "agent_id": str(tool_call.get("agent_id") or ""),
                    "framework_session_id": str(
                        tool_call.get("session_reference") or ""
                    ),
                    "server_ref": server_ref,
                    "tool_name": tool_name,
                }
            )
        except Exception:
            return "emergency_deny_store_unavailable", None
        if result.get("blocked") is True:
            return "emergency_deny_active", result.get("deny_id")
        if result.get("blocked") is not False:
            return "emergency_deny_store_invalid_response", None
        return None, None

    def _emergency_deny_response(
        self,
        *,
        tool_call: dict[str, Any],
        server_id: int | None,
        error_code: str,
        deny_id: str | None,
    ) -> dict[str, Any]:
        decision = _fail_closed_proxy_decision(
            rule_id=error_code,
            reason="Emergency deny gate blocked the tool call.",
            severity="critical",
            evidence={"deny_id": deny_id} if deny_id else {},
            policy_revision="emergency-deny-v1",
        ).model_dump(mode="json")
        return self._skip_response(
            tool_call=tool_call,
            server_id=server_id,
            decision=decision,
            status="blocked",
            execution_status="blocked",
            message="Tool call skipped by the emergency deny gate.",
            error_summary=error_code,
            skip_reason=error_code,
        )

    def _unsafe_resource_guard_reason(
        self,
        prepared_request: PreparedToolRequest,
    ) -> str | None:
        if not prepared_request.arguments_valid:
            return None
        if prepared_request.resource_resolution_status != "resolved":
            return prepared_request.resource_resolution_status
        return None

    def _trusted_identity_error_response(
        self,
        tool_call: dict[str, Any],
        error_code: str,
    ) -> dict[str, Any]:
        decision = _trusted_identity_fail_closed_proxy_decision(error_code)
        return self._response(
            status="blocked",
            decision=decision.model_dump(mode="json"),
            executed=False,
            mcp_called=False,
            execution_status="blocked",
            tool_result=None,
            runtime_log={"created": False, "id": None, "payload": None},
            message="Tool call skipped because trusted identity verification failed.",
            skip_reason=error_code,
        )


def _fail_closed_proxy_decision(
    *,
    rule_id: str,
    reason: str,
    severity: str = "critical",
    evidence: dict[str, Any] | None = None,
    recommended_action: str | None = None,
    policy_revision: str = "proxy-fail-closed-v1",
) -> PolicyDecision:
    raw_decision = {
        "effect": "DENY",
        "obligations": [
            {"type": "LOG", "parameters": {}},
            {"type": "ALERT", "parameters": {}},
        ],
        "rule_ids": [rule_id],
        "reason": reason,
        "severity": severity,
        "evidence": evidence or {},
        "recommended_action": recommended_action,
        "policy_revision": policy_revision,
        "decision": "BLOCK",
        "rule_id": rule_id,
    }
    return PolicyDecision.model_validate(raw_decision)


def _trusted_identity_fail_closed_proxy_decision(error_code: str) -> PolicyDecision:
    return _fail_closed_proxy_decision(
        rule_id="trusted_identity_required",
        reason="Trusted agent identity is required.",
        evidence={"identity_error_code": error_code},
        policy_revision="trusted-identity-fail-closed-v1",
    )


def protocol_verdict_expired(server: dict[str, Any]) -> bool:
    value = server.get("protocol_verdict_expires_at")
    if value in (None, ""):
        return False
    try:
        if isinstance(value, datetime):
            expires_at = value
        elif isinstance(value, str):
            expires_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            return True
    except ValueError:
        return True
    if expires_at.tzinfo is None:
        return datetime.utcnow() >= expires_at
    return datetime.now(timezone.utc) >= expires_at.astimezone(timezone.utc)
