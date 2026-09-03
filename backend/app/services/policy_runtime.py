from copy import deepcopy
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.schemas.policy_context import RuntimePolicyInput
from app.schemas.policy_decision import PolicyDecision
from app.services.identity_replay_store import (
    IdentityReplayError,
    consume_identity_assertion_jti,
)
from app.services.internal_identity_assertion import (
    InternalIdentityAssertionError,
    InternalIdentityAssertionVerifier,
)
from app.services.opa_client import OPAClient, OPAClientError
from app.services.published_configuration import (
    PublishedConfigurationProvider,
    build_security_context_for_snapshot,
)
from app.services.subject_authorization import (
    SubjectAuthorizationError,
    SubjectAuthorizationResolver,
    resolved_authorization_to_policy_subject_fields,
)


def _bind_fail_closed_decision_context(
    result: dict[str, Any],
    context: dict[str, Any] | None,
) -> dict[str, Any]:
    if context is None:
        return result
    try:
        normalized = RuntimePolicyInput.model_validate(context).model_dump(mode="json")
    except Exception:
        return result
    runtime = normalized.get("runtime") or {}
    request = normalized.get("request") or {}
    revision_id = runtime.get("control_plane_revision_id")
    content_hash = runtime.get("control_plane_content_hash")
    arguments_hash = request.get("canonical_arguments_hash")
    if not all(isinstance(value, str) and value for value in (
        revision_id,
        content_hash,
        arguments_hash,
    )):
        return result
    result.update(
        {
            "decision_id": f"{revision_id}:{arguments_hash}",
            "control_plane_revision_id": revision_id,
            "control_plane_content_hash": content_hash,
            "canonical_arguments_hash": arguments_hash,
        }
    )
    return result


def build_opa_fail_closed_decision(
    *,
    error_code: str,
    context: dict[str, Any] | None = None,
) -> PolicyDecision:
    result = {
        "effect": "DENY",
        "obligations": [
            {"type": "LOG", "parameters": {}},
            {"type": "ALERT", "parameters": {}},
        ],
        "rule_ids": [error_code],
        "reason": "OPA policy evaluation failed.",
        "severity": "critical",
        "evidence": {
            "policy_engine": "opa",
            "error_code": error_code,
        },
        "recommended_action": None,
        "policy_revision": "opa-authoritative-fail-closed-v1",
        "decision": "BLOCK",
        "rule_id": error_code,
    }
    return PolicyDecision.model_validate(
        _bind_fail_closed_decision_context(result, context)
    )


def build_subject_authorization_fail_closed_decision(
    *,
    error_code: str,
    context: dict[str, Any] | None = None,
) -> PolicyDecision:
    result = {
        "effect": "DENY",
        "obligations": [
            {"type": "LOG", "parameters": {}},
            {"type": "ALERT", "parameters": {}},
        ],
        "rule_ids": ["subject_authorization_unavailable"],
        "reason": "Subject authorization could not be resolved.",
        "severity": "critical",
        "evidence": {
            "authorization_error_code": error_code,
        },
        "recommended_action": None,
        "policy_revision": "subject-authorization-fail-closed-v1",
        "decision": "BLOCK",
        "rule_id": "subject_authorization_unavailable",
    }
    return PolicyDecision.model_validate(
        _bind_fail_closed_decision_context(result, context)
    )


def build_trusted_identity_fail_closed_decision(
    *,
    error_code: str,
    context: dict[str, Any] | None = None,
) -> PolicyDecision:
    result = {
        "effect": "DENY",
        "obligations": [
            {"type": "LOG", "parameters": {}},
            {"type": "ALERT", "parameters": {}},
        ],
        "rule_ids": ["trusted_identity_required"],
        "reason": "Trusted agent identity is required.",
        "severity": "critical",
        "evidence": {
            "identity_error_code": error_code,
        },
        "recommended_action": None,
        "policy_revision": "trusted-identity-fail-closed-v1",
        "decision": "BLOCK",
        "rule_id": "trusted_identity_required",
    }
    return PolicyDecision.model_validate(
        _bind_fail_closed_decision_context(result, context)
    )


def verify_trusted_identity_context(
    *,
    context: dict[str, Any],
    identity_assertion: str | None,
    db: Session | None,
    assertion_verifier: InternalIdentityAssertionVerifier | None = None,
    replay_consumer=consume_identity_assertion_jti,
) -> dict[str, Any]:
    base_context = RuntimePolicyInput.model_validate(context).model_dump(mode="json")
    verifier = assertion_verifier or InternalIdentityAssertionVerifier()
    verified = verifier.verify(assertion=identity_assertion, context=base_context)

    if base_context["subject"]["identity_status"] != "verified":
        raise InternalIdentityAssertionError("identity_assertion_request_mismatch")

    if db is None:
        raise IdentityReplayError("identity_replay_store_unavailable")

    replay_consumer(
        issuer=verified.issuer,
        jti=verified.token_id,
        expires_at=verified.expires_at,
        db=db,
    )

    trusted_context = deepcopy(base_context)
    trusted_context["subject"]["agent_id"] = verified.subject
    trusted_context["subject"]["identity_status"] = "verified"
    return RuntimePolicyInput.model_validate(trusted_context).model_dump(mode="json")


def enrich_subject_authorization(
    context: dict[str, Any],
    resolver: SubjectAuthorizationResolver | None = None,
    db: Session | None = None,
) -> dict[str, Any]:
    base_context = RuntimePolicyInput.model_validate(context).model_dump(mode="json")
    enriched_context = deepcopy(base_context)
    agent_id = enriched_context["subject"]["agent_id"]
    if resolver is not None:
        subject_resolver = resolver
    else:
        if db is None:
            raise SubjectAuthorizationError("subject_authorization_unavailable")
        revision_id = enriched_context["runtime"].get("control_plane_revision_id")
        content_hash = enriched_context["runtime"].get("control_plane_content_hash")
        if (
            not isinstance(revision_id, str)
            or not revision_id.strip()
            or revision_id == "unknown"
            or not isinstance(content_hash, str)
            or not content_hash.strip()
            or content_hash == "unknown"
        ):
            raise SubjectAuthorizationError("subject_authorization_unavailable")
        try:
            snapshot = PublishedConfigurationProvider(db).load_snapshot(
                revision_id,
                expected_content_hash=content_hash,
                allow_archived=True,
            )
            resolved = snapshot.get_agent_authorization(agent_id)
            _verify_v2_snapshot_context(enriched_context, snapshot)
        except Exception as exc:
            raise SubjectAuthorizationError("subject_authorization_unavailable") from exc
        enriched_context["subject"].update(
            resolved_authorization_to_policy_subject_fields(resolved)
        )
        return RuntimePolicyInput.model_validate(enriched_context).model_dump(mode="json")
    resolved = subject_resolver.resolve(agent_id)
    enriched_context["subject"].update(
        resolved_authorization_to_policy_subject_fields(resolved)
    )
    return RuntimePolicyInput.model_validate(enriched_context).model_dump(mode="json")


def _verify_v2_snapshot_context(context: dict[str, Any], snapshot) -> None:
    request = context["request"]
    runtime = context["runtime"]
    server_ref = context["server"]["server_ref"]
    tool_name = context["tool"]["name"]
    contract = snapshot.get_tool_security_contract(
        server_ref=server_ref,
        tool_name=tool_name,
    )
    if request.get("tool_security_contract") != contract.model_dump(mode="json"):
        raise SubjectAuthorizationError("snapshot_contract_mismatch")
    approval_payload = request.get("tool_observation_approval") or {}
    approval = snapshot.get_tool_observation_approval(
        server_ref=server_ref,
        upstream_protocol_profile_id=runtime["upstream_protocol_profile_id"],
        tool_fingerprint=approval_payload.get("tool_fingerprint", ""),
    )
    if approval_payload != approval.model_dump(mode="json"):
        raise SubjectAuthorizationError("snapshot_approval_mismatch")
    if request.get("authority_resource_scopes") != [
        scope.model_dump(mode="json")
        for scope in snapshot.get_authority_resource_scopes()
    ]:
        raise SubjectAuthorizationError("snapshot_scopes_mismatch")
    if context.get("build_security") != build_security_context_for_snapshot(
        snapshot,
        server_ref,
    ):
        raise SubjectAuthorizationError("snapshot_build_security_mismatch")


def evaluate_opa_authoritative(
    context: dict[str, Any],
    opa_client: OPAClient | None = None,
) -> PolicyDecision:
    RuntimePolicyInput.model_validate(context)

    try:
        client = opa_client or OPAClient(
            base_url=settings.opa_base_url,
            decision_path=settings.opa_decision_path,
            timeout_seconds=settings.opa_timeout_seconds,
        )
        return client.evaluate(context)
    except OPAClientError as exc:
        return build_opa_fail_closed_decision(error_code=exc.code, context=context)
    except Exception:
        return build_opa_fail_closed_decision(
            error_code="opa_authoritative_unexpected_error",
            context=context,
        )


def evaluate_runtime_policy(
    *,
    context: dict[str, Any],
    identity_assertion: str | None = None,
    db: Session | None = None,
    assertion_verifier: InternalIdentityAssertionVerifier | None = None,
    replay_consumer=consume_identity_assertion_jti,
    resolver: SubjectAuthorizationResolver | None = None,
) -> PolicyDecision:
    try:
        trusted_context = verify_trusted_identity_context(
            context=context,
            identity_assertion=identity_assertion,
            db=db,
            assertion_verifier=assertion_verifier,
            replay_consumer=replay_consumer,
        )
    except InternalIdentityAssertionError as exc:
        return build_trusted_identity_fail_closed_decision(
            error_code=exc.code,
            context=context,
        )
    except IdentityReplayError as exc:
        return build_trusted_identity_fail_closed_decision(
            error_code=exc.code,
            context=context,
        )
    except Exception:
        return build_trusted_identity_fail_closed_decision(
            error_code="identity_verification_unexpected_error",
            context=context,
        )

    try:
        authorized_context = enrich_subject_authorization(trusted_context, resolver, db)
    except SubjectAuthorizationError as exc:
        return build_subject_authorization_fail_closed_decision(
            error_code=exc.code,
            context=trusted_context,
        )
    except Exception:
        return build_subject_authorization_fail_closed_decision(
            error_code="subject_authorization_unexpected_error",
            context=trusted_context,
        )

    return evaluate_opa_authoritative(authorized_context)
