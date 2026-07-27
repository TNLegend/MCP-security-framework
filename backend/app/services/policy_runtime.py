from copy import deepcopy
from typing import Any

from fastapi import BackgroundTasks

from app.core.config import PolicyEngineMode, settings
from app.schemas.policy_context import RuntimePolicyInput
from app.schemas.policy_decision import PolicyDecision
from app.services.opa_client import OPAClient, OPAClientError
from app.services.policy_engine import evaluate_policy
from app.services.policy_shadow import run_opa_shadow_evaluation
from app.services.subject_authorization import (
    SubjectAuthorizationError,
    SubjectAuthorizationResolver,
    resolved_authorization_to_policy_subject_fields,
)


def evaluate_legacy_policy(context: dict[str, Any]) -> PolicyDecision:
    RuntimePolicyInput.model_validate(context)
    result = evaluate_policy(context)
    return PolicyDecision.model_validate(result)


def build_opa_fail_closed_decision(*, error_code: str) -> PolicyDecision:
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
    return PolicyDecision.model_validate(result)


def build_subject_authorization_fail_closed_decision(
    *,
    error_code: str,
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
    return PolicyDecision.model_validate(result)


def enrich_subject_authorization(
    context: dict[str, Any],
    resolver: SubjectAuthorizationResolver | None = None,
) -> dict[str, Any]:
    base_context = RuntimePolicyInput.model_validate(context).model_dump(mode="json")
    enriched_context = deepcopy(base_context)
    agent_id = enriched_context["subject"]["agent_id"]
    subject_resolver = resolver or SubjectAuthorizationResolver()
    resolved = subject_resolver.resolve(agent_id)
    enriched_context["subject"].update(
        resolved_authorization_to_policy_subject_fields(resolved)
    )
    return RuntimePolicyInput.model_validate(enriched_context).model_dump(mode="json")


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
        return build_opa_fail_closed_decision(error_code=exc.code)
    except Exception:
        return build_opa_fail_closed_decision(
            error_code="opa_authoritative_unexpected_error"
        )


def evaluate_runtime_policy(
    *,
    context: dict[str, Any],
    background_tasks: BackgroundTasks,
    resolver: SubjectAuthorizationResolver | None = None,
) -> PolicyDecision:
    try:
        authorized_context = enrich_subject_authorization(context, resolver)
    except SubjectAuthorizationError as exc:
        return build_subject_authorization_fail_closed_decision(error_code=exc.code)
    except Exception:
        return build_subject_authorization_fail_closed_decision(
            error_code="subject_authorization_unexpected_error"
        )

    mode = settings.policy_engine_mode

    if mode == PolicyEngineMode.LEGACY:
        return evaluate_legacy_policy(authorized_context)

    if mode == PolicyEngineMode.SHADOW:
        authoritative_decision = evaluate_legacy_policy(authorized_context)
        background_tasks.add_task(
            run_opa_shadow_evaluation,
            context=authorized_context,
            authoritative_decision=authoritative_decision,
        )
        return authoritative_decision

    if mode == PolicyEngineMode.OPA:
        return evaluate_opa_authoritative(authorized_context)

    raise RuntimeError("Unsupported policy engine mode.")
