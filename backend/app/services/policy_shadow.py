import json
import logging
from typing import Any

from app.core.config import settings
from app.schemas.policy_decision import (
    PolicyDecision,
    PolicyEffect,
    PolicyObligationType,
)
from app.schemas.policy_shadow import (
    PolicyShadowComparison,
    PolicyShadowMismatchField,
    PolicyShadowMismatchRisk,
    PolicyShadowStatus,
)
from app.services.opa_client import OPAClient, OPAClientError


logger = logging.getLogger(__name__)


def _sorted_obligation_types(
    decision: PolicyDecision,
) -> list[PolicyObligationType]:
    return sorted(
        (obligation.type for obligation in decision.obligations),
        key=lambda obligation_type: obligation_type.value,
    )


def _sorted_rule_ids(decision: PolicyDecision) -> list[str]:
    return sorted(decision.rule_ids)


def compare_policy_decisions(
    authoritative: PolicyDecision,
    shadow: PolicyDecision,
) -> PolicyShadowComparison:
    mismatch_fields = []

    if authoritative.effect != shadow.effect:
        mismatch_fields.append(PolicyShadowMismatchField.EFFECT)

    authoritative_obligations = _sorted_obligation_types(authoritative)
    shadow_obligations = _sorted_obligation_types(shadow)
    if authoritative_obligations != shadow_obligations:
        mismatch_fields.append(PolicyShadowMismatchField.OBLIGATIONS)

    authoritative_rule_ids = _sorted_rule_ids(authoritative)
    shadow_rule_ids = _sorted_rule_ids(shadow)
    if authoritative_rule_ids != shadow_rule_ids:
        mismatch_fields.append(PolicyShadowMismatchField.RULE_IDS)

    if authoritative.severity != shadow.severity:
        mismatch_fields.append(PolicyShadowMismatchField.SEVERITY)

    if not mismatch_fields:
        return PolicyShadowComparison(
            status=PolicyShadowStatus.MATCH,
            match=True,
            mismatch_fields=[],
            mismatch_risk=PolicyShadowMismatchRisk.NONE,
            authoritative_engine="legacy_yaml",
            shadow_engine="opa",
            authoritative_effect=authoritative.effect,
            shadow_effect=shadow.effect,
            authoritative_rule_ids=authoritative_rule_ids,
            shadow_rule_ids=shadow_rule_ids,
            authoritative_obligations=authoritative_obligations,
            shadow_obligations=shadow_obligations,
            authoritative_severity=authoritative.severity,
            shadow_severity=shadow.severity,
            shadow_policy_revision=shadow.policy_revision,
            error_code=None,
        )

    return PolicyShadowComparison(
        status=PolicyShadowStatus.MISMATCH,
        match=False,
        mismatch_fields=mismatch_fields,
        mismatch_risk=_classify_mismatch_risk(authoritative.effect, shadow.effect),
        authoritative_engine="legacy_yaml",
        shadow_engine="opa",
        authoritative_effect=authoritative.effect,
        shadow_effect=shadow.effect,
        authoritative_rule_ids=authoritative_rule_ids,
        shadow_rule_ids=shadow_rule_ids,
        authoritative_obligations=authoritative_obligations,
        shadow_obligations=shadow_obligations,
        authoritative_severity=authoritative.severity,
        shadow_severity=shadow.severity,
        shadow_policy_revision=shadow.policy_revision,
        error_code=None,
    )


def build_shadow_error_comparison(
    authoritative: PolicyDecision,
    error_code: str,
) -> PolicyShadowComparison:
    return PolicyShadowComparison(
        status=PolicyShadowStatus.ERROR,
        match=None,
        mismatch_fields=[],
        mismatch_risk=PolicyShadowMismatchRisk.UNKNOWN,
        authoritative_engine="legacy_yaml",
        shadow_engine="opa",
        authoritative_effect=authoritative.effect,
        shadow_effect=None,
        authoritative_rule_ids=_sorted_rule_ids(authoritative),
        shadow_rule_ids=[],
        authoritative_obligations=_sorted_obligation_types(authoritative),
        shadow_obligations=[],
        authoritative_severity=authoritative.severity,
        shadow_severity=None,
        shadow_policy_revision=None,
        error_code=error_code,
    )


def run_opa_shadow_evaluation(
    *,
    context: dict[str, Any],
    authoritative_decision: PolicyDecision,
    opa_client: OPAClient | None = None,
) -> PolicyShadowComparison:
    try:
        client = opa_client or OPAClient(
            base_url=settings.opa_base_url,
            decision_path=settings.opa_decision_path,
            timeout_seconds=settings.opa_timeout_seconds,
        )
        shadow_decision = client.evaluate(context)
        comparison = compare_policy_decisions(
            authoritative_decision,
            shadow_decision,
        )
    except OPAClientError as exc:
        comparison = build_shadow_error_comparison(
            authoritative_decision,
            exc.code,
        )
    except Exception:
        comparison = build_shadow_error_comparison(
            authoritative_decision,
            "opa_shadow_unexpected_error",
        )

    _log_shadow_comparison(comparison)
    return comparison


def _classify_mismatch_risk(
    authoritative_effect: PolicyEffect,
    shadow_effect: PolicyEffect,
) -> PolicyShadowMismatchRisk:
    if (
        authoritative_effect in {PolicyEffect.DENY, PolicyEffect.DEFER}
        and shadow_effect == PolicyEffect.ALLOW
    ):
        return PolicyShadowMismatchRisk.DANGEROUS

    if (
        authoritative_effect == PolicyEffect.ALLOW
        and shadow_effect in {PolicyEffect.DENY, PolicyEffect.DEFER}
    ):
        return PolicyShadowMismatchRisk.CONSERVATIVE

    return PolicyShadowMismatchRisk.BEHAVIORAL


def _log_shadow_comparison(comparison: PolicyShadowComparison) -> None:
    payload = comparison.model_dump(mode="json")
    message = json.dumps(payload, sort_keys=True)

    if comparison.status == PolicyShadowStatus.MATCH:
        logger.info("policy_shadow_match %s", message)
    elif comparison.status == PolicyShadowStatus.MISMATCH:
        logger.warning("policy_shadow_mismatch %s", message)
    else:
        logger.warning("policy_shadow_error %s", message)
