import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
BACKEND_TESTS_DIR = BACKEND_DIR / "tests"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(BACKEND_TESTS_DIR))

from app.schemas.policy_context import RuntimePolicyInput  # noqa: E402
from app.schemas.policy_decision import PolicyDecision, PolicyEffect  # noqa: E402
from app.services.opa_client import OPAClient, OPAClientError  # noqa: E402
from app.services.policy_engine import evaluate_policy  # noqa: E402
from policy_parity_cases import POLICY_PARITY_CASES  # noqa: E402


def normalized_policy_decision(decision: PolicyDecision) -> dict[str, Any]:
    payload = decision.model_dump(mode="json", exclude={"policy_revision"})
    payload["rule_ids"] = sorted(payload["rule_ids"])
    payload["obligations"] = sorted(
        payload["obligations"],
        key=lambda obligation: (
            obligation["type"],
            json.dumps(obligation["parameters"], sort_keys=True),
        ),
    )
    return payload


def changed_fields(
    yaml_decision: dict[str, Any],
    opa_decision: dict[str, Any],
) -> list[str]:
    field_order = [
        "effect",
        "obligations",
        "rule_ids",
        "reason",
        "severity",
        "evidence",
        "recommended_action",
        "decision",
        "rule_id",
    ]
    return [
        field
        for field in field_order
        if yaml_decision.get(field) != opa_decision.get(field)
    ]


def classify_mismatch(
    yaml_decision: PolicyDecision,
    opa_decision: PolicyDecision,
) -> str:
    if (
        yaml_decision.effect in {PolicyEffect.DENY, PolicyEffect.DEFER}
        and opa_decision.effect == PolicyEffect.ALLOW
    ):
        return "dangerous"

    if (
        yaml_decision.effect == PolicyEffect.ALLOW
        and opa_decision.effect in {PolicyEffect.DENY, PolicyEffect.DEFER}
    ):
        return "conservative"

    return "behavioral"


def validate_policy_parity(
    *,
    opa_base_url: str,
    decision_path: str,
    timeout_seconds: float,
) -> int:
    client = OPAClient(
        base_url=opa_base_url,
        decision_path=decision_path,
        timeout_seconds=timeout_seconds,
    )

    total_cases = len(POLICY_PARITY_CASES)
    exact_matches = 0
    mismatches = 0
    dangerous_mismatches = 0
    conservative_mismatches = 0
    behavioral_mismatches = 0
    opa_errors = 0
    invalid_contexts = 0

    for case in POLICY_PARITY_CASES:
        try:
            context = RuntimePolicyInput.model_validate(case.context).model_dump(mode="json")
        except Exception:
            invalid_contexts += 1
            print(f"FAIL {case.case_id} fields=context")
            continue

        try:
            yaml_decision = PolicyDecision.model_validate(evaluate_policy(context))
            opa_decision = client.evaluate(context)
        except OPAClientError as exc:
            opa_errors += 1
            print(f"FAIL {case.case_id} fields=opa_error code={exc.code}")
            continue

        yaml_payload = normalized_policy_decision(yaml_decision)
        opa_payload = normalized_policy_decision(opa_decision)

        fields = changed_fields(yaml_payload, opa_payload)
        if yaml_decision.rule_id != case.expected_rule_id:
            fields.append("expected_rule_id")
        if opa_decision.rule_id != case.expected_rule_id:
            fields.append("opa_expected_rule_id")

        if fields:
            mismatches += 1
            risk = classify_mismatch(yaml_decision, opa_decision)
            if risk == "dangerous":
                dangerous_mismatches += 1
            elif risk == "conservative":
                conservative_mismatches += 1
            else:
                behavioral_mismatches += 1
            print(f"FAIL {case.case_id} fields={','.join(fields)}")
            continue

        exact_matches += 1
        print(f"PASS {case.case_id}")

    print(f"total_cases={total_cases}")
    print(f"exact_matches={exact_matches}")
    print(f"mismatches={mismatches}")
    print(f"dangerous_mismatches={dangerous_mismatches}")
    print(f"conservative_mismatches={conservative_mismatches}")
    print(f"behavioral_mismatches={behavioral_mismatches}")
    print(f"opa_errors={opa_errors}")
    print(f"invalid_contexts={invalid_contexts}")

    if (
        exact_matches == total_cases
        and mismatches == 0
        and opa_errors == 0
        and invalid_contexts == 0
    ):
        return 0

    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opa-base-url", default="http://127.0.0.1:8181")
    parser.add_argument(
        "--decision-path",
        default="/v1/data/mcp/security/runtime/decision",
    )
    parser.add_argument("--timeout-seconds", type=float, default=2.0)
    args = parser.parse_args()
    return validate_policy_parity(
        opa_base_url=args.opa_base_url,
        decision_path=args.decision_path,
        timeout_seconds=args.timeout_seconds,
    )


if __name__ == "__main__":
    raise SystemExit(main())
