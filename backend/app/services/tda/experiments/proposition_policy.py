from __future__ import annotations
from app.services.tda.m3_instructions.quoted_enactment import instruction_concerns

POLICY_REVISION = "proposition-policy-v1.1"


def compare_contract(snapshot: dict, extraction: dict, profile: dict | None) -> dict:
    from proxy.tool_security_v2 import ToolSecurityContract
    from proxy.tool_security_v2 import compile_executable_contract_schema
    import re

    if profile is None:
        return {"status": "MISSING", "effects": [], "authority_verified": False}
    try:
        contract = ToolSecurityContract.model_validate(profile["contract"])
        if contract.tool_name != snapshot[
            "name"
        ] or contract.contract_hash != profile.get("contract_hash"):
            raise ValueError("contract_binding_mismatch")
        compile_executable_contract_schema(contract, snapshot["input_schema"])
    except (ValueError, KeyError, TypeError) as exc:
        return {
            "status": "INVALID",
            "effects": [],
            "authority_verified": False,
            "reason": str(exc),
        }
    declared = contract.model_dump(mode="json")["effects"]
    rows = []
    for p in extraction["propositions"]:
        if not p["operational"] or p["quotation"] or p["polarity"] == "NEGATIVE":
            continue
        if p["actor"] == "AGENT":
            status = "NOT_TOOL_AUTHORITY"
            matching = []
        elif p["actor"] != "TOOL":
            status = "UNRESOLVED_ACTOR"
            matching = []
        elif p["action"] == "return" or (
            p["action"] == "compose" and p["destination"] == "CALLER_OUTPUT"
        ):
            status = "OUTPUT_CLAIM_NOT_A_NEW_PERMISSION"
            matching = []
        else:
            matching = [
                e for e in declared if e["capability"].rsplit(".", 1)[-1] == p["action"]
            ]
            bound = [
                e
                for e in matching
                if any(
                    (
                        b.get("path")
                        and re.search(
                            "(?<!\\w)" + re.escape(str(b["path"][-1])) + "(?!\\w)",
                            p["excerpt"],
                            re.I,
                        )
                        for b in e.get("resource_bindings", [])
                    )
                )
            ]
            status = (
                "DECLARED_ARGUMENT_CANDIDATE"
                if bound
                else "UNRESOLVED_BINDING"
                if matching
                else "UNCOVERED"
            )
        rows.append(
            {
                "proposition_id": p["id"],
                "status": status,
                "candidate_effects": [e["effect_id"] for e in matching],
            }
        )
    return {
        "status": "COMPILED_DECLARATIONS_ONLY",
        "effects": rows,
        "authority_verified": False,
        "note": "Compilation is not signed publication or Runtime admission.",
    }


def evaluate_candidate(
    snapshot: dict, extraction: dict, profile: dict | None, *, baseline_status: str
) -> dict:
    concerns = instruction_concerns(extraction)
    unknown = []
    for p in extraction["propositions"]:
        if p["quotation"] or p["speech_act"] in {
            "DOCUMENTARY",
            "PROTECTIVE_GUIDANCE",
            "USAGE_GUIDANCE",
        }:
            continue
        if p["operational"] and (
            p["interpretation"] == "UNACCOUNTED"
            or (
                p["action"] in {"send", "compose"}
                and p["destination"] in {"UNKNOWN", "UNRESOLVED_OUTBOUND"}
            )
        ):
            unknown.append(
                {
                    "code": "unaccounted_operational_clause",
                    "proposition_id": p["id"],
                    "uncertainty": p["uncertainty"],
                }
            )
        if p.get("model_actor_hypothesis") == "AGENT" and p["operational"]:
            unknown.append(
                {
                    "code": "model_agent_role_hypothesis",
                    "proposition_id": p["id"],
                    "uncertainty": ["model_hypothesis_not_observed_evidence"],
                }
            )
    status = baseline_status
    if profile is None:
        status = "QUARANTINED"
    elif baseline_status != "BLOCKED" and (
        concerns or unknown or extraction["omissions"]
    ):
        status = "REVIEW_REQUIRED"
    return {
        "policy": POLICY_REVISION,
        "analysis_status": status,
        "concerns": concerns,
        "unknowns": unknown,
        "contract_comparison": compare_contract(snapshot, extraction, profile),
        "experimental": True,
        "creates_permissions": False,
    }
