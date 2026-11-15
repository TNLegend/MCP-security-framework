from __future__ import annotations
from app.services.tda.types import AnalysisFinding
from app.services.tda.configuration import CRITICAL_DETERMINISTIC_CODES
from app.services.tda.configuration import FINDING_DECISION_BLOCK
from app.services.tda.configuration import FINDING_DECISION_REVIEW
from app.services.tda.configuration import PASSIVE_READ_SCHEMA_CAPABILITIES
from app.services.tda.security_guards.facts import ToolSemanticFacts
from app.services.tda.text import _annotation_text
from app.services.tda.findings import _finding
from app.services.tda.security_guards.extraction import extract_tool_semantic_facts as extract_safety_metadata_facts
from app.services.tda.security_guards.actor_attribution import explicit_agent_contract_view
from typing import Any


def _tool_consistency_result(
    tool_snapshot: dict[str, Any],
    profile_snapshot: dict[str, Any] | None,
    *,
    semantic_facts: ToolSemanticFacts | None = None,
) -> dict[str, Any]:
    facts = semantic_facts or extract_safety_metadata_facts(tool_snapshot)
    description_caps = capabilities_from_text(tool_snapshot.get("description") or "")
    schema_caps = capabilities_from_schema(tool_snapshot.get("input_schema") or {})
    output_schema_caps = capabilities_from_output_schema(
        tool_snapshot.get("output_schema") or {}
    )
    annotation_caps = capabilities_from_text(
        _annotation_text(tool_snapshot.get("annotations") or {})
    )
    execution_caps = capabilities_from_execution(tool_snapshot.get("execution") or {})
    profile_caps = capabilities_from_profile(profile_snapshot or {})
    findings: list[AnalysisFinding] = []
    if profile_snapshot is None:
        return {
            "status": "unconfigured",
            "description_capabilities": sorted(description_caps),
            "schema_capabilities": sorted(schema_caps),
            "output_schema_capabilities": sorted(output_schema_caps),
            "annotation_capabilities": sorted(annotation_caps),
            "execution_capabilities": sorted(execution_caps),
            "profile_capabilities": [],
            "semantic_facts": facts.to_dict(),
            "findings": findings,
        }

    def uncovered_schema_capabilities(capabilities: set[str]) -> set[str]:
        return {
            capability
            for capability in capabilities
            if not _capability_covered_by_contract(capability, profile_caps)
            and (
                not _passive_custom_read_contract_covers_schema_capability(
                    capability,
                    tool_name=str(tool_snapshot.get("name") or ""),
                    profile_snapshot=profile_snapshot,
                )
            )
        }

    extra_capabilities_by_source = {
        "input_schema": uncovered_schema_capabilities(schema_caps),
        "output_schema": uncovered_schema_capabilities(output_schema_caps),
        "annotation": {
            capability
            for capability in annotation_caps
            if not _capability_covered_by_contract(capability, profile_caps)
            and (
                not (
                    capability in {"filesystem.read", "filesystem.list"}
                    and any(
                        (
                            segment
                            in {"docs", "document", "files", "file", "filesystem"}
                            for effect in (profile_snapshot.get("contract") or {}).get(
                                "effects"
                            )
                            or ()
                            if isinstance(effect, dict)
                            for segment in str(effect.get("capability") or "").split(
                                "."
                            )
                        )
                    )
                    and _passive_custom_read_contract_covers_schema_capability(
                        capability,
                        tool_name=str(tool_snapshot.get("name") or ""),
                        profile_snapshot=profile_snapshot,
                    )
                )
            )
        },
        "execution": {
            capability
            for capability in execution_caps
            if not _capability_covered_by_contract(capability, profile_caps)
        },
    }
    candidate_description_caps = (
        description_caps
        if _description_capability_inference_reliable(facts)
        else _description_relation_capabilities(facts)
    )
    extra_description_caps = {
        capability
        for capability in candidate_description_caps
        if not _capability_covered_by_contract(capability, profile_caps)
    }
    for source, extra_capabilities in extra_capabilities_by_source.items():
        for capability in sorted(extra_capabilities):
            code = _capability_mismatch_code({capability})
            output_secret_review = (
                source == "output_schema" and capability == "secret.access"
            )
            findings.append(
                _finding(
                    code,
                    "consistency",
                    source,
                    "high"
                    if output_secret_review
                    else "critical"
                    if code in CRITICAL_DETERMINISTIC_CODES
                    else "high",
                    88,
                    f"{source} capability exceeds profile: {capability}",
                    "Narrow the declared behavior or update the official Tool Security Profile.",
                    decision=FINDING_DECISION_REVIEW
                    if output_secret_review
                    else FINDING_DECISION_BLOCK,
                )
            )
    if extra_description_caps:
        for capability in sorted(extra_description_caps):
            findings.append(
                _finding(
                    _capability_mismatch_code({capability}),
                    "consistency",
                    "description",
                    "medium",
                    78,
                    f"description capability exceeds profile: {capability}",
                    "Review whether the profile authorizes the described behavior.",
                    decision=FINDING_DECISION_REVIEW,
                )
            )
    passive_contract_verbs = {
        "read",
        "list",
        "search",
        "query",
        "select",
        "fetch",
        "get",
        "inspect",
        "lookup",
        "view",
        "browse",
    }
    mutating_actions = {
        "create",
        "update",
        "delete",
        "send",
        "execute",
        "authorize",
        "transact",
    }
    contract_is_read_only = bool(profile_caps) and all(
        (
            capability.rsplit(".", 1)[-1] in passive_contract_verbs
            for capability in profile_caps
        )
    )
    unexplained_effects = (
        facts.values("actions", sources={"description", "execution"}) & mutating_actions
    )
    if contract_is_read_only and unexplained_effects and (not extra_description_caps):
        findings.append(
            _finding(
                "uncontracted_mutating_action",
                "consistency",
                "description",
                "medium",
                78,
                f"Operational metadata declares an effect outside the read-only contract: {', '.join(sorted(unexplained_effects))}",
                "Confirm side effects with an ADMIN and publish an explicit, scoped contract before allowing execution.",
                decision=FINDING_DECISION_REVIEW,
            )
        )
    status = "consistent" if not findings else "mismatch"
    return {
        "status": status,
        "description_capabilities": sorted(description_caps),
        "schema_capabilities": sorted(schema_caps),
        "output_schema_capabilities": sorted(output_schema_caps),
        "annotation_capabilities": sorted(annotation_caps),
        "execution_capabilities": sorted(execution_caps),
        "profile_capabilities": sorted(profile_caps),
        "semantic_facts": facts.to_dict(),
        "findings": findings,
    }


def _capability_covered_by_contract(observed: str, declared: set[str]) -> bool:
    if observed in declared:
        return True
    aliases = {
        "secret.access": {"secret.read"},
        "secret.read": {"secret.access"},
        "database.select": {"database.read"},
        "database.read": {"database.select"},
        "database.modify": {"database.write"},
        "database.write": {"database.modify"},
    }
    if declared.intersection(aliases.get(observed, set())):
        return True
    return False


def _passive_custom_read_contract_covers_schema_capability(
    observed: str, *, tool_name: str, profile_snapshot: dict[str, Any]
) -> bool:
    if observed not in PASSIVE_READ_SCHEMA_CAPABILITIES:
        return False
    contract = profile_snapshot.get("contract")
    security_pack = profile_snapshot.get("security_pack")
    if not isinstance(contract, dict) or not isinstance(security_pack, dict):
        return False
    if contract.get("tool_name") != tool_name:
        return False
    categories = {
        str(value).strip().lower()
        for value in security_pack.get("semantic_categories") or ()
        if str(value).strip()
    }
    if "read-only" not in categories:
        return False
    effects = contract.get("effects")
    if not isinstance(effects, list) or not effects:
        return False
    capabilities = {
        str(effect.get("capability") or "")
        for effect in effects
        if isinstance(effect, dict)
    }
    passive_verbs = {"fetch", "get", "list", "query", "read", "search", "select"}
    if not capabilities or any(
        (
            "." not in capability or capability.rsplit(".", 1)[-1] not in passive_verbs
            for capability in capabilities
        )
    ):
        return False
    result_control = contract.get("result_control")
    if not (
        isinstance(result_control, dict)
        and result_control.get("track_for_exfiltration") is True
    ):
        return False
    aliases_by_domain = {
        "filesystem": {"file", "files", "filesystem", "path", "paths"},
        "database": {"database", "databases", "db", "sql"},
        "cloud": {"cloud", "storage", "object", "objects"},
        "calendar": {"calendar", "calendars"},
        "message": {"message", "messages", "email", "emails", "mail"},
        "identity": {"identity", "identities", "user", "users"},
        "network": {"network", "http", "endpoint", "endpoints"},
        "payment": {"payment", "payments"},
    }
    domain = observed.split(".", 1)[0]
    identifiers = aliases_by_domain.get(domain, set())
    return bool(identifiers) and any(
        (
            bool(identifiers.intersection(capability.lower().split(".")[:-1]))
            for capability in capabilities
        )
    )


def _description_relation_capabilities(facts: ToolSemanticFacts) -> set[str]:
    """Derive only capabilities justified by individual operational clauses.

    Schema/annotation facts and unrelated action/resource pairs cannot create
    extra description-based authority. Negative or example-only clauses have
    no positive description relation to contribute.
    """
    from dataclasses import replace

    supported: set[str] = set()
    for relation in facts.action_resource_relations:
        if relation.evidence.source != "description":
            continue
        scoped = replace(
            facts,
            actions=tuple(
                (
                    fact
                    for fact in facts.actions
                    if fact.value == relation.action
                    and any((item.source == "description" for item in fact.evidence))
                )
            ),
            resources=tuple(
                (
                    fact
                    for fact in facts.resources
                    if fact.value == relation.resource
                    and any((item.source == "description" for item in fact.evidence))
                )
            ),
            side_effects=tuple(
                (
                    fact
                    for fact in facts.side_effects
                    if any((item.source == "description" for item in fact.evidence))
                    and (
                        relation.action == "send"
                        and fact.value == "communication"
                        or (
                            relation.action in {"create", "update"}
                            and fact.value == "state_change"
                        )
                        or (relation.action == "delete" and fact.value == "destructive")
                        or (
                            relation.action == "execute"
                            and fact.value == "code_execution"
                        )
                        or (
                            relation.action == "authorize"
                            and fact.value == "access_control_change"
                        )
                        or (
                            relation.action == "transact"
                            and fact.value == "financial_transaction"
                        )
                    )
                )
            ),
            action_resource_relations=(relation,),
        )
        if scoped.actions and scoped.resources:
            supported.update(_capabilities_from_semantic_facts(scoped))
    return supported


def _description_capability_inference_reliable(facts: ToolSemanticFacts) -> bool:
    actions = facts.values("actions", sources={"description"})
    if not actions:
        return False
    inferred = _capabilities_from_semantic_facts(facts)
    if len(inferred) == 1:
        return True
    resources = facts.values("resources", sources={"description"})
    return len(resources) == 1 and len(actions) <= 2


def capabilities_from_text(text: str) -> set[str]:
    from proxy.security_packs import SecurityPackRegistry

    facts = extract_safety_metadata_facts(
        {
            "name": "",
            "description": text,
            "input_schema": {},
            "output_schema": {},
            "annotations": {},
            "execution": {},
        }
    )
    capabilities = _capabilities_from_semantic_facts(facts)
    lowered = text.lower()
    for pack in SecurityPackRegistry().packs():
        for capability in pack.capabilities:
            if _contains_capability_keyword(lowered, capability.id):
                capabilities.add(capability.id)
    return capabilities


def capabilities_from_profile(profile: dict[str, Any]) -> set[str]:
    return _capabilities_from_v2_contract(profile)


def _unresolved_semantic_unknown_reasons(
    reasons: tuple[str, ...], profile_snapshot: dict[str, Any] | None, *, tool_name: str
) -> tuple[str, ...]:
    return tuple(reasons)


def _contract_declared_unknown_bounds(
    reasons: tuple[str, ...], profile_snapshot: dict[str, Any] | None, *, tool_name: str
) -> tuple[str, ...]:
    """Diagnostic declarations only; neither validation nor permission creation."""
    unresolved = list(reasons)
    contract = (profile_snapshot or {}).get("contract")
    effects = contract.get("effects") if isinstance(contract, dict) else None
    contract_matches_tool = (
        isinstance(contract, dict)
        and contract.get("tool_name") == tool_name
        and isinstance(effects, list)
    )
    known_contract_action_verbs = {
        "authorize",
        "delete",
        "execute",
        "fetch",
        "get",
        "initiate",
        "list",
        "manage",
        "mutate",
        "ping",
        "query",
        "read",
        "refund",
        "request",
        "search",
        "select",
        "send",
        "transact",
        "transfer",
        "update",
        "write",
    }
    has_bound_action = contract_matches_tool and any(
        (
            isinstance(effect, dict)
            and isinstance(effect.get("capability"), str)
            and (
                effect["capability"].rsplit(".", 1)[-1].lower()
                in known_contract_action_verbs
            )
            for effect in effects
        )
    )
    has_bound_resource = contract_matches_tool and any(
        (
            isinstance(effect, dict)
            and (
                bool(effect.get("resource_bindings"))
                or isinstance(effect.get("fixed_resource"), dict)
            )
            for effect in effects
        )
    )
    if has_bound_action:
        unresolved = [
            reason for reason in unresolved if reason != "action_not_evidenced"
        ]
    if has_bound_resource:
        unresolved = [
            reason for reason in unresolved if reason != "resource_not_evidenced"
        ]
    return tuple((reason for reason in reasons if reason not in unresolved))


def capabilities_from_schema(schema: dict[str, Any]) -> set[str]:
    facts = extract_safety_metadata_facts(
        {
            "name": "",
            "description": "",
            "input_schema": schema,
            "output_schema": {},
            "annotations": {},
            "execution": {},
        }
    )
    return _capabilities_from_semantic_facts(facts)


def capabilities_from_output_schema(schema: dict[str, Any]) -> set[str]:
    facts = extract_safety_metadata_facts(
        {
            "name": "",
            "description": "",
            "input_schema": {},
            "output_schema": schema,
            "annotations": {},
            "execution": {},
        }
    )
    capabilities = _capabilities_from_semantic_facts(facts)
    if "credentials" in facts.values(
        "data_categories"
    ) or "secret_store" in facts.values("resources"):
        capabilities.add("secret.access")
    return capabilities


def capabilities_from_execution(execution: dict[str, Any]) -> set[str]:
    facts = extract_safety_metadata_facts(
        {
            "name": "",
            "description": "",
            "input_schema": {},
            "output_schema": {},
            "annotations": {},
            "execution": execution,
        }
    )
    return _capabilities_from_semantic_facts(facts)


def _capabilities_from_semantic_facts(facts: ToolSemanticFacts) -> set[str]:
    from dataclasses import replace

    resolved: set[str] = set()
    for relation in facts.action_resource_relations:
        if relation.evidence.kind != "CLAIM_TEXT":
            continue
        bound = replace(
            facts,
            actions=tuple((x for x in facts.actions if x.value == relation.action)),
            resources=tuple(
                (x for x in facts.resources if x.value == relation.resource)
            ),
            side_effects=tuple(
                (
                    x
                    for x in facts.side_effects
                    if relation.action == "send"
                    and x.value == "communication"
                    or (
                        relation.action in {"create", "update"}
                        and x.value == "state_change"
                    )
                    or (relation.action == "delete" and x.value == "destructive")
                    or (relation.action == "execute" and x.value == "code_execution")
                    or (
                        relation.action == "authorize"
                        and x.value == "access_control_change"
                    )
                    or (
                        relation.action == "transact"
                        and x.value == "financial_transaction"
                    )
                )
            ),
            action_resource_relations=(),
        )
        resolved.update(_capabilities_from_bound_facts(bound))
    if any(
        (
            f.value == "health_check"
            and any((e.kind == "CLAIM_TEXT" for e in f.evidence))
            for f in facts.actions
        )
    ):
        resolved.add("system.ping")
    return resolved


def _capabilities_from_bound_facts(facts: ToolSemanticFacts) -> set[str]:
    """Map only a previously evidenced predicate/object pair to vocabulary."""
    actions = facts.values("actions")
    resources = facts.values("resources")
    side_effects = facts.values("side_effects")
    capabilities: set[str] = set()
    read_actions = actions.intersection({"read", "search"})
    write_actions = actions.intersection({"create", "update"})
    if "filesystem" in resources:
        if "list" in actions:
            capabilities.add("filesystem.list")
        if read_actions:
            capabilities.add("filesystem.read")
        if write_actions:
            capabilities.add("filesystem.write")
        if "delete" in actions:
            capabilities.add("filesystem.delete")
    if "database" in resources:
        if read_actions or "list" in actions:
            capabilities.add("database.read")
        if write_actions:
            capabilities.add("database.write")
        if "delete" in actions:
            capabilities.add("database.delete")
    if "message" in resources:
        if read_actions or "list" in actions:
            capabilities.add("message.read")
        if "send" in actions or "communication" in side_effects:
            capabilities.add("message.send")
        if "delete" in actions:
            capabilities.add("message.delete")
    if "calendar" in resources:
        if read_actions or "list" in actions:
            capabilities.add("calendar.read")
        if write_actions:
            capabilities.add("calendar.write")
        if "delete" in actions:
            capabilities.add("calendar.delete")
    if "cloud_storage" in resources:
        if read_actions or "list" in actions:
            capabilities.add("cloud.object.read")
        if write_actions or "send" in actions:
            capabilities.add("cloud.object.write")
        if "delete" in actions:
            capabilities.add("cloud.object.delete")
    if "identity" in resources:
        if read_actions or "list" in actions:
            capabilities.add("identity.read")
        if write_actions or "delete" in actions or "authorize" in actions:
            capabilities.add("identity.manage")
    if "secret_store" in resources and (read_actions or "list" in actions):
        capabilities.add("secret.access")
    if "network_endpoint" in resources:
        if read_actions or "search" in actions:
            capabilities.add("network.request")
        if "send" in actions or "external_transfer" in side_effects:
            capabilities.add("network.send")
    if "process" in resources and "execute" in actions:
        capabilities.add("process.execute")
    if "payment" in resources:
        if read_actions or "list" in actions:
            capabilities.add("payment.read")
        if "transact" in actions:
            capabilities.add("payment.initiate")
    if "health_check" in actions:
        capabilities.add("system.ping")
    return capabilities


def _contains_capability_keyword(lowered_text: str, keyword: str) -> bool:
    import re

    lowered_keyword = keyword.lower()
    if not lowered_keyword:
        return False
    if any((not (char.isalnum() or char.isspace()) for char in lowered_keyword)):
        return lowered_keyword in lowered_text
    parts = re.findall("[a-z0-9]+", lowered_keyword)
    if not parts:
        return False
    pattern = "(?<![a-z0-9])" + "[\\W_]+".join(map(re.escape, parts)) + "(?![a-z0-9])"
    return re.search(pattern, lowered_text) is not None


def _capabilities_from_v2_contract(profile: dict[str, Any]) -> set[str]:
    contract = profile.get("contract")
    if not isinstance(contract, dict):
        return set()
    effects = contract.get("effects")
    if not isinstance(effects, list):
        return set()
    capabilities: set[str] = set()
    for effect in effects:
        if not isinstance(effect, dict):
            continue
        capability = effect.get("capability")
        if isinstance(capability, str) and capability:
            capabilities.add(capability)
    return capabilities


def _capability_mismatch_code(capabilities: set[str]) -> str:
    if "process.execute" in capabilities:
        return "unexpected_process_execution"
    if "secret.access" in capabilities:
        return "unexpected_secret_access"
    if "filesystem.delete" in capabilities:
        return "unexpected_destructive_operation"
    if "network.send" in capabilities:
        return "unexpected_network_capability"
    return "schema_profile_mismatch"


def consistency_result(
    tool_snapshot: dict[str, Any],
    profile_snapshot: dict[str, Any] | None,
    *,
    semantic_facts: ToolSemanticFacts | None = None,
) -> dict[str, Any]:
    observed = semantic_facts or extract_safety_metadata_facts(tool_snapshot)
    view, attribution = explicit_agent_contract_view(tool_snapshot)
    projected = (
        extract_safety_metadata_facts(view)
        if attribution["excluded_claims"]
        else observed
    )
    result = _tool_consistency_result(view, profile_snapshot, semantic_facts=projected)
    result["actor_attribution"] = attribution
    result["observed_semantic_facts"] = observed.to_dict()
    claims = attribution["excluded_claims"] + attribution["uncertain_claims"]
    if claims:
        finding = _finding(
            "agent_action_not_tool_authority",
            "consistency",
            "metadata",
            "medium",
            78,
            "Metadata instructs the caller to perform an operation; tool permissions are not authority for that action.",
            "Review caller actions separately from this tool's declared effects and permissions.",
            decision=FINDING_DECISION_REVIEW,
        )
        finding.evidence.update(actor_claims=claims)
        result["findings"].append(finding)
        if profile_snapshot is not None:
            result["status"] = "mismatch"
    return result

def inspect_m4_operations_advisory(view: dict[str, Any]) -> dict[str, Any]:
    if (view.get("capability_comparison") != "NOT_EVALUATED"
            or view.get("drift_comparison") != "NOT_EVALUATED"):
        raise ValueError("M6_M4_UNEXPECTED_COMPARISON_AUTHORITY")
    ops = view.get("advisory_operations")
    if not isinstance(ops, list):
        raise ValueError("M6_M4_OPERATIONS_NOT_LIST")
    result = []
    for op in ops:
        if not isinstance(op, dict) or op.get("truth_status") != "MODEL_HYPOTHESIS_UNVERIFIED":
            raise ValueError("M6_M4_UNVERIFIED_OPERATION_REQUIRED")
        if op.get("asserted_capability") is not None or op.get("authorized_effect") is not None:
            raise ValueError("M6_M4_CAPABILITY_OR_AUTHORITY_PROMOTION_REFUSED")
        if not isinstance(op.get("uncertainty_reasons"), list):
            raise ValueError("M6_M4_MISSING_UNCERTAINTY")
        result.append({
            "event_id": op["event_id"],
            "operation": op["predicate"],
            "candidate_labels": op["labels"],
            "candidate_arguments": op["arguments"],
            "uncertainty_reasons": op["uncertainty_reasons"],
            "effect_proven": False,
            "capability_proven": False,
        })
    return {
        "module": "M6", "mode": "ADVISORY",
        "semantic_operation_candidates": result,
        "candidate_operation_count": len(result),
        "contract_consistency_decision": "NOT_EVALUATED",
        "drift_decision": "NOT_EVALUATED",
        "existing_contract_comparison_unchanged": True,
    }

def consistency_result_from_m4(
    tool_snapshot: dict[str, Any],
    profile_snapshot: dict[str, Any] | None,
    m4_view: dict[str, Any],
) -> dict[str, Any]:
    """M6 contract review of verified-source, but *unverified-behavior* M4 candidates.

    This deliberately does not call the historical M4 text-rule extractor or
    reinterpret neural predicates as validated tool capabilities. An unknown
    is a review obligation, never evidence that the contract is satisfied.
    """
    if (m4_view.get("mode") != "ADVISORY" or
            m4_view.get("contract_consistency_decision") != "NOT_EVALUATED"):
        raise ValueError("M6_REQUIRES_NON_AUTHORITATIVE_M4_INPUT")
    operations = m4_view.get("semantic_operation_candidates")
    if not isinstance(operations, list):
        raise ValueError("M6_M4_OPERATIONS_MISSING")
    for item in operations:
        if (item.get("effect_proven") is not False or
                item.get("capability_proven") is not False):
            raise ValueError("M6_M4_UNVERIFIED_CAPABILITY_PROMOTION_REFUSED")
    profile_caps = capabilities_from_profile(profile_snapshot or {})
    finding = _finding(
        "m4_semantic_capabilities_unverified",
        "consistency",
        "description",
        "medium",
        0,
        "Neural semantic candidates describe metadata, not verified tool capabilities.",
        "Review the source-grounded M4 events against independent contracts and schema evidence.",
        decision=FINDING_DECISION_REVIEW,
    )
    return {
        "status": "unconfigured" if profile_snapshot is None else "unverified_m4",
        "description_capabilities": [],
        "schema_capabilities": [],
        "output_schema_capabilities": [],
        "annotation_capabilities": [],
        "execution_capabilities": [],
        "profile_capabilities": sorted(profile_caps),
        "m4_advisory_operations": operations,
        "m4_capabilities_verified": False,
        "m4_unresolved": True,
        "findings": [finding],
    }
