"""Read-only IAM ↔ signed MCP contract comparison.

No IAM writes, no runtime enforcement changes, no secrets stored. Policy
evaluation is conservative: implicit allows, permission boundaries, SCPs,
session policies and resource policies make effective authorization UNKNOWN
unless explicitly disproven by a simple unconditional Deny.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from hashlib import sha256
import json
import logging
import re
from threading import BoundedSemaphore

from sqlalchemy import select

from app.db.database import SessionLocal
from app.models.cloud_security import (
    CloudEnvironment, CloudScan, CloudScanEvent, CloudIAMComparison,
    CloudEvidence, CloudFinding, CloudResource, CloudIAMMapping, new_id,
)
from app.services.cloud_security import check_connection, _safe_error
from app.services.published_configuration import PublishedConfigurationProvider

VERSION = "iam-mcp-manual-bidirectional-v3"
log = logging.getLogger(__name__)
_POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cloud-iam-mcp")
_CAPACITY = BoundedSemaphore(1)
_MAX_POLICY_DOCS = 25
_MAX_POLICY_STATEMENTS = 300


class ComparisonError(ValueError):
    pass


def digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("utf-8")).hexdigest()


def _iam_profile_role(iam, profile_name: str) -> str:
    result = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    roles = result.get("Roles") or []
    if len(roles) != 1 or not isinstance(roles[0].get("Arn"), str):
        raise ComparisonError("IAM_INSTANCE_PROFILE_ROLE_AMBIGUOUS")
    return roles[0]["Arn"]


def _policy_statements(iam, role_name: str) -> tuple[list[dict], list[str], bool]:
    """Bounded role/inline/managed policy fetch; no raw policies returned to API."""
    role = iam.get_role(RoleName=role_name)["Role"]
    incomplete = bool(role.get("PermissionsBoundary"))
    codes = ["IAM_BOUNDARY_REQUIRES_EVALUATION"] if incomplete else []
    inline = iam.list_role_policies(RoleName=role_name)
    attached = iam.list_attached_role_policies(RoleName=role_name)
    if inline.get("IsTruncated") or attached.get("IsTruncated"):
        raise ComparisonError("IAM_POLICY_PAGINATION_INCOMPLETE")
    if len(inline.get("PolicyNames", [])) + len(attached.get("AttachedPolicies", [])) > _MAX_POLICY_DOCS:
        raise ComparisonError("IAM_POLICY_COUNT_LIMIT")
    docs = []
    for name in inline.get("PolicyNames", []):
        docs.append(iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"])
    for ref in attached.get("AttachedPolicies", []):
        meta = iam.get_policy(PolicyArn=ref["PolicyArn"])["Policy"]
        version = iam.get_policy_version(PolicyArn=ref["PolicyArn"],
                  VersionId=meta["DefaultVersionId"])["PolicyVersion"]
        docs.append(version["Document"])
    statements: list[dict] = []
    for doc in docs:
        if isinstance(doc, str):
            import urllib.parse
            doc = json.loads(urllib.parse.unquote(doc))
        if not isinstance(doc, dict):
            raise ComparisonError("IAM_POLICY_DOC_INVALID")
        chunk = doc.get("Statement", [])
        if isinstance(chunk, dict):
            chunk = [chunk]
        if not isinstance(chunk, list) or len(statements) + len(chunk) > _MAX_POLICY_STATEMENTS:
            raise ComparisonError("IAM_POLICY_STATEMENT_LIMIT")
        if not all(isinstance(item, dict) for item in chunk):
            raise ComparisonError("IAM_POLICY_STATEMENT_INVALID")
        statements.extend(chunk)
    return statements, codes, incomplete


def _matches(policy_pattern, value: str, *, action: bool = False) -> bool:
    """Bounded IAM wildcard matching with only * and ? (no regex execution).

    The matcher is case-insensitive for AWS action names but preserves the
    case-sensitive resource portions of ARNs (S3 keys, DynamoDB tables).
    """
    patterns=policy_pattern if isinstance(policy_pattern,list) else [policy_pattern]
    if len(value)>1024:
        return False
    for candidate in patterns[:200]:
        if not isinstance(candidate,str) or len(candidate)>1024:
            continue
        pattern=candidate.lower() if action else candidate
        target=value.lower() if action else value
        i=j=0
        star=-1
        matched=0
        while j<len(target):
            if i<len(pattern) and (pattern[i]=="?" or pattern[i]==target[j]):
                i+=1
                j+=1
            elif i<len(pattern) and pattern[i]=="*":
                star=i
                i+=1
                matched=j
            elif star>=0:
                i=star+1
                matched+=1
                j=matched
            else:
                break
        else:
            while i<len(pattern) and pattern[i]=="*":
                i+=1
            if i==len(pattern):
                return True
    return False


def compare_policy(action: str, resource: str, statements: list[dict],
                   *, restrictions_unknown: bool = True) -> tuple[str, str, list[str]]:
    """Conservative *identity-policy* signals, not effective AWS permission verdicts.

    A principal might also be subject to resource policies, permission boundaries,
    SCPs, session restrictions, and conditions. No identity Allow means
    POTENTIAL_MISSING, never a proven missing effective permission.
    """
    broad: set[str] = set()
    unresolved: set[str] = set()
    complex_seen = False
    matching_allow = False
    for item in statements:
        if not isinstance(item, dict):
            complex_seen = True
            unresolved.add("IAM_UNRECOGNIZED_IDENTITY_STATEMENT")
            continue
        # Unknown policies never become an effective AWS permission verdict.
        # Record the type of unverified statement without exposing its
        # conditions, action patterns or resource values.
        if "NotAction" in item or "NotResource" in item:
            complex_seen = True
            unresolved.add(
                "IAM_NEGATED_ALLOW_POTENTIALLY_BROAD"
                if item.get("Effect") == "Allow"
                else "IAM_NEGATED_STATEMENT_NOT_EVALUATED"
            )
            continue
        if "Condition" in item:
            complex_seen = True
            unresolved.add(
                "IAM_CONDITIONAL_DENY_NOT_EVALUATED"
                if item.get("Effect") == "Deny"
                else "IAM_CONDITIONAL_ALLOW_NOT_EVALUATED"
                if item.get("Effect") == "Allow"
                else "IAM_CONDITIONAL_STATEMENT_NOT_EVALUATED"
            )
            continue
        if not _matches(item.get("Action", []), action, action=True) or not _matches(item.get("Resource", []), resource):
            continue
        if item.get("Effect") == "Deny":
            return "EXPLICIT_DENY", "IAM_IDENTITY_EXPLICIT_DENY", []
        if item.get("Effect") != "Allow":
            complex_seen = True
            continue
        matching_allow = True
        patterns = item.get("Resource", [])
        patterns = patterns if isinstance(patterns, list) else [patterns]
        if any(isinstance(pattern, str) and
               ("*" in pattern or "?" in pattern) and _matches(pattern,resource)
               and pattern!=resource
               for pattern in patterns):
            broad.add("IAM_BROAD_RESOURCE_ALLOW")
        actions = item.get("Action", [])
        actions = actions if isinstance(actions, list) else [actions]
        if any(isinstance(pattern,str) and ("*" in pattern or "?" in pattern)
               and _matches(pattern,action,action=True) for pattern in actions):
            broad.add("IAM_BROAD_ACTION_ALLOW")
    if broad:
        return "POTENTIAL_EXCESS", "IAM_ALLOW_SCOPE_BROADER_THAN_SIGNED_MCP", sorted(broad | unresolved)
    if matching_allow:
        return "UNKNOWN", "IAM_EXACT_IDENTITY_ALLOW_EFFECTIVE_UNKNOWN", sorted(unresolved)
    if complex_seen:
        return "UNKNOWN", "IAM_COMPLEX_POLICY_UNRESOLVED", sorted(unresolved)
    return "POTENTIAL_MISSING", "IAM_IDENTITY_ALLOW_NOT_FOUND_RESOURCE_POLICY_UNVERIFIED", []


def matching_identity_policy_evidence(
    action: str, resource: str, statements: list[dict], *, limit: int = 5
) -> dict:
    """Explain the exact identity-policy patterns behind forward IAM matching.

    Do not claim an AWS effective-permission result. Only report unconditional
    matching Allow/Deny clauses; omit raw policy JSON and sensitive conditions.
    """
    matches: list[dict] = []
    total = 0
    for index, statement in enumerate(statements[:_MAX_POLICY_STATEMENTS]):
        if not isinstance(statement, dict) or statement.get("Effect") not in ("Allow", "Deny"):
            continue
        if any(key in statement for key in ("Condition", "NotAction", "NotResource")):
            continue
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(actions, list) or not isinstance(resources, list):
            continue
        for action_pattern in actions[:200]:
            if not isinstance(action_pattern, str) or len(action_pattern) > 128:
                continue
            if not _matches(action_pattern, action, action=True):
                continue
            for resource_pattern in resources[:200]:
                if not isinstance(resource_pattern, str) or len(resource_pattern) > 512:
                    continue
                if not _matches(resource_pattern, resource):
                    continue
                total += 1
                if len(matches) >= limit:
                    continue
                matches.append({
                    "statement_number": index + 1,
                    "policy_effect": statement["Effect"],
                    "action_pattern": action_pattern,
                    "resource_pattern": resource_pattern,
                    "action_broader": action_pattern.lower() != action.lower(),
                    "resource_broader": resource_pattern != resource,
                })
    return {
        "matching_unconditional_clauses": matches,
        "matching_clause_count": total,
        "clause_examples_truncated": total > len(matches),
        "identity_policy_statements_inspected": min(len(statements), _MAX_POLICY_STATEMENTS),
    }


def _collect(scan_id: str, environment_id: str, mapping_id: str) -> None:
    """Verified signed contract + admin-approved mapping + read-only AWS role."""
    from app.services.cloud_iam_mapping import verify_approved_mapping, MappingError
    from app.services.cloud_iam_workloads import resolve_workload, IdentityResolutionError
    try:
        with SessionLocal.begin() as db:
            scan=db.get(CloudScan,scan_id)
            if scan is None or scan.status!="QUEUED":
                return
            scan.status="RUNNING"
            scan.started_at=datetime.utcnow()
            db.add(CloudScanEvent(scan_id=scan_id,event_type="STATE",message_code="STARTED"))
        with SessionLocal() as db:
            from app.models.mcp_server import MCPServer
            env=db.get(CloudEnvironment,environment_id)
            mapping=db.get(CloudIAMMapping,mapping_id)
            if env is None or mapping is None or mapping.environment_id!=environment_id:
                raise ComparisonError("IAM_MCP_MAPPING_OR_ENVIRONMENT_MISSING")
            server=db.get(MCPServer,mapping.mcp_server_id)
            if server is None or server.status!="active":
                raise ComparisonError("IAM_MCP_SERVER_NOT_ACTIVE")
            snapshot=PublishedConfigurationProvider(db).load_active_snapshot()
            expected=verify_approved_mapping(mapping,snapshot,server.endpoint,env.account_id)
            revision_number=snapshot.revision_number
            signature_hash=snapshot.content_hash
            approved_hash=mapping.approval_digest
            server_id=server.id
            from types import SimpleNamespace
            config=SimpleNamespace(
                credential_mode=env.credential_mode,
                profile_name=env.profile_name,
                role_arn=env.role_arn,
                regions=list(env.regions),
                account_id=env.account_id,
            )
            workload=dict(mapping.configuration["identity"])
        sdk,account,_=check_connection(config)
        selected_region=workload.get("region") or config.regions[0]
        if selected_region not in config.regions:
            raise ComparisonError("IAM_MCP_REGION_NOT_IN_ENVIRONMENT")
        identity=None
        read_errors=[]
        iam_statements=[]
        policy_codes=[]
        try:
            identity=resolve_workload(sdk,account,selected_region,workload)
        except IdentityResolutionError as exc:
            read_errors.append(str(exc))
        except Exception as exc:
            read_errors.append(_safe_error(exc))
        if identity is not None:
            approved_role=workload.get("expected_role_arn")
            if approved_role and approved_role!=identity["role_arn"]:
                raise ComparisonError("IAM_WORKLOAD_ROLE_CHANGED_REAPPROVAL_REQUIRED")
            if not approved_role:
                policy_codes.append("IAM_ROLE_ARN_NOT_PINNED_BY_ADMIN")
            try:
                iam_statements,policy_codes_read,_=_policy_statements(
                    sdk.client("iam"),identity["role_name"])
                policy_codes.extend(policy_codes_read)
            except ComparisonError as exc:
                read_errors.append(str(exc))
            except Exception as exc:
                read_errors.append(_safe_error(exc))
        policy_hash=digest(iam_statements) if identity and not read_errors else None
        from app.services.cloud_iam_policy_delta import reverse_identity_policy
        deltas=(reverse_identity_policy(iam_statements,expected)
                if identity and not read_errors else [])
        with SessionLocal.begin() as db:
            # Revalidate the exact approval and currently published signed
            # revision after network I/O, before persisting any findings.
            current_mapping=db.get(CloudIAMMapping,mapping_id)
            current_server=db.get(MCPServer,server_id)
            current_env=db.get(CloudEnvironment,environment_id)
            if not current_mapping or not current_server or not current_env:
                raise ComparisonError("IAM_MCP_SCAN_BINDING_CHANGED")
            fresh=PublishedConfigurationProvider(db).load_active_snapshot()
            verify_approved_mapping(current_mapping,fresh,current_server.endpoint,
                                    current_env.account_id)
            if (current_mapping.approval_digest!=approved_hash or
                    fresh.content_hash!=signature_hash or
                    fresh.revision_number!=revision_number):
                raise ComparisonError("IAM_MCP_APPROVAL_CHANGED_DURING_SCAN")
            scan=db.get(CloudScan,scan_id)
            if scan is None or scan.status!="RUNNING":
                return
            unknown=0
            issues=0
            role_arn=identity["role_arn"] if identity else None
            res=CloudResource(
                id=new_id(),scan_id=scan.id,environment_id=environment_id,
                resource_type="MCP_CLOUD_WORKLOAD",
                resource_arn=(identity["resource"] if identity else
                              "aws-workload://identity-unverified/"+mapping_id),
                display_name="Configured MCP cloud workload",
                region=selected_region,
                safe_attributes={
                    "workload_type":workload["kind"],
                    "identity_verified":bool(identity),
                    "mcp_workload_association":"OPERATOR_SELECTED",
                    "role_usage_operator_declared":mapping.configuration.get("role_usage","UNKNOWN"),
                    "role_arn_admin_pinned":bool(workload.get("expected_role_arn")),
                    "identity_policy_digest":policy_hash,
                    "signed_revision":revision_number,
                    "signed_revision_hash":signature_hash,
                    "approved_mapping_id":mapping_id,
                    "approved_mapping_digest":approved_hash,
                    "identity_policy_coverage_codes":policy_codes,
                },
            )
            db.add(res)
            db.flush()
            for entry in expected:
                ready=entry["status"]=="READY"
                if not ready or read_errors or not identity:
                    status="UNKNOWN"
                    reason=(entry["reason"] if not ready
                            else "IAM_ROLE_OR_POLICY_READ_UNAVAILABLE")
                    warnings=[]
                else:
                    status,reason,warnings=compare_policy(
                        entry["action"],entry["resource"],iam_statements)
                if status=="UNKNOWN":
                    unknown+=1
                if status in ("EXPLICIT_DENY","POTENTIAL_EXCESS","POTENTIAL_MISSING"):
                    issues+=1
                    title={
                        "EXPLICIT_DENY":"IAM policy explicitly denies an approved MCP capability",
                        "POTENTIAL_EXCESS":"IAM permissions may exceed the approved MCP contract",
                        "POTENTIAL_MISSING":"IAM identity Allow may be missing for an approved MCP capability",
                    }[status]
                    db.add(CloudFinding(
                        scan_id=scan.id,resource_id=res.id,
                        rule_id="IAM_MCP_"+status,
                        severity="HIGH" if status=="EXPLICIT_DENY" else "MEDIUM",
                        result=status,
                        fingerprint=digest([scan.id,entry["tool"],
                                            entry["effect_id"],entry["action"],
                                            entry["resource"],status]),
                        title=title,
                        description=("Identity-policy observation only. Effective authorization "
                                     "depends on resource policies, conditions, session restrictions "
                                     "and organization-level controls."),
                        remediation="Review signed MCP contract and cloud identity policies before any access changes.",
                    ))
                identity_permission_status=(
                    "PRESENT_BROADER_THAN_CONTRACT" if status=="POTENTIAL_EXCESS"
                    else "NO_MATCHING_IDENTITY_ALLOW" if status=="POTENTIAL_MISSING"
                    else "EXPLICIT_IDENTITY_DENY" if status=="EXPLICIT_DENY"
                    else "PRESENT_EXACT_IDENTITY_ALLOW"
                    if reason=="IAM_EXACT_IDENTITY_ALLOW_EFFECTIVE_UNKNOWN"
                    else "UNKNOWN")
                # A role's identity allow does not establish effective access
                # because of SCPs, resource policies, session conditions etc.
                effective_permission_status=(
                    "DENIED_BY_EXPLICIT_IDENTITY_POLICY" if status=="EXPLICIT_DENY"
                    else "UNKNOWN")
                comparison_id=new_id()
                summary={
                    "comparison_id":comparison_id,
                    "identity_permission_status":identity_permission_status,
                    "effective_permission_status":effective_permission_status,
                    "tool":entry["tool"],"effect_id":entry["effect_id"],
                    "action":entry["action"],"resource":entry["resource"],
                    "status":status,"reason_code":reason,"warning_codes":warnings,
                    "role_link_verified":bool(identity),
                    "signed_revision":revision_number,
                    "signed_revision_hash":signature_hash,
                    "approved_mapping_digest":approved_hash,
                    "workload_type":workload["kind"],
                    "role_usage_operator_declared":mapping.configuration.get("role_usage","UNKNOWN"),
                    "role_arn_admin_pinned":bool(workload.get("expected_role_arn")),
                    "identity_policy_digest":policy_hash,
                    "identity_policy_match_evidence": (
                        matching_identity_policy_evidence(
                            entry["action"], entry["resource"], iam_statements,
                        )
                        if ready and identity and not read_errors else None
                    ),
                    "effective_access_limitations": [
                        "ORGANIZATION_SCP_NOT_EVALUATED",
                        "PERMISSIONS_BOUNDARY_OR_SESSION_POLICY_NOT_FULLY_EVALUATED",
                        "RESOURCE_POLICY_NOT_EVALUATED",
                        "CLOUD_RUNTIME_IDENTITY_ACCESS_NOT_SIMULATED",
                    ],
                }
                db.add(CloudIAMComparison(
                    id=comparison_id,
                    scan_id=scan.id,mcp_server_id=server_id,role_arn=role_arn,
                    status=status,tool_name=entry["tool"][:128],
                    identity_permission_status=identity_permission_status,
                    effective_permission_status=effective_permission_status,
                    expected_resource_arn=entry["resource"],
                    policy_digest=policy_hash,signed_revision=revision_number,
                    expected_actions=[entry["action"]] if entry["action"] else [],
                    observed_actions=[entry["action"]] if identity and not read_errors
                    and reason in ("IAM_EXACT_IDENTITY_ALLOW_EFFECTIVE_UNKNOWN",
                                   "IAM_ALLOW_SCOPE_BROADER_THAN_SIGNED_MCP")
                    else [],
                    notes=reason,
                ))
                # Truncate rule identifiers with a digest to distinguish multiple
                # actions for the same MCP tool without collisions.
                rule="IAM_MCP_"+re.sub(r"[^A-Z0-9_]","_",entry["tool"].upper())[:45]
                rule+="_"+digest([entry["effect_id"],entry["action"],
                                   entry["resource"]])[:12].upper()
                db.add(CloudEvidence(
                    scan_id=scan.id,resource_id=res.id,rule_id=rule,
                    outcome="UNKNOWN" if status=="UNKNOWN" else "FAIL",
                    evidence_sha256=digest(summary),safe_summary=summary,
                ))
            for delta in deltas:
                is_extra=delta.status=="OUTSIDE_MCP_MAPPING"
                if is_extra:
                    issues+=1
                    if mapping.configuration.get("role_usage")=="DEDICATED":
                        interpretation="The administrator declares a dedicated role, but exclusivity of its consumers is not independently proven."
                    elif mapping.configuration.get("role_usage")=="SHARED":
                        interpretation="The role is shared: other non-MCP consumers may legitimately need this grant."
                    else:
                        interpretation="The role's other consumers are not established."
                    db.add(CloudFinding(
                        scan_id=scan.id,resource_id=res.id,
                        rule_id="IAM_MCP_OUTSIDE_APPROVED_MAPPING",
                        severity="MEDIUM",result="OUTSIDE_MCP_MAPPING",
                        fingerprint=digest([scan.id,"REVERSE",delta.action,
                                            delta.resource,delta.reason]),
                        title="IAM identity-policy grant outside this MCP's approved mapping",
                        description=("This unconditional identity-policy Allow is not justified by the "
                                     "approved MCP mapping. It does not establish effective AWS access "
                                     "or prove the role can safely lose this grant. "+interpretation),
                        remediation="Review all consumers of the role and the signed MCP needs before changing AWS permissions.",
                    ))
                else:
                    unknown+=1
                comparison_id=new_id()
                reverse_summary={
                    "comparison_id":comparison_id,
                    "direction":"IAM_POLICY_TO_APPROVED_MCP_NEEDS",
                    "status":delta.status,"reason_code":delta.reason,
                    "action":delta.action,"resource":delta.resource,
                    "policy_statement_index":delta.statement_index,
                    "evidence_class":delta.evidence,
                    "role_usage_operator_declared":mapping.configuration.get("role_usage","UNKNOWN"),
                    "all_signed_effects_mapped":all(x["status"]=="READY" for x in expected),
                    "effective_permission_status":"UNKNOWN",
                    "role_arn_admin_pinned":bool(workload.get("expected_role_arn")),
                    "identity_policy_digest":policy_hash,
                    "approved_mapping_digest":approved_hash,
                    "signed_revision_hash":signature_hash,
                }
                db.add(CloudIAMComparison(
                    id=comparison_id,
                    scan_id=scan.id,mcp_server_id=server_id,role_arn=role_arn,
                    status=delta.status,tool_name=None,
                    identity_permission_status=(
                        "IDENTITY_ALLOW_OUTSIDE_MAPPING" if is_extra else "UNKNOWN"),
                    effective_permission_status="UNKNOWN",
                    expected_resource_arn=delta.resource,
                    policy_digest=policy_hash,signed_revision=revision_number,
                    expected_actions=[],observed_actions=[delta.action] if delta.action else [],
                    notes=delta.reason,
                ))
                db.add(CloudEvidence(
                    scan_id=scan.id,resource_id=res.id,
                    rule_id="IAM_MCP_REVERSE_"+digest(
                        [delta.status,delta.action,delta.resource,delta.reason])[:20].upper(),
                    outcome="FAIL" if is_extra else "UNKNOWN",
                    evidence_sha256=digest(reverse_summary),
                    safe_summary=reverse_summary,
                ))
            for issue in sorted(set(read_errors+policy_codes)):
                db.add(CloudScanEvent(
                    scan_id=scan.id,event_type="COVERAGE",
                    message_code=("IAM_MCP_"+issue)[:96],
                ))
            db.add(CloudEvidence(
                scan_id=scan.id,rule_id="IAM_MCP_SIGNED_REVISION",outcome="PASS",
                evidence_sha256=digest([revision_number,signature_hash]),
                safe_summary={"signed_revision":revision_number,
                              "signed_revision_hash":signature_hash,
                              "signed_source":"PUBLISHED_VERIFIED"},
            ))
            approval_summary={"mapping_id":mapping_id,
                              "approved_digest":approved_hash,
                              "signed_revision_hash":signature_hash}
            db.add(CloudEvidence(
                scan_id=scan.id,rule_id="IAM_MCP_ADMIN_APPROVAL",outcome="PASS",
                evidence_sha256=digest(approval_summary),
                safe_summary=approval_summary,
            ))
            scan.resource_count=1
            scan.finding_count=issues
            scan.unknown_checks=unknown
            # Never assert effective IAM PASS by identity-policy Allow alone.
            scan.status="PARTIAL"
            scan.completed_at=datetime.utcnow()
            db.add(CloudScanEvent(scan_id=scan.id,event_type="STATE",
                                  message_code="PARTIAL"))
    except Exception as exc:
        from app.services.cloud_iam_mapping import MappingError
        from app.services.cloud_iam_workloads import IdentityResolutionError
        reason=(str(exc) if isinstance(exc,(ComparisonError,MappingError,
                                            IdentityResolutionError))
                else _safe_error(exc))
        try:
            with SessionLocal.begin() as db:
                scan=db.get(CloudScan,scan_id)
                if scan and scan.status in ("QUEUED","RUNNING"):
                    scan.status="FAILED"
                    scan.error_code=reason[:80]
                    scan.completed_at=datetime.utcnow()
                    db.add(CloudScanEvent(scan_id=scan.id,event_type="STATE",
                                          message_code="FAILED"))
        except Exception:
            log.error("IAM comparison result persistence failure")
        log.warning("IAM comparison failed with code %s",reason)
    finally:
        _CAPACITY.release()


def enqueue_comparison(scan_id: str, environment_id: str, mapping_id: str) -> bool:
    if not _CAPACITY.acquire(blocking=False):
        return False
    try:
        _POOL.submit(_collect,scan_id,environment_id,mapping_id)
    except Exception:
        _CAPACITY.release()
        raise
    return True
