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
import fnmatch
import json
import logging
import re
from threading import BoundedSemaphore

from sqlalchemy import select

from app.db.database import SessionLocal
from app.models.cloud_security import (
    CloudEnvironment, CloudScan, CloudScanEvent, CloudIAMComparison,
    CloudEvidence, CloudFinding, CloudResource, new_id,
)
from app.services.cloud_security import check_connection, _safe_error
from app.services.published_configuration import PublishedConfigurationProvider

VERSION = "iam-mcp-signed-v1"
log = logging.getLogger(__name__)
_POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cloud-iam-mcp")
_CAPACITY = BoundedSemaphore(1)
_INSTANCE_ID = re.compile(r"^i-[0-9a-f]{8}(?:[0-9a-f]{9})?$")
_ACTIONS = {
    "read_document": "s3:GetObject",
    "upload_document": "s3:PutObject",
    "delete_document": "s3:DeleteObject",
    "list_documents": "s3:ListBucket",
}
_CAPABILITIES = {
    "read_document": "cloud.object.read",
    "upload_document": "cloud.object.write",
    "delete_document": "cloud.object.delete",
    "list_documents": "cloud.object.read",
}
_REQUIRED_READ = (
    "iam:GetInstanceProfile", "iam:GetRole", "iam:ListRolePolicies",
    "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
    "iam:GetPolicy", "iam:GetPolicyVersion",
)
_MAX_POLICY_DOCS = 25
_MAX_POLICY_STATEMENTS = 300


class ComparisonError(ValueError):
    pass


def digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("utf-8")).hexdigest()


def _server_ref(endpoint: str) -> str:
    return "streamable_http:" + endpoint


def _signed_expectations(snapshot, endpoint: str) -> tuple[list[dict], str]:
    """Read actual signed contracts and narrow scopes, never construct demo contracts."""
    content = snapshot.content
    server_ref = _server_ref(endpoint)
    contracts = [c for c in content.tool_security_contracts if c.server_ref == server_ref]
    if not contracts:
        raise ComparisonError("IAM_MCP_SIGNED_SERVER_CONTRACT_NOT_FOUND")
    scopes = [s for s in content.authority_resource_scopes if s.authority == server_ref]
    expectations = []
    for contract in contracts:
        if contract.tool_name not in _ACTIONS or len(contract.effects) != 1:
            # An unrecognized tool cannot be mapped to AWS by guessing.
            expectations.append({"tool": contract.tool_name, "action": None,
                                 "resource": None, "status": "UNKNOWN",
                                 "reason": "UNSUPPORTED_MCP_TOOL"})
            continue
        effect = contract.effects[0]
        tool = contract.tool_name
        expected_path = ["key"] if tool == "read_document" else ["filename"]
        precision = getattr(effect.declared_reference_precision, "value",
                            effect.declared_reference_precision)
        bindings = list(effect.resource_bindings)
        if tool == "list_documents":
            shape_verified = (not bindings and effect.fixed_resource is not None
                              and effect.fixed_resource.resource_type == "cloud_object")
        else:
            shape_verified = (effect.fixed_resource is None and len(bindings) == 1
                              and list(bindings[0].path) == expected_path
                              and bindings[0].resource_type == "cloud_object"
                              and bindings[0].role == "RESOURCE")
        if precision != "EXPLICIT" or not shape_verified:
            expectations.append({"tool":tool, "action":None,
                                 "resource":None,"status":"UNKNOWN",
                                 "reason":"MCP_EFFECT_SHAPE_UNVERIFIED"})
            continue
        if effect.capability != _CAPABILITIES[tool]:
            expectations.append({"tool": tool, "action": None, "resource": None,
                                 "status": "UNKNOWN", "reason": "MCP_CAPABILITY_MISMATCH"})
            continue
        if tool == "list_documents":
            fixed = effect.fixed_resource
            matches = ([s for s in scopes if fixed is not None and
                        s.canonical_value == fixed.canonical_value and
                        s.match_mode == "SELF"])
        else:
            # Each signed effect has its own signed scope-id in this release.
            # If the mapping cannot be proven, we return UNKNOWN.
            token = effect.effect_id.split(".", 1)[0]
            if not token.startswith("tool-"):
                matches = []
            else:
                part = token[5:]
                matches = [scope for scope in scopes
                           if scope.match_mode == "SELF"
                           and scope.scope_id.startswith("cloud-storage-" + part + "-")]
        if len(matches) != 1:
            expectations.append({"tool": tool, "action": _ACTIONS[tool],
                                 "resource": None, "status": "UNKNOWN",
                                 "reason": "MCP_SCOPE_UNVERIFIED"})
            continue
        raw = matches[0].canonical_value
        # The fixed S3 bucket name is independently part of the signed list tool.
        list_contract = next((c for c in contracts if c.tool_name == "list_documents"), None)
        bucket = (list_contract.effects[0].fixed_resource.canonical_value
                  if list_contract and list_contract.effects and
                  list_contract.effects[0].fixed_resource else None)
        if not bucket or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{2,62}", bucket):
            expectations.append({"tool": tool, "action": _ACTIONS[tool],
                                 "resource": None, "status": "UNKNOWN",
                                 "reason": "MCP_BUCKET_UNVERIFIED"})
            continue
        if tool == "list_documents":
            resource = "arn:aws:s3:::" + bucket
        else:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,180}", raw) or ".." in raw:
                expectations.append({"tool": tool, "action": _ACTIONS[tool],
                                     "resource": None, "status": "UNKNOWN",
                                     "reason": "MCP_OBJECT_SCOPE_INVALID"})
                continue
            # The real MCP server enforces demo/ for write/delete filenames.
            key = "demo/" + raw if tool in ("upload_document", "delete_document") else raw
            resource = "arn:aws:s3:::" + bucket + "/" + key
        expectations.append({"tool": tool, "action": _ACTIONS[tool],
                             "resource": resource, "status": "READY",
                             "reason": "SIGNED_EXACT_SCOPE"})
    return expectations, snapshot.content_hash


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


def _matches(policy_pattern, value: str) -> bool:
    patterns = policy_pattern if isinstance(policy_pattern, list) else [policy_pattern]
    return any(isinstance(p, str) and fnmatch.fnmatchcase(value.lower(), p.lower())
               for p in patterns)


def compare_policy(action: str, resource: str, statements: list[dict],
                   *, restrictions_unknown: bool = True) -> tuple[str, str, list[str]]:
    """Detect clear unconditioned explicit Deny or broad Allow; never infer effective PASS."""
    broad: list[str] = []
    complex_seen = False
    for item in statements:
        if not isinstance(item, dict) or item.get("Condition") or "NotAction" in item or "NotResource" in item:
            complex_seen = True
            continue
        if not _matches(item.get("Action", []), action):
            continue
        if not _matches(item.get("Resource", []), resource):
            continue
        if item.get("Effect") == "Deny":
            return "EXPLICIT_DENY", "IAM_IDENTITY_EXPLICIT_DENY", []
        if item.get("Effect") == "Allow":
            patterns = item.get("Resource", [])
            patterns = patterns if isinstance(patterns, list) else [patterns]
            if any(isinstance(pattern, str) and ("*" in pattern or "?" in pattern)
                   for pattern in patterns):
                broad.append("IAM_BROAD_RESOURCE_ALLOW")
            if _matches(item.get("Action"), "s3:*") or item.get("Action") == "*":
                broad.append("IAM_BROAD_ACTION_ALLOW")
    if broad:
        return "POTENTIAL_EXCESS", "IAM_ALLOW_SCOPE_BROADER_THAN_SIGNED_MCP", sorted(set(broad))
    return "UNKNOWN", ("IAM_CONDITIONAL_OR_POLICY_CONTEXT_UNKNOWN" if complex_seen or restrictions_unknown
                       else "IAM_NOT_PROVEN"), []


def _collect(scan_id: str, environment_id: str, mcp_server_id: int, instance_id: str) -> None:
    """Worker keeps AWS calls outside DB transactions and stores only normalized observations."""
    try:
        with SessionLocal.begin() as db:
            scan = db.get(CloudScan, scan_id)
            if scan is None or scan.status != "QUEUED":
                return
            scan.status = "RUNNING"
            scan.started_at = datetime.utcnow()
            db.add(CloudScanEvent(scan_id=scan_id, event_type="STATE", message_code="STARTED"))
        with SessionLocal() as db:
            from app.models.mcp_server import MCPServer
            env = db.get(CloudEnvironment, environment_id)
            server = db.get(MCPServer, mcp_server_id)
            if env is None or server is None:
                raise ComparisonError("IAM_MCP_LINK_MISSING")
            snapshot = PublishedConfigurationProvider(db).load_active_snapshot()
            expected, signature_hash = _signed_expectations(snapshot, server.endpoint)
            revision_number = snapshot.revision_number
            from types import SimpleNamespace
            config = SimpleNamespace(credential_mode=env.credential_mode,
                 profile_name=env.profile_name, role_arn=env.role_arn,
                 regions=list(env.regions), account_id=env.account_id)
        sdk, account, _ = check_connection(config)
        profile = None
        role_arn = None
        iam_statements: list[dict] = []
        read_errors = []
        instance = sdk.client("ec2", region_name=config.regions[0]).describe_instances(
            InstanceIds=[instance_id])
        found = [x for res in instance.get("Reservations", [])
                 for x in res.get("Instances", []) if x.get("InstanceId") == instance_id]
        if len(found) != 1:
            raise ComparisonError("IAM_MCP_EC2_INSTANCE_UNVERIFIED")
        profile_link = found[0].get("IamInstanceProfile") or {}
        profile_arn = profile_link.get("Arn")
        if isinstance(profile_arn, str) and ":instance-profile/" in profile_arn:
            profile = profile_arn.split(":instance-profile/", 1)[-1].rsplit("/",1)[-1]
        if not profile:
            read_errors.append("IAM_MCP_INSTANCE_PROFILE_MISSING")
        else:
            iam = sdk.client("iam")
            try:
                role_arn = _iam_profile_role(iam, profile)
                if not role_arn.startswith(f"arn:aws:iam::{account}:role/"):
                    raise ComparisonError("IAM_MCP_ROLE_ACCOUNT_MISMATCH")
                role_name = role_arn.rsplit("/",1)[-1]
                iam_statements, policy_codes, _ = _policy_statements(iam, role_name)
                read_errors.extend(policy_codes)
            except ComparisonError as exc:
                read_errors.append(str(exc))
            except Exception as exc:
                read_errors.append(_safe_error(exc))
        policy_hash = digest(iam_statements) if iam_statements and not read_errors else None
        with SessionLocal.begin() as db:
            scan = db.get(CloudScan, scan_id)
            if scan is None or scan.status != "RUNNING":
                return
            unknown = 0
            issues = 0
            res = CloudResource(id=new_id(),scan_id=scan.id,environment_id=environment_id,
                  resource_type="MCP_EC2_SERVER",resource_arn=f"ec2-instance://{instance_id}",
                  display_name="MCP server EC2 instance",region=config.regions[0],
                  safe_attributes={"instance_id": instance_id,
                    "role_link_verified":role_arn is not None,
                    "mcp_host_association":"OPERATOR_SELECTED",
                    "signed_revision":revision_number,
                    "signed_revision_hash":signature_hash})
            db.add(res)
            db.flush()
            for entry in expected:
                ready = entry["status"] == "READY"
                if not ready or read_errors or not role_arn or not iam_statements:
                    status, reason, warnings = ("UNKNOWN", (
                        entry["reason"] if not ready else
                        "IAM_ROLE_OR_POLICY_READ_UNAVAILABLE"), [])
                else:
                    status, reason, warnings = compare_policy(
                        entry["action"], entry["resource"], iam_statements)
                if status == "UNKNOWN":
                    unknown += 1
                if status in ("EXPLICIT_DENY", "POTENTIAL_EXCESS"):
                    issues += 1
                    db.add(CloudFinding(scan_id=scan.id,resource_id=res.id,
                         rule_id="IAM_MCP_"+status, severity="HIGH" if status=="EXPLICIT_DENY" else "MEDIUM",
                         result=status,
                         fingerprint=digest([scan.id,entry["tool"],status]),
                         title=("AWS explicit denial of signed MCP capability" if status=="EXPLICIT_DENY"
                                else "Potential AWS permission broader than MCP contract"),
                         description="The IAM identity policy may not match the approved MCP tool scope.",
                         remediation="Review the IAM role, resource policies and effective authorization before changing any rights."))
                summary = {"tool":entry["tool"], "action":entry["action"],
                           "resource":entry["resource"], "status":status,
                           "reason_code":reason, "warning_codes":warnings,
                           "role_link_verified":role_arn is not None,
                           "signed_revision":revision_number,
                           "signed_revision_hash":signature_hash}
                db.add(CloudIAMComparison(scan_id=scan.id,mcp_server_id=mcp_server_id,
                    role_arn=role_arn,status=status,
                    tool_name=entry["tool"][:128],
                    expected_resource_arn=entry["resource"],
                    policy_digest=policy_hash,
                    signed_revision=revision_number,
                    expected_actions=[entry["action"]] if entry["action"] else [],
                    observed_actions=sorted({
                        item for statement in iam_statements
                        if statement.get("Effect") == "Allow"
                        for item in (statement.get("Action")
                                    if isinstance(statement.get("Action"), list)
                                    else [statement.get("Action")])
                        if isinstance(item, str) and
                        re.fullmatch(r"(?:s3|kms|sts):[A-Za-z*?]{1,60}", item)
                    })[:20] if role_arn and not read_errors else [],
                    notes=reason))
                db.add(CloudEvidence(scan_id=scan.id,resource_id=res.id,
                       rule_id="IAM_MCP_"+entry["tool"].upper(),
                       outcome="UNKNOWN" if status=="UNKNOWN" else "FAIL",
                       evidence_sha256=digest(summary),safe_summary=summary))
            for issue in sorted(set(read_errors)):
                db.add(CloudScanEvent(scan_id=scan.id,event_type="COVERAGE",
                    message_code=("IAM_MCP_"+issue)[:96]))
            db.add(CloudEvidence(scan_id=scan.id,rule_id="IAM_MCP_SIGNED_REVISION",
                 outcome="PASS",evidence_sha256=digest([revision_number,signature_hash]),
                 safe_summary={"signed_revision":revision_number,
                               "signed_revision_hash":signature_hash,
                               "signed_source":"PUBLISHED_VERIFIED"}))
            scan.resource_count = 1
            scan.finding_count = issues
            scan.unknown_checks = unknown
            # Never claim comprehensive effective IAM compliance based on identity policies.
            scan.status = "PARTIAL"
            scan.completed_at = datetime.utcnow()
            db.add(CloudScanEvent(scan_id=scan.id,event_type="STATE",message_code="PARTIAL"))
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ComparisonError) else _safe_error(exc)
        try:
            with SessionLocal.begin() as db:
                scan = db.get(CloudScan, scan_id)
                if scan and scan.status in ("QUEUED","RUNNING"):
                    scan.status = "FAILED"
                    scan.error_code = reason[:80]
                    scan.completed_at = datetime.utcnow()
                    db.add(CloudScanEvent(scan_id=scan.id,event_type="STATE",message_code="FAILED"))
        except Exception:
            log.error("IAM comparison failure persistence issue")
        log.warning("IAM comparison failed with code %s", reason)
    finally:
        _CAPACITY.release()


def enqueue_comparison(scan_id: str, environment_id: str, mcp_server_id: int, instance_id: str) -> bool:
    if not _CAPACITY.acquire(blocking=False):
        return False
    try:
        _POOL.submit(_collect, scan_id, environment_id, mcp_server_id, instance_id)
    except Exception:
        _CAPACITY.release()
        raise
    return True
