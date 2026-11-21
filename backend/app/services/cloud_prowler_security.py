"""Bounded Prowler AWS audit (read-only, version-pinned, OCSF normalized).

Never puts AWS secret keys or raw scanner output into PostgreSQL. The complete
OCSF JSON is transient and removed at the end of every job.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import lru_cache
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from threading import BoundedSemaphore

from app.core.runtime_paths import PROWLER_EXE, PROWLER_PYTHON, PROWLER_VERSION, RUNTIME_TMP_DIR
from app.db.database import SessionLocal
from app.models.cloud_security import (
    CloudEnvironment, CloudEvidence, CloudFinding, CloudResource, CloudScan, CloudScanEvent, new_id,
)
from app.services.cloud_security import CloudAuditError, _safe_error, check_connection
from scanners.trivy.scanner import _terminate_process_tree

log = logging.getLogger(__name__)
VERSION = "aws-prowler-ocsf-v1"
PROWLER_SCAN_VERSION = VERSION
SERVICES = ("ec2", "s3", "iam", "cloudtrail", "cloudwatch")
ROOT = RUNTIME_TMP_DIR / "cloud-prowler"
MAX_BYTES = 8 * 1024 * 1024
MAX_RESULTS = 250
MAX_RESOURCES = 200
MAX_FINDINGS = 200
TIMEOUT = 180
_POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cloud-prowler")
_CAPACITY = BoundedSemaphore(1)
_RULE_RE = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}
# CL-05: actionable resource identity. Only a well-formed ARN of the SCANNED
# account (or an account-less ARN such as S3) is kept; anything else is
# withheld with an explicit status. No free text from Prowler is stored.
_ARN_RE = re.compile(
    r"^arn:(aws|aws-cn|aws-us-gov):([a-z0-9-]{2,32}):([a-z0-9-]*):(\d{12}|aws)?:"
    r"([A-Za-z0-9+=,.@_/:*-]{1,400})$"
)
_AWS_TYPE_RE = re.compile(r"^Aws[A-Za-z0-9]{2,60}$")
MAX_ARN_LENGTH = 512


def resource_identity(item: dict, account: str, allowed_regions: list[str]) -> dict:
    """Validated, display-safe identity of an OCSF resource (CL-05).

    The OCSF `name` is deliberately ignored: it can carry a tag value or other
    user content, which this adapter never persists."""
    identifier = item.get("uid")
    identity: dict = {"aws_arn": None, "identifier_status": "NON_ARN_IDENTIFIER",
                      "aws_resource_type": None}
    if isinstance(identifier, str) and len(identifier) <= MAX_ARN_LENGTH:
        match = _ARN_RE.fullmatch(identifier)
        if match:
            arn_region, arn_account = match.group(3), match.group(4)
            if arn_account not in (None, "", "aws") and arn_account != account:
                identity["identifier_status"] = "ARN_OUTSIDE_SCANNED_ACCOUNT_WITHHELD"
            elif arn_region and arn_region not in allowed_regions:
                identity["identifier_status"] = "ARN_OUTSIDE_SCANNED_REGIONS_WITHHELD"
            else:
                identity["aws_arn"] = identifier
                identity["identifier_status"] = "ARN_VERIFIED_SCANNED_ACCOUNT"
    elif isinstance(identifier, str):
        identity["identifier_status"] = "IDENTIFIER_TOO_LONG_WITHHELD"
    kind = item.get("type")
    if isinstance(kind, str) and _AWS_TYPE_RE.fullmatch(kind):
        identity["aws_resource_type"] = kind
    return identity


def resource_display_name(identity: dict, resource_hash: str) -> str:
    arn = identity.get("aws_arn")
    if arn:
        tail = re.split(r"[/:]", arn)[-1]
        return (tail or arn)[:255]
    return "AWS resource " + resource_hash[:12]


def _humanized_rule(rule: str) -> str:
    return rule.replace("_", " ")


# Trusted, scanner-independent guidance; never persist untrusted Prowler
# descriptions, tags, response bodies or policy documents.
_RULE_GUIDANCE = {
    "ec2_instance_detailed_monitoring_enabled": (
        "EC2 detailed monitoring is not enabled",
        "Review whether detailed CloudWatch monitoring should be enabled.",
    ),
    "ec2_instance_internet_facing_with_instance_profile": (
        "Internet-facing EC2 instance has an IAM instance profile",
        "Review public exposure and least-privilege permissions of the attached IAM role.",
    ),
    "ec2_instance_managed_by_ssm": (
        "EC2 instance is not managed by Systems Manager",
        "Verify the Systems Manager agent, network access and necessary SSM permissions.",
    ),
    "ec2_instance_public_ip": (
        "EC2 instance has a public IP address",
        "Verify whether a public address is necessary; prefer private connectivity if possible.",
    ),
    "iam_role_cross_service_confused_deputy_prevention": (
        "Review IAM role cross-service confused deputy protection",
        "Review use of aws:SourceArn and aws:SourceAccount trust-policy conditions where applicable.",
    ),
}


class ProwlerAuditError(ValueError):
    pass


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


def engine_version() -> str | None:
    if not PROWLER_EXE.is_file() or not PROWLER_PYTHON.is_file():
        return None
    try:
        return _probe_engine_version(PROWLER_EXE.stat().st_mtime_ns)
    except OSError:
        return None


@lru_cache(maxsize=4)
def _probe_engine_version(_binary_revision: int) -> str | None:
    # Prowler CLI startup is expensive on Windows. Cache a successful/failed
    # probe only for the exact installed executable revision.
    try:
        child = subprocess.run(
            [str(PROWLER_PYTHON), "-c",
             "import importlib.metadata;print(importlib.metadata.version('prowler'))"],
            cwd=PROWLER_PYTHON.parent, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=20, check=False,
        )
        if child.returncode == 0 and child.stdout.decode(
            "utf-8", "replace"
        ).strip() == PROWLER_VERSION:
            cli = subprocess.run(
                [str(PROWLER_EXE), "--version"], cwd=PROWLER_EXE.parent,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=30, check=False,
            )
            if cli.returncode == 0 and PROWLER_VERSION in cli.stdout.decode("utf-8", "replace"):
                return PROWLER_VERSION
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def availability() -> dict:
    version = engine_version()
    return {"scanner": "prowler", "available": version is not None,
            "version": version, "expected_version": PROWLER_VERSION,
            "services": list(SERVICES), "mode": "READ_ONLY"}


# The only actions the GUI may recommend are those we execute in the
# read-only capability check. Never translate arbitrary API/user input to IAM.
_READ_ONLY_PROBE_ACTIONS = frozenset((
    "ec2:DescribeVolumes", "ec2:DescribeSecurityGroups",
    "iam:ListUsers", "iam:ListRoles",
    "s3:ListAllMyBuckets", "cloudtrail:DescribeTrails",
    "cloudwatch:DescribeAlarms",
))
_S3_BUCKET_READ_PROBES = (
    ("s3:GetBucketLocation", "get_bucket_location"),
    ("s3:GetBucketPolicyStatus", "get_bucket_policy_status"),
    ("s3:GetEncryptionConfiguration", "get_bucket_encryption"),
    ("s3:GetBucketVersioning", "get_bucket_versioning"),
    ("s3:GetBucketLogging", "get_bucket_logging"),
)
_S3_BUCKET_READ_ACTIONS = frozenset(action for action, _ in _S3_BUCKET_READ_PROBES)


def _s3_probe_verdict(operation: str, error_code: str) -> str:
    """An absent bucket policy is a successful metadata read, NOT a PASS.

    AWS responds with NoSuchBucketPolicy when the bucket has no bucket
    policy. This confirms an authorized request without claiming the bucket
    is secure (ACLs/public-access settings require separate evaluation).
    """
    if operation == "get_bucket_policy_status" and error_code == "NoSuchBucketPolicy":
        return "ALLOWED"
    if error_code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
        return "DENIED"
    return "UNKNOWN"


def policy_proposal_for_denied_checks(checks: list[dict]) -> dict | None:
    """Generate a manually reviewed, read-only policy; never attach it.

    Bucket-scoped S3 actions are not granted for all buckets by default.
    The reviewer must replace the bucket-name placeholder with the intended
    bucket before applying the proposal in AWS IAM.
    """
    denied = {row.get("action") for row in checks if row.get("status") == "DENIED"}
    general = sorted(denied & _READ_ONLY_PROBE_ACTIONS)
    bucket_actions = sorted(denied & _S3_BUCKET_READ_ACTIONS)
    statements = []
    if general:
        statements.append({
            "Sid": "ProwlerReadOnlyObservedDeniedProbes",
            "Effect": "Allow", "Action": general, "Resource": "*",
        })
    if bucket_actions:
        statements.append({
            "Sid": "ProwlerS3ReviewedBucketReadOnly",
            "Effect": "Allow", "Action": bucket_actions,
            "Resource": "arn:aws:s3:::REPLACE_WITH_REVIEWED_BUCKET_NAME",
        })
    if not statements:
        return None
    return {"Version": "2012-10-17", "Statement": statements}


def permission_preview(env: CloudEnvironment) -> dict:
    """Read-only probes; expose only action identifiers and access verdicts.

    Successful API access is not a claim that a Prowler check passed. Failed
    probes are UNKNOWN or DENIED. No AWS response body is returned or stored.
    """
    from botocore.config import Config
    from botocore.exceptions import ClientError, BotoCoreError
    sdk, account, _ = check_connection(env)
    config = Config(connect_timeout=3, read_timeout=7, retries={"max_attempts": 1})
    checks = (
        ("EC2", "ec2:DescribeVolumes", "ec2", "describe_volumes", {"MaxResults": 5}),
        ("EC2", "ec2:DescribeSecurityGroups", "ec2", "describe_security_groups", {"MaxResults": 5}),
        ("IAM", "iam:ListUsers", "iam", "list_users", {"MaxItems": 1}),
        ("IAM", "iam:ListRoles", "iam", "list_roles", {"MaxItems": 1}),
        ("S3", "s3:ListAllMyBuckets", "s3", "list_buckets", {}),
        ("CloudTrail", "cloudtrail:DescribeTrails", "cloudtrail",
         "describe_trails", {"includeShadowTrails": False}),
        ("CloudWatch", "cloudwatch:DescribeAlarms", "cloudwatch",
         "describe_alarms", {"MaxRecords": 1}),
    )
    rows = []
    listed_buckets = None
    for service, action, client_name, operation, parameters in checks:
        try:
            client = sdk.client(client_name, region_name=env.regions[0], config=config)
            response = getattr(client, operation)(**parameters)
            status = "ALLOWED"
            if operation == "list_buckets" and isinstance(response, dict):
                listed_buckets = response.get("Buckets")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            status = "DENIED" if code in (
                "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
            ) else "UNKNOWN"
        except (BotoCoreError, OSError):
            status = "UNKNOWN"
        rows.append({"service": service, "action": action, "status": status})
    # Bound S3 inspection and never return or persist bucket names.
    if isinstance(listed_buckets, list):
        s3 = sdk.client("s3", region_name=env.regions[0], config=config)
        buckets = [b["Name"] for b in listed_buckets[:5]
                   if isinstance(b, dict) and isinstance(b.get("Name"), str)]
        complete_sample = bool(buckets) and len(listed_buckets) <= 5
        for action, operation in _S3_BUCKET_READ_PROBES:
            results = []
            for bucket_name in buckets:
                try:
                    getattr(s3, operation)(Bucket=bucket_name)
                    results.append("ALLOWED")
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    results.append(_s3_probe_verdict(operation, code))
                except (BotoCoreError, OSError):
                    results.append("UNKNOWN")
            outcome = ("DENIED" if "DENIED" in results else
                       "ALLOWED" if complete_sample and all(x == "ALLOWED" for x in results)
                       else "UNKNOWN")
            rows.append({"service": "S3", "action": action, "status": outcome})
    return {"account_id": account, "role_arn": env.role_arn,
            "permission_checks": rows,
            "read_only_policy_proposal": policy_proposal_for_denied_checks(rows),
            "policy_proposal_requires_manual_review": True,
            "complete_audit_permissions_verified": False}


def _normalize(record: object, account: str, allowed_regions: list[str]) -> dict:
    if not isinstance(record, dict) or record.get("class_uid") != 2004:
        raise ProwlerAuditError("PROWLER_OCSF_SCHEMA_INVALID")
    cloud = record.get("cloud")
    other = cloud.get("account") if isinstance(cloud, dict) else None
    if not isinstance(other, dict) or other.get("uid") != account:
        raise ProwlerAuditError("PROWLER_OCSF_ACCOUNT_MISMATCH")
    metadata = record.get("metadata")
    rule = metadata.get("event_code") if isinstance(metadata, dict) else None
    if not isinstance(rule, str) or not _RULE_RE.fullmatch(rule):
        raise ProwlerAuditError("PROWLER_OCSF_RULE_INVALID")
    status = record.get("status_code")
    if status not in ("PASS", "FAIL", "MANUAL"):
        raise ProwlerAuditError("PROWLER_OCSF_VERDICT_INVALID")
    items = record.get("resources")
    if not isinstance(items, list) or not items or not isinstance(items[0], dict):
        raise ProwlerAuditError("PROWLER_OCSF_RESOURCE_INVALID")
    identifier = items[0].get("uid")
    if not isinstance(identifier, str) or not 0 < len(identifier) <= 2048:
        raise ProwlerAuditError("PROWLER_OCSF_RESOURCE_INVALID")
    resource_hash = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
    region = items[0].get("region") or "global"
    if not isinstance(region, str) or (region != "global" and not _REGION_RE.fullmatch(region)):
        region = "global"
    if region != "global" and region not in allowed_regions:
        raise ProwlerAuditError("PROWLER_OCSF_REGION_MISMATCH")
    severity = str(record.get("severity") or "UNKNOWN").upper()
    if severity not in _SEVERITIES:
        severity = "UNKNOWN"
    return {"rule": rule, "outcome": "UNKNOWN" if status == "MANUAL" else status,
            "severity": severity, "region": region, "resource_hash": resource_hash,
            "identity": resource_identity(items[0], account, allowed_regions),
            "service": next((x for x in SERVICES if rule.startswith(x + "_")), "other")}


def parse_ocsf(raw: bytes, account: str, regions: list[str]) -> tuple[list[dict], int]:
    if not raw or len(raw) > MAX_BYTES:
        raise ProwlerAuditError("PROWLER_REPORT_SIZE_INVALID")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ProwlerAuditError("PROWLER_REPORT_INVALID_JSON") from None
    if not isinstance(doc, list) or not doc:
        raise ProwlerAuditError("PROWLER_REPORT_EMPTY_OR_INVALID")
    overflow = max(0, len(doc) - MAX_RESULTS)
    return [_normalize(row, account, regions) for row in doc[:MAX_RESULTS]], overflow


def _credentials_env(base: Path, frozen, region: str) -> dict[str, str]:
    # This subprocess must not use the operator's local AWS profile or root.
    safe = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL"}
    out = {key: value for key, value in os.environ.items() if key.upper() in safe}
    out.update({
        "HOME": str(base), "USERPROFILE": str(base),
        "TMP": str(base), "TEMP": str(base), "TMPDIR": str(base),
        "XDG_CONFIG_HOME": str(base), "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CONFIG_FILE": str(base / "empty-config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(base / "empty-credentials"),
        "AWS_ACCESS_KEY_ID": frozen.access_key,
        "AWS_SECRET_ACCESS_KEY": frozen.secret_key,
        "AWS_SESSION_TOKEN": frozen.token,
        "AWS_REGION": region, "AWS_DEFAULT_REGION": region,
        "PYTHONNOUSERSITE": "1", "DO_NOT_TRACK": "1", "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8",
    })
    return out


def _cli_execution_result(exit_code: int, has_report: bool) -> str:
    """Prowler 5.51.0 uses exit code 3 when security checks FAIL.

    An exit code of 3 with a report is still a successful execution of the
    scanner, not an incomplete audit. Finding outcomes are stored separately.
    """
    if not has_report:
        return "NO_REPORT" if exit_code == 0 else "EXECUTION_FAILED"
    if exit_code in (0, 3):
        return "COMPLETED"
    return "PARTIAL"


def _run_cli(folder: Path, regions: list[str], frozen) -> tuple[str, bytes | None]:
    report = folder / "report"
    report.mkdir(mode=0o700)
    args = [str(PROWLER_EXE), "aws", "--services", *SERVICES,
            "--filter-region", *regions, "-M", "json-ocsf",
            "-o", str(report), "-F", "cloud-advanced"]
    flags = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {
        "start_new_session": True,
    }
    outpath, errpath = folder / "stdout.log", folder / "stderr.log"
    try:
        with outpath.open("wb") as stdout, errpath.open("wb") as stderr:
            try:
                child = subprocess.Popen(
                    args, cwd=folder, env=_credentials_env(folder, frozen, regions[0]),
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                    shell=False, **flags,
                )
            except OSError:
                return "UNAVAILABLE", None
            deadline = time.monotonic() + TIMEOUT
            while child.poll() is None:
                if time.monotonic() >= deadline:
                    _terminate_process_tree(child)
                    return "TIMED_OUT", None
                files = [outpath, errpath, *report.glob("*")]
                if len(files) > 8 or any(
                    p.stat().st_size > (MAX_BYTES if p.suffix == ".json" else 2 * 1024 * 1024)
                    for p in files if p.is_file()
                ):
                    _terminate_process_tree(child)
                    return "OUTPUT_LIMIT", None
                time.sleep(0.1)
            code = child.wait(timeout=10)
        matches = list(report.glob("*.ocsf.json"))
        if len(matches) != 1:
            # Without an OCSF report, neither successful nor check-failure
            # CLI exit codes establish a clean security verdict.
            return _cli_execution_result(code, False), None
        if matches[0].stat().st_size > MAX_BYTES:
            return "OUTPUT_LIMIT", None
        return _cli_execution_result(code, True), matches[0].read_bytes()
    except (OSError, subprocess.TimeoutExpired):
        return "EXECUTION_FAILED", None


def _preflight_read_coverage(sdk, regions: list[str]) -> dict[str, str]:
    """Conservative read-access sampling; a successful probe is NOT a full IAM audit.

    Store only generic result codes, never SDK exception messages or AWS data.
    """
    operations = {
        "ec2": ("ec2", "describe_volumes", {"MaxResults": 5}),
        "s3": ("s3", "list_buckets", {}),
        "iam": ("iam", "list_users", {"MaxItems": 1}),
        "cloudtrail": ("cloudtrail", "describe_trails", {"includeShadowTrails": False}),
        "cloudwatch": ("cloudwatch", "describe_alarms", {"MaxRecords": 1}),
    }
    result: dict[str, str] = {}
    for name, (service, method, kwargs) in operations.items():
        try:
            sdk_client = sdk.client(service, region_name=regions[0])
            getattr(sdk_client, method)(**kwargs)
        except Exception as exc:
            result[name] = _safe_error(exc)
        else:
            result[name] = "READ_PROBE_OK"
    return result


def _store(db, scan: CloudScan, rows: list[dict], overflow: int, result: str,
           coverage: dict[str, str] | None = None,
           identity_binding: dict[str, object] | None = None) -> None:
    if identity_binding is not None:
        binding = {
            "scanner": "prowler",
            "account_sha256": _sha(identity_binding["account_id"]),
            "audit_role_sha256": _sha(identity_binding["role_arn"]),
            "regions_sha256": _sha(sorted(identity_binding["regions"])),
        }
        db.add(CloudEvidence(
            scan_id=scan.id, rule_id="PROWLER_IDENTITY_BOUND",
            outcome="PASS", evidence_sha256=_sha(binding), safe_summary=binding,
        ))
    indexed: dict[str, CloudResource] = {}
    findings: set[str] = set()
    services: set[str] = set()
    unknown = overflow + int(result != "COMPLETED")
    if coverage:
        for service in SERVICES:
            code = coverage.get(service, "PROWLER_READ_PROBE_MISSING")
            if code != "READ_PROBE_OK":
                unknown += 1
                db.add(CloudScanEvent(
                    scan_id=scan.id, event_type="COVERAGE",
                    message_code=f"PROWLER_{service.upper()}_READ_UNKNOWN"[:96],
                ))
                obs = {"scanner": "prowler", "service": service,
                       "coverage": "UNKNOWN", "reason_code": code[:80]}
                db.add(CloudEvidence(
                    scan_id=scan.id,
                    rule_id=f"PROWLER_READ_{service.upper()}",
                    outcome="UNKNOWN",
                    evidence_sha256=_sha(obs),
                    safe_summary=obs,
                ))
    # Persist resource parents before FK-linked CloudEvidence/CloudFinding rows.
    # SQLAlchemy bulk flush can otherwise insert evidence first when there are
    # no ORM relationship objects connecting the mapped entities.
    for row in rows:
        key = row["resource_hash"]
        if key in indexed:
            continue
        if len(indexed) >= MAX_RESOURCES:
            unknown += 1
            continue
        identity = row.get("identity") or {
            "aws_arn": None, "identifier_status": "NOT_RECORDED",
            "aws_resource_type": None}
        # resource_arn/resource_type stay the stable integrity identity that
        # deploy governance verifies; the actionable identity is alongside.
        res = CloudResource(
            id=new_id(), scan_id=scan.id, environment_id=scan.environment_id,
            resource_type="AWS_RESOURCE", resource_arn=f"prowler://{key}",
            region=row["region"], display_name=resource_display_name(identity, key),
            safe_attributes={"scanner": "prowler", "resource_sha256": key, **identity},
        )
        db.add(res)
        indexed[key] = res
    if indexed:
        db.flush()

    for row in rows:
        services.add(row["service"])
        key = row["resource_hash"]
        if key not in indexed:
            continue
        res = indexed[key]
        obs = {"scanner": "prowler", "version": PROWLER_VERSION,
               "rule": row["rule"], "status": row["outcome"],
               "severity": row["severity"], "region": row["region"],
               "service": row["service"], "resource_hash": key}
        db.add(CloudEvidence(
            scan_id=scan.id, resource_id=res.id, rule_id=row["rule"],
            outcome=row["outcome"], evidence_sha256=_sha(obs), safe_summary=obs,
        ))
        if row["outcome"] == "UNKNOWN":
            unknown += 1
        if row["outcome"] == "FAIL":
            fp = _sha({"rule": row["rule"], "resource": key})
            if fp not in findings and len(findings) < MAX_FINDINGS:
                findings.add(fp)
                title, remediation = _RULE_GUIDANCE.get(
                    row["rule"],
                    ("Prowler check failed: " + _humanized_rule(row["rule"]),
                     "Review the AWS configuration and the Prowler check " + row["rule"] + "."),
                )
                attrs = res.safe_attributes
                where = attrs.get("aws_arn") or (
                    res.display_name + " (identifier withheld: "
                    + attrs.get("identifier_status", "NOT_RECORDED") + ")")
                kind = attrs.get("aws_resource_type") or "AWS resource"
                db.add(CloudFinding(
                    scan_id=scan.id, resource_id=res.id, rule_id=row["rule"],
                    fingerprint=fp, severity=row["severity"], result="FAIL",
                    title=title,
                    description=(f"Prowler check {row['rule']} failed for {kind} {where} "
                                 f"in region {row['region']}.")[:2000],
                    remediation=remediation,
                ))
            elif len(findings) >= MAX_FINDINGS:
                unknown += 1
    for service in SERVICES:
        if service not in services:
            unknown += 1
            db.add(CloudScanEvent(scan_id=scan.id,event_type="SCANNER",
                                  message_code="PROWLER_UNASSESSED_" + service.upper()))
    db.add(CloudEvidence(
        scan_id=scan.id, rule_id="PROWLER_EXECUTION",
        outcome="PASS" if result == "COMPLETED" else "UNKNOWN",
        evidence_sha256=_sha({"scanner":"prowler","version":PROWLER_VERSION,"status":result}),
        safe_summary={"scanner":"prowler","version":PROWLER_VERSION,
                      "execution_status":result,"records":len(rows)},
    ))
    scan.resource_count = len(indexed)
    scan.finding_count = len(findings)
    scan.unknown_checks = unknown
    scan.status = "COMPLETED" if not unknown else "PARTIAL"
    scan.completed_at = datetime.utcnow()
    db.add(CloudScanEvent(scan_id=scan.id,event_type="STATE",message_code=scan.status))


def _worker(scan_id: str) -> None:
    folder = ROOT / scan_id
    try:
        with SessionLocal.begin() as db:
            scan = db.get(CloudScan, scan_id)
            if scan is None or scan.status != "QUEUED":
                return
            scan.status = "RUNNING"
            scan.started_at = datetime.utcnow()
            db.add(CloudScanEvent(scan_id=scan_id,event_type="STATE",message_code="STARTED"))
        # The database connection must not be held open while AWS/Prowler runs.
        # Snapshot only the non-secret environment configuration first.
        from types import SimpleNamespace
        with SessionLocal() as db:
            scan = db.get(CloudScan, scan_id)
            if scan is None or scan.status != "RUNNING":
                return
            env = db.get(CloudEnvironment, scan.environment_id)
            if env is None or not env.role_arn:
                raise ProwlerAuditError("PROWLER_AUDIT_ROLE_REQUIRED")
            config = SimpleNamespace(
                credential_mode=env.credential_mode,
                profile_name=env.profile_name,
                role_arn=env.role_arn,
                external_id=env.external_id,
                expected_account_id=env.expected_account_id,
                regions=list(env.regions),
                account_id=env.account_id,
            )
        sdk, account, _ = check_connection(config)
        coverage = _preflight_read_coverage(sdk, list(config.regions))
        creds = sdk.get_credentials()
        frozen = creds.get_frozen_credentials() if creds is not None else None
        if frozen is None or not frozen.token:
            raise ProwlerAuditError("PROWLER_TEMPORARY_CREDENTIALS_REQUIRED")
        if engine_version() is None:
            raise ProwlerAuditError("PROWLER_NOT_INSTALLED")
        folder.parent.mkdir(parents=True, exist_ok=True)
        folder.mkdir(mode=0o700, exist_ok=False)
        status, data = _run_cli(folder, list(config.regions), frozen)
        if status == "NO_REPORT" and data is None:
            rows, overflow = [], 0
        elif data is None:
            raise ProwlerAuditError("PROWLER_" + status)
        else:
            rows, overflow = parse_ocsf(data, account, list(config.regions))
        with SessionLocal.begin() as db:
            scan = db.get(CloudScan, scan_id)
            if scan is None or scan.status != "RUNNING":
                return
            _store(db, scan, rows, overflow, status, coverage, {
                "account_id": account, "role_arn": config.role_arn,
                "regions": config.regions,
            })
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ProwlerAuditError) else _safe_error(exc)
        if reason == "CLOUD_SCAN_INTERNAL_ERROR":
            # Structured error class is safe; exception messages can embed
            # AWS identifiers and subprocess command output, so never emit them.
            reason = "PROWLER_INTERNAL_" + type(exc).__name__.upper()[:40]
        log.warning("Prowler cloud scan failed: %s", reason)
        try:
            with SessionLocal.begin() as db:
                scan = db.get(CloudScan, scan_id)
                if scan and scan.status in ("QUEUED", "RUNNING"):
                    scan.status = "FAILED"
                    scan.error_code = reason[:80]
                    scan.completed_at = datetime.utcnow()
                    db.add(CloudScanEvent(scan_id=scan_id,event_type="STATE",message_code="FAILED"))
        except Exception:
            log.error("Prowler scan failure could not be persisted")
    finally:
        shutil.rmtree(folder, ignore_errors=True)
        _CAPACITY.release()


def enqueue_advanced(scan_id: str) -> bool:
    if not _CAPACITY.acquire(blocking=False):
        return False
    try:
        _POOL.submit(_worker, scan_id)
    except Exception:
        _CAPACITY.release()
        raise
    return True


def clean_interrupted() -> None:
    if ROOT.exists():
        for folder in ROOT.iterdir():
            if folder.is_dir():
                shutil.rmtree(folder, ignore_errors=True)
