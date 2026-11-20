"""Read-only AWS baseline inventory and bounded cloud scan executor.

AWS credentials are resolved by botocore at call time, never stored here.
Only STS/Describe/List/Get APIs are used. Failures are explicit UNKNOWNs,
not a fabricated PASS. No resource mutation or IAM change is performed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import BoundedSemaphore

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound
from sqlalchemy import select, update

from app.db.database import SessionLocal
from app.models.cloud_security import (
    CloudEnvironment, CloudEvidence, CloudFinding, CloudResource,
    CloudScan, CloudScanEvent, new_id,
)

log = logging.getLogger(__name__)
SCAN_VERSION = "boto3-baseline-v1"
MAX_RESOURCES = 250
MAX_FINDINGS = 300
MAX_EVENTS = 100
MAX_REGIONS = 3
_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cloud-security")
_CAPACITY = BoundedSemaphore(value=2)
_CONFIG = Config(connect_timeout=3, read_timeout=7, retries={"max_attempts":1},
                 user_agent_extra="mcp-framework-deploy-audit-v1")


class CloudAuditError(ValueError):
    pass


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, ProfileNotFound):
        return "AWS_PROFILE_NOT_FOUND"
    if isinstance(exc, NoCredentialsError):
        return "AWS_CREDENTIALS_UNAVAILABLE"
    if isinstance(exc, ClientError):
        code=exc.response.get("Error",{}).get("Code","")
        if code in ("AccessDenied","AccessDeniedException","UnauthorizedOperation"):
            return "AWS_ACCESS_DENIED"
        if code in ("ExpiredToken","ExpiredTokenException","RequestExpired"):
            return "AWS_SESSION_EXPIRED"
        if code in ("Throttling","ThrottlingException","RequestLimitExceeded"):
            return "AWS_RATE_LIMITED"
        if code in ("InvalidClientTokenId","UnrecognizedClientException"):
            return "AWS_INVALID_CREDENTIALS"
        return "AWS_API_ERROR"
    if isinstance(exc, (BotoCoreError, ConnectionError, TimeoutError)):
        return "AWS_CONNECTION_FAILED"
    return "CLOUD_SCAN_INTERNAL_ERROR"


def _sdk_session(env: CloudEnvironment):
    # Only client-side AWS profile reference, no key material and no custom endpoints.
    if env.credential_mode=="NAMED_PROFILE":
        base=boto3.Session(profile_name=env.profile_name,region_name=env.regions[0])
    else:
        base=boto3.Session(region_name=env.regions[0])
    if env.role_arn:
        sts=base.client("sts",config=_CONFIG)
        source=sts.get_caller_identity()
        if str(source.get("Arn","")).endswith(":root"):
            raise CloudAuditError("ROOT_AWS_IDENTITY_FORBIDDEN")
        data=sts.assume_role(RoleArn=env.role_arn,RoleSessionName="McpDeploySecurityAudit",
                             DurationSeconds=900)
        keys=data["Credentials"]
        # In-memory only for this scan. Never persist, log or return these values.
        return boto3.Session(
            aws_access_key_id=keys["AccessKeyId"],
            aws_secret_access_key=keys["SecretAccessKey"],
            aws_session_token=keys["SessionToken"],
            region_name=env.regions[0],
        )
    return base


def check_connection(env: CloudEnvironment):
    sdk=_sdk_session(env)
    identity=sdk.client("sts",config=_CONFIG).get_caller_identity()
    arn=str(identity["Arn"])
    account=str(identity["Account"])
    if not re.fullmatch(r"[0-9]{12}",account):
        raise CloudAuditError("AWS_ACCOUNT_INVALID")
    if arn.endswith(":root"):
        raise CloudAuditError("ROOT_AWS_IDENTITY_FORBIDDEN")
    if env.account_id and env.account_id != account:
        raise CloudAuditError("AWS_ACCOUNT_CHANGED")
    return sdk,account,arn.split(":")[-1].split("/")[0]


def _sha(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(",",":"),
           ensure_ascii=True).encode("utf-8")).hexdigest()


class Collector:
    def __init__(self, env: CloudEnvironment, scan: CloudScan):
        self.env=env
        self.scan=scan
        self.resources=[]
        self.findings=[]
        self.evidence=[]
        self.events=[]
        self.unknown=0
        self.partial=False
        self.deadline=time.monotonic()+120

    def budget_ok(self):
        if time.monotonic() < self.deadline:
            return True
        if not self.partial:
            self.event("SCAN_TIME_BUDGET_EXHAUSTED")
        self.partial=True
        self.unknown+=1
        return False

    def event(self, code: str):
        if len(self.events)<MAX_EVENTS:
            self.events.append(CloudScanEvent(scan_id=self.scan.id,event_type="AUDIT",
                                              message_code=code))

    def resource(self, rtype: str, arn: str, region: str, name: str, attrs: dict):
        if len(self.resources)>=MAX_RESOURCES:
            self.partial=True
            self.event("RESOURCE_LIMIT_REACHED")
            return None
        item=CloudResource(id=new_id(),scan_id=self.scan.id,environment_id=self.env.id,
                           resource_type=rtype,resource_arn=arn,region=region,
                           display_name=name[:255],safe_attributes=attrs)
        self.resources.append(item)
        return item

    def check(self, resource, rule: str, outcome: str, summary: dict,
              title: str, severity: str="MEDIUM", remediation: str | None=None):
        if outcome=="UNKNOWN":
            self.unknown+=1
            self.partial=True
        # Whitelist normalized safe facts only; no full AWS responses, secrets, policies or tags.
        record={"rule":rule,"outcome":outcome,"summary":summary,
                "resource":resource.resource_arn if resource else None}
        self.evidence.append(CloudEvidence(
            scan_id=self.scan.id,resource_id=resource.id if resource else None,
            rule_id=rule,outcome=outcome,evidence_sha256=_sha(record),
            safe_summary=summary,
        ))
        if outcome=="FAIL" and len(self.findings)<MAX_FINDINGS:
            self.findings.append(CloudFinding(
                scan_id=self.scan.id,resource_id=resource.id if resource else None,
                rule_id=rule,fingerprint=_sha({"rule":rule,"resource":record["resource"]}),
                severity=severity,result="FAIL",title=title,description=title,
                remediation=remediation,
            ))
        elif outcome=="FAIL":
            self.partial=True
            self.event("FINDING_LIMIT_REACHED")

    def collect(self, sdk, account: str):
        services = set(self.env.services)
        if "EC2" in services:
            for region in self.env.regions[:MAX_REGIONS]:
                if not self.budget_ok():return
                self._ec2(sdk,account,region)
        if "S3" in services:
            if not self.budget_ok():return
            self._s3(sdk,account)
        if "IAM" in services:
            if not self.budget_ok():return
            self._iam(sdk,account)

    def _ec2(self,sdk,account,region):
        client=sdk.client("ec2",region_name=region,config=_CONFIG)
        try:
            # Never enumerate an unlimited account: strict service-side MaxResults.
            response=client.describe_instances(MaxResults=100)
            reservations=response.get("Reservations",[])
            if response.get("NextToken"):
                self.partial=True
                self.event("EC2_INSTANCE_RESULTS_TRUNCATED")
            for reservation in reservations:
                for item in reservation.get("Instances",[]):
                    iid=str(item["InstanceId"])
                    self.resource("EC2_INSTANCE",f"arn:aws:ec2:{region}:{account}:instance/{iid}",
                                  region,iid,{"state":item.get("State",{}).get("Name"),
                                              "instance_type":item.get("InstanceType")})
            response=client.describe_security_groups(MaxResults=100)
            if response.get("NextToken"):
                self.partial=True
                self.event("SECURITY_GROUP_RESULTS_TRUNCATED")
            for group in response.get("SecurityGroups",[]):
                gid=str(group["GroupId"])
                res=self.resource("SECURITY_GROUP",f"arn:aws:ec2:{region}:{account}:security-group/{gid}",
                                  region,gid,{"vpc_id":group.get("VpcId")})
                if res is None:continue
                ingress=group.get("IpPermissions",[])
                open_any=any(
                    ("0.0.0.0/0" in [r.get("CidrIp") for r in perm.get("IpRanges",[])]
                     or "::/0" in [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges",[])])
                    and (perm.get("IpProtocol")=="-1" or (
                        int(perm.get("FromPort") if perm.get("FromPort") is not None else -1)<=22<=int(perm.get("ToPort") if perm.get("ToPort") is not None else -1)))
                    for perm in ingress
                )
                self.check(res,"AWS_SG_SSH_PUBLIC","FAIL" if open_any else "PASS",
                           {"public_ssh_access":open_any},"Security group permits SSH from the internet",
                           severity="HIGH",remediation="Restrict port 22 to trusted networks or use SSM.")
        except (ClientError,BotoCoreError) as exc:
            self.partial=True;self.unknown+=1
            self.event("EC2_"+_safe_error(exc))

    def _iam(self,sdk,account):
        client=sdk.client('iam',config=_CONFIG)
        try:
            resp=client.list_roles(MaxItems=100)
            if resp.get('IsTruncated'):
                self.partial=True
                self.event('IAM_ROLE_RESULTS_TRUNCATED')
            for role in resp.get('Roles',[]):
                self.resource('IAM_ROLE',str(role['Arn']),'global',
                              str(role['RoleName']),{'role_name':str(role['RoleName'])})
        except (ClientError,BotoCoreError) as exc:
            self.partial=True
            self.unknown+=1
            self.event('IAM_'+_safe_error(exc))

    def _s3(self,sdk,account):
        client=sdk.client("s3",region_name=self.env.regions[0],config=_CONFIG)
        try:
            resp=client.list_buckets()
            buckets=resp.get("Buckets",[])
            if len(buckets)>MAX_RESOURCES or resp.get("ContinuationToken"):
                self.partial=True
                self.event("S3_BUCKET_RESULTS_TRUNCATED")
            for bucket in buckets[:MAX_RESOURCES]:
                if not self.budget_ok():break
                name=str(bucket["Name"])
                res=self.resource("S3_BUCKET",f"arn:aws:s3:::{name}","global",name,{})
                if res is None:break
                try:
                    pb=client.get_public_access_block(Bucket=name)
                    conf=pb.get("PublicAccessBlockConfiguration",{})
                    blocked=all(conf.get(k) is True for k in (
                        "BlockPublicAcls","IgnorePublicAcls","BlockPublicPolicy","RestrictPublicBuckets"
                    ))
                    self.check(res,"AWS_S3_BLOCK_PUBLIC_ACCESS",
                               "PASS" if blocked else "FAIL",
                               {"all_public_access_blocked":blocked},
                               "S3 public-access-block settings are incomplete",
                               remediation="Enable all four S3 Block Public Access settings.")
                except ClientError as exc:
                    code=exc.response.get("Error",{}).get("Code","")
                    if code=="NoSuchPublicAccessBlockConfiguration":
                        self.check(res,"AWS_S3_BLOCK_PUBLIC_ACCESS","FAIL",
                                   {"block_configuration_present":False},
                                   "S3 bucket has no Block Public Access configuration",
                                   severity="HIGH")
                    else:
                        self.check(res,"AWS_S3_BLOCK_PUBLIC_ACCESS","UNKNOWN",
                                   {"reason":_safe_error(exc)},
                                   "S3 public access cannot be evaluated")
        except (ClientError,BotoCoreError) as exc:
            self.partial=True;self.unknown+=1
            self.event("S3_"+_safe_error(exc))


def _run_worker(scan_id: str):
    try:
        with SessionLocal.begin() as db:
            scan=db.get(CloudScan,scan_id)
            if scan is None or scan.status!="QUEUED":return
            scan.status="RUNNING"
            scan.started_at=datetime.utcnow()
            db.add(CloudScanEvent(scan_id=scan_id,event_type="STATE",message_code="STARTED"))
        with SessionLocal() as db:
            scan=db.get(CloudScan,scan_id)
            env=db.get(CloudEnvironment,scan.environment_id)
            # Credentials never leave the process memory.
            sdk,account,_=check_connection(env)
            collector=Collector(env,scan)
            collector.collect(sdk,account)
            with SessionLocal.begin() as out:
                current=out.get(CloudScan,scan_id)
                if current.status!="RUNNING":return
                out.add_all(collector.resources)
                out.flush()
                out.add_all(collector.findings+collector.evidence+collector.events)
                current.resource_count=len(collector.resources)
                current.finding_count=len(collector.findings)
                current.unknown_checks=collector.unknown
                current.status="PARTIAL" if collector.partial else "COMPLETED"
                current.completed_at=datetime.utcnow()
                out.add(CloudScanEvent(scan_id=scan_id,event_type="STATE",
                                       message_code=current.status))
    except Exception as exc:
        code=str(exc) if isinstance(exc,CloudAuditError) else _safe_error(exc)
        # Never persist AWS exception strings; they can contain account detail or tokens.
        log.warning("Cloud scan failed (code=%s)",code)
        with SessionLocal.begin() as db:
            scan=db.get(CloudScan,scan_id)
            if scan and scan.status in ("QUEUED","RUNNING"):
                scan.status="FAILED"
                scan.error_code=code[:80]
                scan.completed_at=datetime.utcnow()
                db.add(CloudScanEvent(scan_id=scan_id,event_type="STATE",
                                      message_code="FAILED"))
    finally:
        _CAPACITY.release()


def enqueue_scan(scan_id: str) -> bool:
    if not _CAPACITY.acquire(blocking=False):
        return False
    try:
        _POOL.submit(_run_worker,scan_id)
    except Exception:
        _CAPACITY.release()
        raise
    return True


def mark_interrupted_scans():
    """Fail closed on restart; never silently report an unfinished audit as completed."""
    with SessionLocal.begin() as db:
        db.execute(update(CloudScan).where(CloudScan.status.in_(("QUEUED","RUNNING")))
                   .values(status="INTERRUPTED",error_code="WORKER_RESTARTED",
                           completed_at=datetime.utcnow()))
