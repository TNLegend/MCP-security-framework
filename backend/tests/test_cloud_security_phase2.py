from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from app.schemas.cloud_security import EnvironmentCreate
from app.models.cloud_security import (
    CloudEnvironment, CloudScan, CloudResource, CloudFinding, CloudEvidence, CloudScanEvent
)
from app.services.cloud_security import Collector, CloudAuditError, _safe_error, check_connection

class FakeEC2:
    def describe_instances(self, **kwargs):
        assert kwargs["MaxResults"] <= 100
        return {"Reservations":[{"Instances":[{"InstanceId":"i-lab","State":{"Name":"running"},"InstanceType":"t3.micro"}]}]}
    def describe_security_groups(self, **kwargs):
        assert kwargs["MaxResults"] <= 100
        return {"SecurityGroups":[
          {"GroupId":"sg-safe","VpcId":"vpc-lab","IpPermissions":[]},
          {"GroupId":"sg-open","VpcId":"vpc-lab","IpPermissions":[{
              "IpProtocol":"tcp","FromPort":22,"ToPort":22,
              "IpRanges":[{"CidrIp":"0.0.0.0/0"}],"Ipv6Ranges":[]}]},
        ]}

class FakeS3:
    def list_buckets(self):
        return {"Buckets":[{"Name":"lab-private"}]}
    def get_public_access_block(self,**kwargs):
        return {"PublicAccessBlockConfiguration":{
          "BlockPublicAcls":True,"IgnorePublicAcls":True,
          "BlockPublicPolicy":True,"RestrictPublicBuckets":True}}

class FakeIAM:
    def list_roles(self,**kwargs):
        return {"IsTruncated":False,"Roles":[{"Arn":"arn:aws:iam::123456789012:role/audit","RoleName":"audit"}]}

class FakeSDK:
    def client(self,service,**kwargs):
        return {"ec2":FakeEC2(),"s3":FakeS3(),"iam":FakeIAM()}[service]

def env():
    return SimpleNamespace(id="e"*36,regions=["eu-west-3"],services=["EC2","S3","IAM"])

def scan():
    return SimpleNamespace(id="s"*36)

def test_create_schema_idempotent_in_sqlite():
    engine=create_engine("sqlite+pysqlite:///:memory:")
    tables=[CloudEnvironment.__table__,CloudScan.__table__,CloudResource.__table__,
            CloudFinding.__table__,CloudEvidence.__table__,CloudScanEvent.__table__]
    for _ in (1,2):
        from app.db.database import Base
        Base.metadata.create_all(engine,tables=tables,checkfirst=True)
    assert len([x for x in inspect(engine).get_table_names() if x.startswith("cloud_")])==6
    engine.dispose()

@pytest.mark.parametrize("kwargs",[
    {"regions":["http://evil.invalid"]},
    {"regions":["eu-west-3","eu-west-3"]},
    {"credential_mode":"NAMED_PROFILE","profile_name":"../../aws"},
    {"credential_mode":"NAMED_PROFILE","profile_name":None},
    {"credential_mode":"SDK_DEFAULT","profile_name":"private"},
    {"role_arn":"arn:aws:iam::123456789012:root"},
])
def test_cloud_inputs_reject_unsafe(kwargs):
    data={"name":"Lab","regions":["eu-west-3"]}
    data.update(kwargs)
    with pytest.raises(ValidationError):
        EnvironmentCreate.model_validate(data)

def test_cloud_inputs_accept_profile_and_assume_role():
    env=EnvironmentCreate.model_validate({
        "name":"Demo account","regions":["eu-west-3"],
        "credential_mode":"NAMED_PROFILE","profile_name":"temporary-audit",
        "role_arn":"arn:aws:iam::123456789012:role/CloudAuditRole"})
    assert env.profile_name=="temporary-audit"

def test_baseline_has_verified_finding_and_safe_evidence():
    c=Collector(env(),scan())
    c.collect(FakeSDK(),"123456789012")
    assert len(c.resources)==5
    assert c.partial is False
    assert c.unknown==0
    assert len(c.findings)==1
    assert c.findings[0].rule_id=="AWS_SG_SSH_PUBLIC"
    assert c.findings[0].severity=="HIGH"
    assert all(len(e.evidence_sha256)==64 for e in c.evidence)
    assert all(e.resource_id is not None for e in c.evidence)
    assert c.findings[0].resource_id in [r.id for r in c.resources]

def test_missing_s3_permissions_are_unknown_not_success():
    from botocore.exceptions import ClientError
    class BadS3(FakeS3):
        def get_public_access_block(self,**kwargs):
            raise ClientError({"Error":{"Code":"AccessDenied","Message":"sensitive account detail"}},"GetPublicAccessBlock")
    class DeniedSDK(FakeSDK):
        def client(self,service,**kwargs):
            return BadS3() if service=="s3" else super().client(service,**kwargs)
    c=Collector(env(),scan())
    c.collect(DeniedSDK(),"123456789012")
    assert c.partial and c.unknown>=1
    assert any(e.outcome=="UNKNOWN" and e.safe_summary=={"reason":"AWS_ACCESS_DENIED"} for e in c.evidence)
    assert not any(f.rule_id=="AWS_S3_BLOCK_PUBLIC_ACCESS" for f in c.findings)

def test_failed_iam_is_not_pass():
    from botocore.exceptions import ClientError
    class DeniedIAM(FakeIAM):
        def list_roles(self,**kwargs):
            raise ClientError({"Error":{"Code":"AccessDenied","Message":"secret"}},"ListRoles")
    class DeniedSDK(FakeSDK):
        def client(self,service,**kwargs):
            return DeniedIAM() if service=="iam" else super().client(service,**kwargs)
    c=Collector(env(),scan())
    c.collect(DeniedSDK(),"123456789012")
    assert c.partial and c.unknown>=1
    assert any(e.message_code=="IAM_AWS_ACCESS_DENIED" for e in c.events)

def test_root_identity_is_never_a_valid_audit_identity(monkeypatch):
    class StubSTS:
        def get_caller_identity(self):
            return {"Arn":"arn:aws:iam::123456789012:root","Account":"123456789012"}
    class StubSession:
        def client(self,*args,**kwargs):
            return StubSTS()
    import app.services.cloud_security as module
    monkeypatch.setattr(module,"_sdk_session",lambda _:StubSession())
    e=SimpleNamespace(account_id=None)
    with pytest.raises(CloudAuditError,match="ROOT_AWS_IDENTITY_FORBIDDEN"):
        check_connection(e)

def test_account_switch_is_rejected(monkeypatch):
    class StubSTS:
        def get_caller_identity(self):
            return {"Arn":"arn:aws:sts::123456789012:assumed-role/AuditRole/session","Account":"123456789012"}
    class StubSession:
        def client(self,*args,**kwargs):return StubSTS()
    import app.services.cloud_security as module
    monkeypatch.setattr(module,"_sdk_session",lambda _:StubSession())
    with pytest.raises(CloudAuditError,match="AWS_ACCOUNT_CHANGED"):
        check_connection(SimpleNamespace(account_id="999999999999"))

def test_root_source_cannot_assume_audit_role(monkeypatch):
    import app.services.cloud_security as module
    called=[]
    class StubSTS:
        def get_caller_identity(self):
            return {"Arn":"arn:aws:iam::123456789012:root","Account":"123456789012"}
        def assume_role(self,**kwargs):
            called.append(kwargs)
            raise AssertionError("root must never assume a role via Cloud Security")
    class StubSession:
        def client(self,service,**kwargs):
            assert service=="sts"
            return StubSTS()
    monkeypatch.setattr(module.boto3,"Session",lambda **kwargs:StubSession())
    e=SimpleNamespace(credential_mode="NAMED_PROFILE",profile_name="root-login",
                      regions=["eu-west-3"],
                      role_arn="arn:aws:iam::123456789012:role/CloudAudit")
    with pytest.raises(CloudAuditError,match="ROOT_AWS_IDENTITY_FORBIDDEN"):
        module._sdk_session(e)
    assert called==[]

def test_only_selected_aws_services_are_collected():
    e=SimpleNamespace(id="e"*36,regions=["eu-west-3"],services=["S3"])
    c=Collector(e,scan())
    class S3OnlySDK:
        def client(self,service,**kwargs):
            assert service=="s3", "Unselected services must not be accessed"
            return FakeS3()
    c.collect(S3OnlySDK(),"123456789012")
    assert [r.resource_type for r in c.resources]==["S3_BUCKET"]
    assert c.partial is False
