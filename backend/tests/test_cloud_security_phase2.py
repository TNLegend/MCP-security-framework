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

def test_assumed_role_keeps_named_profile_when_no_default_exists(monkeypatch, tmp_path):
    """AWS CLI login profiles need not define [default] for an assumed role."""
    import boto3
    import app.services.cloud_security as module

    config = tmp_path / "config"
    config.write_text("[profile cloud-audit]\\nregion = eu-west-3\\n".replace("\\n", "\n"), encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "missing-credentials"))
    monkeypatch.setenv("AWS_PROFILE", "default")

    real_session = boto3.Session
    calls = []

    class FakeSTS:
        def get_caller_identity(self):
            return {"Arn": "arn:aws:iam::123456789012:user/operator", "Account": "123456789012"}

        def assume_role(self, **kwargs):
            assert kwargs["RoleArn"] == "arn:aws:iam::123456789012:role/CloudAudit"
            return {"Credentials": {
                "AccessKeyId": "SYNTHETIC_ACCESS", "SecretAccessKey": "SYNTHETIC_SECRET",
                "SessionToken": "SYNTHETIC_SESSION",
            }}

    class FakeBase:
        def client(self, name, **kwargs):
            assert name == "sts"
            return FakeSTS()

    def make_session(**kwargs):
        calls.append(kwargs)
        if "aws_access_key_id" not in kwargs:
            assert kwargs["profile_name"] == "cloud-audit"
            return FakeBase()
        session = real_session(**kwargs)
        session.client("sts")  # No network I/O, but config resolution occurs.
        return session

    monkeypatch.setattr(module.boto3, "Session", make_session)
    environment = SimpleNamespace(
        credential_mode="NAMED_PROFILE", profile_name="cloud-audit",
        regions=["eu-west-3"], role_arn="arn:aws:iam::123456789012:role/CloudAudit",
    )
    session = module._sdk_session(environment)
    assert calls[1]["profile_name"] == "cloud-audit"
    assert session.get_credentials().access_key == "SYNTHETIC_ACCESS"


@pytest.mark.parametrize("values", [
    {"expected_account_id": "12345678901"},
    {"expected_account_id": "12345678901X"},
    {"external_id": "untrusted\\nvalue", "role_arn": "arn:aws:iam::123456789012:role/Audit"},
    {"external_id": "only-external-id"},
    {"external_id": "" , "role_arn": "arn:aws:iam::123456789012:role/Audit"},
    {"expected_account_id": "210987654321", "role_arn": "arn:aws:iam::123456789012:role/Audit"},
])
def test_cross_account_inputs_reject_invalid_identity_bindings(values):
    with pytest.raises(ValidationError):
        EnvironmentCreate.model_validate({"name": "External account", "regions": ["eu-west-3"], **values})


def test_cross_account_inputs_accept_pinned_identity_and_external_id():
    payload = EnvironmentCreate.model_validate({
        "name": "Third-party AWS environment",
        "regions": ["eu-west-3"],
        "credential_mode": "SDK_DEFAULT",
        "role_arn": "arn:aws:iam::123456789012:role/ReadOnlyAuditRole",
        "expected_account_id": "123456789012",
        "external_id": "mcp-deployment-87654321",
    })
    assert payload.expected_account_id == "123456789012"
    assert payload.external_id == "mcp-deployment-87654321"


@pytest.mark.parametrize("external_id", [None, "mcp-my-sandbox-9988"])
def test_cross_account_role_sts_receives_external_id_only_when_configured(monkeypatch, external_id):
    import app.services.cloud_security as module
    assume_arguments = []

    class FakeSTS:
        def get_caller_identity(self):
            return {
                "Arn": "arn:aws:iam::000000000001:user/operator",
                "Account": "000000000001",
            }

        def assume_role(self, **kwargs):
            assume_arguments.append(kwargs)
            return {"Credentials": {
                "AccessKeyId": "SYNTHETIC", "SecretAccessKey": "SYNTHETIC",
                "SessionToken": "SYNTHETIC",
            }}

    class FakeSession:
        def client(self, service, **kwargs):
            assert service == "sts"
            return FakeSTS()

    monkeypatch.setattr(module.boto3, "Session", lambda **kwargs: FakeSession())
    env = SimpleNamespace(
        credential_mode="SDK_DEFAULT", regions=["eu-west-3"],
        role_arn="arn:aws:iam::123456789012:role/Audit",
        external_id=external_id,
    )
    module._sdk_session(env)
    assert len(assume_arguments) == 1
    assert ("ExternalId" in assume_arguments[0]) == (external_id is not None)
    if external_id:
        assert assume_arguments[0]["ExternalId"] == external_id


def test_cross_account_expected_id_is_checked_on_first_connection(monkeypatch):
    import app.services.cloud_security as module

    class FakeSTS:
        def get_caller_identity(self):
            return {
                "Arn": "arn:aws:sts::123456789012:assumed-role/Audit/session",
                "Account": "123456789012",
            }

    class FakeSDK:
        def client(self, service, **kwargs):
            assert service == "sts"
            return FakeSTS()

    monkeypatch.setattr(module, "_sdk_session", lambda _: FakeSDK())
    good = SimpleNamespace(account_id=None, expected_account_id="123456789012")
    assert module.check_connection(good)[1] == "123456789012"
    bad = SimpleNamespace(account_id=None, expected_account_id="210987654321")
    with pytest.raises(CloudAuditError, match="AWS_ACCOUNT_CHANGED"):
        module.check_connection(bad)


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
