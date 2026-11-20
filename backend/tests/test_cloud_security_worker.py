"""Isolated persistence test for the cloud worker; no AWS connection."""
from __future__ import annotations

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.models.cloud_security import (
    CloudEnvironment, CloudScan, CloudResource, CloudFinding, CloudEvidence,
    CloudScanEvent,
)
import app.services.cloud_security as cloud


class EC2:
    def describe_instances(self, **kw):
        return {"Reservations":[{"Instances":[{"InstanceId":"i-test",
                    "State":{"Name":"running"},"InstanceType":"t3.micro"}]}]}
    def describe_security_groups(self, **kw):
        return {"SecurityGroups":[{"GroupId":"sg-test","IpPermissions":[],
                                   "VpcId":"vpc-test"}]}

class S3:
    def list_buckets(self):
        return {"Buckets":[{"Name":"test-bucket"}]}
    def get_public_access_block(self,**kw):
        return {"PublicAccessBlockConfiguration":{k:True for k in (
            "BlockPublicAcls","IgnorePublicAcls","BlockPublicPolicy","RestrictPublicBuckets")}}

class IAM:
    def list_roles(self,**kw):
        return {"Roles":[{"RoleName":"ReadOnlyAudit","Arn":"arn:aws:iam::123456789012:role/ReadOnlyAudit"}]}

class FakeSDK:
    def client(self, name, **kw):
        return {"ec2":EC2(),"s3":S3(),"iam":IAM()}[name]


def test_worker_persists_resources_and_evidence_without_aws_credentials(monkeypatch):
    engine=create_engine("sqlite+pysqlite://",poolclass=StaticPool,
                         connect_args={"check_same_thread":False})
    models=[CloudEnvironment,CloudScan,CloudResource,CloudFinding,CloudEvidence,CloudScanEvent]
    Base.metadata.create_all(bind=engine,tables=[x.__table__ for x in models])
    factory=sessionmaker(bind=engine)
    monkeypatch.setattr(cloud,"SessionLocal",factory)
    monkeypatch.setattr(cloud,"check_connection",lambda e:(FakeSDK(),"123456789012","assumed-role"))
    with factory.begin() as db:
        env=CloudEnvironment(name="Sandbox",regions=["eu-west-3"],
            services=["EC2","S3","IAM"],provider="AWS",account_id="123456789012",
            credential_mode="NAMED_PROFILE",profile_name="temp",status="CONNECTED",
            created_by="u"*36)
        db.add(env)
        db.flush()
        scan=CloudScan(environment_id=env.id,kind="AWS_BASELINE",
            status="QUEUED",requested_by="u"*36)
        db.add(scan)
        db.flush()
        scan_id=scan.id

    assert cloud._CAPACITY.acquire(blocking=False)
    cloud._run_worker(scan_id)
    with factory() as db:
        scan=db.get(CloudScan,scan_id)
        assert scan.status=="COMPLETED"
        assert scan.resource_count==4
        assert scan.finding_count==0
        assert scan.unknown_checks==0
        assert db.scalar(select(func.count()).select_from(CloudEvidence).where(
            CloudEvidence.scan_id==scan_id))==2
        assert all(e.safe_summary.get("all_public_access_blocked", True) for e in db.scalars(
            select(CloudEvidence).where(CloudEvidence.scan_id==scan_id)))
        assert [e.message_code for e in db.scalars(select(CloudScanEvent)
            .where(CloudScanEvent.scan_id==scan_id))]==["STARTED","COMPLETED"]
        assert db.scalar(select(CloudEnvironment).where(CloudEnvironment.id==scan.environment_id)).profile_name=="temp"
    engine.dispose()
