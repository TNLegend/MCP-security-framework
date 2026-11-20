"""Cloud scan recovery and redaction behavior on an isolated database."""
from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from botocore.exceptions import ClientError

from app.db.database import Base
from app.models.cloud_security import (
    CloudEnvironment, CloudScan, CloudResource, CloudFinding, CloudEvidence,
    CloudScanEvent,
)
import app.services.cloud_security as cloud


def _db(monkeypatch):
    engine=create_engine("sqlite+pysqlite://",poolclass=StaticPool,
                         connect_args={"check_same_thread":False})
    models=(CloudEnvironment,CloudScan,CloudResource,CloudFinding,CloudEvidence,CloudScanEvent)
    Base.metadata.create_all(bind=engine,tables=[m.__table__ for m in models])
    factory=sessionmaker(bind=engine)
    monkeypatch.setattr(cloud,"SessionLocal",factory)
    with factory.begin() as db:
        env=CloudEnvironment(name="Recovery QA",regions=["eu-west-3"],
            services=["EC2"],provider="AWS",account_id="123456789012",
            credential_mode="NAMED_PROFILE",profile_name="session",
            status="CONNECTED",created_by="u"*36)
        db.add(env);db.flush()
        scan=CloudScan(environment_id=env.id,kind="AWS_BASELINE",
            status="QUEUED",requested_by="u"*36)
        db.add(scan);db.flush()
        id=scan.id
    return engine,factory,id


def test_interrupted_queued_scan_is_never_reported_as_success(monkeypatch):
    engine,factory,scan_id=_db(monkeypatch)
    cloud.mark_interrupted_scans()
    cloud.mark_interrupted_scans()
    with factory() as db:
        record=db.get(CloudScan,scan_id)
        assert record.status=="INTERRUPTED"
        assert record.error_code=="WORKER_RESTARTED"
        assert record.completed_at is not None
        assert record.resource_count==0
    engine.dispose()


def test_expired_token_failure_is_generic_and_never_persists_secret(monkeypatch):
    engine,factory,scan_id=_db(monkeypatch)
    fake_secret="ACCESS_SECRET_DO_NOT_STORE"
    def expired(_env):
        raise ClientError(
            {"Error":{"Code":"ExpiredToken","Message":"invalid token "+fake_secret}},
            "GetCallerIdentity")
    monkeypatch.setattr(cloud,"check_connection",expired)
    assert cloud._CAPACITY.acquire(blocking=False)
    cloud._run_worker(scan_id)
    with factory() as db:
        record=db.get(CloudScan,scan_id)
        assert record.status=="FAILED"
        assert record.error_code=="AWS_SESSION_EXPIRED"
        assert record.resource_count==0
        assert fake_secret not in str(record.__dict__)
        events=list(db.scalars(select(CloudScanEvent).where(CloudScanEvent.scan_id==scan_id)))
        assert [x.message_code for x in events]==["STARTED","FAILED"]
        assert fake_secret not in str([x.__dict__ for x in events])
    engine.dispose()
