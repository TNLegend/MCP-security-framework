-- Deploy Security phase 6, additive PostgreSQL migration (apply with approved change control).
-- DO NOT run on a production database without backup/release procedure.
BEGIN;
CREATE TABLE IF NOT EXISTS cloud_deploy_governance_decisions (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL REFERENCES cloud_scans(id),
    actor_user_id VARCHAR(36) NOT NULL REFERENCES control_plane_users(id),
    classification VARCHAR(32) NOT NULL,
    policy_revision VARCHAR(80) NOT NULL,
    policy_bundle_sha256 VARCHAR(64) NOT NULL,
    input_sha256 VARCHAR(64) NOT NULL,
    output_sha256 VARCHAR(64) NOT NULL,
    result JSON NOT NULL,
    previous_entry_sha256 VARCHAR(64),
    entry_sha256 VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cloud_deploy_decision_scan_time
    ON cloud_deploy_governance_decisions (scan_id, created_at);
CREATE TABLE IF NOT EXISTS cloud_deploy_exception_events (
    id VARCHAR(36) PRIMARY KEY,
    exception_id VARCHAR(36) NOT NULL,
    scan_id VARCHAR(36) NOT NULL REFERENCES cloud_scans(id),
    finding_id VARCHAR(36) NOT NULL REFERENCES cloud_findings(id),
    actor_user_id VARCHAR(36) NOT NULL REFERENCES control_plane_users(id),
    operation VARCHAR(24) NOT NULL,
    reason VARCHAR(1000) NOT NULL,
    expires_at TIMESTAMP,
    previous_entry_sha256 VARCHAR(64),
    entry_sha256 VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cloud_deploy_exception_trace
    ON cloud_deploy_exception_events (exception_id, created_at);
CREATE OR REPLACE FUNCTION deploy_governance_append_only()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'deploy_governance_append_only';
END;
$$;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_cloud_deploy_governance_decisions_append_only') THEN
        CREATE TRIGGER trg_cloud_deploy_governance_decisions_append_only
        BEFORE UPDATE OR DELETE ON cloud_deploy_governance_decisions
        FOR EACH ROW EXECUTE FUNCTION deploy_governance_append_only();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_cloud_deploy_exception_events_append_only') THEN
        CREATE TRIGGER trg_cloud_deploy_exception_events_append_only
        BEFORE UPDATE OR DELETE ON cloud_deploy_exception_events
        FOR EACH ROW EXECUTE FUNCTION deploy_governance_append_only();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_cloud_deploy_governance_decisions_no_truncate') THEN
        CREATE TRIGGER trg_cloud_deploy_governance_decisions_no_truncate
        BEFORE TRUNCATE ON cloud_deploy_governance_decisions
        FOR EACH STATEMENT EXECUTE FUNCTION deploy_governance_append_only();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_cloud_deploy_exception_events_no_truncate') THEN
        CREATE TRIGGER trg_cloud_deploy_exception_events_no_truncate
        BEFORE TRUNCATE ON cloud_deploy_exception_events
        FOR EACH STATEMENT EXECUTE FUNCTION deploy_governance_append_only();
    END IF;
END;
$$;
COMMIT;
