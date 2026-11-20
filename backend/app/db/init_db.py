import app.models  # noqa: F401
from sqlalchemy import inspect, text

from app.db.database import Base, engine

PHASE2_INVENTORY_COLUMNS = {
    "mcp_servers": [
        "ADD COLUMN IF NOT EXISTS protocol_version VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS auth_mode VARCHAR(32) DEFAULT 'NONE' NOT NULL",
        "ADD COLUMN IF NOT EXISTS credential_ref VARCHAR(128)",
        "ADD COLUMN IF NOT EXISTS oauth_config JSON",
        "ADD COLUMN IF NOT EXISTS oauth_status VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS oauth_connected_at TIMESTAMP",
        "ADD COLUMN IF NOT EXISTS oauth_last_error VARCHAR(128)",
        "ADD COLUMN IF NOT EXISTS server_info_name VARCHAR(255)",
        "ADD COLUMN IF NOT EXISTS server_info_title VARCHAR(255)",
        "ADD COLUMN IF NOT EXISTS server_info_version VARCHAR(100)",
        "ADD COLUMN IF NOT EXISTS server_info_description TEXT",
        "ADD COLUMN IF NOT EXISTS server_info_icons JSON",
        "ADD COLUMN IF NOT EXISTS server_info_website_url VARCHAR(500)",
        "ADD COLUMN IF NOT EXISTS capabilities JSON",
        "ADD COLUMN IF NOT EXISTS instructions TEXT",
        "ADD COLUMN IF NOT EXISTS transport VARCHAR(100) DEFAULT 'streamable_http' NOT NULL",
        "ADD COLUMN IF NOT EXISTS raw_initialize_result JSON",
        "ADD COLUMN IF NOT EXISTS detected_protocol_era VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS supported_protocol_versions JSON",
        "ADD COLUMN IF NOT EXISTS preferred_protocol_version VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS negotiated_protocol_version VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS protocol_transport_kind VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS protocol_verdict_expires_at TIMESTAMP",
        "ADD COLUMN IF NOT EXISTS supported_protocol_profiles JSON",
        "ADD COLUMN IF NOT EXISTS preferred_upstream_profile VARCHAR(100)",
        "ADD COLUMN IF NOT EXISTS last_protocol_probe_at TIMESTAMP",
        "ADD COLUMN IF NOT EXISTS protocol_probe_status VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS protocol_probe_error TEXT",
        "ADD COLUMN IF NOT EXISTS trust_status VARCHAR(50) DEFAULT 'unknown' NOT NULL",
        "ADD COLUMN IF NOT EXISTS security_status VARCHAR(50) DEFAULT 'not_analyzed' NOT NULL",
        "ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP",
        "ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMP",
        "ADD COLUMN IF NOT EXISTS notes TEXT",
    ],
    "mcp_tools": [
        "ADD COLUMN IF NOT EXISTS title VARCHAR(255)",
        "ADD COLUMN IF NOT EXISTS icons JSON",
        "ADD COLUMN IF NOT EXISTS input_schema JSON",
        "ADD COLUMN IF NOT EXISTS output_schema JSON",
        "ADD COLUMN IF NOT EXISTS annotations JSON",
        "ADD COLUMN IF NOT EXISTS execution JSON",
        "ADD COLUMN IF NOT EXISTS raw_tool_definition JSON",
        "ADD COLUMN IF NOT EXISTS sensitivity VARCHAR(50) DEFAULT 'low' NOT NULL",
        "ADD COLUMN IF NOT EXISTS description_risk_score INTEGER DEFAULT 0 NOT NULL",
        "ADD COLUMN IF NOT EXISTS policy_status VARCHAR(50) DEFAULT 'not_reviewed' NOT NULL",
        "ADD COLUMN IF NOT EXISTS is_sensitive BOOLEAN DEFAULT FALSE NOT NULL",
        "ADD COLUMN IF NOT EXISTS last_analyzed_at TIMESTAMP",
        "ADD COLUMN IF NOT EXISTS current_fingerprint VARCHAR(64)",
        "ADD COLUMN IF NOT EXISTS approved_fingerprint VARCHAR(64)",
        "ADD COLUMN IF NOT EXISTS approved_fingerprint_match BOOLEAN DEFAULT FALSE NOT NULL",
        "ADD COLUMN IF NOT EXISTS analysis_status VARCHAR(50) DEFAULT 'PENDING_ANALYSIS' NOT NULL",
        "ADD COLUMN IF NOT EXISTS risk_level VARCHAR(50) DEFAULT 'unknown' NOT NULL",
        "ADD COLUMN IF NOT EXISTS semantic_flagged BOOLEAN DEFAULT FALSE NOT NULL",
        "ADD COLUMN IF NOT EXISTS deterministic_critical_finding BOOLEAN DEFAULT FALSE NOT NULL",
        "ADD COLUMN IF NOT EXISTS consistency_status VARCHAR(50) DEFAULT 'unknown' NOT NULL",
        "ADD COLUMN IF NOT EXISTS drift_status VARCHAR(50) DEFAULT 'NONE' NOT NULL",
        "ADD COLUMN IF NOT EXISTS review_status VARCHAR(50) DEFAULT 'REVIEW_REQUIRED' NOT NULL",
        "ADD COLUMN IF NOT EXISTS analyzer_revision VARCHAR(100)",
    ],
    "runtime_calls": [
        "ADD COLUMN IF NOT EXISTS operation_id VARCHAR(36)",
        "ADD COLUMN IF NOT EXISTS event_phase VARCHAR(12)",
        "ADD COLUMN IF NOT EXISTS tool_fingerprint VARCHAR(64)",
        "ADD COLUMN IF NOT EXISTS decision VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS rule_id VARCHAR(255)",
        "ADD COLUMN IF NOT EXISTS decision_reason TEXT",
        "ADD COLUMN IF NOT EXISTS severity VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS control_plane_revision_id VARCHAR(36)",
        "ADD COLUMN IF NOT EXISTS control_plane_revision_number INTEGER",
        "ADD COLUMN IF NOT EXISTS control_plane_content_hash VARCHAR(64)",
        "ADD COLUMN IF NOT EXISTS executed BOOLEAN DEFAULT FALSE NOT NULL",
        "ADD COLUMN IF NOT EXISTS execution_status VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS result_summary TEXT",
        "ADD COLUMN IF NOT EXISTS error_summary TEXT",
        "ADD COLUMN IF NOT EXISTS client_protocol_profile_id VARCHAR(100)",
        "ADD COLUMN IF NOT EXISTS client_protocol_era VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS client_protocol_version VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS client_transport_kind VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS upstream_protocol_profile_id VARCHAR(100)",
        "ADD COLUMN IF NOT EXISTS upstream_protocol_era VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS upstream_protocol_version VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS upstream_transport_kind VARCHAR(50)",
        "ADD COLUMN IF NOT EXISTS total_duration_ms DOUBLE PRECISION",
        "ADD COLUMN IF NOT EXISTS policy_duration_ms DOUBLE PRECISION",
        "ADD COLUMN IF NOT EXISTS upstream_duration_ms DOUBLE PRECISION",
        "ADD COLUMN IF NOT EXISTS result_guard_duration_ms DOUBLE PRECISION",
    ],
    "control_plane_config_revisions": [
        "ADD COLUMN IF NOT EXISTS previous_revision_hash VARCHAR(64)",
        "ADD COLUMN IF NOT EXISTS signature TEXT",
        "ADD COLUMN IF NOT EXISTS signature_key_id VARCHAR(128)",
        "ADD COLUMN IF NOT EXISTS signature_algorithm VARCHAR(32)",
        "ADD COLUMN IF NOT EXISTS signature_version VARCHAR(16)",
    ],
    "control_plane_state": [
        "ADD COLUMN IF NOT EXISTS last_revision_number INTEGER DEFAULT 0 NOT NULL",
    ],
    "tool_protocol_observations": [
        "ADD COLUMN IF NOT EXISTS protocol_era VARCHAR(50) DEFAULT 'legacy' NOT NULL",
        "ADD COLUMN IF NOT EXISTS protocol_version VARCHAR(50) DEFAULT '2025-11-25' NOT NULL",
        "ADD COLUMN IF NOT EXISTS transport_kind VARCHAR(50) DEFAULT 'legacy_streamable_http' NOT NULL",
    ],
    "tool_analyses": [
        "ADD COLUMN IF NOT EXISTS analysis_context_hash VARCHAR(64)",
    ],
    "tool_approved_baselines": [
        "ADD COLUMN IF NOT EXISTS analysis_context_hash VARCHAR(64)",
        "ADD COLUMN IF NOT EXISTS approval_source VARCHAR(32) DEFAULT 'ADMIN' NOT NULL",
    ],
    "tool_observation_review_approvals": [
        "ADD COLUMN IF NOT EXISTS evidence_bundle JSON",
    ],
}

IDENTITY_REPLAY_INDEXES = [
    (
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "uq_identity_assertion_replay_issuer_jti_hash "
        "ON identity_assertion_replays (issuer, jti_hash)"
    ),
]

RUNTIME_CALL_INDEXES = [
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_runtime_call_operation_phase "
    "ON runtime_calls (operation_id, event_phase)",
    "CREATE INDEX IF NOT EXISTS ix_runtime_calls_operation_id ON runtime_calls (operation_id)",
    "CREATE INDEX IF NOT EXISTS ix_runtime_calls_created_at ON runtime_calls (created_at DESC)",
    "CREATE INDEX IF NOT EXISTS ix_runtime_calls_decision_id ON runtime_calls (decision, id DESC)",
    "CREATE INDEX IF NOT EXISTS ix_runtime_calls_server_id_id ON runtime_calls (server_id, id DESC)",
    "CREATE INDEX IF NOT EXISTS ix_runtime_calls_tool_name_id ON runtime_calls (tool_name, id DESC)",
    "CREATE INDEX IF NOT EXISTS ix_runtime_calls_agent_id_id ON runtime_calls (agent_id, id DESC)",
]


TRUSTED_SESSION_INDEXES = [
    (
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "uq_trusted_agent_sessions_session_reference "
        "ON trusted_agent_sessions (session_reference)"
    ),
    (
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "uq_trusted_agent_sessions_token_hash "
        "ON trusted_agent_sessions (token_hash)"
    ),
    (
        "CREATE INDEX IF NOT EXISTS "
        "ix_trusted_agent_sessions_agent_active "
        "ON trusted_agent_sessions (agent_id, expires_at, revoked_at)"
    ),
]


def ensure_phase2_inventory_columns() -> None:
    with engine.begin() as connection:
        existing_tables = set(inspect(connection).get_table_names())
        for table_name, column_definitions in PHASE2_INVENTORY_COLUMNS.items():
            if table_name not in existing_tables:
                continue
            for column_definition in column_definitions:
                connection.execute(text(f"ALTER TABLE {table_name} {column_definition}"))
        _migrate_legacy_tool_approval_statuses(connection)
        _deactivate_orphaned_observation_reviews(connection)
        _backfill_control_plane_revision_high_water(connection)
        for statement in IDENTITY_REPLAY_INDEXES:
            connection.execute(text(statement))
        for statement in TRUSTED_SESSION_INDEXES:
            connection.execute(text(statement))
        if "runtime_calls" in existing_tables:
            for statement in RUNTIME_CALL_INDEXES:
                connection.execute(text(statement))


def _deactivate_orphaned_observation_reviews(connection) -> None:
    inspector = inspect(connection)
    if "tool_observation_review_approvals" not in inspector.get_table_names():
        return
    columns = {
        column["name"]
        for column in inspector.get_columns("tool_observation_review_approvals")
    }
    if not {"revision_id", "active"} <= columns:
        return
    connection.execute(
        text(
            "UPDATE tool_observation_review_approvals SET active = FALSE "
            "WHERE active = TRUE AND NOT EXISTS ("
            "SELECT 1 FROM control_plane_config_revisions revision "
            "WHERE revision.id = tool_observation_review_approvals.revision_id)"
        )
    )


def _backfill_control_plane_revision_high_water(connection) -> None:
    inspector = inspect(connection)
    tables = set(inspector.get_table_names())
    if not {"control_plane_state", "control_plane_config_revisions"} <= tables:
        return
    state_columns = {
        column["name"] for column in inspector.get_columns("control_plane_state")
    }
    if "last_revision_number" not in state_columns:
        return
    connection.execute(
        text(
            "UPDATE control_plane_state "
            "SET last_revision_number = CASE "
            "WHEN last_revision_number < COALESCE(("
            "SELECT MAX(revision_number) FROM control_plane_config_revisions"
            "), 0) "
            "THEN COALESCE(("
            "SELECT MAX(revision_number) FROM control_plane_config_revisions"
            "), 0) "
            "ELSE last_revision_number END "
            "WHERE id = 1"
        )
    )


def _migrate_legacy_tool_approval_statuses(connection) -> None:
    inspector = inspect(connection)
    analysis_columns = {
        column["name"] for column in inspector.get_columns("tool_analyses")
    }
    if {"analysis_status", "review_status", "fingerprint", "tool_id"} <= analysis_columns:
        connection.execute(
            text(
                "UPDATE tool_analyses SET analysis_status = 'ADMIN_ALLOWED', "
                "review_status = 'ADMIN_ALLOWED' "
                "WHERE analysis_status = 'APPROVED' AND review_status = 'APPROVED' "
                "AND EXISTS (SELECT 1 FROM tool_approved_baselines baseline "
                "WHERE baseline.tool_id = tool_analyses.tool_id "
                "AND baseline.fingerprint = tool_analyses.fingerprint "
                "AND baseline.approval_source = 'ADMIN')"
            )
        )

    tool_columns = {column["name"] for column in inspector.get_columns("mcp_tools")}
    if {
        "analysis_status",
        "review_status",
        "policy_status",
        "status",
        "current_fingerprint",
    } <= tool_columns:
        connection.execute(
            text(
                "UPDATE mcp_tools SET analysis_status = 'ADMIN_ALLOWED', "
                "review_status = 'ADMIN_ALLOWED', policy_status = 'ADMIN_ALLOWED', "
                "status = 'ADMIN_ALLOWED' "
                "WHERE analysis_status = 'APPROVED' AND review_status = 'APPROVED' "
                "AND EXISTS (SELECT 1 FROM tool_approved_baselines baseline "
                "WHERE baseline.tool_id = mcp_tools.id "
                "AND baseline.fingerprint = mcp_tools.current_fingerprint "
                "AND baseline.approval_source = 'ADMIN')"
            )
        )


def init_db() -> None:
    # New cloud tables are created idempotently alongside the existing schema.
    # No altering of signed runtime tables or existing production rows.
    Base.metadata.create_all(bind=engine)
    ensure_phase2_inventory_columns()
    # Verify the new Deploy Security tables also exist on fresh and upgraded DBs.
    ensure_cloud_security_schema()
    print("Database tables created successfully.")


def ensure_cloud_security_schema() -> None:
    """Add-only, repeatable migration for the seven new Deploy Security tables."""
    from app.models.cloud_security import (
        CloudEnvironment, CloudScan, CloudResource, CloudFinding,
        CloudEvidence, CloudIAMComparison, CloudScanEvent,
    )
    tables = [model.__table__ for model in (
        CloudEnvironment, CloudScan, CloudResource, CloudFinding,
        CloudEvidence, CloudIAMComparison, CloudScanEvent,
    )]
    Base.metadata.create_all(bind=engine, tables=tables, checkfirst=True)
    with engine.begin() as connection:
        # Add-only upgrade for environments created before service selection existed.
        connection.execute(text(
            """ALTER TABLE cloud_environments
            ADD COLUMN IF NOT EXISTS services JSON DEFAULT '["EC2","S3","IAM"]' NOT NULL"""
        ))
        # IaC scans are account-independent. Existing AWS observations remain intact.
        connection.execute(text("ALTER TABLE cloud_scans ALTER COLUMN environment_id DROP NOT NULL"))
        connection.execute(text("ALTER TABLE cloud_resources ALTER COLUMN environment_id DROP NOT NULL"))
        connection.execute(text("ALTER TABLE cloud_scans ADD COLUMN IF NOT EXISTS source_fingerprint VARCHAR(64)"))
        connection.execute(text("ALTER TABLE cloud_scans ADD COLUMN IF NOT EXISTS source_file_count INTEGER DEFAULT 0 NOT NULL"))
        names = set(inspect(connection).get_table_names())
    if missing := {table.name for table in tables} - names:
        raise RuntimeError(f"cloud_schema_incomplete: {sorted(missing)}")


if __name__ == '__main__':
    init_db()
