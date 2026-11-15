-- Additive step 6 schema. Apply only under an explicitly authorized migration.
-- No legacy approval lineage or authority identity is backfilled.
BEGIN;


CREATE TABLE IF NOT EXISTS analyzer_authority (
	id SERIAL NOT NULL,
	generation BIGINT NOT NULL,
	pipeline_identity VARCHAR(64) NOT NULL,
	closure_digest VARCHAR(64) NOT NULL,
	execution_digest VARCHAR(64),
	analyzer_revision VARCHAR(100) NOT NULL,
	manifest_approval_ref VARCHAR(255) NOT NULL,
	activated_by VARCHAR(36) NOT NULL,
	activated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE IF NOT EXISTS analyzer_migrations (
	id VARCHAR(36) NOT NULL,
	state VARCHAR(32) NOT NULL,
	prepared_by VARCHAR(36) NOT NULL,
	prepared_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
	payload JSON NOT NULL,
	packet_hash VARCHAR(64) NOT NULL,
	activated_revision_id VARCHAR(36),
	activated_generation INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(prepared_by) REFERENCES control_plane_users (id)
)

;


CREATE TABLE IF NOT EXISTS analyzer_migration_activations (
	id VARCHAR(36) NOT NULL,
	migration_id VARCHAR(36) NOT NULL,
	admin_id VARCHAR(36) NOT NULL,
	generation INTEGER NOT NULL,
	revision_id VARCHAR(36) NOT NULL,
	activated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (migration_id),
	FOREIGN KEY(migration_id) REFERENCES analyzer_migrations (id),
	FOREIGN KEY(admin_id) REFERENCES control_plane_users (id)
)

;


CREATE TABLE IF NOT EXISTS analyzer_migration_decisions (
	id VARCHAR(36) NOT NULL,
	migration_id VARCHAR(36) NOT NULL,
	observation_id INTEGER NOT NULL,
	admin_id VARCHAR(36) NOT NULL,
	decided_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
	act JSON NOT NULL,
	signature VARCHAR NOT NULL,
	signature_key_id VARCHAR(128) NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_analyzer_migration_observation_decision UNIQUE (migration_id, observation_id),
	FOREIGN KEY(migration_id) REFERENCES analyzer_migrations (id),
	FOREIGN KEY(admin_id) REFERENCES control_plane_users (id)
)

;


CREATE TABLE IF NOT EXISTS analysis_authority_bindings (
	analysis_id INTEGER NOT NULL,
	generation BIGINT NOT NULL,
	pipeline_identity VARCHAR(64) NOT NULL,
	PRIMARY KEY (analysis_id),
	FOREIGN KEY(analysis_id) REFERENCES tool_analyses (id)
)

;


CREATE TABLE IF NOT EXISTS tool_approval_lineage (
	approval_id INTEGER NOT NULL,
	source_approval_id INTEGER,
	root_approval_id INTEGER NOT NULL,
	original_admin_id VARCHAR(255) NOT NULL,
	original_approved_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
	original_revision_id VARCHAR(64) NOT NULL,
	recorded_by VARCHAR(255) NOT NULL,
	PRIMARY KEY (approval_id),
	FOREIGN KEY(approval_id) REFERENCES tool_observation_review_approvals (id),
	FOREIGN KEY(source_approval_id) REFERENCES tool_observation_review_approvals (id),
	FOREIGN KEY(root_approval_id) REFERENCES tool_observation_review_approvals (id)
)

;

ALTER TABLE analyzer_authority ADD COLUMN IF NOT EXISTS execution_digest VARCHAR(64);

COMMIT;
