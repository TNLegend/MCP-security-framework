-- F11 discovery generations — staged PostgreSQL migration for REVIEW.
-- Do not execute on production before a backup, schema audit and
-- approved deployment. This DDL matches the active MCPDiscoveryHead and
-- MCPDiscoveryGeneration models (not the superseded preparatory design).
BEGIN;
CREATE TABLE IF NOT EXISTS mcp_discovery_heads (
    scope_key VARCHAR(64) PRIMARY KEY,
    latest_generation INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS mcp_discovery_generations (
    id VARCHAR(36) PRIMARY KEY,
    scope_key VARCHAR(64) NOT NULL
      REFERENCES mcp_discovery_heads(scope_key),
    generation INTEGER NOT NULL CHECK (generation > 0),
    status VARCHAR(20) NOT NULL
      CHECK (status IN ('RUNNING', 'SUPERSEDED', 'FAILED', 'PUBLISHED')),
    context_hash VARCHAR(64),
    started_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITHOUT TIME ZONE,
    error_code VARCHAR(128),
    CONSTRAINT uq_mcp_discovery_scope_generation
      UNIQUE (scope_key, generation)
);
-- Additive upgrade for already-initialized F11 databases. Pre-existing
-- RUNNING reservations without a context hash must not be published by
-- newly context-bound API routes.
ALTER TABLE mcp_discovery_generations
    ADD COLUMN IF NOT EXISTS context_hash VARCHAR(64);
CREATE INDEX IF NOT EXISTS ix_mcp_discovery_generations_scope_key
    ON mcp_discovery_generations(scope_key);
COMMIT;
