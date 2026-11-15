-- F11 Analyzer staging (REVIEW ONLY). QA schema first; no production
-- migration without separately approved backup and migration plan.
BEGIN;
CREATE TABLE IF NOT EXISTS mcp_discovery_analysis_stages (
    generation_id VARCHAR(36) PRIMARY KEY
      REFERENCES mcp_discovery_generations(id) ON DELETE CASCADE,
    source_digest VARCHAR(64) NOT NULL,
    configuration_hash VARCHAR(64) NOT NULL,
    stage_digest VARCHAR(64) NOT NULL,
    stage_data JSON NOT NULL,
    completed_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMIT;
