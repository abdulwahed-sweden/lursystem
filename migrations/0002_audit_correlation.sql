-- Lursystem — Phase 5 audit-correlation migration.
--
-- Adds `correlation_id` to the two audit-bearing tables so the
-- auditor surface (Phase 5) can pivot from any case-level event
-- to every other event under the same HTTP request. The framework
-- already injects a `correlation_id` per request via
-- `middleware::correlation_id` (mounted in `main.rs`); this
-- migration just lets the project's audit overlay record it.
--
-- The column is nullable: rows written before this migration
-- (Phases 2-4 of lursystem) get NULL and remain queryable, just
-- without the correlation pivot. The audit UI tolerates NULL.
--
-- Idempotent (every ADD COLUMN / CREATE INDEX uses IF NOT
-- EXISTS) so re-running on an already-migrated DB is a no-op.

ALTER TABLE case_actions
    ADD COLUMN IF NOT EXISTS correlation_id TEXT;

ALTER TABLE disclosures
    ADD COLUMN IF NOT EXISTS correlation_id TEXT;

CREATE INDEX IF NOT EXISTS case_actions_correlation_idx
    ON case_actions (correlation_id);

CREATE INDEX IF NOT EXISTS disclosures_correlation_idx
    ON disclosures (correlation_id);

-- Composite index supporting the auditor's primary read pattern:
-- "all case-level events, newest first." A vanilla index on
-- created_at alone serves the unfiltered listing; pairing it with
-- action_type lets the filtered queries (e.g. only
-- `disclosure_consumed`) avoid a sequential scan.
CREATE INDEX IF NOT EXISTS case_actions_audit_idx
    ON case_actions (created_at DESC, action_type);
