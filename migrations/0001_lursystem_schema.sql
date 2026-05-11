-- Lursystem — Phase 1 schema.
--
-- Five domain tables that compose the whistleblower-reporting +
-- case-handling surface. All tables are additive on top of the
-- framework's existing rustio_users / rustio_sessions /
-- rustio_admin_actions schemas, which `auth::init_tables`
-- migrates separately.
--
-- Idempotent (every CREATE uses IF NOT EXISTS) so re-running the
-- migration on an already-migrated DB is a no-op.

-- ---- Reports ----------------------------------------------------
--
-- The submission. Anonymous-capable: `reporter_email` is nullable
-- when the reporter chose not to disclose. `reporter_token` is
-- the opaque random handle the reporter uses to check status
-- without authenticating; it is INDEXED so the lookup is an
-- index seek.

CREATE TABLE IF NOT EXISTS reports (
    id              BIGSERIAL    PRIMARY KEY,
    summary         TEXT         NOT NULL,
    body            TEXT         NOT NULL DEFAULT '',
    severity        TEXT         NOT NULL DEFAULT 'medium',
    channel         TEXT         NOT NULL DEFAULT 'web',
    status          TEXT         NOT NULL DEFAULT 'intake',
    reporter_email  TEXT,
    reporter_token  TEXT         NOT NULL UNIQUE,
    submitted_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS reports_status_idx
    ON reports (status);
CREATE INDEX IF NOT EXISTS reports_submitted_at_idx
    ON reports (submitted_at DESC);

-- ---- Cases ------------------------------------------------------
--
-- Handler-assigned wrapper around a report. `assignee_id` is
-- nullable until a compliance lead assigns the case; the partial
-- index supports the "unassigned cases" triage list. `closed_at`
-- is stamped when the status transitions to `resolved` or
-- `archived`.

CREATE TABLE IF NOT EXISTS cases (
    id           BIGSERIAL    PRIMARY KEY,
    report_id    BIGINT       NOT NULL REFERENCES reports(id),
    assignee_id  BIGINT       REFERENCES rustio_users(id),
    status       TEXT         NOT NULL DEFAULT 'triage',
    opened_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    closed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS cases_assignee_idx
    ON cases (assignee_id)
    WHERE assignee_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS cases_status_idx
    ON cases (status);
CREATE INDEX IF NOT EXISTS cases_report_idx
    ON cases (report_id);

-- ---- Case actions ----------------------------------------------
--
-- Case-level audit overlay. Every state change, internal note,
-- document download, and disclosure request lands here.
-- Complements the framework's `rustio_admin_actions` table
-- (which captures the lower-level "who hit which endpoint when"
-- chain); this table captures the case-narrative view.
--
-- `action_type` is open-ended TEXT so phase-2 commits can add
-- new action types without a schema migration.

CREATE TABLE IF NOT EXISTS case_actions (
    id          BIGSERIAL    PRIMARY KEY,
    case_id     BIGINT       NOT NULL REFERENCES cases(id),
    actor_id    BIGINT       NOT NULL REFERENCES rustio_users(id),
    action_type TEXT         NOT NULL,
    note        TEXT         NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS case_actions_case_idx
    ON case_actions (case_id, created_at DESC);

-- ---- Documents -------------------------------------------------
--
-- Attachments uploaded with the report. Stored on the local
-- filesystem under `storage_path`; the DB row carries only the
-- metadata + the pointer. The handler's UI streams the file at
-- download time after the framework's role + re-auth gates pass.

CREATE TABLE IF NOT EXISTS documents (
    id            BIGSERIAL    PRIMARY KEY,
    report_id     BIGINT       NOT NULL REFERENCES reports(id),
    filename      TEXT         NOT NULL,
    content_type  TEXT         NOT NULL DEFAULT 'application/octet-stream',
    size_bytes    BIGINT       NOT NULL DEFAULT 0,
    storage_path  TEXT         NOT NULL,
    uploaded_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS documents_report_idx
    ON documents (report_id);

-- ---- Disclosures -----------------------------------------------
--
-- Every request to read reporter-identifying data (the
-- `reporter_email` column on `reports`). Writes here are
-- irreversible: once a Disclosure row lands, the disclosure
-- happened. The framework's re-auth wall gates the runtime path
-- that inserts these rows so a stolen cookie cannot generate a
-- Disclosure without password (and TOTP, when enrolled)
-- re-entry.

CREATE TABLE IF NOT EXISTS disclosures (
    id           BIGSERIAL    PRIMARY KEY,
    case_id      BIGINT       NOT NULL REFERENCES cases(id),
    requested_by BIGINT       NOT NULL REFERENCES rustio_users(id),
    reason       TEXT         NOT NULL,
    disclosed_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS disclosures_case_idx
    ON disclosures (case_id);
CREATE INDEX IF NOT EXISTS disclosures_requested_by_idx
    ON disclosures (requested_by);
