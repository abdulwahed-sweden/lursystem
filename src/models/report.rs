//! `Report` — the whistleblower submission.
//!
//! Anonymous-capable: `reporter_email` is `Option<String>`,
//! mirroring the SQL column's nullability. Reporters who choose
//! not to disclose their identity see status updates via the
//! `reporter_token` self-service surface (Phase 2).
//!
//! ## Lifecycle
//!
//! `status` is an open-ended string column. The expected values
//! progress through the case workflow:
//!
//! - `intake` — just submitted, awaiting triage.
//! - `triage` — picked up by a compliance lead.
//! - `investigating` — handler assigned, case open.
//! - `resolved` — investigation concluded.
//! - `archived` — closed and retained for compliance review.
//!
//! The framework's list_filter chip will surface the values
//! actually present in the DB; we don't enforce a Rust enum
//! today to keep the column flexible across operator workflows.

use chrono::{DateTime, Utc};
use rustio_admin::orm::{Model, Row, Value};
use rustio_admin::{ModelAdmin, Result, RustioAdmin};

#[derive(RustioAdmin)]
pub struct Report {
    pub id: i64,
    pub summary: String,
    pub body: String,
    pub severity: String,
    pub channel: String,
    pub status: String,
    pub reporter_email: Option<String>,
    pub reporter_token: String,
    pub submitted_at: DateTime<Utc>,
}

impl ModelAdmin for Report {
    fn list_display() -> &'static [&'static str] {
        &["summary", "severity", "status", "submitted_at"]
    }
    fn list_filter() -> &'static [&'static str] {
        &["severity", "status", "channel"]
    }
    fn search_fields() -> &'static [&'static str] {
        &["summary", "body", "reporter_email"]
    }
    fn ordering() -> &'static [&'static str] {
        &["-submitted_at"]
    }
}

impl Model for Report {
    const TABLE: &'static str = "reports";
    const COLUMNS: &'static [&'static str] = &[
        "id",
        "summary",
        "body",
        "severity",
        "channel",
        "status",
        "reporter_email",
        "reporter_token",
        "submitted_at",
    ];
    const INSERT_COLUMNS: &'static [&'static str] = &[
        "summary",
        "body",
        "severity",
        "channel",
        "status",
        "reporter_email",
        "reporter_token",
        "submitted_at",
    ];

    fn id(&self) -> i64 {
        self.id
    }

    fn from_row(row: Row<'_>) -> Result<Self> {
        Ok(Self {
            id: row.get_i64("id")?,
            summary: row.get_string("summary")?,
            body: row.get_string("body")?,
            severity: row.get_string("severity")?,
            channel: row.get_string("channel")?,
            status: row.get_string("status")?,
            reporter_email: row.get_optional_string("reporter_email")?,
            reporter_token: row.get_string("reporter_token")?,
            submitted_at: row.get_datetime("submitted_at")?,
        })
    }

    fn insert_values(&self) -> Vec<Value> {
        vec![
            Value::Text(self.summary.clone()),
            Value::Text(self.body.clone()),
            Value::Text(self.severity.clone()),
            Value::Text(self.channel.clone()),
            Value::Text(self.status.clone()),
            match &self.reporter_email {
                Some(email) => Value::Text(email.clone()),
                None => Value::Null,
            },
            Value::Text(self.reporter_token.clone()),
            Value::DateTime(self.submitted_at),
        ]
    }
}
