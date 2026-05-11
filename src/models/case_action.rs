//! `CaseAction` — case-level audit overlay.
//!
//! Complements the framework's `rustio_admin_actions` table.
//! The framework captures every HTTP request's audit chain
//! (`correlation_id`, `session_id`, lower-level action_type).
//! This table captures the case-narrative view — the things a
//! compliance auditor needs to read to understand how a case
//! progressed: state changes, internal notes, document
//! downloads, disclosure requests.
//!
//! `action_type` is open-ended TEXT so adding new action types
//! does not require a schema migration. Expected values today:
//!
//! - `status_changed`
//! - `assigned` / `reassigned`
//! - `note_added`
//! - `document_uploaded` / `document_downloaded`
//! - `disclosure_requested` / `disclosure_consumed`

use chrono::{DateTime, Utc};
use rustio_admin::orm::{Model, Row, Value};
use rustio_admin::{ModelAdmin, Result, RustioAdmin};

#[derive(RustioAdmin)]
pub struct CaseAction {
    pub id: i64,
    pub case_id: i64,
    pub actor_id: i64,
    pub action_type: String,
    pub note: String,
    pub created_at: DateTime<Utc>,
}

impl ModelAdmin for CaseAction {
    fn list_display() -> &'static [&'static str] {
        &["case_id", "actor_id", "action_type", "created_at"]
    }
    fn list_filter() -> &'static [&'static str] {
        &["action_type"]
    }
    fn search_fields() -> &'static [&'static str] {
        &["note", "action_type"]
    }
    fn ordering() -> &'static [&'static str] {
        &["-created_at"]
    }
}

impl Model for CaseAction {
    const TABLE: &'static str = "case_actions";
    const COLUMNS: &'static [&'static str] = &[
        "id",
        "case_id",
        "actor_id",
        "action_type",
        "note",
        "created_at",
    ];
    const INSERT_COLUMNS: &'static [&'static str] =
        &["case_id", "actor_id", "action_type", "note", "created_at"];

    fn id(&self) -> i64 {
        self.id
    }

    fn from_row(row: Row<'_>) -> Result<Self> {
        Ok(Self {
            id: row.get_i64("id")?,
            case_id: row.get_i64("case_id")?,
            actor_id: row.get_i64("actor_id")?,
            action_type: row.get_string("action_type")?,
            note: row.get_string("note")?,
            created_at: row.get_datetime("created_at")?,
        })
    }

    fn insert_values(&self) -> Vec<Value> {
        vec![
            Value::I64(self.case_id),
            Value::I64(self.actor_id),
            Value::Text(self.action_type.clone()),
            Value::Text(self.note.clone()),
            Value::DateTime(self.created_at),
        ]
    }
}
