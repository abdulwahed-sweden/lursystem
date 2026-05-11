//! `Case` — handler-assigned wrapper around a `Report`.
//!
//! A Case picks up a Report from the intake queue and tracks
//! the investigation through to resolution. `assignee_id` is
//! `Option<i64>` to mirror the SQL column's nullability — a
//! case in the `triage` state may exist before a compliance
//! lead assigns a handler.
//!
//! ## Framework gap: nullable `closed_at`
//!
//! The schema's `closed_at TIMESTAMPTZ` column is intentionally
//! absent from the Rust struct. `RustioAdmin`'s derive macro
//! in 0.7 does not yet support `Option<DateTime<Utc>>` field
//! types (the underlying `Row::get_optional_datetime` helper
//! exists from 0.6, but the macro hasn't been updated). The
//! Phase-3 handler workflow stamps `closed_at = NOW()` via
//! direct sqlx queries when the case transitions to a terminal
//! status. Same workaround the Stockholm POS uses for its
//! nullable `ended_at` / `last_restocked_at` columns; lifts when
//! the framework's derive macro picks up the helper.

use chrono::{DateTime, Utc};
use rustio_admin::orm::{Model, Row, Value};
use rustio_admin::{ModelAdmin, Result, RustioAdmin};

#[derive(RustioAdmin)]
pub struct Case {
    pub id: i64,
    pub report_id: i64,
    pub assignee_id: Option<i64>,
    pub status: String,
    pub opened_at: DateTime<Utc>,
}

impl ModelAdmin for Case {
    fn list_display() -> &'static [&'static str] {
        &["id", "report_id", "assignee_id", "status", "opened_at"]
    }
    fn list_filter() -> &'static [&'static str] {
        &["status"]
    }
    fn ordering() -> &'static [&'static str] {
        &["-opened_at"]
    }
}

impl Model for Case {
    const TABLE: &'static str = "cases";
    const COLUMNS: &'static [&'static str] =
        &["id", "report_id", "assignee_id", "status", "opened_at"];
    const INSERT_COLUMNS: &'static [&'static str] =
        &["report_id", "assignee_id", "status", "opened_at"];

    fn id(&self) -> i64 {
        self.id
    }

    fn from_row(row: Row<'_>) -> Result<Self> {
        Ok(Self {
            id: row.get_i64("id")?,
            report_id: row.get_i64("report_id")?,
            assignee_id: row.get_optional_i64("assignee_id")?,
            status: row.get_string("status")?,
            opened_at: row.get_datetime("opened_at")?,
        })
    }

    fn insert_values(&self) -> Vec<Value> {
        vec![
            Value::I64(self.report_id),
            match self.assignee_id {
                Some(id) => Value::I64(id),
                None => Value::Null,
            },
            Value::Text(self.status.clone()),
            Value::DateTime(self.opened_at),
        ]
    }
}
