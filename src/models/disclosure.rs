//! `Disclosure` — every reporter-identity unmask, audited.
//!
//! Inserting a Disclosure row IS the unmask. Phase 4's runtime
//! function will write this row inside the same handler that
//! returns the reporter's identity to the requesting compliance
//! lead — gated by the framework's re-auth wall (both factors
//! when MFA is enrolled) so a stolen cookie cannot trigger an
//! unmask.
//!
//! The row is irreversible: there is no DELETE path on this
//! table in the framework code. Operator retention policies
//! handle archival; the audit chain is the regulatory artefact.

use chrono::{DateTime, Utc};
use rustio_admin::orm::{Model, Row, Value};
use rustio_admin::{ModelAdmin, Result, RustioAdmin};

#[derive(RustioAdmin)]
pub struct Disclosure {
    pub id: i64,
    pub case_id: i64,
    pub requested_by: i64,
    pub reason: String,
    pub disclosed_at: DateTime<Utc>,
}

impl ModelAdmin for Disclosure {
    fn list_display() -> &'static [&'static str] {
        &["case_id", "requested_by", "disclosed_at"]
    }
    fn search_fields() -> &'static [&'static str] {
        &["reason"]
    }
    fn ordering() -> &'static [&'static str] {
        &["-disclosed_at"]
    }
}

impl Model for Disclosure {
    const TABLE: &'static str = "disclosures";
    const COLUMNS: &'static [&'static str] =
        &["id", "case_id", "requested_by", "reason", "disclosed_at"];
    const INSERT_COLUMNS: &'static [&'static str] =
        &["case_id", "requested_by", "reason", "disclosed_at"];

    fn id(&self) -> i64 {
        self.id
    }

    fn from_row(row: Row<'_>) -> Result<Self> {
        Ok(Self {
            id: row.get_i64("id")?,
            case_id: row.get_i64("case_id")?,
            requested_by: row.get_i64("requested_by")?,
            reason: row.get_string("reason")?,
            disclosed_at: row.get_datetime("disclosed_at")?,
        })
    }

    fn insert_values(&self) -> Vec<Value> {
        vec![
            Value::I64(self.case_id),
            Value::I64(self.requested_by),
            Value::Text(self.reason.clone()),
            Value::DateTime(self.disclosed_at),
        ]
    }
}
