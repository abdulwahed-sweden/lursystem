//! `Document` — attachment metadata.
//!
//! The DB row carries only the metadata; the bytes live on the
//! local filesystem under `storage_path`. The Phase 3 handler
//! workflow streams the file at download time after the
//! framework's role guard + re-auth gate pass; the path is not
//! exposed to clients.
//!
//! Documents are scoped to a `Report`, not a `Case`, because
//! attachments arrive with the original submission (Phase 2's
//! public form). A case-level upload surface is deferred.

use chrono::{DateTime, Utc};
use rustio_admin::orm::{Model, Row, Value};
use rustio_admin::{ModelAdmin, Result, RustioAdmin};

#[derive(RustioAdmin)]
pub struct Document {
    pub id: i64,
    pub report_id: i64,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub storage_path: String,
    pub uploaded_at: DateTime<Utc>,
}

impl ModelAdmin for Document {
    fn list_display() -> &'static [&'static str] {
        &[
            "filename",
            "report_id",
            "content_type",
            "size_bytes",
            "uploaded_at",
        ]
    }
    fn search_fields() -> &'static [&'static str] {
        &["filename"]
    }
    fn ordering() -> &'static [&'static str] {
        &["-uploaded_at"]
    }
}

impl Model for Document {
    const TABLE: &'static str = "documents";
    const COLUMNS: &'static [&'static str] = &[
        "id",
        "report_id",
        "filename",
        "content_type",
        "size_bytes",
        "storage_path",
        "uploaded_at",
    ];
    const INSERT_COLUMNS: &'static [&'static str] = &[
        "report_id",
        "filename",
        "content_type",
        "size_bytes",
        "storage_path",
        "uploaded_at",
    ];

    fn id(&self) -> i64 {
        self.id
    }

    fn from_row(row: Row<'_>) -> Result<Self> {
        Ok(Self {
            id: row.get_i64("id")?,
            report_id: row.get_i64("report_id")?,
            filename: row.get_string("filename")?,
            content_type: row.get_string("content_type")?,
            size_bytes: row.get_i64("size_bytes")?,
            storage_path: row.get_string("storage_path")?,
            uploaded_at: row.get_datetime("uploaded_at")?,
        })
    }

    fn insert_values(&self) -> Vec<Value> {
        vec![
            Value::I64(self.report_id),
            Value::Text(self.filename.clone()),
            Value::Text(self.content_type.clone()),
            Value::I64(self.size_bytes),
            Value::Text(self.storage_path.clone()),
            Value::DateTime(self.uploaded_at),
        ]
    }
}
