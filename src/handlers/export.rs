//! Compliance export — Phase 6's tamper-evident artefact.
//!
//! ## Route
//!
//! - `GET /admin/audit/export?from=YYYY-MM-DD&to=YYYY-MM-DD` → [`do_export`]
//!
//! ## Why this exists
//!
//! Swedish lag (2021:890) §22-25 + EU Whistleblower Directive
//! Article 18 require employers to maintain audit-trail records
//! of every whistleblower report and disposition, retained for at
//! least the statutory minimum (3 years in Sweden, longer in
//! several other EU member states), and producible on demand for
//! supervisory authorities (in Sweden: Arbetsmiljöverket / IMY
//! depending on the report subject matter).
//!
//! This handler produces a single signed JSON file covering every
//! audit-bearing row in a date range. The signature is the
//! tamper-evidence: a verifier with the operator's
//! `RUSTIO_SECRET_KEY` can recompute the HMAC and confirm the file
//! has not been edited since export.
//!
//! ## Authority
//!
//! `Role::Supervisor` floor (same as `/admin/audit`).
//! Administrators and Developers inherit the access. Staff
//! handlers and reporters cannot reach the export.
//!
//! ## Signing
//!
//! HMAC-SHA256 over the compact serde_json encoding of the
//! [`ExportPayload`] struct, keyed by `RUSTIO_SECRET_KEY`. The
//! signature is base64-standard. The verification protocol is
//! documented inline below — a verifier must:
//!
//!   1. Parse the JSON.
//!   2. Take the `payload` sub-object (NOT the top-level object
//!      that also contains the signature).
//!   3. Re-serialize it with compact serde_json, same field
//!      order.
//!   4. Compute HMAC-SHA256(secret, payload_bytes).
//!   5. Base64-encode and compare to the signature value.
//!
//! Field order must match the struct's declared order; this
//! handler depends on serde_json's stable in-order serialization.
//!
//! ## What the export DOES NOT contain
//!
//! Reporter e-mail addresses. The Phase 4 unmask flow is the only
//! surface that renders a reporter's e-mail. An export handed to
//! a regulator carries the audit chain (every disclosure event,
//! including the reason) but never the e-mail itself; a regulator
//! that needs the e-mail must contact the operator to trigger a
//! fresh disclosure, which itself audits.
//!
//! The reporter token is also excluded — it is the reporter's
//! own credential for the `/report/status` page, not part of the
//! audit chain.
//!
//! ## Audit of the audit
//!
//! Each export emits a `log::info!` line carrying the actor,
//! correlation_id, date range, and row counts. The framework's
//! correlation_id middleware ties the export request to the
//! operator's session and the wider request log. A future phase
//! could add a dedicated `exports` table; for now the structured
//! log line is the artefact.

use base64::Engine;
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;

use rustio_admin::auth::Role;
use rustio_admin::middleware::CorrelationId;
use rustio_admin::{Db, Error, Request, Response, Result};

use crate::auth_helper::{require_role, AccessGuard};

type HmacSha256 = Hmac<Sha256>;

// ---- Locked decisions (Phase 6) -------------------------------------------

/// Export schema version. Bump when the [`ExportPayload`] field
/// shape changes. Verifiers use this to pick the right parsing
/// path.
const EXPORT_VERSION: u32 = 1;

/// Maximum date-range width the export accepts. Set to ~14
/// months so a "full year" + a one-month overlap is fine but
/// pathological "give me the last decade" requests are rejected.
/// A regulator wanting more than a year's worth of data should
/// pull two adjacent exports and concatenate them downstream.
const MAX_RANGE_DAYS: i64 = 14 * 31;

// ---- GET /admin/audit/export ----------------------------------------------

pub(crate) async fn do_export(db: Db, req: Request) -> Result<Response> {
    let identity = match require_role(&db, &req, Role::Supervisor).await? {
        AccessGuard::Redirect(r) => return Ok(r),
        AccessGuard::Allow(i) => i,
    };

    let q = req.query();
    let from_raw = q.get("from").unwrap_or("").to_string();
    let to_raw = q.get("to").unwrap_or("").to_string();

    let from_date = match NaiveDate::parse_from_str(&from_raw, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => {
            return Ok(bad_request(
                "Saknar eller ogiltigt 'from'-datum (förväntat YYYY-MM-DD).",
            ))
        }
    };
    let to_date = match NaiveDate::parse_from_str(&to_raw, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => {
            return Ok(bad_request(
                "Saknar eller ogiltigt 'to'-datum (förväntat YYYY-MM-DD).",
            ))
        }
    };
    if to_date < from_date {
        return Ok(bad_request(
            "'to'-datumet måste vara samma eller efter 'from'.",
        ));
    }
    let span_days = (to_date - from_date).num_days();
    if span_days > MAX_RANGE_DAYS {
        return Ok(bad_request(
            "Datumintervallet är för stort. Max omkring 14 månader per export.",
        ));
    }

    let from_ts = Utc
        .from_local_datetime(&from_date.and_hms_opt(0, 0, 0).expect("00:00 is valid"))
        .single()
        .expect("UTC has no DST");
    // Exclusive upper bound: the 'to' date is INCLUSIVE so we
    // bump it to the next midnight and use `<`. This way "from
    // 2026-04-01 to 2026-06-30" covers Q2 cleanly.
    let to_ts_exclusive = Utc
        .from_local_datetime(
            &to_date
                .succ_opt()
                .ok_or_else(|| {
                    Error::BadRequest(
                        "to-datumet är otillräckligt för att räkna ut nästa dag".into(),
                    )
                })?
                .and_hms_opt(0, 0, 0)
                .expect("00:00 is valid"),
        )
        .single()
        .expect("UTC has no DST");

    let correlation = req.ctx().get::<CorrelationId>().map(|c| c.0.clone());

    // ---- Pull every audit-bearing row in the range ----

    let reports: Vec<ReportRow> = sqlx::query_as::<_, ReportRow>(
        "SELECT id, status, severity, channel, summary, body, submitted_at \
           FROM reports \
          WHERE submitted_at >= $1 AND submitted_at < $2 \
          ORDER BY id",
    )
    .bind(from_ts)
    .bind(to_ts_exclusive)
    .fetch_all(db.pool())
    .await
    .map_err(Error::from)?;

    let cases: Vec<CaseRow> = sqlx::query_as::<_, CaseRow>(
        "SELECT id, report_id, assignee_id, status, opened_at, closed_at \
           FROM cases \
          WHERE opened_at >= $1 AND opened_at < $2 \
          ORDER BY id",
    )
    .bind(from_ts)
    .bind(to_ts_exclusive)
    .fetch_all(db.pool())
    .await
    .map_err(Error::from)?;

    let case_actions: Vec<CaseActionRow> = sqlx::query_as::<_, CaseActionRow>(
        "SELECT ca.id, ca.case_id, ca.actor_id, \
                COALESCE(u.email, '<deleted>') AS actor_email, \
                ca.action_type, ca.note, ca.created_at, ca.correlation_id \
           FROM case_actions ca \
           LEFT JOIN rustio_users u ON u.id = ca.actor_id \
          WHERE ca.created_at >= $1 AND ca.created_at < $2 \
          ORDER BY ca.id",
    )
    .bind(from_ts)
    .bind(to_ts_exclusive)
    .fetch_all(db.pool())
    .await
    .map_err(Error::from)?;

    let disclosures: Vec<DisclosureRow> = sqlx::query_as::<_, DisclosureRow>(
        "SELECT d.id, d.case_id, d.requested_by, \
                COALESCE(u.email, '<deleted>') AS requested_by_email, \
                d.reason, d.disclosed_at, d.correlation_id \
           FROM disclosures d \
           LEFT JOIN rustio_users u ON u.id = d.requested_by \
          WHERE d.disclosed_at >= $1 AND d.disclosed_at < $2 \
          ORDER BY d.id",
    )
    .bind(from_ts)
    .bind(to_ts_exclusive)
    .fetch_all(db.pool())
    .await
    .map_err(Error::from)?;

    // ---- Build the payload ----

    let metadata = ExportMetadata {
        system: "lursystem",
        generated_at: Utc::now(),
        generated_by: identity.email.clone(),
        generated_by_user_id: identity.user_id,
        range_from: from_date.format("%Y-%m-%d").to_string(),
        range_to: to_date.format("%Y-%m-%d").to_string(),
        correlation_id: correlation.clone(),
        counts: Counts {
            reports: reports.len() as u64,
            cases: cases.len() as u64,
            case_actions: case_actions.len() as u64,
            disclosures: disclosures.len() as u64,
        },
    };

    let payload = ExportPayload {
        v: EXPORT_VERSION,
        metadata,
        reports,
        cases,
        case_actions,
        disclosures,
    };

    // ---- Sign ----

    let secret = std::env::var("RUSTIO_SECRET_KEY").map_err(|_| {
        Error::Internal("RUSTIO_SECRET_KEY must be set for compliance export signing".into())
    })?;
    if secret.len() < 32 {
        // Same minimum the framework's AES-256-GCM init enforces.
        // A short key here means the operator deployed without
        // generating a real key; refuse to sign rather than emit
        // a low-entropy artefact.
        return Err(Error::Internal(
            "RUSTIO_SECRET_KEY too short (<32 bytes); refusing to sign export".into(),
        ));
    }

    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|e| Error::Internal(format!("serde_json failed on payload: {e}")))?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|e| Error::Internal(format!("HMAC init failed: {e}")))?;
    mac.update(&payload_bytes);
    let sig_bytes = mac.finalize().into_bytes();
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig_bytes);

    // ---- Emit the signed envelope ----

    let envelope = SignedExport {
        payload,
        signature: Signature {
            algorithm: "HMAC-SHA256",
            scope: "payload (compact serde_json encoding)",
            value: sig_b64,
        },
    };

    let body = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| Error::Internal(format!("serde_json failed on envelope: {e}")))?;

    log::info!(
        "lursystem: compliance export from={} to={} reports={} cases={} actions={} disclosures={} by user_id={} bytes={}",
        from_date,
        to_date,
        envelope.payload.metadata.counts.reports,
        envelope.payload.metadata.counts.cases,
        envelope.payload.metadata.counts.case_actions,
        envelope.payload.metadata.counts.disclosures,
        identity.user_id,
        body.len(),
    );

    let filename = format!(
        "lursystem-audit-{}-to-{}.json",
        from_date.format("%Y%m%d"),
        to_date.format("%Y%m%d"),
    );

    Ok(Response::new(hyper::StatusCode::OK, body)
        .with_header("content-type", "application/json; charset=utf-8")
        .with_header(
            "content-disposition",
            format!("attachment; filename=\"{filename}\""),
        ))
}

// ---- Serializable rows ----------------------------------------------------
//
// Field declaration order IS the canonical signing order. Do not
// reorder fields in these structs without bumping
// `EXPORT_VERSION`; verifiers depend on the order being stable.

#[derive(Serialize)]
struct SignedExport {
    payload: ExportPayload,
    signature: Signature,
}

#[derive(Serialize)]
struct Signature {
    algorithm: &'static str,
    scope: &'static str,
    value: String,
}

#[derive(Serialize)]
struct ExportPayload {
    v: u32,
    metadata: ExportMetadata,
    reports: Vec<ReportRow>,
    cases: Vec<CaseRow>,
    case_actions: Vec<CaseActionRow>,
    disclosures: Vec<DisclosureRow>,
}

#[derive(Serialize)]
struct ExportMetadata {
    system: &'static str,
    generated_at: DateTime<Utc>,
    generated_by: String,
    generated_by_user_id: i64,
    range_from: String,
    range_to: String,
    correlation_id: Option<String>,
    counts: Counts,
}

#[derive(Serialize)]
struct Counts {
    reports: u64,
    cases: u64,
    case_actions: u64,
    disclosures: u64,
}

#[derive(Serialize, sqlx::FromRow)]
struct ReportRow {
    id: i64,
    status: String,
    severity: String,
    channel: String,
    summary: String,
    body: String,
    submitted_at: DateTime<Utc>,
    // NOT included: reporter_email, reporter_token. The audit
    // chain records THAT a disclosure happened (via disclosures
    // rows below); the email itself is gated by the Phase 4
    // unmask flow, not by the export.
}

#[derive(Serialize, sqlx::FromRow)]
struct CaseRow {
    id: i64,
    report_id: i64,
    assignee_id: Option<i64>,
    status: String,
    opened_at: DateTime<Utc>,
    closed_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, sqlx::FromRow)]
struct CaseActionRow {
    id: i64,
    case_id: i64,
    actor_id: i64,
    actor_email: String,
    action_type: String,
    note: String,
    created_at: DateTime<Utc>,
    correlation_id: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct DisclosureRow {
    id: i64,
    case_id: i64,
    requested_by: i64,
    requested_by_email: String,
    reason: String,
    disclosed_at: DateTime<Utc>,
    correlation_id: Option<String>,
}

// ---- Error path -----------------------------------------------------------

fn bad_request(message: &str) -> Response {
    let body = format!(
        r#"<!doctype html>
<html lang="sv"><head><meta charset="utf-8">
<title>Felaktig exportbegäran — Lursystem</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       background: #f4f6f7; color: #1c2326; margin: 0; padding: 40px; }}
main {{ max-width: 640px; margin: 0 auto; background: #fff; border: 1px solid #dde3e6;
       padding: 28px 32px; }}
h1 {{ font-size: 22px; margin: 0 0 16px; }}
p  {{ font-size: 14px; line-height: 1.6; color: #3a464d; }}
a  {{ color: #0a6e62; }}
</style></head>
<body>
<main>
<h1>Felaktig exportbegäran</h1>
<p>{}</p>
<p><a href="/admin/audit">← Tillbaka till granskningsloggen</a></p>
</main>
</body></html>"#,
        html_escape(message),
    );
    Response::html(body).with_status(hyper::StatusCode::BAD_REQUEST)
}

fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}
