//! Case detail page — the handler's primary workflow surface.
//!
//! ## Route
//!
//! - `GET /admin/cases/:case_id/work` → [`show_case_detail`]
//!
//! ## Authority
//!
//! Gated at `Role::Staff` (handler tier) via the project's
//! `auth_helper::require_role`, with an in-handler filter:
//!
//! - Compliance leads (Administrator or higher) see every case.
//! - Handlers (Staff) see only cases where they are the assignee.
//! - Anyone else falls back to 403.
//!
//! ## What this page shows (Phase 3b)
//!
//! Read-only view of a single case. Five sections:
//!
//! 1. **Metadata** — case id, status, severity, channel,
//!    opened_at, assignee.
//! 2. **Reporter identity** — whether the reporter disclosed
//!    an email. The email value itself is intentionally NOT
//!    rendered on this page; reading it requires the Phase 4
//!    Disclosure unmask flow (re-auth + Disclosure row +
//!    irreversible audit). Phase 3b shows only the boolean
//!    state ("Anonym rapport" / "E-post angiven — kräver
//!    identitetsupplysning för att läsas").
//! 3. **Original report** — summary + body, exactly as the
//!    reporter submitted.
//! 4. **Action history** — every `case_actions` row joined to
//!    the actor's email, ordered newest-first. The
//!    case-level audit narrative.
//! 5. **Workflow buttons** — placeholder for Phase 3c's
//!    status transitions, internal notes, and assignment.
//!    Phase 3b's page renders the section header + a
//!    "Kommande funktion" note; the buttons themselves land
//!    in the next commit.

use rustio_admin::auth::Role;
use rustio_admin::{Db, Request, Response, Result};

use crate::auth_helper::{require_role, AccessGuard};

// ---- Case detail (GET /admin/cases/:case_id/work) --------------------------

pub(crate) async fn show_case_detail(db: Db, case_id: i64, req: Request) -> Result<Response> {
    let identity = match require_role(&db, &req, Role::Staff).await? {
        AccessGuard::Redirect(r) => return Ok(r),
        AccessGuard::Allow(i) => i,
    };

    // Load the case row + the linked report row + the assignee
    // email in three small queries. We could collapse this into
    // one JOIN, but three queries against indexed primary keys
    // run in microseconds and the code reads cleanly.

    let case_row: Option<CaseRow> = sqlx::query_as::<_, CaseRow>(
        "SELECT id, report_id, assignee_id, status, opened_at, closed_at \
           FROM cases WHERE id = $1",
    )
    .bind(case_id)
    .fetch_optional(db.pool())
    .await
    .map_err(rustio_admin::Error::from)?;

    let case = match case_row {
        Some(c) => c,
        None => return Ok(not_found()),
    };

    // Handler-tier authority filter: a Staff user without
    // Administrator rights sees only their own assigned cases.
    let is_lead = identity.role.includes(Role::Administrator);
    let is_assignee = case.assignee_id == Some(identity.user_id);
    if !is_lead && !is_assignee {
        return Ok(forbidden());
    }

    let report: ReportRow = sqlx::query_as::<_, ReportRow>(
        "SELECT summary, body, severity, channel, reporter_email IS NOT NULL AS has_email, \
                submitted_at \
           FROM reports WHERE id = $1",
    )
    .bind(case.report_id)
    .fetch_one(db.pool())
    .await
    .map_err(rustio_admin::Error::from)?;

    let assignee_email: Option<String> = match case.assignee_id {
        Some(uid) => sqlx::query_scalar("SELECT email FROM rustio_users WHERE id = $1")
            .bind(uid)
            .fetch_optional(db.pool())
            .await
            .map_err(rustio_admin::Error::from)?,
        None => None,
    };

    let actions: Vec<ActionRow> = sqlx::query_as::<_, ActionRow>(
        "SELECT ca.action_type, ca.note, ca.created_at, COALESCE(u.email, '<deleted user>') AS actor_email \
           FROM case_actions ca \
           LEFT JOIN rustio_users u ON u.id = ca.actor_id \
          WHERE ca.case_id = $1 \
          ORDER BY ca.created_at DESC",
    )
    .bind(case_id)
    .fetch_all(db.pool())
    .await
    .map_err(rustio_admin::Error::from)?;

    Ok(Response::html(render_detail(
        &identity.email,
        &case,
        &report,
        assignee_email.as_deref(),
        &actions,
    )))
}

// ---- Row structs (sqlx FromRow) --------------------------------------------
//
// These are local to this handler — they exist only because
// `sqlx::query_as` needs a target type. The framework's `Model`
// surface deliberately omits `closed_at` from `Case` because the
// 0.7 `RustioAdmin` derive does not yet support
// `Option<DateTime<Utc>>`; here we read the column directly with
// sqlx::FromRow so the case detail page can surface it once
// Phase 3c lands status-transitions that stamp it.

#[derive(sqlx::FromRow)]
struct CaseRow {
    id: i64,
    report_id: i64,
    assignee_id: Option<i64>,
    status: String,
    opened_at: chrono::DateTime<chrono::Utc>,
    #[allow(dead_code)] // surfaces once Phase 3c stamps `closed_at` on terminal transitions
    closed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(sqlx::FromRow)]
struct ReportRow {
    summary: String,
    body: String,
    severity: String,
    channel: String,
    has_email: bool,
    submitted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow)]
struct ActionRow {
    action_type: String,
    note: String,
    created_at: chrono::DateTime<chrono::Utc>,
    actor_email: String,
}

// ---- Swedish labels --------------------------------------------------------
//
// Duplicated from the public + triage handlers for Phase 3b
// self-containment. A later refactor will extract to
// `crate::labels` once the trio drifts enough to warrant it.

fn status_label_sv(status: &str) -> &'static str {
    match status {
        "intake" => "Mottagen",
        "triage" => "Under granskning",
        "investigating" => "Under utredning",
        "resolved" => "Avslutad",
        "archived" => "Arkiverad",
        _ => "Okänd",
    }
}

fn severity_label_sv(severity: &str) -> &'static str {
    match severity {
        "low" => "Låg",
        "medium" => "Medel",
        "high" => "Hög",
        "critical" => "Kritisk",
        _ => "Okänd",
    }
}

fn channel_label_sv(channel: &str) -> &'static str {
    match channel {
        "web" => "Webb",
        "phone" => "Telefon",
        "in_person" => "Personlig",
        "email" => "E-post",
        _ => "Okänd",
    }
}

fn action_type_label_sv(action_type: &str) -> &'static str {
    match action_type {
        "case_opened" => "Ärende öppnat",
        "assigned" => "Tilldelad",
        "reassigned" => "Omtilldelad",
        "status_changed" => "Status ändrad",
        "note_added" => "Anteckning tillagd",
        "document_uploaded" => "Dokument uppladdat",
        "document_downloaded" => "Dokument nedladdat",
        "disclosure_requested" => "Identitetsupplysning begärd",
        "disclosure_consumed" => "Identitet avslöjad",
        _ => "Okänd händelse",
    }
}

// ---- Rendering -------------------------------------------------------------

fn render_detail(
    actor_email: &str,
    case: &CaseRow,
    report: &ReportRow,
    assignee_email: Option<&str>,
    actions: &[ActionRow],
) -> String {
    let assignee_html = match assignee_email {
        Some(email) => format!(r#"<strong>{}</strong>"#, escape(email)),
        None => r#"<em class="lur-muted">Ingen tilldelad</em>"#.to_string(),
    };

    let reporter_html = if report.has_email {
        r#"<div class="lur-reporter-state">
  <span class="lur-pill lur-pill-warn">E-post angiven</span>
  <p>Reporterns e-post finns lagrad men visas inte här. För att
  läsa identiteten krävs en formell identitetsupplysning som
  loggas i ärendet (kommande funktion — Phase 4).</p>
</div>"#
            .to_string()
    } else {
        r#"<div class="lur-reporter-state">
  <span class="lur-pill lur-pill-neutral">Anonym rapport</span>
  <p>Reportern har inte angett någon e-postadress. Det finns
  ingen identitet att läsa.</p>
</div>"#
            .to_string()
    };

    let history_html = if actions.is_empty() {
        r#"<p class="lur-muted">Inga åtgärder registrerade.</p>"#.to_string()
    } else {
        let mut buf = String::from(r#"<ul class="lur-history">"#);
        for a in actions {
            let note_html = if a.note.is_empty() {
                String::new()
            } else {
                format!(r#"<p class="lur-history-note">{}</p>"#, escape(&a.note))
            };
            buf.push_str(&format!(
                r#"<li class="lur-history-item">
  <div class="lur-history-head">
    <span class="lur-history-action">{action_label}</span>
    <span class="lur-history-meta">{actor} · {when}</span>
  </div>
  {note_html}
</li>"#,
                action_label = escape(action_type_label_sv(&a.action_type)),
                actor = escape(&a.actor_email),
                when = a.created_at.format("%Y-%m-%d %H:%M"),
                note_html = note_html,
            ));
        }
        buf.push_str("</ul>");
        buf
    };

    format!(
        r#"<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ärende #{case_id} — Lursystem</title>
<style>{css}</style>
</head>
<body>
<header class="lur-op-header">
  <div class="lur-op-shell">
    <span class="lur-op-brand">Lursystem · Operatörsgränssnitt</span>
    <span class="lur-op-actor">Inloggad som <strong>{actor_email}</strong>
      · <a href="/admin/triage">Triage</a>
      · <a href="/admin">Adminpanel</a>
      · <a href="/admin/logout">Logga ut</a></span>
  </div>
</header>

<main class="lur-op-shell lur-op-detail">
  <div class="lur-detail-titlebar">
    <h1 class="lur-op-title">Ärende #{case_id}</h1>
    <span class="lur-status-pill lur-status-{case_status}">{case_status_label}</span>
  </div>

  <section class="lur-section">
    <h2>Metadata</h2>
    <dl class="lur-dl">
      <dt>Rapport</dt><dd>#{report_id}</dd>
      <dt>Allvarlighetsgrad</dt><dd>{severity_label}</dd>
      <dt>Kanal</dt><dd>{channel_label}</dd>
      <dt>Inlämnad</dt><dd>{submitted_at}</dd>
      <dt>Öppnad</dt><dd>{opened_at}</dd>
      <dt>Tilldelad</dt><dd>{assignee_html}</dd>
    </dl>
  </section>

  <section class="lur-section">
    <h2>Reportern</h2>
    {reporter_html}
  </section>

  <section class="lur-section">
    <h2>Sammanfattning</h2>
    <p class="lur-report-summary">{summary}</p>
  </section>

  <section class="lur-section">
    <h2>Beskrivning</h2>
    <pre class="lur-report-body">{body}</pre>
  </section>

  <section class="lur-section">
    <h2>Historik</h2>
    {history_html}
  </section>

  <section class="lur-section">
    <h2>Åtgärder</h2>
    <p class="lur-muted">Statusändringar, anteckningar och tilldelningar — kommande
    funktion (Phase 3c).</p>
  </section>
</main>
</body>
</html>
"#,
        case_id = case.id,
        case_status = escape(&case.status),
        case_status_label = escape(status_label_sv(&case.status)),
        report_id = case.report_id,
        severity_label = escape(severity_label_sv(&report.severity)),
        channel_label = escape(channel_label_sv(&report.channel)),
        submitted_at = report.submitted_at.format("%Y-%m-%d %H:%M"),
        opened_at = case.opened_at.format("%Y-%m-%d %H:%M"),
        assignee_html = assignee_html,
        reporter_html = reporter_html,
        summary = escape(&report.summary),
        body = escape(&report.body),
        history_html = history_html,
        actor_email = escape(actor_email),
        css = operator_css(),
    )
}

fn not_found() -> Response {
    Response::html(
        format!(
            r#"<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<title>Ärende saknas — Lursystem</title>
<style>{css}</style>
</head>
<body>
<main class="lur-op-shell">
  <h1 class="lur-op-title">Ärende saknas</h1>
  <p class="lur-muted">Det finns inget ärende med den ID:n.</p>
  <p><a href="/admin/triage">← Tillbaka till triage</a></p>
</main>
</body>
</html>
"#,
            css = operator_css()
        )
        .to_string(),
    )
    .with_status(hyper::StatusCode::NOT_FOUND)
}

fn forbidden() -> Response {
    Response::html(
        format!(
            r#"<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<title>Åtkomst nekad — Lursystem</title>
<style>{css}</style>
</head>
<body>
<main class="lur-op-shell">
  <h1 class="lur-op-title">Åtkomst nekad</h1>
  <p class="lur-muted">Det här ärendet är tilldelat någon annan.</p>
  <p><a href="/admin">← Tillbaka</a></p>
</main>
</body>
</html>
"#,
            css = operator_css()
        )
        .to_string(),
    )
    .with_status(hyper::StatusCode::FORBIDDEN)
}

fn operator_css() -> &'static str {
    r#"
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: #f4f6f7;
  color: #1c2326;
  font-size: 14px;
  line-height: 1.5;
}
.lur-op-header {
  background: #0e1f1e;
  color: #d9e3e1;
  border-bottom: 1px solid #0a1716;
}
.lur-op-shell {
  max-width: 1100px;
  margin: 0 auto;
  padding: 14px 28px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 13px;
}
.lur-op-brand {
  font-weight: 600;
  letter-spacing: 0.02em;
}
.lur-op-actor a {
  color: #6dd6c4;
  text-decoration: none;
  margin-left: 4px;
}
.lur-op-actor a:hover { text-decoration: underline; }
main.lur-op-shell {
  display: block;
  background: transparent;
  padding-top: 32px;
  padding-bottom: 96px;
}
main.lur-op-detail { max-width: 880px; }
.lur-detail-titlebar {
  display: flex;
  align-items: center;
  gap: 16px;
  margin: 0 0 32px;
}
.lur-op-title {
  font-size: 26px;
  font-weight: 600;
  margin: 0;
  letter-spacing: -0.01em;
}
.lur-section {
  background: #ffffff;
  border: 1px solid #dde3e6;
  padding: 24px 28px;
  margin-bottom: 16px;
}
.lur-section h2 {
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: #5d6a72;
  font-weight: 600;
  margin: 0 0 16px;
}
.lur-dl {
  display: grid;
  grid-template-columns: 200px 1fr;
  gap: 8px 16px;
  margin: 0;
}
.lur-dl dt {
  color: #5d6a72;
  font-size: 13px;
}
.lur-dl dd {
  margin: 0;
  font-weight: 500;
}
.lur-muted {
  color: #5d6a72;
}
.lur-reporter-state p {
  margin: 12px 0 0;
  font-size: 13px;
  color: #5d6a72;
  max-width: 580px;
}
.lur-pill {
  display: inline-block;
  font-size: 12px;
  font-weight: 600;
  padding: 3px 10px;
  border-radius: 10px;
}
.lur-pill-neutral { background: #eef2f3; color: #5d6a72; }
.lur-pill-warn    { background: #fcf6e3; color: #6d5108; }
.lur-status-pill {
  display: inline-block;
  font-size: 12px;
  font-weight: 600;
  padding: 4px 14px;
  border-radius: 12px;
}
.lur-status-intake        { background: #eef2f3; color: #5d6a72; }
.lur-status-triage        { background: #e0eef9; color: #1c4a78; }
.lur-status-investigating { background: #fcf6e3; color: #6d5108; }
.lur-status-resolved      { background: #ecf6f3; color: #0a6e62; }
.lur-status-archived      { background: #eaeef0; color: #444b50; }
.lur-report-summary {
  margin: 0;
  font-weight: 500;
  font-size: 15px;
}
.lur-report-body {
  margin: 0;
  font-family: inherit;
  white-space: pre-wrap;
  word-wrap: break-word;
  font-size: 14px;
  line-height: 1.6;
  background: #fafbfc;
  padding: 16px;
  border-radius: 2px;
  max-height: 480px;
  overflow: auto;
}
.lur-history { list-style: none; margin: 0; padding: 0; }
.lur-history-item {
  padding: 14px 0;
  border-bottom: 1px solid #eef2f3;
}
.lur-history-item:last-child { border-bottom: 0; }
.lur-history-head {
  display: flex;
  align-items: baseline;
  gap: 12px;
}
.lur-history-action {
  font-weight: 600;
  font-size: 14px;
}
.lur-history-meta {
  color: #5d6a72;
  font-size: 12px;
}
.lur-history-note {
  margin: 6px 0 0;
  color: #1c2326;
  font-size: 13px;
}
a { color: #0a6e62; }
"#
}

fn escape(input: &str) -> String {
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
