//! Triage queue — the compliance lead's intake-review surface.
//!
//! ## Routes
//!
//! - `GET  /admin/triage`                        → [`show_triage_queue`]
//! - `POST /admin/triage/:report_id/open-case`   → [`do_open_case`]
//!
//! ## Authority
//!
//! Both routes are gated at `Role::Administrator` via the
//! project's `auth_helper::require_role`. In the project's
//! role model (per the README) the Compliance lead carries
//! the Administrator framework role; Handlers carry Staff.
//! Triage is a Compliance-lead-only surface — handlers see
//! cases only after a lead has opened one and assigned it.
//!
//! ## What triage does
//!
//! `GET /admin/triage` shows every report still in
//! `status='intake'` — these are the submissions that have
//! never been touched. The compliance lead reviews each, then
//! clicks "Öppna ärende" (open case) to transition the
//! report into the active workflow.
//!
//! `POST /admin/triage/:report_id/open-case` runs the
//! transition inside a single transaction:
//!
//!   1. `SELECT … FOR UPDATE` the report row to serialise
//!      concurrent triage actions on the same report.
//!   2. Reject if the report is not in `intake` status —
//!      another lead got there first.
//!   3. INSERT a fresh `cases` row referencing the report,
//!      `status='triage'`, `opened_at=NOW()`, no assignee
//!      yet (assignment lands in Phase 3c).
//!   4. UPDATE the report's status to `triage` so the
//!      reporter's status-check page reflects the change.
//!   5. INSERT a `case_actions` row with
//!      `action_type='case_opened'` — the case-level audit
//!      overlay's first entry.
//!
//! The framework's `rustio_admin_actions` audit chain captures
//! the lower-level "POST /admin/triage/X/open-case landed,
//! correlation_id=Y, session_id=Z" record automatically via
//! the middleware (R0+ scaffolding). This handler does NOT
//! emit a framework-level AuditEvent because there isn't a
//! variant for "case opened" — that's a project-domain
//! signal, captured in `case_actions`.

use rustio_admin::auth::Role;
use rustio_admin::middleware::CsrfGuard;
use rustio_admin::{Db, Request, Response, Result};

use crate::auth_helper::{require_role, AccessGuard};

// ---- Triage queue (GET /admin/triage) --------------------------------------

pub(crate) async fn show_triage_queue(db: Db, req: Request) -> Result<Response> {
    let identity = match require_role(&db, &req, Role::Administrator).await? {
        AccessGuard::Redirect(r) => return Ok(r),
        AccessGuard::Allow(i) => i,
    };

    let csrf = csrf_token_from(&req);

    let rows: Vec<(i64, String, String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT id, summary, severity, channel, submitted_at \
           FROM reports \
          WHERE status = 'intake' \
          ORDER BY submitted_at ASC",
    )
    .fetch_all(db.pool())
    .await
    .map_err(rustio_admin::Error::from)?;

    Ok(Response::html(render_queue(&csrf, &identity.email, &rows)))
}

// ---- Open case (POST /admin/triage/:report_id/open-case) -------------------

pub(crate) async fn do_open_case(db: Db, report_id: i64, req: Request) -> Result<Response> {
    let identity = match require_role(&db, &req, Role::Administrator).await? {
        AccessGuard::Redirect(r) => return Ok(r),
        AccessGuard::Allow(i) => i,
    };

    let mut tx = db.pool().begin().await.map_err(rustio_admin::Error::from)?;

    // 1. Lock the report row + check status.
    let report_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM reports WHERE id = $1 FOR UPDATE")
            .bind(report_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(rustio_admin::Error::from)?;

    let report_status = match report_status {
        Some(s) => s,
        None => {
            // Unknown report id. Surfaces if a stale form is
            // submitted after the report has been deleted by
            // another path. Redirect back to triage.
            return Ok(Response::redirect("/admin/triage?error=unknown"));
        }
    };

    if report_status != "intake" {
        // Another compliance lead already opened a case for
        // this report between the GET and the POST. The race
        // is benign — refresh the page.
        return Ok(Response::redirect("/admin/triage?error=race"));
    }

    // 2. INSERT the case.
    let case_id: i64 = sqlx::query_scalar(
        "INSERT INTO cases (report_id, status, opened_at) \
         VALUES ($1, 'triage', NOW()) \
         RETURNING id",
    )
    .bind(report_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(rustio_admin::Error::from)?;

    // 3. UPDATE the report's status to keep it in sync with
    //    the case. The reporter's /report/status page reads
    //    the report's status column.
    sqlx::query("UPDATE reports SET status = 'triage' WHERE id = $1")
        .bind(report_id)
        .execute(&mut *tx)
        .await
        .map_err(rustio_admin::Error::from)?;

    // 4. INSERT the case-level audit overlay row.
    sqlx::query(
        "INSERT INTO case_actions (case_id, actor_id, action_type, note) \
         VALUES ($1, $2, 'case_opened', $3)",
    )
    .bind(case_id)
    .bind(identity.user_id)
    .bind(format!("Opened from report #{report_id}"))
    .execute(&mut *tx)
    .await
    .map_err(rustio_admin::Error::from)?;

    tx.commit().await.map_err(rustio_admin::Error::from)?;

    log::info!(
        "lursystem: case opened id={} report_id={} by user_id={}",
        case_id,
        report_id,
        identity.user_id,
    );

    // Redirect back to the triage queue. Phase 3b's case
    // detail page (when it lands) will redirect to
    // /admin/cases/{case_id}/work instead so the lead lands
    // on the new case directly.
    Ok(Response::redirect("/admin/triage"))
}

// ---- Helpers ---------------------------------------------------------------

fn csrf_token_from(req: &Request) -> String {
    req.ctx()
        .get::<CsrfGuard>()
        .map(|g| g.token.clone())
        .unwrap_or_default()
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

fn render_queue(
    csrf: &str,
    actor_email: &str,
    rows: &[(i64, String, String, String, chrono::DateTime<chrono::Utc>)],
) -> String {
    let actor_email_escaped = escape(actor_email);

    let table_html = if rows.is_empty() {
        r#"<p class="lur-empty">Inga rapporter i kö.</p>"#.to_string()
    } else {
        let mut buf = String::new();
        buf.push_str(
            r#"<table class="lur-queue">
<thead>
<tr>
  <th>ID</th>
  <th>Inlämnad</th>
  <th>Allvarlighetsgrad</th>
  <th>Kanal</th>
  <th>Sammanfattning</th>
  <th class="lur-col-action">Åtgärd</th>
</tr>
</thead>
<tbody>
"#,
        );
        for (id, summary, severity, channel, submitted_at) in rows {
            let summary_short = if summary.chars().count() > 80 {
                let truncated: String = summary.chars().take(77).collect();
                format!("{truncated}…")
            } else {
                summary.clone()
            };
            buf.push_str(&format!(
                r#"<tr>
  <td class="lur-mono">#{id}</td>
  <td>{date}</td>
  <td><span class="lur-sev-{sev}">{sev_label}</span></td>
  <td>{channel_label}</td>
  <td>{summary}</td>
  <td class="lur-col-action">
    <form method="post" action="/admin/triage/{id}/open-case">
      <input type="hidden" name="_csrf" value="{csrf}">
      <button type="submit">Öppna ärende</button>
    </form>
  </td>
</tr>
"#,
                id = id,
                date = submitted_at.format("%Y-%m-%d %H:%M"),
                sev = severity,
                sev_label = severity_label_sv(severity),
                channel_label = channel_label_sv(channel),
                summary = escape(&summary_short),
                csrf = escape(csrf),
            ));
        }
        buf.push_str("</tbody>\n</table>");
        buf
    };

    format!(
        r#"<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Triagekö — Lursystem</title>
<style>{css}</style>
</head>
<body>
<header class="lur-op-header">
  <div class="lur-op-shell">
    <span class="lur-op-brand">Lursystem · Operatörsgränssnitt</span>
    <span class="lur-op-actor">Inloggad som <strong>{actor_email_escaped}</strong> · <a href="/admin">Adminpanel</a> · <a href="/admin/logout">Logga ut</a></span>
  </div>
</header>

<main class="lur-op-shell">
  <h1 class="lur-op-title">Triagekö</h1>
  <p class="lur-op-intro">
    Rapporter som väntar på första bedömning. Öppna ett ärende
    för att starta utredningsflödet — rapportens status flyttas
    från <em>Mottagen</em> till <em>Under granskning</em> och
    ett <code>case_action</code>-spår skapas.
  </p>

  {table_html}
</main>
</body>
</html>
"#,
        css = operator_css(),
        actor_email_escaped = actor_email_escaped,
        table_html = table_html,
    )
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
.lur-op-title {
  font-size: 26px;
  font-weight: 600;
  margin: 0 0 8px;
  letter-spacing: -0.01em;
}
.lur-op-intro {
  color: #5d6a72;
  margin: 0 0 24px;
  font-size: 14px;
  max-width: 640px;
}
.lur-op-intro em {
  font-style: normal;
  font-weight: 600;
  color: #1c2326;
}
.lur-op-intro code {
  font-family: "SF Mono", "JetBrains Mono", Consolas, monospace;
  font-size: 13px;
  background: #eaeef0;
  padding: 1px 6px;
  border-radius: 2px;
}
.lur-empty {
  background: #ffffff;
  border: 1px solid #dde3e6;
  padding: 32px;
  text-align: center;
  color: #5d6a72;
}
.lur-queue {
  width: 100%;
  border-collapse: collapse;
  background: #ffffff;
  border: 1px solid #dde3e6;
}
.lur-queue th,
.lur-queue td {
  padding: 12px 16px;
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid #eef2f3;
}
.lur-queue th {
  background: #fafbfc;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: #5d6a72;
}
.lur-queue tbody tr:last-child td { border-bottom: 0; }
.lur-mono {
  font-family: "SF Mono", "JetBrains Mono", Consolas, monospace;
  color: #5d6a72;
}
.lur-col-action {
  width: 1%;
  white-space: nowrap;
}
.lur-col-action button {
  background: #0f8c7e;
  color: #ffffff;
  border: 0;
  padding: 8px 16px;
  font: inherit;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  border-radius: 2px;
}
.lur-col-action button:hover { background: #0a6e62; }
.lur-sev-low,
.lur-sev-medium,
.lur-sev-high,
.lur-sev-critical {
  display: inline-block;
  font-size: 12px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 10px;
}
.lur-sev-low      { background: #eef2f3; color: #5d6a72; }
.lur-sev-medium   { background: #fcf6e3; color: #6d5108; }
.lur-sev-high     { background: #fde5d0; color: #7d3a14; }
.lur-sev-critical { background: #fde0de; color: #832723; }
"#
}

/// Minimal HTML-escape. Same shape as the public handler's helper;
/// duplicated locally to keep this module self-contained — refactor
/// to a shared `lur::escape` in a later phase if a third surface
/// needs it.
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
