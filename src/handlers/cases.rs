//! Case detail page — the handler's primary workflow surface.
//!
//! ## Routes
//!
//! - `GET  /admin/cases/:case_id/work`      → [`show_case_detail`]
//! - `POST /admin/cases/:case_id/status`    → [`do_status_transition`]
//! - `POST /admin/cases/:case_id/notes`     → [`do_add_note`]
//! - `POST /admin/cases/:case_id/reassign`  → [`do_reassign`]
//!
//! ## Authority
//!
//! - `show_case_detail` and `do_add_note` and `do_status_transition`:
//!   gated at `Role::Staff` with the in-handler filter
//!   (Administrator+ sees every case; Staff sees only their
//!   own assigned case; otherwise 403).
//! - `do_reassign`: gated at `Role::Administrator` — only the
//!   compliance lead can reassign cases. The reassign form is
//!   conditionally rendered only when the viewer is a lead.
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
use rustio_admin::middleware::{CorrelationId, CsrfGuard};
use rustio_admin::{Db, Request, Response, Result};

use crate::auth_helper::{is_session_elevated, require_role, AccessGuard};

// ---- Locked decisions (Phase 3c) -------------------------------------------

/// Internal-note size envelope. Floor catches accidental empty
/// submits; ceiling sits well below Postgres TEXT limits but
/// far enough above any real handler note that good-faith
/// users will never bump it.
const NOTE_MIN: usize = 3;
const NOTE_MAX: usize = 5_000;

/// Reassignment-target role floor. Cases get assigned to a
/// `Staff`-or-higher user (Handler, Compliance lead,
/// Developer). The reporter role (`User`) is never assignable.
const ASSIGNABLE_ROLES: &[&str] = &["staff", "supervisor", "administrator", "developer"];

// ---- Status state machine --------------------------------------------------

/// Returns the list of valid `target_status` values for a
/// case currently in `current_status`. An empty result means
/// the case is in a terminal state; the workflow buttons
/// render nothing.
///
/// Locked transitions:
///   triage        → investigating | archived
///   investigating → resolved | triage
///   resolved      → archived
///   archived      → (terminal — no transitions)
///
/// "investigating → triage" is the de-escalation path used
/// when an investigator decides the case should go back to the
/// triage queue (e.g. needs more information from the reporter,
/// needs reassignment to a different handler with different
/// expertise).
fn allowed_next_statuses(current: &str) -> &'static [&'static str] {
    match current {
        "triage" => &["investigating", "archived"],
        "investigating" => &["resolved", "triage"],
        "resolved" => &["archived"],
        _ => &[],
    }
}

/// Whether the transition `current → target` requires re-auth.
/// Terminal transitions (`resolved`, `archived`) demand a
/// fresh elevation because they are operationally
/// irreversible — once a case is marked resolved, the
/// investigation is signed off; once archived, the case is
/// closed for compliance review.
fn transition_requires_reauth(target: &str) -> bool {
    matches!(target, "resolved" | "archived")
}

/// Whether the transition is terminal — `closed_at` gets
/// stamped via direct sqlx for these (the framework's
/// `RustioAdmin` derive doesn't support
/// `Option<DateTime<Utc>>` so the column lives in SQL but
/// not on the `Case` Rust struct).
fn is_terminal_status(status: &str) -> bool {
    matches!(status, "resolved" | "archived")
}

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

    // Reassign-target list. Loaded only for compliance leads;
    // handlers viewing their own case don't see the reassign
    // form so the SELECT is skipped for them.
    let assignable_users: Vec<AssignableUser> = if is_lead {
        sqlx::query_as::<_, AssignableUser>(
            "SELECT id, email \
               FROM rustio_users \
              WHERE is_active = TRUE \
                AND role IN ('staff', 'supervisor', 'administrator', 'developer') \
              ORDER BY email",
        )
        .fetch_all(db.pool())
        .await
        .map_err(rustio_admin::Error::from)?
    } else {
        Vec::new()
    };

    let csrf = req
        .ctx()
        .get::<CsrfGuard>()
        .map(|g| g.token.clone())
        .unwrap_or_default();

    Ok(Response::html(render_detail(
        &identity.email,
        is_lead,
        &case,
        &report,
        assignee_email.as_deref(),
        &actions,
        &assignable_users,
        &csrf,
    )))
}

// ---- POST /admin/cases/:case_id/status -------------------------------------

pub(crate) async fn do_status_transition(db: Db, case_id: i64, req: Request) -> Result<Response> {
    let identity = match require_role(&db, &req, Role::Staff).await? {
        AccessGuard::Redirect(r) => return Ok(r),
        AccessGuard::Allow(i) => i,
    };

    let form = req.form()?;
    let target_status = form.get("target_status").unwrap_or("").trim().to_string();

    // Load the current case state. Authority filter (Staff
    // sees only their own assigned case) re-applied here.
    let row: Option<(i64, Option<i64>, String)> =
        sqlx::query_as("SELECT report_id, assignee_id, status FROM cases WHERE id = $1")
            .bind(case_id)
            .fetch_optional(db.pool())
            .await
            .map_err(rustio_admin::Error::from)?;

    let (report_id, assignee_id, current_status) = match row {
        Some(t) => t,
        None => return Ok(Response::redirect("/admin/triage")),
    };

    let is_lead = identity.role.includes(Role::Administrator);
    if !is_lead && assignee_id != Some(identity.user_id) {
        return Ok(forbidden());
    }

    // Validate the transition against the state machine.
    if !allowed_next_statuses(&current_status).contains(&target_status.as_str()) {
        return Ok(redirect_back(case_id));
    }

    // Terminal transitions require a fresh elevated-session.
    // A handler clicking "Mark resolved" without recent
    // re-auth bounces to /admin/reauth?return_to=… and lands
    // back on the case detail page after re-auth, where they
    // click the button again.
    if transition_requires_reauth(&target_status) && !is_session_elevated(&db, &req).await? {
        return Ok(Response::redirect(format!(
            "/admin/reauth?return_to=/admin/cases/{case_id}/work"
        )));
    }

    // Execute the transition atomically.
    let mut tx = db.pool().begin().await.map_err(rustio_admin::Error::from)?;

    // 1. UPDATE cases.status (+ closed_at on terminal).
    if is_terminal_status(&target_status) {
        sqlx::query("UPDATE cases SET status = $1, closed_at = NOW() WHERE id = $2")
            .bind(&target_status)
            .bind(case_id)
            .execute(&mut *tx)
            .await
            .map_err(rustio_admin::Error::from)?;
    } else {
        // Non-terminal transition. closed_at stays NULL.
        sqlx::query("UPDATE cases SET status = $1 WHERE id = $2")
            .bind(&target_status)
            .bind(case_id)
            .execute(&mut *tx)
            .await
            .map_err(rustio_admin::Error::from)?;
    }

    // 2. UPDATE reports.status to keep the reporter's view
    //    in sync. The reporter's /report/status page reads
    //    the report's column directly.
    sqlx::query("UPDATE reports SET status = $1 WHERE id = $2")
        .bind(&target_status)
        .bind(report_id)
        .execute(&mut *tx)
        .await
        .map_err(rustio_admin::Error::from)?;

    // 3. INSERT the case_actions audit overlay row, with the
    //    request's correlation_id so Phase 5's audit pivot can
    //    follow the chain.
    let correlation = req.ctx().get::<CorrelationId>().map(|c| c.0.clone());
    sqlx::query(
        "INSERT INTO case_actions (case_id, actor_id, action_type, note, correlation_id) \
         VALUES ($1, $2, 'status_changed', $3, $4)",
    )
    .bind(case_id)
    .bind(identity.user_id)
    .bind(format!("{current_status} → {target_status}"))
    .bind(correlation)
    .execute(&mut *tx)
    .await
    .map_err(rustio_admin::Error::from)?;

    tx.commit().await.map_err(rustio_admin::Error::from)?;

    log::info!(
        "lursystem: case status transition id={} {} → {} by user_id={}",
        case_id,
        current_status,
        target_status,
        identity.user_id,
    );

    Ok(redirect_back(case_id))
}

// ---- POST /admin/cases/:case_id/notes --------------------------------------

pub(crate) async fn do_add_note(db: Db, case_id: i64, req: Request) -> Result<Response> {
    let identity = match require_role(&db, &req, Role::Staff).await? {
        AccessGuard::Redirect(r) => return Ok(r),
        AccessGuard::Allow(i) => i,
    };

    let form = req.form()?;
    let note = form.get("note").unwrap_or("").trim().to_string();

    if note.len() < NOTE_MIN || note.len() > NOTE_MAX {
        // Silently ignore out-of-envelope notes. The form's
        // client-side `minlength` / `maxlength` attrs catch
        // these client-side; this server-side check is the
        // belt to the form's braces.
        return Ok(redirect_back(case_id));
    }

    // Authority filter: load the case, gate on assignee or
    // lead role.
    let row: Option<(Option<i64>,)> = sqlx::query_as("SELECT assignee_id FROM cases WHERE id = $1")
        .bind(case_id)
        .fetch_optional(db.pool())
        .await
        .map_err(rustio_admin::Error::from)?;
    let assignee_id = match row {
        Some((a,)) => a,
        None => return Ok(Response::redirect("/admin/triage")),
    };
    let is_lead = identity.role.includes(Role::Administrator);
    if !is_lead && assignee_id != Some(identity.user_id) {
        return Ok(forbidden());
    }

    let correlation = req.ctx().get::<CorrelationId>().map(|c| c.0.clone());
    sqlx::query(
        "INSERT INTO case_actions (case_id, actor_id, action_type, note, correlation_id) \
         VALUES ($1, $2, 'note_added', $3, $4)",
    )
    .bind(case_id)
    .bind(identity.user_id)
    .bind(&note)
    .bind(correlation)
    .execute(db.pool())
    .await
    .map_err(rustio_admin::Error::from)?;

    log::info!(
        "lursystem: case note added id={} by user_id={} len={}",
        case_id,
        identity.user_id,
        note.len(),
    );

    Ok(redirect_back(case_id))
}

// ---- POST /admin/cases/:case_id/reassign -----------------------------------

pub(crate) async fn do_reassign(db: Db, case_id: i64, req: Request) -> Result<Response> {
    // Reassignment is a Compliance-lead-only action — distinct
    // from the Staff-gated routes above. Handlers cannot
    // reassign themselves or others.
    let identity = match require_role(&db, &req, Role::Administrator).await? {
        AccessGuard::Redirect(r) => return Ok(r),
        AccessGuard::Allow(i) => i,
    };

    let form = req.form()?;
    let target_assignee_id: i64 = form
        .get("assignee_id")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    if target_assignee_id <= 0 {
        return Ok(redirect_back(case_id));
    }

    // Validate the target user. Must exist, be active, and
    // carry one of the assignable roles. A hostile lead
    // submitting an arbitrary user_id (e.g. a Reporter's
    // user_id) bounces here.
    let target_user: Option<(String, String)> = sqlx::query_as(
        "SELECT email, role FROM rustio_users \
          WHERE id = $1 AND is_active = TRUE",
    )
    .bind(target_assignee_id)
    .fetch_optional(db.pool())
    .await
    .map_err(rustio_admin::Error::from)?;

    let (target_email, target_role) = match target_user {
        Some(t) => t,
        None => return Ok(redirect_back(case_id)),
    };
    if !ASSIGNABLE_ROLES.contains(&target_role.as_str()) {
        return Ok(redirect_back(case_id));
    }

    // Load the case to determine action_type (assigned vs
    // reassigned) and to short-circuit no-op reassignments.
    let row: Option<(Option<i64>,)> = sqlx::query_as("SELECT assignee_id FROM cases WHERE id = $1")
        .bind(case_id)
        .fetch_optional(db.pool())
        .await
        .map_err(rustio_admin::Error::from)?;
    let previous_assignee = match row {
        Some((a,)) => a,
        None => return Ok(Response::redirect("/admin/triage")),
    };

    if previous_assignee == Some(target_assignee_id) {
        // Lead picked the current assignee from the dropdown.
        // No-op — skip the writes.
        return Ok(redirect_back(case_id));
    }

    let action_type = if previous_assignee.is_some() {
        "reassigned"
    } else {
        "assigned"
    };
    let note = match previous_assignee {
        Some(prev) => format!("user_id {prev} → user_id {target_assignee_id} ({target_email})"),
        None => format!("Assigned to user_id {target_assignee_id} ({target_email})"),
    };

    // Atomic: UPDATE cases.assignee_id + INSERT case_actions.
    let mut tx = db.pool().begin().await.map_err(rustio_admin::Error::from)?;

    sqlx::query("UPDATE cases SET assignee_id = $1 WHERE id = $2")
        .bind(target_assignee_id)
        .bind(case_id)
        .execute(&mut *tx)
        .await
        .map_err(rustio_admin::Error::from)?;

    let correlation = req.ctx().get::<CorrelationId>().map(|c| c.0.clone());
    sqlx::query(
        "INSERT INTO case_actions (case_id, actor_id, action_type, note, correlation_id) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(case_id)
    .bind(identity.user_id)
    .bind(action_type)
    .bind(&note)
    .bind(correlation)
    .execute(&mut *tx)
    .await
    .map_err(rustio_admin::Error::from)?;

    tx.commit().await.map_err(rustio_admin::Error::from)?;

    log::info!(
        "lursystem: case {} id={} new_assignee=user_id:{} by user_id={}",
        action_type,
        case_id,
        target_assignee_id,
        identity.user_id,
    );

    Ok(redirect_back(case_id))
}

// ---- Shared helpers --------------------------------------------------------

fn redirect_back(case_id: i64) -> Response {
    Response::redirect(format!("/admin/cases/{case_id}/work"))
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

#[derive(sqlx::FromRow)]
struct AssignableUser {
    id: i64,
    email: String,
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

#[allow(clippy::too_many_arguments)]
fn render_detail(
    actor_email: &str,
    is_lead: bool,
    case: &CaseRow,
    report: &ReportRow,
    assignee_email: Option<&str>,
    actions: &[ActionRow],
    assignable_users: &[AssignableUser],
    csrf: &str,
) -> String {
    let assignee_html = match assignee_email {
        Some(email) => format!(r#"<strong>{}</strong>"#, escape(email)),
        None => r#"<em class="lur-muted">Ingen tilldelad</em>"#.to_string(),
    };

    let reporter_html = if report.has_email {
        let disclose_link = if is_lead {
            format!(
                r#"<p class="lur-reporter-action">
  <a class="lur-disclose-cta" href="/admin/cases/{case_id}/disclose">→ Begär identitetsupplysning</a>
  <span class="lur-reauth-marker" title="Kräver återautentisering">↑</span>
</p>"#,
                case_id = case.id,
            )
        } else {
            String::new()
        };
        format!(
            r#"<div class="lur-reporter-state">
  <span class="lur-pill lur-pill-warn">E-post angiven</span>
  <p>Reporterns e-post finns lagrad men visas inte här. För att
  läsa identiteten krävs en formell identitetsupplysning som
  loggas oåterkalleligt i ärendet. Varje visning loggas separat.</p>
  {disclose_link}
</div>"#
        )
    } else {
        r#"<div class="lur-reporter-state">
  <span class="lur-pill lur-pill-neutral">Anonym rapport</span>
  <p>Reportern har inte angett någon e-postadress. Det finns
  ingen identitet att läsa.</p>
</div>"#
            .to_string()
    };

    let workflow_html = render_workflow_forms(is_lead, case, assignable_users, csrf);

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
    {workflow_html}
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
        workflow_html = workflow_html,
        actor_email = escape(actor_email),
        css = operator_css(),
    )
}

fn render_workflow_forms(
    is_lead: bool,
    case: &CaseRow,
    assignable_users: &[AssignableUser],
    csrf: &str,
) -> String {
    let case_id = case.id;
    let mut buf = String::new();

    // --- Status transitions ---
    let next_statuses = allowed_next_statuses(&case.status);
    if next_statuses.is_empty() {
        buf.push_str(
            r#"<div class="lur-workflow-block">
  <p class="lur-muted">Ärendet är avslutat. Inga statusändringar möjliga.</p>
</div>
"#,
        );
    } else {
        buf.push_str(
            r#"<div class="lur-workflow-block">
  <h3 class="lur-workflow-title">Ändra status</h3>
  <div class="lur-workflow-buttons">
"#,
        );
        for target in next_statuses {
            let reauth_warning = if transition_requires_reauth(target) {
                r#"<span class="lur-reauth-marker" title="Kräver återautentisering">↑</span>"#
            } else {
                ""
            };
            buf.push_str(&format!(
                r#"    <form method="post" action="/admin/cases/{case_id}/status">
      <input type="hidden" name="_csrf" value="{csrf}">
      <input type="hidden" name="target_status" value="{target}">
      <button type="submit" class="lur-btn-{target}">→ {label}{reauth}</button>
    </form>
"#,
                case_id = case_id,
                csrf = escape(csrf),
                target = escape(target),
                label = escape(status_label_sv(target)),
                reauth = reauth_warning,
            ));
        }
        buf.push_str("  </div>\n");
        buf.push_str(
            r#"  <p class="lur-workflow-hint">Statusändringar markerade med ↑
  kräver en färsk återautentisering (lösenord + 2FA om aktiverat).</p>
"#,
        );
        buf.push_str("</div>\n");
    }

    // --- Internal notes ---
    buf.push_str(&format!(
        r#"<div class="lur-workflow-block">
  <h3 class="lur-workflow-title">Lägg till intern anteckning</h3>
  <form method="post" action="/admin/cases/{case_id}/notes" class="lur-notes-form">
    <input type="hidden" name="_csrf" value="{csrf}">
    <textarea name="note" rows="4" required minlength="{NOTE_MIN}" maxlength="{NOTE_MAX}"
              placeholder="Anteckningen syns endast för utredare och granskare."></textarea>
    <button type="submit">Spara anteckning</button>
  </form>
</div>
"#,
        case_id = case_id,
        csrf = escape(csrf),
        NOTE_MIN = NOTE_MIN,
        NOTE_MAX = NOTE_MAX,
    ));

    // --- Reassign (compliance lead only) ---
    if is_lead {
        let options = if assignable_users.is_empty() {
            r#"<option value="" disabled>Inga utredare tillgängliga</option>"#.to_string()
        } else {
            let mut opts = String::new();
            for u in assignable_users {
                let selected = if case.assignee_id == Some(u.id) {
                    " selected"
                } else {
                    ""
                };
                opts.push_str(&format!(
                    r#"<option value="{id}"{selected}>{email}</option>"#,
                    id = u.id,
                    selected = selected,
                    email = escape(&u.email),
                ));
            }
            opts
        };
        buf.push_str(&format!(
            r#"<div class="lur-workflow-block">
  <h3 class="lur-workflow-title">Tilldela ärende</h3>
  <form method="post" action="/admin/cases/{case_id}/reassign" class="lur-reassign-form">
    <input type="hidden" name="_csrf" value="{csrf}">
    <select name="assignee_id" required>
      {options}
    </select>
    <button type="submit">Spara tilldelning</button>
  </form>
</div>
"#,
            case_id = case_id,
            csrf = escape(csrf),
            options = options,
        ));
    }

    buf
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
.lur-reporter-action {
  margin-top: 16px !important;
  font-size: 13px !important;
}
.lur-disclose-cta {
  display: inline-block;
  padding: 8px 16px;
  background: #fcf6e3;
  border: 1px solid #c9b58c;
  color: #4a3a14 !important;
  font-weight: 600;
  text-decoration: none;
  border-radius: 2px;
}
.lur-disclose-cta:hover {
  background: #f6e8b8;
  border-color: #c69a3a;
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
.lur-workflow-block {
  padding: 16px 0;
  border-bottom: 1px solid #eef2f3;
}
.lur-workflow-block:last-child { border-bottom: 0; padding-bottom: 0; }
.lur-workflow-block:first-child { padding-top: 0; }
.lur-workflow-title {
  font-size: 13px;
  font-weight: 600;
  margin: 0 0 12px;
  letter-spacing: 0.01em;
  text-transform: none;
  color: #1c2326;
}
.lur-workflow-buttons {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
}
.lur-workflow-buttons button {
  background: #ffffff;
  color: #1c2326;
  border: 1px solid #c9d1d6;
  padding: 8px 16px;
  font: inherit;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  border-radius: 2px;
}
.lur-workflow-buttons button:hover {
  border-color: #0f8c7e;
  color: #0a6e62;
}
.lur-btn-resolved,
.lur-btn-archived {
  background: #fafbfc !important;
  border-color: #c9b58c !important;
  color: #4a3a14 !important;
}
.lur-btn-resolved:hover,
.lur-btn-archived:hover {
  border-color: #c69a3a !important;
  color: #4a3a14 !important;
}
.lur-reauth-marker {
  display: inline-block;
  margin-left: 4px;
  color: #c69a3a;
  font-weight: 700;
}
.lur-workflow-hint {
  margin: 12px 0 0;
  font-size: 12px;
  color: #5d6a72;
  max-width: 580px;
}
.lur-notes-form textarea {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid #c9d1d6;
  background: #fafbfc;
  font: inherit;
  font-size: 14px;
  color: inherit;
  border-radius: 2px;
  resize: vertical;
  min-height: 96px;
  margin-bottom: 12px;
}
.lur-notes-form button,
.lur-reassign-form button {
  background: #0f8c7e;
  color: #ffffff;
  border: 0;
  padding: 8px 18px;
  font: inherit;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  border-radius: 2px;
}
.lur-notes-form button:hover,
.lur-reassign-form button:hover { background: #0a6e62; }
.lur-reassign-form {
  display: flex;
  gap: 10px;
  align-items: center;
}
.lur-reassign-form select {
  padding: 8px 12px;
  border: 1px solid #c9d1d6;
  background: #fafbfc;
  font: inherit;
  font-size: 13px;
  color: inherit;
  border-radius: 2px;
  min-width: 280px;
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
