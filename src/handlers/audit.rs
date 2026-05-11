//! Auditor read-only surface — Phase 5's forensic-reconstruction view.
//!
//! ## Route
//!
//! - `GET /admin/audit` → [`show_audit_log`]
//!
//! ## Authority
//!
//! `Role::Supervisor` floor. Supervisors are the lursystem audit
//! tier — a separate person from the Administrator (compliance
//! lead) who acts on cases. The framework's role hierarchy treats
//! Administrator as including Supervisor, so compliance leads can
//! also view the audit log; the floor only excludes Staff
//! (handlers) and User (reporters).
//!
//! ## What this page shows
//!
//! Chronological list of every `case_actions` row across every
//! case, joined to the actor's email and the case's current
//! status. Read-only — no forms, no buttons that mutate.
//!
//! Filters (query string):
//!
//! - `?action_type=disclosure_consumed` — narrow to a single
//!   action type. The disclosure_consumed filter is the
//!   regulatory shortlist.
//! - `?correlation=<id>` — pivot on a single HTTP request. Every
//!   row sharing the correlation_id rendered together — the
//!   forensic-reconstruction view of one user action.
//! - `?actor=<email>` — narrow to a single user's actions.
//! - `?case=<case_id>` — narrow to a single case.
//! - `?since=YYYY-MM-DD` — events on or after the given date
//!   (UTC midnight).
//! - `?page=N` — pagination, 50 rows per page.
//!
//! Filters compose: `?action_type=note_added&actor=alice@example.com`
//! lists every note added by alice.
//!
//! ## What this page does NOT show
//!
//! - **Reporter identities.** Disclosure events appear with the
//!   reason in the note column; the reporter's email is NOT
//!   rendered on this surface. Reading the email still requires
//!   the Phase 4 unmask flow.
//! - **Framework-level audit rows.** The framework's
//!   `rustio_admin_actions` table (login, session promotion,
//!   etc.) lives under the framework's own admin surface. The
//!   pivot path is the correlation_id: a row here with
//!   `correlation_id = X` corresponds to framework rows with the
//!   same correlation_id.
//! - **Mutation controls.** Auditors cannot delete, edit, or
//!   re-classify audit rows from this surface. The framework has
//!   no DELETE path on case_actions or disclosures either.

use chrono::{DateTime, NaiveDate, TimeZone, Utc};

use rustio_admin::auth::Role;
use rustio_admin::{Db, Request, Response, Result};

use crate::auth_helper::{require_role, AccessGuard};

// ---- Locked decisions (Phase 5) -------------------------------------------

const PAGE_SIZE: i64 = 50;
const MAX_PAGE: i64 = 200; // soft cap; refuses to render beyond this

/// Filters parsed from the query string. Every field is
/// independently optional so callers can combine filters freely.
#[derive(Default, Clone)]
struct AuditFilters {
    action_type: Option<String>,
    correlation: Option<String>,
    actor: Option<String>,
    case_id: Option<i64>,
    since: Option<DateTime<Utc>>,
    page: i64,
}

impl AuditFilters {
    fn from_request(req: &Request) -> Self {
        let q = req.query();
        let action_type = q
            .get("action_type")
            .map(str::to_string)
            .filter(|s| !s.is_empty());
        let correlation = q
            .get("correlation")
            .map(str::to_string)
            .filter(|s| !s.is_empty());
        let actor = q.get("actor").map(str::to_string).filter(|s| !s.is_empty());
        let case_id = q.get("case").and_then(|s| s.parse::<i64>().ok());
        let since = q
            .get("since")
            .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .and_then(|ndt| Utc.from_local_datetime(&ndt).single());
        let page = q
            .get("page")
            .and_then(|s| s.parse::<i64>().ok())
            .map(|n| n.clamp(1, MAX_PAGE))
            .unwrap_or(1);
        Self {
            action_type,
            correlation,
            actor,
            case_id,
            since,
            page,
        }
    }

    /// Re-emit the filter set as a `?…` query string suitable for
    /// the pagination links + filter chips. Skips the `page` slot
    /// because the link template adds its own page number.
    fn to_query_without_page(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(a) = &self.action_type {
            parts.push(format!("action_type={}", urlencode(a)));
        }
        if let Some(c) = &self.correlation {
            parts.push(format!("correlation={}", urlencode(c)));
        }
        if let Some(a) = &self.actor {
            parts.push(format!("actor={}", urlencode(a)));
        }
        if let Some(c) = self.case_id {
            parts.push(format!("case={c}"));
        }
        if let Some(s) = self.since {
            parts.push(format!("since={}", s.format("%Y-%m-%d")));
        }
        parts.join("&")
    }
}

// ---- GET /admin/audit -----------------------------------------------------

pub(crate) async fn show_audit_log(db: Db, req: Request) -> Result<Response> {
    let identity = match require_role(&db, &req, Role::Supervisor).await? {
        AccessGuard::Redirect(r) => return Ok(r),
        AccessGuard::Allow(i) => i,
    };

    let filters = AuditFilters::from_request(&req);
    let offset = (filters.page - 1) * PAGE_SIZE;

    // Build the WHERE clause dynamically. Each bind is added to
    // a homogeneous-type sqlx::QueryAs builder via the
    // `Query::bind` chain; the parameter index is tracked
    // manually so the SQL placeholders line up with the binds.
    let mut where_clauses: Vec<String> = Vec::new();
    let mut bind_idx = 1;

    if filters.action_type.is_some() {
        where_clauses.push(format!("ca.action_type = ${bind_idx}"));
        bind_idx += 1;
    }
    if filters.correlation.is_some() {
        where_clauses.push(format!("ca.correlation_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if filters.actor.is_some() {
        where_clauses.push(format!("LOWER(u.email) = LOWER(${bind_idx})"));
        bind_idx += 1;
    }
    if filters.case_id.is_some() {
        where_clauses.push(format!("ca.case_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if filters.since.is_some() {
        where_clauses.push(format!("ca.created_at >= ${bind_idx}"));
        bind_idx += 1;
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_clauses.join(" AND "))
    };

    let list_sql = format!(
        "SELECT ca.id, ca.case_id, ca.action_type, ca.note, ca.created_at, \
                ca.correlation_id, \
                COALESCE(u.email, '<deleted>') AS actor_email, \
                c.status AS case_status \
           FROM case_actions ca \
           LEFT JOIN rustio_users u ON u.id = ca.actor_id \
           JOIN cases c ON c.id = ca.case_id \
           {where_sql} \
          ORDER BY ca.created_at DESC \
          LIMIT ${limit_idx} OFFSET ${offset_idx}",
        where_sql = where_sql,
        limit_idx = bind_idx,
        offset_idx = bind_idx + 1,
    );

    let count_sql = format!(
        "SELECT COUNT(*) FROM case_actions ca \
           LEFT JOIN rustio_users u ON u.id = ca.actor_id \
           JOIN cases c ON c.id = ca.case_id \
           {where_sql}",
        where_sql = where_sql,
    );

    // Bind the filter values in the same order the WHERE
    // clauses were appended, then bind LIMIT + OFFSET. Inlined
    // (rather than a shared closure) because sqlx::query::QueryAs
    // is invariant over its lifetime parameter, which makes
    // returning the builder from a closure non-trivial.
    let mut list_q = sqlx::query_as::<_, AuditRow>(&list_sql);
    if let Some(a) = &filters.action_type {
        list_q = list_q.bind(a.clone());
    }
    if let Some(c) = &filters.correlation {
        list_q = list_q.bind(c.clone());
    }
    if let Some(a) = &filters.actor {
        list_q = list_q.bind(a.clone());
    }
    if let Some(c) = filters.case_id {
        list_q = list_q.bind(c);
    }
    if let Some(s) = filters.since {
        list_q = list_q.bind(s);
    }
    let rows: Vec<AuditRow> = list_q
        .bind(PAGE_SIZE)
        .bind(offset)
        .fetch_all(db.pool())
        .await
        .map_err(rustio_admin::Error::from)?;

    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql);
    if let Some(a) = &filters.action_type {
        count_q = count_q.bind(a.clone());
    }
    if let Some(c) = &filters.correlation {
        count_q = count_q.bind(c.clone());
    }
    if let Some(a) = &filters.actor {
        count_q = count_q.bind(a.clone());
    }
    if let Some(c) = filters.case_id {
        count_q = count_q.bind(c);
    }
    if let Some(s) = filters.since {
        count_q = count_q.bind(s);
    }
    let total: i64 = count_q
        .fetch_one(db.pool())
        .await
        .map_err(rustio_admin::Error::from)?;

    Ok(Response::html(render(
        &identity.email,
        &filters,
        total,
        &rows,
    )))
}

// ---- Row struct -----------------------------------------------------------

#[derive(sqlx::FromRow)]
struct AuditRow {
    #[allow(dead_code)] // unique row id, kept for future deep-links / forensics
    id: i64,
    case_id: i64,
    action_type: String,
    note: String,
    created_at: DateTime<Utc>,
    correlation_id: Option<String>,
    actor_email: String,
    case_status: String,
}

// ---- Swedish labels (duplicated from cases.rs for Phase 5 self-containment) --

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

// ---- Rendering ------------------------------------------------------------

fn render(actor_email: &str, filters: &AuditFilters, total: i64, rows: &[AuditRow]) -> String {
    let chips_html = render_filter_chips(filters);
    let filter_form_html = render_filter_form(filters);
    let rows_html = render_rows(rows);
    let pagination_html = render_pagination(filters, total);

    let total_label = if total == 1 {
        "1 händelse".to_string()
    } else {
        format!("{total} händelser")
    };

    format!(
        r#"<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Granskningslogg — Lursystem</title>
<style>{css}</style>
</head>
<body>
<header class="lur-op-header">
  <div class="lur-op-shell">
    <span class="lur-op-brand">Lursystem · Granskningsläge</span>
    <span class="lur-op-actor">Inloggad som <strong>{actor}</strong>
      · <a href="/admin/triage">Triage</a>
      · <a href="/admin">Adminpanel</a>
      · <a href="/admin/logout">Logga ut</a></span>
  </div>
</header>

<main class="lur-op-shell lur-op-audit">
  <div class="lur-audit-titlebar">
    <h1 class="lur-op-title">Granskningslogg</h1>
    <span class="lur-audit-total">{total_label}</span>
  </div>
  <p class="lur-lede">Oåterkallelig kronologisk logg över varje
  åtgärd i ärendehanteringen. Filtrera nedan. Klicka på en
  korrelations-ID för att se alla händelser från samma HTTP-anrop.</p>

  {chips_html}

  <section class="lur-section">
    <h2>Filter</h2>
    {filter_form_html}
  </section>

  <section class="lur-section">
    <h2>Händelser</h2>
    {rows_html}
    {pagination_html}
  </section>
</main>
</body>
</html>
"#,
        actor = escape(actor_email),
        total_label = escape(&total_label),
        chips_html = chips_html,
        filter_form_html = filter_form_html,
        rows_html = rows_html,
        pagination_html = pagination_html,
        css = operator_css(),
    )
}

fn render_filter_chips(filters: &AuditFilters) -> String {
    let mut chips: Vec<String> = Vec::new();
    let clear_other = |skip: &str| -> String {
        let mut q = filters.clone();
        match skip {
            "action_type" => q.action_type = None,
            "correlation" => q.correlation = None,
            "actor" => q.actor = None,
            "case" => q.case_id = None,
            "since" => q.since = None,
            _ => {}
        }
        let qs = q.to_query_without_page();
        if qs.is_empty() {
            "/admin/audit".to_string()
        } else {
            format!("/admin/audit?{qs}")
        }
    };

    if let Some(a) = &filters.action_type {
        chips.push(format!(
            r#"<a class="lur-chip" href="{href}">{label}: <strong>{val}</strong> ✕</a>"#,
            href = escape(&clear_other("action_type")),
            label = "Typ",
            val = escape(action_type_label_sv(a)),
        ));
    }
    if let Some(c) = &filters.correlation {
        chips.push(format!(
            r#"<a class="lur-chip lur-chip-corr" href="{href}">{label}: <strong>{val}</strong> ✕</a>"#,
            href = escape(&clear_other("correlation")),
            label = "Korrelation",
            val = escape(c),
        ));
    }
    if let Some(a) = &filters.actor {
        chips.push(format!(
            r#"<a class="lur-chip" href="{href}">{label}: <strong>{val}</strong> ✕</a>"#,
            href = escape(&clear_other("actor")),
            label = "Användare",
            val = escape(a),
        ));
    }
    if let Some(c) = filters.case_id {
        chips.push(format!(
            r#"<a class="lur-chip" href="{href}">{label}: <strong>#{val}</strong> ✕</a>"#,
            href = escape(&clear_other("case")),
            label = "Ärende",
            val = c,
        ));
    }
    if let Some(s) = filters.since {
        chips.push(format!(
            r#"<a class="lur-chip" href="{href}">{label}: <strong>{val}</strong> ✕</a>"#,
            href = escape(&clear_other("since")),
            label = "Från",
            val = escape(&s.format("%Y-%m-%d").to_string()),
        ));
    }
    if chips.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="lur-chip-row">{}</div>"#, chips.join(""))
    }
}

fn render_filter_form(filters: &AuditFilters) -> String {
    let action_type_value = filters.action_type.as_deref().unwrap_or("");
    let correlation_value = filters.correlation.as_deref().unwrap_or("");
    let actor_value = filters.actor.as_deref().unwrap_or("");
    let case_value = filters.case_id.map(|c| c.to_string()).unwrap_or_default();
    let since_value = filters
        .since
        .map(|s| s.format("%Y-%m-%d").to_string())
        .unwrap_or_default();

    // The action_type <select> options must reflect every
    // action_type written by lursystem handlers. New types added
    // in future phases need an entry here.
    let action_options = [
        ("", "Alla"),
        ("case_opened", "Ärende öppnat"),
        ("assigned", "Tilldelad"),
        ("reassigned", "Omtilldelad"),
        ("status_changed", "Status ändrad"),
        ("note_added", "Anteckning tillagd"),
        ("disclosure_consumed", "Identitet avslöjad"),
    ];
    let action_options_html = action_options
        .iter()
        .map(|(val, label)| {
            let selected = if *val == action_type_value {
                " selected"
            } else {
                ""
            };
            format!(
                r#"<option value="{val}"{selected}>{label}</option>"#,
                val = escape(val),
                selected = selected,
                label = escape(label),
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"<form method="get" action="/admin/audit" class="lur-filter-form">
  <div class="lur-filter-grid">
    <label>Händelsetyp
      <select name="action_type">
        {action_options}
      </select>
    </label>
    <label>Korrelation
      <input type="text" name="correlation" value="{correlation}" placeholder="t.ex. 9f3e…">
    </label>
    <label>Användare (e-post)
      <input type="text" name="actor" value="{actor}" placeholder="t.ex. lead@…">
    </label>
    <label>Ärende #
      <input type="number" name="case" value="{case}" min="1">
    </label>
    <label>Från datum
      <input type="date" name="since" value="{since}">
    </label>
  </div>
  <div class="lur-filter-actions">
    <a href="/admin/audit" class="lur-cancel">Rensa alla</a>
    <button type="submit">Tillämpa filter</button>
  </div>
</form>
"#,
        action_options = action_options_html,
        correlation = escape(correlation_value),
        actor = escape(actor_value),
        case = escape(&case_value),
        since = escape(&since_value),
    )
}

fn render_rows(rows: &[AuditRow]) -> String {
    if rows.is_empty() {
        return r#"<p class="lur-muted">Inga händelser matchar filtret.</p>"#.to_string();
    }
    let mut buf = String::from(
        r#"<table class="lur-audit-table">
  <thead>
    <tr>
      <th class="lur-col-when">Tidpunkt</th>
      <th class="lur-col-type">Händelse</th>
      <th class="lur-col-actor">Användare</th>
      <th class="lur-col-case">Ärende</th>
      <th class="lur-col-corr">Korrelation</th>
      <th class="lur-col-note">Detalj</th>
    </tr>
  </thead>
  <tbody>
"#,
    );
    for r in rows {
        let is_disclosure = r.action_type == "disclosure_consumed";
        let row_class = if is_disclosure {
            "lur-audit-row lur-audit-row-disclose"
        } else {
            "lur-audit-row"
        };
        let correlation_cell = match &r.correlation_id {
            Some(c) => format!(
                r#"<a href="/admin/audit?correlation={enc}" class="lur-corr" title="{full}">{short}</a>"#,
                enc = urlencode(c),
                full = escape(c),
                short = escape(&short_correlation(c)),
            ),
            None => r#"<span class="lur-muted">—</span>"#.to_string(),
        };
        let note_cell = if r.note.is_empty() {
            String::new()
        } else {
            escape(&truncate(&r.note, 160))
        };
        buf.push_str(&format!(
            r#"    <tr class="{row_class}">
      <td class="lur-col-when">{when}</td>
      <td class="lur-col-type">{type_label}</td>
      <td class="lur-col-actor"><a href="/admin/audit?actor={actor_enc}">{actor}</a></td>
      <td class="lur-col-case"><a href="/admin/cases/{case_id}/work">#{case_id}</a>
        <span class="lur-case-status lur-status-{case_status_raw}">{case_status_label}</span></td>
      <td class="lur-col-corr">{correlation_cell}</td>
      <td class="lur-col-note">{note_cell}</td>
    </tr>
"#,
            row_class = row_class,
            when = r.created_at.format("%Y-%m-%d %H:%M:%S"),
            type_label = escape(action_type_label_sv(&r.action_type)),
            actor_enc = urlencode(&r.actor_email),
            actor = escape(&r.actor_email),
            case_id = r.case_id,
            case_status_raw = escape(&r.case_status),
            case_status_label = escape(status_label_sv(&r.case_status)),
            correlation_cell = correlation_cell,
            note_cell = note_cell,
        ));
    }
    buf.push_str("  </tbody>\n</table>\n");
    buf
}

fn render_pagination(filters: &AuditFilters, total: i64) -> String {
    if total <= PAGE_SIZE {
        return String::new();
    }
    let pages = (total + PAGE_SIZE - 1) / PAGE_SIZE;
    let current = filters.page;
    let base_qs = filters.to_query_without_page();
    let link = |page: i64| -> String {
        if base_qs.is_empty() {
            format!("/admin/audit?page={page}")
        } else {
            format!("/admin/audit?{base_qs}&page={page}")
        }
    };
    let prev_html = if current > 1 {
        format!(
            r#"<a class="lur-pager-link" href="{}">← Föregående</a>"#,
            escape(&link(current - 1))
        )
    } else {
        r#"<span class="lur-pager-disabled">← Föregående</span>"#.to_string()
    };
    let next_html = if current < pages {
        format!(
            r#"<a class="lur-pager-link" href="{}">Nästa →</a>"#,
            escape(&link(current + 1))
        )
    } else {
        r#"<span class="lur-pager-disabled">Nästa →</span>"#.to_string()
    };
    format!(
        r#"<nav class="lur-pager">
  {prev_html}
  <span class="lur-pager-status">Sida {current} av {pages}</span>
  {next_html}
</nav>
"#,
        prev_html = prev_html,
        next_html = next_html,
        current = current,
        pages = pages,
    )
}

// ---- Small helpers --------------------------------------------------------

fn short_correlation(c: &str) -> String {
    // The framework's correlation_id is a hyphenated UUID (36
    // chars). Truncate to the first 8 for the table cell;
    // hover/title shows the full id, and the link carries the
    // full id.
    if c.len() > 8 {
        format!("{}…", &c[..8])
    } else {
        c.to_string()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

/// Minimal urlencoder for the query-string emit path. Encodes
/// the small set of reserved characters we expect to encounter
/// in filter values (`&`, `=`, `?`, `#`, space, plus). Anything
/// else passes through. Project-local; not a full RFC 3986
/// implementation.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
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
  max-width: 1280px;
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
main.lur-op-audit { max-width: 1280px; }
.lur-audit-titlebar {
  display: flex;
  align-items: baseline;
  gap: 16px;
  margin: 0 0 8px;
}
.lur-op-title {
  font-size: 26px;
  font-weight: 600;
  margin: 0;
  letter-spacing: -0.01em;
}
.lur-audit-total {
  font-size: 13px;
  color: #5d6a72;
  font-variant-numeric: tabular-nums;
}
.lur-lede {
  margin: 0 0 24px;
  font-size: 13px;
  color: #3a464d;
  max-width: 720px;
}
.lur-muted { color: #5d6a72; }
.lur-section {
  background: #ffffff;
  border: 1px solid #dde3e6;
  padding: 20px 24px;
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
.lur-chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 0 0 16px;
}
.lur-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  background: #ecf6f3;
  border: 1px solid #b6dad1;
  color: #0a3d36 !important;
  font-size: 12px;
  text-decoration: none;
  border-radius: 14px;
  font-variant-numeric: tabular-nums;
}
.lur-chip:hover {
  background: #d8ece5;
}
.lur-chip strong { font-weight: 700; }
.lur-chip-corr {
  background: #fcf6e3;
  border-color: #e6d18a;
  color: #4a3a14 !important;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.lur-chip-corr:hover { background: #f6e8b8; }
.lur-filter-form { font-size: 13px; }
.lur-filter-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 14px 18px;
  margin-bottom: 16px;
}
.lur-filter-grid label {
  display: flex;
  flex-direction: column;
  font-size: 12px;
  color: #5d6a72;
  font-weight: 600;
  gap: 6px;
}
.lur-filter-grid select,
.lur-filter-grid input {
  padding: 7px 10px;
  border: 1px solid #c9d1d6;
  background: #fafbfc;
  font: inherit;
  font-size: 13px;
  color: #1c2326;
  border-radius: 2px;
}
.lur-filter-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  align-items: center;
}
.lur-filter-actions button {
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
.lur-filter-actions button:hover { background: #0a6e62; }
.lur-cancel {
  color: #5d6a72;
  text-decoration: none;
  font-size: 12px;
}
.lur-cancel:hover { color: #0a6e62; text-decoration: underline; }
.lur-audit-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.lur-audit-table th {
  text-align: left;
  font-weight: 600;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: #5d6a72;
  padding: 8px 10px;
  border-bottom: 1px solid #dde3e6;
}
.lur-audit-table td {
  padding: 10px 10px;
  border-bottom: 1px solid #eef2f3;
  vertical-align: top;
}
.lur-audit-row-disclose {
  background: #fcf6e3;
}
.lur-audit-row-disclose td { border-bottom-color: #e6d18a; }
.lur-col-when {
  white-space: nowrap;
  font-variant-numeric: tabular-nums;
  color: #5d6a72;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
.lur-col-type { font-weight: 600; }
.lur-col-actor a {
  color: #0a6e62;
  text-decoration: none;
}
.lur-col-actor a:hover { text-decoration: underline; }
.lur-col-case a {
  color: #0a6e62;
  text-decoration: none;
  font-weight: 600;
}
.lur-col-case a:hover { text-decoration: underline; }
.lur-case-status {
  display: inline-block;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 6px;
  border-radius: 8px;
  margin-left: 6px;
  vertical-align: middle;
}
.lur-status-intake        { background: #eef2f3; color: #5d6a72; }
.lur-status-triage        { background: #e0eef9; color: #1c4a78; }
.lur-status-investigating { background: #fcf6e3; color: #6d5108; }
.lur-status-resolved      { background: #ecf6f3; color: #0a6e62; }
.lur-status-archived      { background: #eaeef0; color: #444b50; }
.lur-corr {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  color: #4a3a14 !important;
  text-decoration: none;
}
.lur-corr:hover { text-decoration: underline; }
.lur-col-note { color: #1c2326; }
.lur-pager {
  margin-top: 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 13px;
}
.lur-pager-link {
  color: #0a6e62;
  text-decoration: none;
  font-weight: 600;
}
.lur-pager-link:hover { text-decoration: underline; }
.lur-pager-disabled { color: #b6c0c5; }
.lur-pager-status {
  color: #5d6a72;
  font-variant-numeric: tabular-nums;
}
a { color: #0a6e62; }
"#
}
