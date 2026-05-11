//! Reporter-identity unmask — Phase 4's load-bearing surface.
//!
//! ## Routes
//!
//! - `GET  /admin/cases/:case_id/disclose` → [`show_disclose_form`]
//! - `POST /admin/cases/:case_id/disclose` → [`do_disclose`]
//!
//! ## Contract
//!
//! Writing a `disclosures` row IS the unmask. The act of revealing
//! the reporter's email to the compliance lead is what the row
//! records. The row is irreversible — there is no DELETE path in
//! the framework or the project. Operator retention policies handle
//! archival; the audit chain is the regulatory artefact.
//!
//! Two locks gate the runtime path:
//!
//! 1. **Role floor — `Role::Administrator`.** Only compliance leads
//!    can unmask. Handlers (Staff) viewing their own assigned case
//!    cannot reach this surface.
//! 2. **Re-auth wall.** The session's `elevated_until` must be in
//!    the future. The framework's R2 `/admin/reauth` handler is the
//!    canonical writer of that column; when the user has TOTP
//!    enrolled, the re-auth flow demands password + TOTP code.
//!    Both factors when MFA is enrolled — exactly what the
//!    R3 MFA stack was built for.
//!
//! ## UX shape
//!
//! GET is the form. If the session is not yet elevated, we bounce
//! to `/admin/reauth?return_to=…` from the GET so the user only
//! fills the form once. After re-auth, the framework lands them
//! back on the GET, the form renders, they enter a reason, POST.
//! The POST re-verifies elevation as belt-and-braces.
//!
//! POST renders the result page with `reporter_email` shown
//! inline. This is the ONLY surface in lursystem that renders the
//! email. The case detail page (`/admin/cases/:id/work`) never
//! does, even after a disclosure has been written: each viewing
//! of the email requires a fresh disclosure event. Operationally
//! strict, but matches the doctrine that every read of identifying
//! data is an audited event.
//!
//! ## Schema
//!
//! ```sql
//! CREATE TABLE disclosures (
//!     id           BIGSERIAL    PRIMARY KEY,
//!     case_id      BIGINT       NOT NULL REFERENCES cases(id),
//!     requested_by BIGINT       NOT NULL REFERENCES rustio_users(id),
//!     reason       TEXT         NOT NULL,
//!     disclosed_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
//! );
//! ```

use rustio_admin::auth::Role;
use rustio_admin::middleware::CsrfGuard;
use rustio_admin::{Db, Request, Response, Result};

use crate::auth_helper::{is_session_elevated, require_role, AccessGuard};

// ---- Locked decisions (Phase 4) -------------------------------------------

/// Disclosure-reason size envelope. The reason is the regulatory
/// artefact answering "why was this identity read." A handful of
/// characters ("asdf") is rejected by the floor; the ceiling sits
/// well below Postgres TEXT limits but well above any realistic
/// reason a lead would type.
const REASON_MIN: usize = 10;
const REASON_MAX: usize = 1_000;

// ---- GET /admin/cases/:case_id/disclose ------------------------------------

pub(crate) async fn show_disclose_form(db: Db, case_id: i64, req: Request) -> Result<Response> {
    let identity = match require_role(&db, &req, Role::Administrator).await? {
        AccessGuard::Redirect(r) => return Ok(r),
        AccessGuard::Allow(i) => i,
    };

    // Load the case + the linked report's `has_email` flag. The
    // email value itself is NOT loaded on this surface — only
    // `do_disclose` reads it, and only after writing the audit
    // row.
    let row: Option<(i64, String, bool)> = sqlx::query_as(
        "SELECT c.report_id, c.status, (r.reporter_email IS NOT NULL) AS has_email \
           FROM cases c JOIN reports r ON r.id = c.report_id \
          WHERE c.id = $1",
    )
    .bind(case_id)
    .fetch_optional(db.pool())
    .await
    .map_err(rustio_admin::Error::from)?;

    let (_report_id, _status, has_email) = match row {
        Some(t) => t,
        None => return Ok(not_found()),
    };

    // Anonymous report path: render the "no identity to disclose"
    // stub. No form, no re-auth bounce — there is nothing to
    // unmask, so the page is purely informational.
    if !has_email {
        return Ok(Response::html(render_anonymous_stub(
            case_id,
            &identity.email,
        )));
    }

    // Re-auth gate. Bouncing from the GET (rather than the POST)
    // means the user fills the reason form exactly once. If we
    // gated on POST instead, a re-auth bounce would lose the
    // form body and the user would re-type the reason after
    // landing back. UX cost is not worth the symmetry.
    if !is_session_elevated(&db, &req).await? {
        return Ok(Response::redirect(format!(
            "/admin/reauth?return_to=/admin/cases/{case_id}/disclose"
        )));
    }

    let csrf = req
        .ctx()
        .get::<CsrfGuard>()
        .map(|g| g.token.clone())
        .unwrap_or_default();

    Ok(Response::html(render_form(
        case_id,
        &identity.email,
        &csrf,
        None,
    )))
}

// ---- POST /admin/cases/:case_id/disclose -----------------------------------

pub(crate) async fn do_disclose(db: Db, case_id: i64, req: Request) -> Result<Response> {
    let identity = match require_role(&db, &req, Role::Administrator).await? {
        AccessGuard::Redirect(r) => return Ok(r),
        AccessGuard::Allow(i) => i,
    };

    // Re-verify elevation. A hostile lead crafting a POST
    // without going through the GET (and therefore skipping the
    // GET's bounce-to-reauth) lands here. The check is the hard
    // contract; the GET's redirect is the UX path.
    if !is_session_elevated(&db, &req).await? {
        return Ok(Response::redirect(format!(
            "/admin/reauth?return_to=/admin/cases/{case_id}/disclose"
        )));
    }

    let form = req.form()?;
    let reason = form.get("reason").unwrap_or("").trim().to_string();

    let csrf = req
        .ctx()
        .get::<CsrfGuard>()
        .map(|g| g.token.clone())
        .unwrap_or_default();

    // Validate the reason envelope. Out-of-range submissions
    // re-render the form with an error message so the lead can
    // correct without losing context.
    if reason.len() < REASON_MIN {
        return Ok(Response::html(render_form(
            case_id,
            &identity.email,
            &csrf,
            Some(format!(
                "Ange en motivering på minst {REASON_MIN} tecken. \
                 Motiveringen är en regulatorisk del av loggen."
            )),
        )));
    }
    if reason.len() > REASON_MAX {
        return Ok(Response::html(render_form(
            case_id,
            &identity.email,
            &csrf,
            Some(format!(
                "Motiveringen får vara högst {REASON_MAX} tecken. \
                 Korta ned och försök igen."
            )),
        )));
    }

    // Load the case + reporter's email atomically. The SELECT
    // sits inside the transaction so the read, the disclosure
    // INSERT, and the case_actions INSERT are one unit; a
    // concurrent edit cannot land between them.
    let mut tx = db.pool().begin().await.map_err(rustio_admin::Error::from)?;

    let row: Option<(i64, Option<String>)> = sqlx::query_as(
        "SELECT c.report_id, r.reporter_email \
           FROM cases c JOIN reports r ON r.id = c.report_id \
          WHERE c.id = $1 \
          FOR UPDATE OF c",
    )
    .bind(case_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(rustio_admin::Error::from)?;

    let (_report_id, reporter_email) = match row {
        Some(t) => t,
        None => {
            // Case vanished between GET and POST. Roll back, 404.
            tx.rollback().await.map_err(rustio_admin::Error::from)?;
            return Ok(not_found());
        }
    };

    let reporter_email = match reporter_email {
        Some(e) => e,
        None => {
            // Anonymous report. Roll back and route to the
            // informational stub. No disclosure row written.
            tx.rollback().await.map_err(rustio_admin::Error::from)?;
            return Ok(Response::html(render_anonymous_stub(
                case_id,
                &identity.email,
            )));
        }
    };

    // Write the disclosure row. This IS the audit event.
    sqlx::query(
        "INSERT INTO disclosures (case_id, requested_by, reason) \
         VALUES ($1, $2, $3)",
    )
    .bind(case_id)
    .bind(identity.user_id)
    .bind(&reason)
    .execute(&mut *tx)
    .await
    .map_err(rustio_admin::Error::from)?;

    // Write the case-level audit row so the case history
    // surface ("Historik" on /admin/cases/:id/work) shows the
    // disclosure event alongside the rest of the workflow.
    sqlx::query(
        "INSERT INTO case_actions (case_id, actor_id, action_type, note) \
         VALUES ($1, $2, 'disclosure_consumed', $3)",
    )
    .bind(case_id)
    .bind(identity.user_id)
    .bind(&reason)
    .execute(&mut *tx)
    .await
    .map_err(rustio_admin::Error::from)?;

    tx.commit().await.map_err(rustio_admin::Error::from)?;

    log::info!(
        "lursystem: disclosure consumed case_id={} by user_id={} reason_len={}",
        case_id,
        identity.user_id,
        reason.len(),
    );

    Ok(Response::html(render_result(
        case_id,
        &identity.email,
        &reporter_email,
        &reason,
    )))
}

// ---- Rendering -------------------------------------------------------------

fn render_form(case_id: i64, actor_email: &str, csrf: &str, error: Option<String>) -> String {
    let error_html = match error {
        Some(msg) => format!(r#"<div class="lur-error">{}</div>"#, escape(&msg)),
        None => String::new(),
    };

    format!(
        r#"<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Identitetsupplysning — Ärende #{case_id} — Lursystem</title>
<style>{css}</style>
</head>
<body>
<header class="lur-op-header">
  <div class="lur-op-shell">
    <span class="lur-op-brand">Lursystem · Operatörsgränssnitt</span>
    <span class="lur-op-actor">Inloggad som <strong>{actor}</strong>
      · <a href="/admin/cases/{case_id}/work">← Ärende #{case_id}</a>
      · <a href="/admin/logout">Logga ut</a></span>
  </div>
</header>

<main class="lur-op-shell lur-op-detail">
  <h1 class="lur-op-title">Begär identitetsupplysning</h1>
  <p class="lur-lede">Ärende #{case_id}. När du bekräftar nedan
  skrivs en oåterkallelig logg som kopplar dig till denna
  identitetsläsning. Reporterns e-postadress visas på följande
  sida.</p>

  <section class="lur-section lur-section-warn">
    <h2>Detta loggas oåterkalleligt</h2>
    <ul class="lur-warn-list">
      <li>Din användare (<strong>{actor}</strong>) registreras som
      den som begärt upplysningen.</li>
      <li>Motiveringen sparas ordagrant i loggen.</li>
      <li>Loggraden kan inte raderas. Tillsynsmyndigheten kan
      begära den vid revision.</li>
      <li>Visningen sker en gång. Om du behöver e-postadressen
      igen krävs en ny begäran med ny motivering — varje läsning
      loggas.</li>
    </ul>
  </section>

  {error_html}

  <section class="lur-section">
    <h2>Motivering</h2>
    <form method="post" action="/admin/cases/{case_id}/disclose" class="lur-disclose-form">
      <input type="hidden" name="_csrf" value="{csrf}">
      <label for="reason" class="lur-form-label">
        Ange varför du behöver läsa reporterns identitet
        (minst {REASON_MIN} tecken, högst {REASON_MAX}).
      </label>
      <textarea id="reason" name="reason" rows="6" required
                minlength="{REASON_MIN}" maxlength="{REASON_MAX}"
                placeholder="Exempel: Reportern har bett att bli kontaktad direkt enligt e-postsignatur i rapporten."></textarea>
      <div class="lur-form-actions">
        <a href="/admin/cases/{case_id}/work" class="lur-cancel">Avbryt</a>
        <button type="submit">Bekräfta och visa identitet</button>
      </div>
    </form>
  </section>
</main>
</body>
</html>
"#,
        case_id = case_id,
        actor = escape(actor_email),
        csrf = escape(csrf),
        error_html = error_html,
        REASON_MIN = REASON_MIN,
        REASON_MAX = REASON_MAX,
        css = operator_css(),
    )
}

fn render_result(case_id: i64, actor_email: &str, reporter_email: &str, reason: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Identitet visad — Ärende #{case_id} — Lursystem</title>
<style>{css}</style>
</head>
<body>
<header class="lur-op-header">
  <div class="lur-op-shell">
    <span class="lur-op-brand">Lursystem · Operatörsgränssnitt</span>
    <span class="lur-op-actor">Inloggad som <strong>{actor}</strong>
      · <a href="/admin/cases/{case_id}/work">← Ärende #{case_id}</a>
      · <a href="/admin/logout">Logga ut</a></span>
  </div>
</header>

<main class="lur-op-shell lur-op-detail">
  <h1 class="lur-op-title">Identitet visad</h1>
  <p class="lur-lede">Ärende #{case_id}. Loggraden är skriven och
  kan inte ångras. Notera adressen nu — vid behov av ny visning
  krävs en ny begäran.</p>

  <section class="lur-section lur-section-disclose">
    <h2>Reporterns e-post</h2>
    <p class="lur-disclose-email">{email}</p>
  </section>

  <section class="lur-section">
    <h2>Loggad motivering</h2>
    <pre class="lur-disclose-reason">{reason}</pre>
  </section>

  <section class="lur-section">
    <h2>Vad händer nu</h2>
    <p>Händelsen <em>Identitet avslöjad</em> finns nu i ärendets
    historik på arbetsytan. Den kan granskas av revisor men inte
    raderas.</p>
    <p><a class="lur-cta" href="/admin/cases/{case_id}/work">→ Återgå till ärende #{case_id}</a></p>
  </section>
</main>
</body>
</html>
"#,
        case_id = case_id,
        actor = escape(actor_email),
        email = escape(reporter_email),
        reason = escape(reason),
        css = operator_css(),
    )
}

fn render_anonymous_stub(case_id: i64, actor_email: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Anonym rapport — Ärende #{case_id} — Lursystem</title>
<style>{css}</style>
</head>
<body>
<header class="lur-op-header">
  <div class="lur-op-shell">
    <span class="lur-op-brand">Lursystem · Operatörsgränssnitt</span>
    <span class="lur-op-actor">Inloggad som <strong>{actor}</strong>
      · <a href="/admin/cases/{case_id}/work">← Ärende #{case_id}</a>
      · <a href="/admin/logout">Logga ut</a></span>
  </div>
</header>

<main class="lur-op-shell lur-op-detail">
  <h1 class="lur-op-title">Anonym rapport</h1>
  <section class="lur-section">
    <p>Reportern har inte angett någon e-postadress. Det finns
    ingen identitet att avslöja för ärende #{case_id}.</p>
    <p><a class="lur-cta" href="/admin/cases/{case_id}/work">→ Återgå till ärendet</a></p>
  </section>
</main>
</body>
</html>
"#,
        case_id = case_id,
        actor = escape(actor_email),
        css = operator_css(),
    )
}

fn not_found() -> Response {
    Response::html(format!(
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
    ))
    .with_status(hyper::StatusCode::NOT_FOUND)
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
main.lur-op-detail { max-width: 720px; }
.lur-op-title {
  font-size: 26px;
  font-weight: 600;
  margin: 0 0 8px;
  letter-spacing: -0.01em;
}
.lur-lede {
  margin: 0 0 28px;
  font-size: 14px;
  color: #3a464d;
  max-width: 620px;
}
.lur-muted { color: #5d6a72; }
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
.lur-section-warn {
  background: #fdf8e8;
  border-color: #e6d18a;
}
.lur-section-warn h2 { color: #6d5108; }
.lur-warn-list {
  margin: 0;
  padding: 0 0 0 20px;
}
.lur-warn-list li {
  margin: 0 0 8px;
  font-size: 14px;
  color: #4a3a14;
}
.lur-warn-list li:last-child { margin-bottom: 0; }
.lur-error {
  background: #fbe7e2;
  border: 1px solid #d4604a;
  color: #6a1d10;
  padding: 14px 18px;
  font-size: 14px;
  margin-bottom: 16px;
  border-radius: 2px;
}
.lur-form-label {
  display: block;
  font-size: 13px;
  color: #3a464d;
  margin-bottom: 10px;
}
.lur-disclose-form textarea {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid #c9d1d6;
  background: #fafbfc;
  font: inherit;
  font-size: 14px;
  color: inherit;
  border-radius: 2px;
  resize: vertical;
  min-height: 128px;
  margin-bottom: 16px;
}
.lur-form-actions {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: flex-end;
}
.lur-form-actions button {
  background: #c69a3a;
  color: #ffffff;
  border: 0;
  padding: 10px 20px;
  font: inherit;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  border-radius: 2px;
}
.lur-form-actions button:hover { background: #a47e26; }
.lur-cancel {
  color: #5d6a72;
  text-decoration: none;
  font-size: 13px;
}
.lur-cancel:hover { color: #0a6e62; text-decoration: underline; }
.lur-section-disclose {
  background: #ecf6f3;
  border-color: #4ea99a;
}
.lur-section-disclose h2 { color: #0a6e62; }
.lur-disclose-email {
  margin: 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 20px;
  font-weight: 600;
  color: #0a3d36;
  word-break: break-all;
  padding: 4px 0;
}
.lur-disclose-reason {
  margin: 0;
  font-family: inherit;
  white-space: pre-wrap;
  word-wrap: break-word;
  font-size: 14px;
  line-height: 1.6;
  background: #fafbfc;
  padding: 14px 16px;
  border-radius: 2px;
  border: 1px solid #eef2f3;
}
.lur-cta {
  display: inline-block;
  margin-top: 8px;
  color: #0a6e62;
  font-weight: 600;
  text-decoration: none;
}
.lur-cta:hover { text-decoration: underline; }
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
