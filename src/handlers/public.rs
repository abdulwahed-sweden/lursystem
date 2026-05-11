//! Public anonymous submission flow.
//!
//! Two routes, mounted at the router root BEFORE
//! `register_admin_routes`:
//!
//!   GET  /report/new    → [`show_report_form`]
//!   POST /report/new    → [`do_submit_report`]
//!
//! Both routes are reachable without authentication. The
//! framework's `csrf_protect` middleware still applies — the
//! middleware injects a `CsrfGuard` into the request context
//! on every request, sets a cookie on first GET, and validates
//! the hidden `_csrf` form field on POST. The form renders the
//! token; the cookie carries it back.
//!
//! No session is created for the reporter. The submission lands
//! a `Report` row in `status = 'intake'` and returns a freshly
//! generated `reporter_token` (256-bit URL-safe-base64) the
//! reporter saves to check status later. Phase 2.5 adds the
//! `/report/status?token=…` self-service surface.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use rand::RngCore;

use rustio_admin::middleware::CsrfGuard;
use rustio_admin::{Db, Request, Response, Result};

// ---- Locked decisions ------------------------------------------------------
//
// These values define the public form's contract. Changing them
// is a UX change that may break already-issued reporter_tokens
// or in-flight submissions, so we pin them as explicit
// constants here rather than scattering them through the
// handler.

/// Reporter-token length in raw bytes. 32 bytes → ~256 bits of
/// entropy → 43-char URL-safe-base64 string. Same shape as the
/// framework's session-token generation in `auth::sessions`.
const REPORTER_TOKEN_BYTES: usize = 32;

/// Summary field minimum / maximum. Forces the reporter to write
/// SOMETHING (not just whitespace) but caps the field length
/// so the list-display column stays scannable.
const SUMMARY_MIN: usize = 5;
const SUMMARY_MAX: usize = 200;

/// Body field minimum / maximum. The minimum is a soft anti-spam
/// floor; the maximum sits well below Postgres TEXT limits but
/// far enough above a real submission to never be reached by a
/// good-faith reporter.
const BODY_MIN: usize = 10;
const BODY_MAX: usize = 50_000;

/// Allowed `severity` values. Matches the DB column's expected
/// vocabulary. The form's `<select>` constrains the client side;
/// the handler re-validates on the server because a hostile
/// client can submit anything.
const SEVERITY_ALLOWED: &[&str] = &["low", "medium", "high", "critical"];

/// Allowed `channel` values. The web form always submits `web`;
/// the column accepts the other values for cases recorded by an
/// operator after a phone call / in-person conversation / email
/// thread. Phase 1's schema migration ships the column with the
/// `web` default; this constant pins the validator.
const CHANNEL_ALLOWED: &[&str] = &["web", "phone", "in_person", "email"];

// ---- Handlers --------------------------------------------------------------

/// Render the submission form. Reads the CSRF token from the
/// request context (injected by `csrf_protect` middleware on
/// every request) and embeds it in the hidden `_csrf` field.
pub(crate) async fn show_report_form(req: Request) -> Result<Response> {
    let csrf = csrf_token_from(&req);
    Ok(Response::html(render_form(&csrf, None)))
}

/// Process the submission. Validates the four required fields,
/// generates a fresh reporter token, INSERTs the Report row,
/// renders the success page with the token shown ONCE.
pub(crate) async fn do_submit_report(db: Db, req: Request) -> Result<Response> {
    let csrf = csrf_token_from(&req);
    let form = req.form()?;

    let summary = form.get("summary").unwrap_or("").trim().to_string();
    let body = form.get("body").unwrap_or("").trim().to_string();
    let severity = form.get("severity").unwrap_or("medium").trim().to_string();
    let channel = form.get("channel").unwrap_or("web").trim().to_string();
    let reporter_email = form
        .get("reporter_email")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    // Validate. On any error, re-render the form with a single
    // banner message + the user's input preserved client-side
    // (the browser keeps it via the back button if needed; the
    // server does not persist a half-validated submission).
    if let Err(msg) = validate(&summary, &body, &severity, &channel, &reporter_email) {
        return Ok(Response::html(render_form(&csrf, Some(&msg))));
    }

    // Generate the reporter token. 32 random bytes →
    // URL-safe-base64-no-padding → 43 char string. Same shape
    // and entropy as the framework's session tokens.
    let token = generate_reporter_token();

    // INSERT. Direct sqlx (rather than the framework's Model::insert
    // path) so we control the on-disk shape exactly and can
    // RETURN the row id for a future receipt page. The
    // submission lands in `status = 'intake'`; the compliance
    // lead picks it up from the triage queue (Phase 3).
    let row: (i64,) = sqlx::query_as(
        "INSERT INTO reports \
            (summary, body, severity, channel, status, reporter_email, reporter_token) \
         VALUES ($1, $2, $3, $4, 'intake', $5, $6) \
         RETURNING id",
    )
    .bind(&summary)
    .bind(&body)
    .bind(&severity)
    .bind(&channel)
    .bind(reporter_email.as_deref())
    .bind(&token)
    .fetch_one(db.pool())
    .await
    .map_err(rustio_admin::Error::from)?;

    log::info!(
        "lursystem: report received id={} severity={} channel={} submitted_at={}",
        row.0,
        severity,
        channel,
        Utc::now().to_rfc3339(),
    );

    Ok(Response::html(render_success(&token)))
}

// ---- Pure helpers ----------------------------------------------------------

/// Read the CSRF token from the request context. Returns an
/// empty string if the middleware did not inject one; the
/// `csrf_protect` POST handler will reject the form anyway, so
/// the empty fallback only ever surfaces during unit-style local
/// experimentation.
fn csrf_token_from(req: &Request) -> String {
    req.ctx()
        .get::<CsrfGuard>()
        .map(|g| g.token.clone())
        .unwrap_or_default()
}

fn generate_reporter_token() -> String {
    let mut bytes = vec![0u8; REPORTER_TOKEN_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

fn validate(
    summary: &str,
    body: &str,
    severity: &str,
    channel: &str,
    reporter_email: &Option<String>,
) -> std::result::Result<(), String> {
    if summary.len() < SUMMARY_MIN {
        return Err(format!(
            "Summary must be at least {SUMMARY_MIN} characters."
        ));
    }
    if summary.len() > SUMMARY_MAX {
        return Err(format!(
            "Summary must be no more than {SUMMARY_MAX} characters."
        ));
    }
    if body.len() < BODY_MIN {
        return Err(format!(
            "Description must be at least {BODY_MIN} characters."
        ));
    }
    if body.len() > BODY_MAX {
        return Err(format!(
            "Description must be no more than {BODY_MAX} characters."
        ));
    }
    if !SEVERITY_ALLOWED.contains(&severity) {
        return Err("Invalid severity.".into());
    }
    if !CHANNEL_ALLOWED.contains(&channel) {
        return Err("Invalid channel.".into());
    }
    if let Some(email) = reporter_email {
        // Lightweight email shape check. Not a full RFC 5322
        // validator — we just want to reject obvious noise. The
        // field is optional anyway.
        if !email.contains('@') || email.len() > 254 {
            return Err("Email address looks invalid.".into());
        }
    }
    Ok(())
}

// ---- Inline templates ------------------------------------------------------
//
// Project-side templates live as inline string constants for
// Phase 2. The framework's bundled template system targets the
// `/admin` chrome (sidebar, top bar, etc.); the public
// submission page is intentionally chrome-free, so we render it
// without going through `minijinja`. Phase 2.5 may revisit this
// when the `/report/status` page lands and shared layout
// becomes useful.

fn render_form(csrf: &str, error: Option<&str>) -> String {
    let error_html = match error {
        Some(msg) => format!(
            r#"<div class="lur-error" role="alert">{}</div>"#,
            escape(msg)
        ),
        None => String::new(),
    };
    format!(
        r#"<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lämna en rapport — Lursystem</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f4f6f7;
    color: #1c2326;
    font-size: 15px;
    line-height: 1.5;
  }}
  .lur-shell {{
    max-width: 640px;
    margin: 0 auto;
    padding: 48px 24px 96px;
  }}
  .lur-title {{
    font-size: 28px;
    font-weight: 600;
    margin: 0 0 12px;
    letter-spacing: -0.01em;
  }}
  .lur-intro {{
    color: #5d6a72;
    margin: 0 0 32px;
    font-size: 16px;
  }}
  .lur-error {{
    background: #fdecec;
    border-left: 3px solid #c8443d;
    padding: 12px 16px;
    margin-bottom: 24px;
    font-size: 14px;
  }}
  .lur-form {{
    background: #ffffff;
    border: 1px solid #dde3e6;
    padding: 32px;
  }}
  .lur-field {{
    margin-bottom: 24px;
  }}
  .lur-field:last-of-type {{
    margin-bottom: 32px;
  }}
  label {{
    display: block;
    font-weight: 600;
    margin-bottom: 6px;
    font-size: 14px;
  }}
  .lur-hint {{
    color: #5d6a72;
    font-size: 13px;
    margin: -2px 0 8px;
  }}
  input[type="text"],
  input[type="email"],
  textarea,
  select {{
    width: 100%;
    padding: 10px 12px;
    border: 1px solid #c9d1d6;
    background: #fafbfc;
    font: inherit;
    color: inherit;
    border-radius: 2px;
  }}
  textarea {{
    min-height: 180px;
    resize: vertical;
    font-family: inherit;
  }}
  input:focus,
  textarea:focus,
  select:focus {{
    outline: 2px solid #0f8c7e;
    outline-offset: -1px;
    border-color: #0f8c7e;
  }}
  button {{
    background: #0f8c7e;
    color: #ffffff;
    border: 0;
    padding: 12px 28px;
    font: inherit;
    font-weight: 600;
    cursor: pointer;
    border-radius: 2px;
  }}
  button:hover {{ background: #0a6e62; }}
  .lur-footer {{
    margin-top: 32px;
    font-size: 13px;
    color: #5d6a72;
  }}
</style>
</head>
<body>
<div class="lur-shell">
  <h1 class="lur-title">Lämna en rapport</h1>
  <p class="lur-intro">
    Den här kanalen är till för anställda och tidigare anställda
    som vill rapportera misstänkta missförhållanden. Inlämningar
    är konfidentiella och kan vara anonyma.
  </p>

  {error_html}

  <form method="post" action="/report/new" class="lur-form" autocomplete="off">
    <input type="hidden" name="_csrf" value="{csrf}">

    <div class="lur-field">
      <label for="lur-summary">Kort sammanfattning</label>
      <p class="lur-hint">En mening som beskriver vad rapporten gäller.</p>
      <input type="text" id="lur-summary" name="summary"
             required minlength="{SUMMARY_MIN}" maxlength="{SUMMARY_MAX}">
    </div>

    <div class="lur-field">
      <label for="lur-body">Beskrivning</label>
      <p class="lur-hint">Var så detaljerad du kan: vad hände, när, vilka var inblandade.</p>
      <textarea id="lur-body" name="body"
                required minlength="{BODY_MIN}" maxlength="{BODY_MAX}"></textarea>
    </div>

    <div class="lur-field">
      <label for="lur-severity">Allvarlighetsgrad</label>
      <select id="lur-severity" name="severity">
        <option value="low">Låg</option>
        <option value="medium" selected>Medel</option>
        <option value="high">Hög</option>
        <option value="critical">Kritisk</option>
      </select>
    </div>

    <div class="lur-field">
      <label for="lur-email">E-postadress (valfritt)</label>
      <p class="lur-hint">
        Anges endast om du vill kunna kontaktas. Lämna tomt för att
        rapportera helt anonymt.
      </p>
      <input type="email" id="lur-email" name="reporter_email" maxlength="254">
    </div>

    <input type="hidden" name="channel" value="web">

    <button type="submit">Skicka rapport</button>
  </form>

  <p class="lur-footer">
    Lursystem · Skyddat av lag (2021:890) om skydd för personer
    som rapporterar om missförhållanden.
  </p>
</div>
</body>
</html>
"#,
        error_html = error_html,
        csrf = escape(csrf),
        SUMMARY_MIN = SUMMARY_MIN,
        SUMMARY_MAX = SUMMARY_MAX,
        BODY_MIN = BODY_MIN,
        BODY_MAX = BODY_MAX,
    )
}

fn render_success(token: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport mottagen — Lursystem</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f4f6f7;
    color: #1c2326;
    font-size: 15px;
    line-height: 1.5;
  }}
  .lur-shell {{
    max-width: 640px;
    margin: 0 auto;
    padding: 48px 24px 96px;
  }}
  .lur-title {{
    font-size: 28px;
    font-weight: 600;
    margin: 0 0 12px;
    letter-spacing: -0.01em;
  }}
  .lur-intro {{
    color: #5d6a72;
    margin: 0 0 24px;
    font-size: 16px;
  }}
  .lur-success {{
    background: #ecf6f3;
    border-left: 3px solid #0f8c7e;
    padding: 16px 20px;
    margin-bottom: 32px;
    font-size: 15px;
  }}
  .lur-token-block {{
    background: #ffffff;
    border: 1px solid #dde3e6;
    padding: 24px 28px;
    margin-bottom: 24px;
  }}
  .lur-token-label {{
    font-weight: 600;
    font-size: 14px;
    margin-bottom: 8px;
  }}
  .lur-token {{
    font-family: "SF Mono", "JetBrains Mono", Consolas, monospace;
    font-size: 14px;
    background: #f4f6f7;
    padding: 12px 14px;
    word-break: break-all;
    border-radius: 2px;
  }}
  .lur-warning {{
    color: #4a3a14;
    background: #fcf6e3;
    border-left: 3px solid #c69a3a;
    padding: 14px 18px;
    margin-top: 32px;
    font-size: 14px;
  }}
  .lur-footer {{
    margin-top: 48px;
    font-size: 13px;
    color: #5d6a72;
  }}
</style>
</head>
<body>
<div class="lur-shell">
  <h1 class="lur-title">Rapport mottagen</h1>

  <div class="lur-success" role="status">
    Din rapport har tagits emot och kommer att granskas av
    en utredare. Behandlingen är konfidentiell.
  </div>

  <p class="lur-intro">
    Spara koden nedan. Den är ditt enda sätt att följa upp ärendet
    utan att lämna ut din identitet — vi visar den bara en gång.
  </p>

  <div class="lur-token-block">
    <div class="lur-token-label">Din uppföljningskod</div>
    <div class="lur-token">{token}</div>
  </div>

  <div class="lur-warning" role="note">
    Kopiera koden nu. Den visas inte igen och vi kan inte
    återskapa den.
  </div>

  <p class="lur-footer">
    Lursystem · Skyddat av lag (2021:890) om skydd för personer
    som rapporterar om missförhållanden.
  </p>
</div>
</body>
</html>
"#,
        token = escape(token),
    )
}

/// Minimal HTML-escape for values interpolated into the inline
/// templates. Covers the five characters that matter for
/// preventing reflected XSS through attribute or text contexts.
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
