//! Project-side auth helper for custom `/admin/*` routes.
//!
//! ## Framework gap (rustio-admin 0.7)
//!
//! The framework's `login_guard` / `role_guard` (in
//! `rustio_admin::admin::routes`) are `pub(crate)` and reach
//! the framework's full auth stack — cookie resolution,
//! `is_active` check, must-change-password redirect, MFA-required
//! redirect, pending-MFA-verify redirect, role-tier comparison.
//!
//! Project code that mounts custom `/admin/*` routes does not
//! have access to those guards. The flagship project (this
//! one) needs them to gate the triage queue, case detail, and
//! transition pages. Until the framework lifts those guards
//! into the public API, this helper reproduces the SUBSET we
//! need: cookie → session → identity → `is_active` →
//! role-tier comparison.
//!
//! ## What this helper does NOT do (vs. the framework's
//! `login_guard`)
//!
//! - **Must-change-password gate.** A user with the flag set
//!   would currently reach our custom pages even though the
//!   framework would have redirected them. The fix is one of:
//!   (a) the framework exposes `login_guard` publicly, (b)
//!   this helper also re-implements the must-change check
//!   against `identity.must_change_password`. We choose to
//!   wait for the framework rather than copy more of the
//!   framework's gate logic into the project.
//! - **MFA-required gate.** Same shape: a user under
//!   `MfaPolicy::Required` who has not enrolled would reach
//!   our custom pages. Same fix path.
//! - **Pending-MFA-verify gate.** A session with
//!   `trust_level = 'authenticated'` (not yet promoted to
//!   `mfa_verified` after login) would reach our pages.
//!   Same fix path.
//!
//! The triage flow (Phase 3) does not perform destructive
//! authority mutations on user accounts; the MFA + must-change
//! gaps reduce to "users who could not reach the framework's
//! own admin can reach our triage page." That's an
//! enforcement-uniformity gap, not a privilege-escalation
//! gap. The framework's existing R2 destructive routes
//! (lock, unlock, revoke, admin-reset) remain gated by the
//! framework's own login_guard since they use
//! `register_admin_routes`'s routing path.
//!
//! Lifts when rustio-admin publishes a `pub guards` module.

use chrono::{DateTime, Utc};

use rustio_admin::auth::{self, Identity, Role};
use rustio_admin::{Db, Request, Response, Result};

/// Outcome of a role check. Mirrors the framework's internal
/// `Guard` enum; the handler matches on this to decide between
/// proceeding with the user's identity or returning a redirect.
pub enum AccessGuard {
    /// Caller has the required role tier. Identity is the
    /// resolved session's user.
    Allow(Identity),
    /// Caller has been redirected (typically to `/admin/login`
    /// for unauthenticated callers, or `/admin` for
    /// authenticated-but-wrong-role callers).
    Redirect(Response),
}

/// Resolve the request's session and assert the user's role
/// includes `min_role`. Returns the identity or a redirect.
pub async fn require_role(db: &Db, req: &Request, min_role: Role) -> Result<AccessGuard> {
    // 1. Read the cookie header.
    let cookie = match req.header("cookie") {
        Some(c) => c,
        None => return Ok(AccessGuard::Redirect(Response::redirect("/admin/login"))),
    };

    // 2. Extract the session token. The framework's helper
    //    parses the Cookie header and returns the token from
    //    the `rustio_session` cookie specifically.
    let token = match auth::session_token_from_cookie(cookie) {
        Some(t) => t,
        None => return Ok(AccessGuard::Redirect(Response::redirect("/admin/login"))),
    };

    // 3. Resolve to an identity. The framework's
    //    `identity_from_session` does the SQL lookup (hashed
    //    token path with the 0.4.0-era plaintext fallback),
    //    rejects revoked / expired rows, and joins onto
    //    `rustio_users` so the role + active flag come back
    //    in one query.
    let identity = match auth::identity_from_session(db, token.as_str()).await? {
        Some(i) => i,
        None => return Ok(AccessGuard::Redirect(Response::redirect("/admin/login"))),
    };

    // 4. is_active check. Deactivated users have a live row
    //    but the framework's authn floor rejects them on
    //    every request. We mirror that floor here.
    if !identity.is_active {
        return Ok(AccessGuard::Redirect(Response::redirect("/admin/login")));
    }

    // 5. Role-tier comparison. `Role::includes` is the
    //    framework's hierarchical predicate — Administrator
    //    includes Supervisor includes Staff includes User,
    //    and Developer includes everyone.
    if !identity.role.includes(min_role) {
        // Authenticated but wrong tier. Redirect to the
        // admin landing page rather than the login page so
        // we do not look like a session-expiry case to a
        // user who is actually signed in.
        return Ok(AccessGuard::Redirect(Response::redirect("/admin")));
    }

    Ok(AccessGuard::Allow(identity))
}

/// Whether the request's session has been re-authenticated
/// within `RecoveryPolicy::reauth_window()` (default 15 min).
///
/// ## Framework gap (rustio-admin 0.7)
///
/// `auth::recovery_admin::check_session_elevated` is the
/// canonical reader, but the `recovery_admin` module is
/// `pub(crate)` so project code cannot reach it. Until the
/// framework lifts that module (or just this function) into
/// the public API, we query `rustio_sessions.elevated_until`
/// directly. Same comparison logic the framework uses.
///
/// The framework's R2 `do_reauth` handler is the canonical
/// writer of `elevated_until`. Project code that wants to
/// gate destructive admin actions (Phase 3c's terminal
/// status transitions, Phase 4's reporter unmask) checks
/// elevation via this helper, then redirects to
/// `/admin/reauth?return_to=…` if the session is not yet
/// elevated.
pub async fn is_session_elevated(db: &Db, req: &Request) -> Result<bool> {
    let cookie = match req.header("cookie") {
        Some(c) => c,
        None => return Ok(false),
    };
    let token = match auth::session_token_from_cookie(cookie) {
        Some(t) => t,
        None => return Ok(false),
    };
    let session_id = match auth::current_session_id(db, token.as_str()).await? {
        Some(sid) => sid,
        None => return Ok(false),
    };
    let elevated_until: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT elevated_until FROM rustio_sessions \
          WHERE session_id = $1 AND revoked_at IS NULL",
    )
    .bind(session_id)
    .fetch_optional(db.pool())
    .await
    .map_err(rustio_admin::Error::from)?
    .flatten();

    Ok(match elevated_until {
        Some(eu) => eu > Utc::now(),
        None => false,
    })
}
