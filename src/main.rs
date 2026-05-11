//! Lursystem — whistleblower reporting + case handling.
//!
//! See `README.md` for the project's scope, role hierarchy, and
//! build roadmap. Security-sensitive behaviour (sessions, MFA,
//! audit, recovery) is governed by the rustio-admin DESIGN_*.md
//! contracts; the project-side code lives in `src/models/` and
//! (Phase 2+) `src/handlers/`.
//!
//! ## What lives here today
//!
//! - Phase 1: five domain models registered with `Admin::new()`,
//!   schemas migrated from `migrations/`. The framework's CRUD
//!   pages are reachable at `/admin/reports`, `/admin/cases`,
//!   `/admin/case-actions`, `/admin/documents`,
//!   `/admin/disclosures`.
//! - Phase 2: public anonymous submission flow at
//!   `/report/new` (GET + POST). Mounted on the root router
//!   BEFORE `register_admin_routes` so the framework's
//!   `/admin/*` wildcard never shadows it. CSRF-gated by the
//!   global middleware. Lands a `Report` row in `status =
//!   'intake'` and shows the reporter a single-use token for
//!   future status checks.
//!
//! ## What comes next
//!
//! - Phase 2.5: `/report/status?token=…` reporter self-service
//!   page for checking the case's current status without
//!   authenticating.
//! - Phase 3: handler case workflow — status transitions,
//!   internal notes, document downloads, all audited via
//!   `CaseAction`.
//! - Phase 4: reporter-identity unmask. Re-auth required;
//!   `Disclosure` row written; framework's audit chain ties
//!   the disclosure to the request, the session, and the
//!   compliance lead.
//! - Phase 5: auditor read-only surface — audit-log view
//!   with a `correlation_id` pivot to reconstruct the full
//!   forensic chain.
//! - Phase 6: quarterly compliance export.

mod auth_helper;
mod handlers;
mod models;

use rustio_admin::admin::Admin;
use rustio_admin::middleware;
use rustio_admin::templates::Templates;
use rustio_admin::{auth, migrations, register_admin_routes, Db, Response, Result, Router, Server};

use models::{Case, CaseAction, Disclosure, Document, Report};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init();

    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set (see .env.example)");

    let db = Db::connect(&database_url).await?;
    auth::init_tables(&db).await?;
    migrations::apply(&db, "migrations").await?;

    let admin = Admin::new()
        .model::<Report>()
        .model::<Case>()
        .model::<CaseAction>()
        .model::<Document>()
        .model::<Disclosure>();
    admin.seed_permissions(&db).await?;

    let templates = Templates::new(None)?;

    // Build the router. Middleware order is locked by
    // DESIGN_AUDIT.md §11: logger → correlation_id →
    // security_headers → csrf_protect. The R3-era frameworks
    // assume this order; do not reorder without re-reading
    // the doctrine.
    //
    // The public `/report/*` routes mount BEFORE
    // `register_admin_routes` so the framework's admin wildcards
    // never shadow them. The submission flow runs through the
    // same CSRF + correlation_id middleware as the admin routes,
    // so failed POSTs still trace through the framework's audit
    // surface.
    let router = Router::new()
        .middleware(middleware::logger)
        .middleware(middleware::correlation_id)
        .middleware(middleware::security_headers)
        .middleware(middleware::csrf_protect)
        .get("/", |_req| async {
            Ok(Response::text(
                "lursystem alive — see /report/new to submit a report, \
                 or /admin for the operator panel",
            ))
        });

    // Public submission flow (Phase 2).
    let router = router.get("/report/new", |req| async move {
        handlers::public::show_report_form(req).await
    });
    let db_for_submit = db.clone();
    let router = router.post("/report/new", move |req| {
        let db = db_for_submit.clone();
        async move { handlers::public::do_submit_report(db, req).await }
    });

    // Public status-check flow (Phase 2.5). Reporters paste the
    // token they were shown at submission time; the handler
    // returns the case's current status. Token rides POST form
    // body so it stays out of browser history + logger lines.
    let router = router.get("/report/status", |req| async move {
        handlers::public::show_status_form(req).await
    });
    let db_for_status = db.clone();
    let router = router.post("/report/status", move |req| {
        let db = db_for_status.clone();
        async move { handlers::public::do_status_lookup(db, req).await }
    });

    // Operator triage queue (Phase 3a). Compliance-lead-gated
    // via `auth_helper::require_role(Role::Administrator)`.
    // Mounts BEFORE `register_admin_routes` so the framework's
    // model-CRUD wildcards never shadow these paths.
    let db_for_triage = db.clone();
    let router = router.get("/admin/triage", move |req| {
        let db = db_for_triage.clone();
        async move { handlers::triage::show_triage_queue(db, req).await }
    });
    let db_for_open = db.clone();
    let router = router.post("/admin/triage/:report_id/open-case", move |req| {
        let db = db_for_open.clone();
        async move {
            let report_id: i64 = req
                .param("report_id")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            handlers::triage::do_open_case(db, report_id, req).await
        }
    });

    // Case detail / work surface (Phase 3b). Read-only view of
    // a single case. Staff+ can read; the in-handler filter
    // restricts handlers to their own assigned cases while
    // leads (Administrator+) see every case.
    let db_for_case_detail = db.clone();
    let router = router.get("/admin/cases/:case_id/work", move |req| {
        let db = db_for_case_detail.clone();
        async move {
            let case_id: i64 = req
                .param("case_id")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            handlers::cases::show_case_detail(db, case_id, req).await
        }
    });

    // Case workflow mutations (Phase 3c). Three POSTs hung off
    // the case detail page:
    //
    //   /admin/cases/:case_id/status    — status transition
    //                                     (terminal targets
    //                                     require re-auth)
    //   /admin/cases/:case_id/notes     — internal note
    //   /admin/cases/:case_id/reassign  — change assignee
    //                                     (lead-only)
    //
    // Each writes a `case_actions` row + updates the relevant
    // primary state (`cases.status` / `cases.assignee_id`).
    // The terminal-status path stamps `cases.closed_at`.
    let db_for_status = db.clone();
    let router = router.post("/admin/cases/:case_id/status", move |req| {
        let db = db_for_status.clone();
        async move {
            let case_id: i64 = req
                .param("case_id")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            handlers::cases::do_status_transition(db, case_id, req).await
        }
    });

    let db_for_notes = db.clone();
    let router = router.post("/admin/cases/:case_id/notes", move |req| {
        let db = db_for_notes.clone();
        async move {
            let case_id: i64 = req
                .param("case_id")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            handlers::cases::do_add_note(db, case_id, req).await
        }
    });

    let db_for_reassign = db.clone();
    let router = router.post("/admin/cases/:case_id/reassign", move |req| {
        let db = db_for_reassign.clone();
        async move {
            let case_id: i64 = req
                .param("case_id")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            handlers::cases::do_reassign(db, case_id, req).await
        }
    });

    // Reporter-identity unmask (Phase 4). Compliance-lead-only.
    // The GET bounces to /admin/reauth if the session is not
    // elevated; the POST writes a `disclosures` row + a
    // `case_actions` row (action_type='disclosure_consumed')
    // atomically and renders the reporter's e-mail to the lead.
    // The case detail page never renders the e-mail — each
    // viewing of the identity is an audited event.
    let db_for_disclose_get = db.clone();
    let router = router.get("/admin/cases/:case_id/disclose", move |req| {
        let db = db_for_disclose_get.clone();
        async move {
            let case_id: i64 = req
                .param("case_id")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            handlers::disclosure::show_disclose_form(db, case_id, req).await
        }
    });
    let db_for_disclose_post = db.clone();
    let router = router.post("/admin/cases/:case_id/disclose", move |req| {
        let db = db_for_disclose_post.clone();
        async move {
            let case_id: i64 = req
                .param("case_id")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            handlers::disclosure::do_disclose(db, case_id, req).await
        }
    });

    // Auditor read-only surface (Phase 5). Gated at
    // `Role::Supervisor` (the audit floor — supervisors review;
    // staff handlers do not see other handlers' work through this
    // surface). The page is read-only — no forms, no mutations.
    // Filters via query string: action_type, correlation, actor,
    // case, since-date. Paginated at 50/page. Each row carries a
    // correlation_id link so an auditor can pivot to every event
    // under the same HTTP request.
    let db_for_audit = db.clone();
    let router = router.get("/admin/audit", move |req| {
        let db = db_for_audit.clone();
        async move { handlers::audit::show_audit_log(db, req).await }
    });

    // Compliance export (Phase 6). Tamper-evident JSON artefact
    // covering every audit-bearing row in a date range, signed
    // with HMAC-SHA256 keyed by RUSTIO_SECRET_KEY. The Phase 4
    // privacy invariant is preserved — reporter_email is NOT in
    // the export. Reporter identities still require the Phase 4
    // disclosure flow. Supervisor-or-higher only; mounted before
    // register_admin_routes so the framework's wildcards do not
    // shadow it.
    let db_for_export = db.clone();
    let router = router.get("/admin/audit/export", move |req| {
        let db = db_for_export.clone();
        async move { handlers::export::do_export(db, req).await }
    });

    // Framework admin surface (R0-R3).
    let router = register_admin_routes(router, admin, db, templates);

    let addr: std::net::SocketAddr = "127.0.0.1:8000".parse().expect("bind addr");
    log::info!("lursystem booting on http://{addr}/admin");
    Server::new(router, addr).run().await?;

    Ok(())
}
