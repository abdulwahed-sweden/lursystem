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

    // Framework admin surface (R0-R3).
    let router = register_admin_routes(router, admin, db, templates);

    let addr: std::net::SocketAddr = "127.0.0.1:8000".parse().expect("bind addr");
    log::info!("lursystem booting on http://{addr}/admin");
    Server::new(router, addr).run().await?;

    Ok(())
}
