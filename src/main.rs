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
//! Phase 1 complete: five domain models registered with
//! `Admin::new()`, schemas migrated from `migrations/`. The
//! framework's CRUD pages are reachable at `/admin/reports`,
//! `/admin/cases`, `/admin/case-actions`, `/admin/documents`,
//! `/admin/disclosures`.
//!
//! ## What comes next
//!
//! - Phase 2: the public anonymous submission page at
//!   `/report/new`, outside `/admin`. CSRF-gated, captcha
//!   optional, lands a `Report` row + any `Document` rows.
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

    let router = Router::new()
        .middleware(middleware::logger)
        // Doctrine 8: correlation_id sits BEFORE csrf_protect so
        // every rejected request still carries a forensic trace.
        .middleware(middleware::correlation_id)
        .middleware(middleware::security_headers)
        .middleware(middleware::csrf_protect)
        .get("/", |_req| async {
            Ok(Response::text(
                "lursystem alive — see /admin for the admin panel",
            ))
        });

    let router = register_admin_routes(router, admin, db, templates);

    let addr: std::net::SocketAddr = "127.0.0.1:8000".parse().expect("bind addr");
    log::info!("lursystem booting on http://{addr}/admin");
    Server::new(router, addr).run().await?;

    Ok(())
}
