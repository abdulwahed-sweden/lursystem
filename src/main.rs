//! Lursystem — whistleblower reporting + case handling.
//!
//! See `README.md` for the project's scope, role hierarchy, and
//! build roadmap. Security-sensitive behaviour (sessions, MFA,
//! audit, recovery) is governed by the rustio-admin DESIGN_*.md
//! contracts.
//!
//! ## What lives here today
//!
//! Bare boot. `Admin::new()` with no project schemas registered
//! yet — the framework's User / Group / Permission surface is
//! the only thing reachable at `/admin`. The five domain models
//! (Report, Case, CaseAction, Document, Disclosure) land in
//! subsequent commits per the README's build roadmap.
//!
//! ## What comes next
//!
//! 1. Database migrations for the 5 domain tables.
//! 2. Model registrations (`Admin::model::<Report>()`, etc.).
//! 3. The public anonymous submission page (outside `/admin`).
//! 4. The handler case workflow + reporter-identity unmask.
//! 5. The auditor read-only surface.
//! 6. The quarterly export.

use rustio_admin::admin::Admin;
use rustio_admin::middleware;
use rustio_admin::templates::Templates;
use rustio_admin::{auth, register_admin_routes, Db, Response, Result, Router, Server};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init();

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set (see .env.example)");

    let db = Db::connect(&database_url).await?;
    auth::init_tables(&db).await?;

    let admin = Admin::new();
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
