//! Project-side HTTP handlers.
//!
//! The framework's admin routes are registered via
//! `register_admin_routes` from `rustio_admin`. This module owns
//! the routes that live ALONGSIDE `/admin` — both the public
//! anonymous submission flow that reporters reach without
//! authenticating (`public`), and the operator-side workflow
//! pages (`triage`, …) that gate access through
//! `crate::auth_helper::require_role`.

pub mod cases;
pub mod public;
pub mod triage;
