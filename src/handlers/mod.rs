//! Project-side HTTP handlers.
//!
//! The framework's admin routes are registered via
//! `register_admin_routes` from `rustio_admin`. This module owns
//! the routes that live OUTSIDE `/admin` — primarily the public
//! anonymous submission flow that reporters reach without
//! authenticating.

pub mod public;
