//! Lursystem domain models.
//!
//! Each submodule declares one `#[derive(RustioAdmin)]` struct
//! plus its `Model + ModelAdmin` impls — the framework reads the
//! derive's metadata and the trait body to generate the admin
//! CRUD pages, list filters, search box, and ordering. See
//! `rustio-admin`'s `ModelAdmin` documentation for the override
//! surface.

pub mod case;
pub mod case_action;
pub mod disclosure;
pub mod document;
pub mod report;

pub use case::Case;
pub use case_action::CaseAction;
pub use disclosure::Disclosure;
pub use document::Document;
pub use report::Report;
