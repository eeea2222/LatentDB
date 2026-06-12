//! LatentDB business modules: CRM, Finance/ERP, Procurement, Inventory/SCM, HCM,
//! Projects, and Contracts — all expressed as metadata on the shared kernel.
//!
//! Modules contribute object types, workflows, and roles (see [`schema`] and
//! [`roles`]). They never bypass the kernel's tenant, permission, workflow, or
//! audit systems.

pub mod install;
pub mod roles;
pub mod schema;

pub use install::install;
