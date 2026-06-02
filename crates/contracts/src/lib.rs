//! LatentDB shared contracts.
//!
//! This crate is the single source of truth for the data shapes that cross every
//! boundary in LatentDB: ids, errors, permissions, field/object/record models,
//! workflow definitions, audit events, auth context, and feature flags.
//!
//! Nothing here performs IO or talks to a database. Keeping these types in one
//! dependency-light crate is how every other crate (kernel, ai, accel, modules,
//! api) shares *stable contracts* instead of inventing parallel models.

pub mod audit;
pub mod auth;
pub mod error;
pub mod field;
pub mod flags;
pub mod ids;
pub mod object;
pub mod page;
pub mod permission;
pub mod record;
pub mod workflow;

pub use audit::{AuditEvent, AuditQuery};
pub use auth::{ActorType, AuthContext, Source};
pub use error::{ApiError, ErrorBody, ErrorCode, Result};
pub use field::{FieldDefinition, FieldType};
pub use flags::FeatureFlags;
pub use ids::{new_id, now, now_rfc3339, to_rfc3339};
pub use object::ObjectTypeDef;
pub use page::{ListResponse, Page, RecordFilter};
pub use permission::{
    Action, Condition, ConditionOp, FieldRule, FieldRuleMode, PermissionGrant, Role, Scope,
};
pub use record::{NewRecord, Record, RecordPatch};
pub use workflow::{Transition, WorkflowDef, WorkflowState};
