//! The authentication context threaded through every kernel call.
//!
//! Every service method takes an [`AuthContext`]. It carries *who* the actor is,
//! *which tenant/org* they are scoped to, and their resolved role keys. There is
//! no kernel entry point that omits it, which is how tenant isolation and
//! permission checks become unavoidable rather than optional.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// A human user.
    User,
    /// A non-human credential (API key holder) acting on behalf of an integration.
    ServiceAccount,
    /// An AI agent acting under a constrained role and safety policy.
    Agent,
    /// The platform itself (migrations, seeding, scheduled jobs). System actions
    /// are still audited.
    System,
}

/// Where a request originated. Recorded on audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Api,
    AdminUi,
    Agent,
    System,
    Seed,
}

/// Resolved identity + scope for a single operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthContext {
    pub actor_type: ActorType,
    pub actor_id: String,
    pub tenant_id: String,
    pub org_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Resolved role keys (already expanded from user/service-account assignments).
    #[serde(default)]
    pub role_keys: Vec<String>,
    /// Platform admins may operate across tenants (still audited). Almost all
    /// actors have this `false`.
    #[serde(default)]
    pub is_platform_admin: bool,
    /// Correlation id for tracing + audit.
    pub request_id: String,
    pub source: Source,
    /// For `Agent` actors: the safety level the agent is permitted to operate at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_safety_level: Option<u8>,
}

impl AuthContext {
    /// Build a system context for the given tenant/org (used by seeding,
    /// migrations, and scheduled jobs). System actions are audited like any other.
    pub fn system(tenant_id: impl Into<String>, org_id: impl Into<String>) -> Self {
        Self {
            actor_type: ActorType::System,
            actor_id: "system".to_string(),
            tenant_id: tenant_id.into(),
            org_id: org_id.into(),
            workspace_id: None,
            role_keys: vec!["system".to_string()],
            is_platform_admin: true,
            request_id: crate::ids::new_id(),
            source: Source::System,
            agent_safety_level: None,
        }
    }

    pub fn is_agent(&self) -> bool {
        matches!(self.actor_type, ActorType::Agent)
    }

    pub fn is_system(&self) -> bool {
        matches!(self.actor_type, ActorType::System)
    }
}
