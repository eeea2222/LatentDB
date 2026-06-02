//! The permission model: roles, structured grants, scopes, ABAC conditions, and
//! field-level rules.
//!
//! This is *data only*. The single decision function `authorize(...)` that
//! interprets it lives in the kernel's RBAC service, so there is exactly one
//! place in the whole platform where access is decided.

use serde::{Deserialize, Serialize};

/// What an actor is trying to do. Every read, write, search, relation traversal,
/// report, export, workflow transition, approval, and AI operation maps to one
/// of these verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Create,
    Read,
    Update,
    Archive,
    Restore,
    Relate,
    Transition,
    Approve,
    Export,
    Search,
    /// Read/admin configuration (object types, roles, providers, settings, ...).
    Configure,
    /// Execute an AI action or automation with side effects.
    Execute,
    /// Run an AI action in dry-run mode (no side effects).
    DryRun,
    /// Manage a whole resource family (broad admin grant).
    Manage,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Read => "read",
            Action::Update => "update",
            Action::Archive => "archive",
            Action::Restore => "restore",
            Action::Relate => "relate",
            Action::Transition => "transition",
            Action::Approve => "approve",
            Action::Export => "export",
            Action::Search => "search",
            Action::Configure => "configure",
            Action::Execute => "execute",
            Action::DryRun => "dry_run",
            Action::Manage => "manage",
        }
    }
}

/// How widely a grant applies. Evaluated against the [`crate::AuthContext`] and,
/// for record-level checks, against the target record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Platform-wide (cross-tenant). Only ever granted to platform admins.
    Platform,
    /// Anything inside the actor's tenant.
    Tenant,
    /// Anything inside the actor's organization.
    Org,
    /// Anything inside the actor's workspace.
    Workspace,
    /// Only records the actor owns / is assigned to / created.
    Own,
}

/// A single permission rule on a role.
///
/// `resource` is a resource key such as `"object:invoice"`, `"record"`,
/// `"report"`, `"agent:finance"`, `"admin:users"`, or `"*"` for any resource of
/// the given action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionGrant {
    pub action: Action,
    pub resource: String,
    #[serde(default = "default_scope")]
    pub scope: Scope,
    /// Optional field-level restriction applied when this grant authorizes a read
    /// or write of record fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<FieldRule>,
    /// Optional ABAC conditions; all must hold for the grant to apply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

fn default_scope() -> Scope {
    Scope::Org
}

impl PermissionGrant {
    pub fn new(action: Action, resource: impl Into<String>, scope: Scope) -> Self {
        Self {
            action,
            resource: resource.into(),
            scope,
            fields: None,
            conditions: Vec::new(),
        }
    }

    /// Does this grant's resource pattern match the requested resource key?
    /// Supports exact match, `"*"` wildcard, and `"object:*"` prefix wildcards.
    pub fn matches_resource(&self, resource: &str) -> bool {
        if self.resource == "*" || self.resource == resource {
            return true;
        }
        if let Some(prefix) = self.resource.strip_suffix('*') {
            return resource.starts_with(prefix);
        }
        false
    }
}

/// Field-level access control. A grant either allows only the listed fields
/// (`Allow`, an allow-list) or allows everything except the listed fields
/// (`Deny`, a deny-list — e.g. hiding HR salary/compensation fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldRule {
    pub mode: FieldRuleMode,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldRuleMode {
    Allow,
    Deny,
}

impl FieldRule {
    /// Is `field` visible/writable under this rule?
    pub fn permits(&self, field: &str) -> bool {
        match self.mode {
            FieldRuleMode::Allow => self.fields.iter().any(|f| f == field),
            FieldRuleMode::Deny => !self.fields.iter().any(|f| f == field),
        }
    }
}

/// An ABAC condition compared against a record field (or actor attribute).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    /// Dotted path; `record.<field>` or `actor.<attr>`.
    pub field: String,
    pub op: ConditionOp,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOp {
    Eq,
    Ne,
    In,
    Gt,
    Lt,
    Gte,
    Lte,
    Contains,
}

/// A named role: a bundle of grants assigned to users/service accounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    /// Stable key, e.g. `"tenant_admin"`, `"finance_user"`, `"sales_rep"`.
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// System roles are seeded and cannot be deleted by tenant admins.
    #[serde(default)]
    pub system: bool,
    pub grants: Vec<PermissionGrant>,
}
