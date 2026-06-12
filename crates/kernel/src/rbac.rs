//! Role-based + attribute-based access control.
//!
//! This module owns the *only* access decision in the platform:
//! [`Kernel::authorize`]. Reads, writes, search, relations, reports, exports,
//! workflow transitions, approvals, and every AI operation route through it.
//! Field-level and record-level checks live here too, so there is exactly one
//! place to reason about "who can do what".

use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::{
    Action, ApiError, AuthContext, Condition, ConditionOp, FieldRuleMode, ObjectTypeDef,
    PermissionGrant, Record, Role, Scope,
};
use serde_json::Value;
use sqlx::Row;

/// The system roles seeded into every new tenant. `tenant_admin` can manage the
/// entire tenant (and, via a deny-nothing field rule, see restricted fields).
/// `member` is a minimal baseline used as a safe default for ordinary users.
pub fn system_roles() -> Vec<Role> {
    use latentdb_contracts::FieldRule;
    let mut admin_manage = PermissionGrant::new(Action::Manage, "*", Scope::Tenant);
    admin_manage.fields = Some(FieldRule {
        mode: FieldRuleMode::Deny,
        fields: vec![], // deny nothing => admins see/write all fields, incl. restricted
    });

    vec![
        Role {
            id: "role_tenant_admin".into(),
            key: "tenant_admin".into(),
            name: "Tenant Administrator".into(),
            description: Some("Full management of this tenant".into()),
            system: true,
            grants: vec![admin_manage],
        },
        Role {
            id: "role_member".into(),
            key: "member".into(),
            name: "Member".into(),
            description: Some("Baseline read access within the organization".into()),
            system: true,
            grants: vec![
                PermissionGrant::new(Action::Read, "object:*", Scope::Org),
                PermissionGrant::new(Action::Search, "object:*", Scope::Org),
                PermissionGrant::new(Action::Create, "object:*", Scope::Org),
                PermissionGrant::new(Action::Update, "object:*", Scope::Own),
                PermissionGrant::new(Action::Read, "tenant", Scope::Tenant),
                PermissionGrant::new(Action::Read, "organization", Scope::Tenant),
                PermissionGrant::new(Action::Read, "report", Scope::Org),
                PermissionGrant::new(Action::Read, "metric", Scope::Org),
                PermissionGrant::new(Action::Read, "dashboard", Scope::Org),
            ],
        },
    ]
}

/// Does a grant for `grant_action` authorize a request for `requested`? A
/// `Manage` grant covers every action; otherwise actions must match exactly.
fn action_covered_by(grant_action: Action, requested: Action) -> bool {
    grant_action == requested || grant_action == Action::Manage
}

/// Evaluate a grant's scope against the context and (optionally) the target
/// record. With no target (creates, list endpoints) scopes that need a record to
/// compare against pass; the kernel applies the same scope per-row when listing.
fn scope_ok(scope: Scope, ctx: &AuthContext, target: Option<&Record>) -> bool {
    match scope {
        Scope::Platform => ctx.is_platform_admin,
        Scope::Tenant => true,
        Scope::Org => match target {
            Some(r) => r.org_id == ctx.org_id,
            None => true,
        },
        Scope::Workspace => match target {
            Some(r) => r.workspace_id == ctx.workspace_id,
            None => true,
        },
        Scope::Own => match target {
            Some(r) => r.owner_candidates().iter().any(|o| o == &ctx.actor_id),
            None => true,
        },
    }
}

/// Evaluate ABAC conditions against the target record / actor. Conditions that
/// reference a record are skipped when there is no target.
fn conditions_ok(conditions: &[Condition], ctx: &AuthContext, target: Option<&Record>) -> bool {
    conditions.iter().all(|c| eval_condition(c, ctx, target))
}

fn eval_condition(cond: &Condition, ctx: &AuthContext, target: Option<&Record>) -> bool {
    let lhs: Option<Value> = if let Some(field) = cond.field.strip_prefix("record.") {
        target.and_then(|r| r.data.get(field).cloned())
    } else if let Some(attr) = cond.field.strip_prefix("actor.") {
        match attr {
            "id" => Some(Value::String(ctx.actor_id.clone())),
            "org_id" => Some(Value::String(ctx.org_id.clone())),
            _ => None,
        }
    } else {
        None
    };

    // If we can't resolve the operand (e.g. record-scoped condition on a create),
    // do not let the condition block the grant.
    let Some(lhs) = lhs else { return true };
    compare(&lhs, cond.op, &cond.value)
}

/// Public(crate) comparison used by record field filters as well as ABAC.
pub(crate) fn value_matches(lhs: &Value, op: ConditionOp, rhs: &Value) -> bool {
    compare(lhs, op, rhs)
}

fn compare(lhs: &Value, op: ConditionOp, rhs: &Value) -> bool {
    match op {
        ConditionOp::Eq => lhs == rhs,
        ConditionOp::Ne => lhs != rhs,
        ConditionOp::In => rhs.as_array().map(|a| a.contains(lhs)).unwrap_or(false),
        ConditionOp::Contains => match (lhs, rhs) {
            (Value::String(s), Value::String(sub)) => s.contains(sub.as_str()),
            (Value::Array(arr), v) => arr.contains(v),
            _ => false,
        },
        ConditionOp::Gt | ConditionOp::Lt | ConditionOp::Gte | ConditionOp::Lte => {
            match (lhs.as_f64(), rhs.as_f64()) {
                (Some(a), Some(b)) => match op {
                    ConditionOp::Gt => a > b,
                    ConditionOp::Lt => a < b,
                    ConditionOp::Gte => a >= b,
                    ConditionOp::Lte => a <= b,
                    _ => unreachable!(),
                },
                _ => false,
            }
        }
    }
}

/// Whether a field is visible/writable given the actor's applicable grants for
/// the relevant action. Non-restricted fields are always allowed (the actor
/// already holds the action); restricted fields require a grant whose field rule
/// explicitly permits the key.
pub(crate) fn field_permitted(
    grants: &[&PermissionGrant],
    object_type: &ObjectTypeDef,
    field_key: &str,
) -> bool {
    let restricted = object_type
        .field(field_key)
        .map(|f| f.restricted)
        .unwrap_or(false);
    if !restricted {
        return true;
    }
    grants.iter().any(|g| {
        g.fields
            .as_ref()
            .map(|fr| fr.permits(field_key))
            .unwrap_or(false)
    })
}

impl Kernel {
    /// The single authorization decision. Returns `Ok(())` if permitted, or a
    /// `Forbidden` error (and writes a security audit event) if not.
    pub async fn authorize(
        &self,
        ctx: &AuthContext,
        action: Action,
        resource: &str,
        target: Option<&Record>,
    ) -> latentdb_contracts::Result<()> {
        // System actors (migrations, seeding, scheduled jobs) and platform admins
        // are trusted; their actions are still audited by the calling services.
        if ctx.is_system() || ctx.is_platform_admin {
            return Ok(());
        }

        let grants = self.effective_grants(ctx).await?;
        let advanced = self.flags().enable_advanced_permissions;
        let allowed = grants.iter().any(|g| {
            action_covered_by(g.action, action)
                && g.matches_resource(resource)
                && scope_ok(g.scope, ctx, target)
                && (!advanced || conditions_ok(&g.conditions, ctx, target))
        });

        if allowed {
            Ok(())
        } else {
            self.audit_denial(
                ctx,
                action.as_str(),
                resource,
                target.map(|r| r.id.as_str()),
            )
            .await;
            Err(ApiError::forbidden(format!(
                "not permitted: {} on {}",
                action.as_str(),
                resource
            )))
        }
    }

    /// Synchronous, non-auditing permission check against an already-loaded grant
    /// set. Used by list/query paths to filter many rows after a single grant
    /// load, applying the same scope and ABAC rules as [`Self::authorize`].
    pub(crate) fn grants_allow(
        &self,
        grants: &[PermissionGrant],
        ctx: &AuthContext,
        action: Action,
        resource: &str,
        target: Option<&Record>,
    ) -> bool {
        if ctx.is_system() || ctx.is_platform_admin {
            return true;
        }
        let advanced = self.flags().enable_advanced_permissions;
        grants.iter().any(|g| {
            action_covered_by(g.action, action)
                && g.matches_resource(resource)
                && scope_ok(g.scope, ctx, target)
                && (!advanced || conditions_ok(&g.conditions, ctx, target))
        })
    }

    /// The applicable read grants for a specific record (subset of `grants` that
    /// authorize reading it), used to compute field-level visibility per row.
    pub(crate) fn applicable_read_grants<'a>(
        &self,
        grants: &'a [PermissionGrant],
        ctx: &AuthContext,
        resource: &str,
        target: Option<&Record>,
    ) -> Vec<&'a PermissionGrant> {
        let advanced = self.flags().enable_advanced_permissions;
        grants
            .iter()
            .filter(|g| {
                action_covered_by(g.action, Action::Read)
                    && g.matches_resource(resource)
                    && scope_ok(g.scope, ctx, target)
                    && (!advanced || conditions_ok(&g.conditions, ctx, target))
            })
            .collect()
    }

    /// Load and flatten every permission grant the actor holds via their roles.
    pub(crate) async fn effective_grants(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<Vec<PermissionGrant>> {
        if ctx.role_keys.is_empty() {
            return Ok(vec![]);
        }
        // Build a parameterized IN clause for the role keys.
        let placeholders = std::iter::repeat("?")
            .take(ctx.role_keys.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT grants_json FROM roles WHERE tenant_id = ? AND key IN ({placeholders})"
        );
        let mut q = sqlx::query(&sql).bind(&ctx.tenant_id);
        for key in &ctx.role_keys {
            q = q.bind(key);
        }
        let rows = q.fetch_all(self.pool()).await.map_err(map_db_err)?;
        let mut grants = Vec::new();
        for row in &rows {
            let json: String = row.try_get("grants_json").map_err(map_db_err)?;
            if let Ok(mut parsed) = serde_json::from_str::<Vec<PermissionGrant>>(&json) {
                grants.append(&mut parsed);
            }
        }
        Ok(grants)
    }

    /// The subset of the actor's grants that authorize `action` on `resource`
    /// (ignoring per-field rules), used to compute field-level visibility.
    pub(crate) async fn grants_for(
        &self,
        ctx: &AuthContext,
        action: Action,
        resource: &str,
        target: Option<&Record>,
    ) -> latentdb_contracts::Result<Vec<PermissionGrant>> {
        if ctx.is_system() || ctx.is_platform_admin {
            // A synthetic admin grant that permits all fields.
            use latentdb_contracts::FieldRule;
            let mut g = PermissionGrant::new(Action::Manage, "*", Scope::Tenant);
            g.fields = Some(FieldRule {
                mode: FieldRuleMode::Deny,
                fields: vec![],
            });
            return Ok(vec![g]);
        }
        let advanced = self.flags().enable_advanced_permissions;
        let all = self.effective_grants(ctx).await?;
        Ok(all
            .into_iter()
            .filter(|g| {
                action_covered_by(g.action, action)
                    && g.matches_resource(resource)
                    && scope_ok(g.scope, ctx, target)
                    && (!advanced || conditions_ok(&g.conditions, ctx, target))
            })
            .collect())
    }
}
