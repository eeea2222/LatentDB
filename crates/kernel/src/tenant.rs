//! Tenant, organization, and workspace services, plus the bootstrap flow that
//! provisions a brand-new tenant (default org, system roles, first admin user).

use crate::audit::{event_from, insert_audit};
use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::{ids, Action, ApiError, AuthContext};
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub slug: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: String,
    pub tenant_id: String,
    pub org_id: String,
    pub name: String,
    pub created_at: String,
}

/// Result of provisioning a fresh tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapResult {
    pub tenant: Tenant,
    pub org: Organization,
    pub admin_user_id: String,
}

impl Kernel {
    /// Provision a new tenant end-to-end: tenant row, a default organization, the
    /// two system roles (`tenant_admin`, `member`), and the first admin user
    /// assigned `tenant_admin`. Runs as a `System` actor and is fully audited.
    ///
    /// This is the admin-bootstrap flow used by seeding and first-run setup.
    pub async fn bootstrap_tenant(
        &self,
        name: &str,
        slug: &str,
        admin_email: &str,
        admin_name: &str,
        admin_password: &str,
    ) -> latentdb_contracts::Result<BootstrapResult> {
        let slug = slug.trim().to_lowercase();
        validate_slug(&slug)?;
        let admin_email = crate::auth::normalize_email(admin_email);
        crate::identity::validate_email(&admin_email)?;
        crate::crypto::validate_password_strength(admin_password)?;
        let now = ids::now_rfc3339();
        let tenant_id = ids::new_id();
        let org_id = ids::new_id();
        let admin_id = ids::new_id();
        let ctx = AuthContext::system(&tenant_id, &org_id);
        let pw_hash = crate::crypto::hash_password(admin_password)?;

        let mut tx = self.pool().begin().await.map_err(map_db_err)?;

        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at) VALUES (?,?,?,?,?,?)",
        )
        .bind(&tenant_id)
        .bind(name)
        .bind(&slug)
        .bind("standard")
        .bind("active")
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(map_db_err)?;

        sqlx::query(
            "INSERT INTO organizations (id, tenant_id, name, slug, created_at) VALUES (?,?,?,?,?)",
        )
        .bind(&org_id)
        .bind(&tenant_id)
        .bind(name)
        .bind("default")
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(map_db_err)?;

        // System roles.
        for role in crate::rbac::system_roles() {
            let grants = serde_json::to_string(&role.grants).unwrap_or_else(|_| "[]".into());
            sqlx::query("INSERT INTO roles (id, tenant_id, key, name, description, system, grants_json, created_at) VALUES (?,?,?,?,?,?,?,?)")
                .bind(ids::new_id()).bind(&tenant_id).bind(&role.key).bind(&role.name)
                .bind(&role.description).bind(role.system as i64).bind(&grants).bind(&now)
                .execute(&mut *tx).await.map_err(map_db_err)?;
        }

        // Admin user.
        sqlx::query("INSERT INTO users (id, tenant_id, email, name, password_hash, status, is_platform_admin, default_org_id, created_at) VALUES (?,?,?,?,?,?,?,?,?)")
            .bind(&admin_id).bind(&tenant_id).bind(&admin_email).bind(admin_name)
            .bind(&pw_hash).bind("active").bind(0i64).bind(&org_id).bind(&now)
            .execute(&mut *tx).await.map_err(map_db_err)?;

        sqlx::query("INSERT INTO role_assignments (id, tenant_id, principal_type, principal_id, role_key, org_id, created_at) VALUES (?,?,?,?,?,?,?)")
            .bind(ids::new_id()).bind(&tenant_id).bind("user").bind(&admin_id)
            .bind("tenant_admin").bind(&org_id).bind(&now)
            .execute(&mut *tx).await.map_err(map_db_err)?;

        let ev = event_from(
            &ctx,
            "tenant.create",
            Some("tenant"),
            Some(&tenant_id),
            None,
            Some(serde_json::json!({"name": name, "slug": slug, "admin": admin_email})),
        );
        insert_audit(&mut tx, &ev).await?;

        tx.commit().await.map_err(map_db_err)?;

        Ok(BootstrapResult {
            tenant: Tenant {
                id: tenant_id.clone(),
                name: name.into(),
                slug,
                plan: "standard".into(),
                status: "active".into(),
                created_at: now.clone(),
            },
            org: Organization {
                id: org_id,
                tenant_id,
                name: name.into(),
                slug: "default".into(),
                created_at: now,
            },
            admin_user_id: admin_id,
        })
    }

    /// Fetch the tenant the caller belongs to.
    pub async fn get_tenant(&self, ctx: &AuthContext) -> latentdb_contracts::Result<Tenant> {
        self.authorize(ctx, Action::Read, "tenant", None).await?;
        let row = sqlx::query("SELECT * FROM tenants WHERE id = ?")
            .bind(&ctx.tenant_id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::not_found("tenant not found"))?;
        Ok(Tenant {
            id: row.try_get("id").map_err(map_db_err)?,
            name: row.try_get("name").map_err(map_db_err)?,
            slug: row.try_get("slug").map_err(map_db_err)?,
            plan: row.try_get("plan").map_err(map_db_err)?,
            status: row.try_get("status").map_err(map_db_err)?,
            created_at: row.try_get("created_at").map_err(map_db_err)?,
        })
    }

    /// List all tenants. Platform-admin only (cross-tenant view).
    pub async fn list_tenants(&self, ctx: &AuthContext) -> latentdb_contracts::Result<Vec<Tenant>> {
        if !ctx.is_platform_admin && !ctx.is_system() {
            self.audit_denial(ctx, "read", "platform:tenants", None)
                .await;
            return Err(ApiError::forbidden("platform admin required"));
        }
        let rows = sqlx::query("SELECT * FROM tenants ORDER BY created_at DESC")
            .fetch_all(self.pool())
            .await
            .map_err(map_db_err)?;
        rows.iter()
            .map(|row| {
                Ok(Tenant {
                    id: row.try_get("id").map_err(map_db_err)?,
                    name: row.try_get("name").map_err(map_db_err)?,
                    slug: row.try_get("slug").map_err(map_db_err)?,
                    plan: row.try_get("plan").map_err(map_db_err)?,
                    status: row.try_get("status").map_err(map_db_err)?,
                    created_at: row.try_get("created_at").map_err(map_db_err)?,
                })
            })
            .collect()
    }

    /// List organizations within the caller's tenant.
    pub async fn list_organizations(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<Vec<Organization>> {
        self.authorize(ctx, Action::Read, "organization", None)
            .await?;
        let rows =
            sqlx::query("SELECT * FROM organizations WHERE tenant_id = ? ORDER BY created_at")
                .bind(&ctx.tenant_id)
                .fetch_all(self.pool())
                .await
                .map_err(map_db_err)?;
        rows.iter()
            .map(|row| {
                Ok(Organization {
                    id: row.try_get("id").map_err(map_db_err)?,
                    tenant_id: row.try_get("tenant_id").map_err(map_db_err)?,
                    name: row.try_get("name").map_err(map_db_err)?,
                    slug: row.try_get("slug").map_err(map_db_err)?,
                    created_at: row.try_get("created_at").map_err(map_db_err)?,
                })
            })
            .collect()
    }

    /// Whether any tenant has been provisioned yet. Drives the one-time
    /// unauthenticated first-run bootstrap.
    pub async fn tenants_exist(&self) -> latentdb_contracts::Result<bool> {
        let row = sqlx::query("SELECT 1 FROM tenants LIMIT 1")
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?;
        Ok(row.is_some())
    }

    /// Suspend or re-activate a tenant. Platform-admin only. Suspension takes
    /// effect immediately: every session and API key of the tenant is refused
    /// at verification time while the status is not `active`.
    pub async fn set_tenant_status(
        &self,
        ctx: &AuthContext,
        tenant_id: &str,
        status: &str,
    ) -> latentdb_contracts::Result<Tenant> {
        if !ctx.is_platform_admin && !ctx.is_system() {
            self.audit_denial(ctx, "configure", "platform:tenants", None)
                .await;
            return Err(ApiError::forbidden("platform admin required"));
        }
        if !matches!(status, "active" | "suspended") {
            return Err(ApiError::validation(
                "status must be 'active' or 'suspended'",
            ));
        }
        let row = sqlx::query("SELECT * FROM tenants WHERE id = ?")
            .bind(tenant_id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::not_found("tenant not found"))?;
        let before: String = row.try_get("status").map_err(map_db_err)?;

        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("UPDATE tenants SET status = ? WHERE id = ?")
            .bind(status)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(map_db_err)?;
        let ev = event_from(
            ctx,
            "tenant.set_status",
            Some("tenant"),
            Some(tenant_id),
            Some(serde_json::json!({"status": before})),
            Some(serde_json::json!({"status": status})),
        );
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;

        Ok(Tenant {
            id: row.try_get("id").map_err(map_db_err)?,
            name: row.try_get("name").map_err(map_db_err)?,
            slug: row.try_get("slug").map_err(map_db_err)?,
            plan: row.try_get("plan").map_err(map_db_err)?,
            status: status.to_string(),
            created_at: row.try_get("created_at").map_err(map_db_err)?,
        })
    }

    /// Create a workspace inside the caller's org.
    pub async fn create_workspace(
        &self,
        ctx: &AuthContext,
        name: &str,
    ) -> latentdb_contracts::Result<Workspace> {
        self.authorize(ctx, Action::Configure, "organization", None)
            .await?;
        let id = ids::new_id();
        let now = ids::now_rfc3339();
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query(
            "INSERT INTO workspaces (id, tenant_id, org_id, name, created_at) VALUES (?,?,?,?,?)",
        )
        .bind(&id)
        .bind(&ctx.tenant_id)
        .bind(&ctx.org_id)
        .bind(name)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(map_db_err)?;
        let ev = event_from(
            ctx,
            "workspace.create",
            Some("workspace"),
            Some(&id),
            None,
            Some(serde_json::json!({"name": name})),
        );
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(Workspace {
            id,
            tenant_id: ctx.tenant_id.clone(),
            org_id: ctx.org_id.clone(),
            name: name.into(),
            created_at: now,
        })
    }
}

/// Tenant slugs become URL/login identifiers, so keep them strict: 2–63 chars,
/// lowercase alphanumerics plus hyphen/underscore, starting and ending
/// alphanumeric.
fn validate_slug(slug: &str) -> latentdb_contracts::Result<()> {
    let bytes = slug.as_bytes();
    let alnum_edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let ok = (2..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| alnum_edge(b) || *b == b'-' || *b == b'_')
        && bytes.first().is_some_and(alnum_edge)
        && bytes.last().is_some_and(alnum_edge);
    if ok {
        Ok(())
    } else {
        Err(ApiError::validation(
            "slug must be 2-63 chars of lowercase letters, digits, hyphens, or underscores, starting and ending alphanumeric",
        ))
    }
}
