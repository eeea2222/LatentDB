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
        .bind(slug)
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
            .bind(&admin_id).bind(&tenant_id).bind(admin_email).bind(admin_name)
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
                slug: slug.into(),
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
