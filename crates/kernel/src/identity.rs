//! Identity services: users, service accounts, roles, role assignments, API keys.

use crate::audit::{event_from, insert_audit};
use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::{ids, Action, ApiError, AuthContext, PermissionGrant, Role};
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub name: String,
    pub status: String,
    pub is_platform_admin: bool,
    pub default_org_id: Option<String>,
    pub role_keys: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub id: String,
    pub tenant_id: String,
    pub org_id: String,
    pub name: String,
    pub status: String,
    pub role_keys: Vec<String>,
    pub created_at: String,
}

/// API key metadata. The secret itself is shown only once at creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub principal_type: String,
    pub principal_id: String,
    pub status: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// A freshly minted API key, including the one-time plaintext secret.
#[derive(Debug, Clone, Serialize)]
pub struct NewApiKey {
    pub info: ApiKeyInfo,
    /// Plaintext token — returned exactly once; only its hash is stored.
    pub token: String,
}

impl Kernel {
    /// Resolve the role keys assigned to a principal (user or service account).
    pub(crate) async fn roles_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
    ) -> latentdb_contracts::Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT role_key FROM role_assignments WHERE tenant_id = ? AND principal_id = ?",
        )
        .bind(tenant_id)
        .bind(principal_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_db_err)?;
        rows.iter()
            .map(|r| r.try_get::<String, _>("role_key").map_err(map_db_err))
            .collect()
    }

    /// Create a user and assign roles. Requires `configure` on `admin:users`.
    pub async fn create_user(
        &self,
        ctx: &AuthContext,
        email: &str,
        name: &str,
        password: &str,
        role_keys: &[String],
    ) -> latentdb_contracts::Result<User> {
        self.authorize(ctx, Action::Configure, "admin:users", None).await?;
        let id = ids::new_id();
        let now = ids::now_rfc3339();
        let pw_hash = crate::crypto::hash_password(password)?;

        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("INSERT INTO users (id, tenant_id, email, name, password_hash, status, is_platform_admin, default_org_id, created_at) VALUES (?,?,?,?,?,?,?,?,?)")
            .bind(&id).bind(&ctx.tenant_id).bind(email).bind(name)
            .bind(&pw_hash).bind("active").bind(0i64).bind(&ctx.org_id).bind(&now)
            .execute(&mut *tx).await.map_err(map_db_err)?;
        for key in role_keys {
            sqlx::query("INSERT INTO role_assignments (id, tenant_id, principal_type, principal_id, role_key, org_id, created_at) VALUES (?,?,?,?,?,?,?)")
                .bind(ids::new_id()).bind(&ctx.tenant_id).bind("user").bind(&id)
                .bind(key).bind(&ctx.org_id).bind(&now)
                .execute(&mut *tx).await.map_err(map_db_err)?;
        }
        let ev = event_from(ctx, "user.create", Some("user"), Some(&id), None,
            Some(serde_json::json!({"email": email, "roles": role_keys})));
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;

        Ok(User {
            id,
            tenant_id: ctx.tenant_id.clone(),
            email: email.into(),
            name: name.into(),
            status: "active".into(),
            is_platform_admin: false,
            default_org_id: Some(ctx.org_id.clone()),
            role_keys: role_keys.to_vec(),
            created_at: now,
        })
    }

    pub async fn list_users(&self, ctx: &AuthContext) -> latentdb_contracts::Result<Vec<User>> {
        self.authorize(ctx, Action::Read, "admin:users", None).await?;
        let rows = sqlx::query("SELECT * FROM users WHERE tenant_id = ? ORDER BY created_at")
            .bind(&ctx.tenant_id)
            .fetch_all(self.pool())
            .await
            .map_err(map_db_err)?;
        let mut users = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: String = row.try_get("id").map_err(map_db_err)?;
            let role_keys = self.roles_for_principal(&ctx.tenant_id, &id).await?;
            users.push(row_to_user(row, role_keys)?);
        }
        Ok(users)
    }

    pub async fn get_user(&self, ctx: &AuthContext, id: &str) -> latentdb_contracts::Result<User> {
        self.authorize(ctx, Action::Read, "admin:users", None).await?;
        let row = sqlx::query("SELECT * FROM users WHERE tenant_id = ? AND id = ?")
            .bind(&ctx.tenant_id)
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::not_found("user not found"))?;
        let role_keys = self.roles_for_principal(&ctx.tenant_id, id).await?;
        row_to_user(&row, role_keys)
    }

    /// Assign a role to a principal. Requires `configure` on `admin:roles`.
    pub async fn assign_role(
        &self,
        ctx: &AuthContext,
        principal_id: &str,
        role_key: &str,
    ) -> latentdb_contracts::Result<()> {
        self.authorize(ctx, Action::Configure, "admin:roles", None).await?;
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("INSERT OR IGNORE INTO role_assignments (id, tenant_id, principal_type, principal_id, role_key, org_id, created_at) VALUES (?,?,?,?,?,?,?)")
            .bind(ids::new_id()).bind(&ctx.tenant_id).bind("user").bind(principal_id)
            .bind(role_key).bind(&ctx.org_id).bind(ids::now_rfc3339())
            .execute(&mut *tx).await.map_err(map_db_err)?;
        let ev = event_from(ctx, "role.assign", Some("user"), Some(principal_id), None,
            Some(serde_json::json!({"role": role_key})));
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(())
    }

    /// Create a custom role. Requires `configure` on `admin:roles`.
    pub async fn create_role(
        &self,
        ctx: &AuthContext,
        key: &str,
        name: &str,
        description: Option<&str>,
        grants: &[PermissionGrant],
    ) -> latentdb_contracts::Result<Role> {
        self.authorize(ctx, Action::Configure, "admin:roles", None).await?;
        let id = ids::new_id();
        let now = ids::now_rfc3339();
        let grants_json = serde_json::to_string(grants).unwrap_or_else(|_| "[]".into());
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("INSERT INTO roles (id, tenant_id, key, name, description, system, grants_json, created_at) VALUES (?,?,?,?,?,?,?,?)")
            .bind(&id).bind(&ctx.tenant_id).bind(key).bind(name)
            .bind(description).bind(0i64).bind(&grants_json).bind(&now)
            .execute(&mut *tx).await.map_err(map_db_err)?;
        let ev = event_from(ctx, "role.create", Some("role"), Some(&id), None,
            Some(serde_json::json!({"key": key})));
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(Role {
            id,
            key: key.into(),
            name: name.into(),
            description: description.map(|s| s.to_string()),
            system: false,
            grants: grants.to_vec(),
        })
    }

    pub async fn list_roles(&self, ctx: &AuthContext) -> latentdb_contracts::Result<Vec<Role>> {
        self.authorize(ctx, Action::Read, "admin:roles", None).await?;
        let rows = sqlx::query("SELECT * FROM roles WHERE tenant_id = ? ORDER BY key")
            .bind(&ctx.tenant_id)
            .fetch_all(self.pool())
            .await
            .map_err(map_db_err)?;
        rows.iter().map(row_to_role).collect()
    }

    /// Create an API key for a principal (defaults to the current actor).
    /// Returns the one-time plaintext secret.
    pub async fn create_api_key(
        &self,
        ctx: &AuthContext,
        name: &str,
        principal_id: Option<&str>,
        principal_type: &str,
    ) -> latentdb_contracts::Result<NewApiKey> {
        self.authorize(ctx, Action::Configure, "admin:api_keys", None).await?;
        let principal_id = principal_id.unwrap_or(&ctx.actor_id);
        let id = ids::new_id();
        let now = ids::now_rfc3339();
        let (token, hash) = crate::crypto::new_token("ldb_");
        let prefix = token.chars().take(11).collect::<String>();

        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("INSERT INTO api_keys (id, tenant_id, org_id, principal_type, principal_id, name, prefix, token_hash, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
            .bind(&id).bind(&ctx.tenant_id).bind(&ctx.org_id).bind(principal_type).bind(principal_id)
            .bind(name).bind(&prefix).bind(&hash).bind("active").bind(&now)
            .execute(&mut *tx).await.map_err(map_db_err)?;
        let ev = event_from(ctx, "api_key.create", Some("api_key"), Some(&id), None,
            Some(serde_json::json!({"name": name, "principal_id": principal_id})));
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;

        Ok(NewApiKey {
            info: ApiKeyInfo {
                id,
                name: name.into(),
                prefix,
                principal_type: principal_type.into(),
                principal_id: principal_id.into(),
                status: "active".into(),
                created_at: now,
                last_used_at: None,
            },
            token,
        })
    }

    /// Create a service account with roles. Returns the account; create an API
    /// key separately to obtain a usable credential.
    pub async fn create_service_account(
        &self,
        ctx: &AuthContext,
        name: &str,
        role_keys: &[String],
    ) -> latentdb_contracts::Result<ServiceAccount> {
        self.authorize(ctx, Action::Configure, "admin:users", None).await?;
        let id = ids::new_id();
        let now = ids::now_rfc3339();
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("INSERT INTO service_accounts (id, tenant_id, org_id, name, status, created_at) VALUES (?,?,?,?,?,?)")
            .bind(&id).bind(&ctx.tenant_id).bind(&ctx.org_id).bind(name).bind("active").bind(&now)
            .execute(&mut *tx).await.map_err(map_db_err)?;
        for key in role_keys {
            sqlx::query("INSERT INTO role_assignments (id, tenant_id, principal_type, principal_id, role_key, org_id, created_at) VALUES (?,?,?,?,?,?,?)")
                .bind(ids::new_id()).bind(&ctx.tenant_id).bind("service_account").bind(&id)
                .bind(key).bind(&ctx.org_id).bind(&now)
                .execute(&mut *tx).await.map_err(map_db_err)?;
        }
        let ev = event_from(ctx, "service_account.create", Some("service_account"), Some(&id), None,
            Some(serde_json::json!({"name": name})));
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(ServiceAccount {
            id,
            tenant_id: ctx.tenant_id.clone(),
            org_id: ctx.org_id.clone(),
            name: name.into(),
            status: "active".into(),
            role_keys: role_keys.to_vec(),
            created_at: now,
        })
    }
}

fn row_to_user(row: &sqlx::sqlite::SqliteRow, role_keys: Vec<String>) -> latentdb_contracts::Result<User> {
    Ok(User {
        id: row.try_get("id").map_err(map_db_err)?,
        tenant_id: row.try_get("tenant_id").map_err(map_db_err)?,
        email: row.try_get("email").map_err(map_db_err)?,
        name: row.try_get("name").map_err(map_db_err)?,
        status: row.try_get("status").map_err(map_db_err)?,
        is_platform_admin: row.try_get::<i64, _>("is_platform_admin").map_err(map_db_err)? != 0,
        default_org_id: row.try_get("default_org_id").map_err(map_db_err)?,
        role_keys,
        created_at: row.try_get("created_at").map_err(map_db_err)?,
    })
}

fn row_to_role(row: &sqlx::sqlite::SqliteRow) -> latentdb_contracts::Result<Role> {
    let grants_json: String = row.try_get("grants_json").map_err(map_db_err)?;
    let grants = serde_json::from_str(&grants_json).unwrap_or_default();
    Ok(Role {
        id: row.try_get("id").map_err(map_db_err)?,
        key: row.try_get("key").map_err(map_db_err)?,
        name: row.try_get("name").map_err(map_db_err)?,
        description: row.try_get("description").map_err(map_db_err)?,
        system: row.try_get::<i64, _>("system").map_err(map_db_err)? != 0,
        grants,
    })
}
