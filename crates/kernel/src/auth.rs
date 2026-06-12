//! Authentication: login, session issuance, and token verification.
//!
//! Login and token verification are the only kernel entry points that do *not*
//! already have an [`AuthContext`] — they produce one. Everything downstream
//! requires the context, which is what makes tenant + permission enforcement
//! unavoidable.

use crate::audit::{event_from, insert_audit};
use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::{ids, ActorType, ApiError, AuthContext, MigrationReport, Source};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use time::Duration;

/// Result of a successful login. The `token` is an opaque bearer secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResult {
    pub token: String,
    pub expires_at: String,
    pub user_id: String,
    pub tenant_id: String,
    pub org_id: String,
    pub name: String,
    pub email: String,
    pub role_keys: Vec<String>,
    pub is_platform_admin: bool,
}

const SESSION_TTL_DAYS: i64 = 30;

impl Kernel {
    /// Authenticate a user with tenant slug + email + password and issue a
    /// session. A generic error is returned for every failure mode so the
    /// endpoint cannot be used to enumerate tenants or users.
    pub async fn login(
        &self,
        tenant_slug: &str,
        email: &str,
        password: &str,
        request_id: &str,
        source: Source,
    ) -> latentdb_contracts::Result<LoginResult> {
        let invalid = || ApiError::unauthorized("invalid credentials");

        let tenant = sqlx::query("SELECT id FROM tenants WHERE slug = ? AND status = 'active'")
            .bind(tenant_slug)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(invalid)?;
        let tenant_id: String = tenant.try_get("id").map_err(map_db_err)?;

        let user = sqlx::query("SELECT * FROM users WHERE tenant_id = ? AND email = ?")
            .bind(&tenant_id)
            .bind(email)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(invalid)?;

        let status: String = user.try_get("status").map_err(map_db_err)?;
        if status != "active" {
            return Err(invalid());
        }
        let pw_hash: String = user.try_get("password_hash").map_err(map_db_err)?;
        if !crate::crypto::verify_password(password, &pw_hash)? {
            return Err(invalid());
        }

        let user_id: String = user.try_get("id").map_err(map_db_err)?;
        let name: String = user.try_get("name").map_err(map_db_err)?;
        let is_platform_admin = user
            .try_get::<i64, _>("is_platform_admin")
            .map_err(map_db_err)?
            != 0;
        let org_id: String = user
            .try_get::<Option<String>, _>("default_org_id")
            .map_err(map_db_err)?
            .unwrap_or_default();
        let role_keys = self.roles_for_principal(&tenant_id, &user_id).await?;

        let (token, token_hash) = crate::crypto::new_token("lds_");
        let now = ids::now();
        let expires = now + Duration::days(SESSION_TTL_DAYS);
        let created_at = ids::to_rfc3339(now);
        let expires_at = ids::to_rfc3339(expires);

        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query("INSERT INTO sessions (id, tenant_id, user_id, org_id, token_hash, created_at, expires_at, revoked) VALUES (?,?,?,?,?,?,?,0)")
            .bind(ids::new_id()).bind(&tenant_id).bind(&user_id).bind(&org_id)
            .bind(&token_hash).bind(&created_at).bind(&expires_at)
            .execute(&mut *tx).await.map_err(map_db_err)?;

        let login_ctx = AuthContext {
            actor_type: ActorType::User,
            actor_id: user_id.clone(),
            tenant_id: tenant_id.clone(),
            org_id: org_id.clone(),
            workspace_id: None,
            role_keys: role_keys.clone(),
            is_platform_admin,
            request_id: request_id.to_string(),
            source,
            agent_safety_level: None,
        };
        let ev = event_from(
            &login_ctx,
            "auth.login",
            Some("user"),
            Some(&user_id),
            None,
            None,
        );
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;

        Ok(LoginResult {
            token,
            expires_at,
            user_id,
            tenant_id,
            org_id,
            name,
            email: email.to_string(),
            role_keys,
            is_platform_admin,
        })
    }

    /// Verify a bearer token (session secret `lds_…` or API key `ldb_…`) and
    /// build the resulting [`AuthContext`]. Returns `Unauthorized` if the token
    /// is unknown, revoked, or expired.
    pub async fn authenticate(
        &self,
        token: &str,
        request_id: &str,
        source: Source,
    ) -> latentdb_contracts::Result<AuthContext> {
        let hash = crate::crypto::sha256_hex(token);
        if token.starts_with("ldb_") {
            self.authenticate_api_key(&hash, request_id, source).await
        } else {
            self.authenticate_session(&hash, request_id, source).await
        }
    }

    async fn authenticate_session(
        &self,
        token_hash: &str,
        request_id: &str,
        source: Source,
    ) -> latentdb_contracts::Result<AuthContext> {
        let row = sqlx::query("SELECT * FROM sessions WHERE token_hash = ? AND revoked = 0")
            .bind(token_hash)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::unauthorized("invalid or expired session"))?;

        let expires_at: String = row.try_get("expires_at").map_err(map_db_err)?;
        if let Some(exp) = ids::parse_rfc3339(&expires_at) {
            if exp <= ids::now() {
                return Err(ApiError::unauthorized("session expired"));
            }
        }
        let tenant_id: String = row.try_get("tenant_id").map_err(map_db_err)?;
        let user_id: String = row.try_get("user_id").map_err(map_db_err)?;
        let org_id: String = row.try_get("org_id").map_err(map_db_err)?;

        let user = sqlx::query("SELECT is_platform_admin, status FROM users WHERE id = ?")
            .bind(&user_id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::unauthorized("user not found"))?;
        let status: String = user.try_get("status").map_err(map_db_err)?;
        if status != "active" {
            return Err(ApiError::unauthorized("user inactive"));
        }
        let is_platform_admin = user
            .try_get::<i64, _>("is_platform_admin")
            .map_err(map_db_err)?
            != 0;
        let role_keys = self.roles_for_principal(&tenant_id, &user_id).await?;

        Ok(AuthContext {
            actor_type: ActorType::User,
            actor_id: user_id,
            tenant_id,
            org_id,
            workspace_id: None,
            role_keys,
            is_platform_admin,
            request_id: request_id.to_string(),
            source,
            agent_safety_level: None,
        })
    }

    async fn authenticate_api_key(
        &self,
        token_hash: &str,
        request_id: &str,
        source: Source,
    ) -> latentdb_contracts::Result<AuthContext> {
        let row = sqlx::query("SELECT * FROM api_keys WHERE token_hash = ? AND status = 'active'")
            .bind(token_hash)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::unauthorized("invalid api key"))?;

        let tenant_id: String = row.try_get("tenant_id").map_err(map_db_err)?;
        let org_id: String = row.try_get("org_id").map_err(map_db_err)?;
        let principal_id: String = row.try_get("principal_id").map_err(map_db_err)?;
        let principal_type: String = row.try_get("principal_type").map_err(map_db_err)?;
        let key_id: String = row.try_get("id").map_err(map_db_err)?;

        let actor_type = if principal_type == "user" {
            ActorType::User
        } else {
            ActorType::ServiceAccount
        };
        let role_keys = self.roles_for_principal(&tenant_id, &principal_id).await?;

        // Best-effort last-used stamp; not part of the auth decision.
        let _ = sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
            .bind(ids::now_rfc3339())
            .bind(&key_id)
            .execute(self.pool())
            .await;

        Ok(AuthContext {
            actor_type,
            actor_id: principal_id,
            tenant_id,
            org_id,
            workspace_id: None,
            role_keys,
            is_platform_admin: false,
            request_id: request_id.to_string(),
            source,
            agent_safety_level: None,
        })
    }

    /// Revoke a session by its token. For a first-time user who is still in
    /// onboarding, this also emits the non-destructive migration report for the
    /// system they were booted into ("output appropriate to either the old or the
    /// selected system") and returns it. Report generation never blocks logout:
    /// any failure (or absence of a session) simply yields `None`.
    pub async fn logout(&self, token: &str) -> latentdb_contracts::Result<Option<MigrationReport>> {
        let hash = crate::crypto::sha256_hex(token);

        // Resolve the live session *before* revoking so we still have the tenant
        // scope needed to build the report.
        let report = match sqlx::query(
            "SELECT tenant_id, org_id FROM sessions WHERE token_hash = ? AND revoked = 0",
        )
        .bind(&hash)
        .fetch_optional(self.pool())
        .await
        .map_err(map_db_err)?
        {
            Some(row) => {
                let tenant_id: String = row.try_get("tenant_id").map_err(map_db_err)?;
                let org_id: String = row.try_get("org_id").map_err(map_db_err)?;
                // A tenant-scoped system context: trusted for reading the tenant's
                // own data to assemble an internal onboarding report.
                let ctx = AuthContext::system(&tenant_id, &org_id);
                self.logout_migration_output(&ctx).await.unwrap_or(None)
            }
            None => None,
        };

        sqlx::query("UPDATE sessions SET revoked = 1 WHERE token_hash = ?")
            .bind(&hash)
            .execute(self.pool())
            .await
            .map_err(map_db_err)?;
        Ok(report)
    }
}
