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

const DEFAULT_SESSION_TTL_DAYS: i64 = 30;

/// Session lifetime, configurable via `LATENTDB_SESSION_TTL_DAYS` (1..=365).
fn session_ttl_days() -> i64 {
    std::env::var("LATENTDB_SESSION_TTL_DAYS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|d| d.clamp(1, 365))
        .unwrap_or(DEFAULT_SESSION_TTL_DAYS)
}

/// Canonical form for stored/looked-up emails: trimmed + lowercased, so login
/// is case-insensitive and a user cannot be shadowed by a case variant.
pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

impl Kernel {
    /// Authenticate a user with tenant slug + email + password and issue a
    /// session. A generic error is returned for every failure mode so the
    /// endpoint cannot be used to enumerate tenants or users; the unknown-user
    /// path burns the same Argon2 work as a real verification so response
    /// timing does not leak account existence. Repeated failures per
    /// tenant+email are rate limited, and every failed attempt is audited.
    pub async fn login(
        &self,
        tenant_slug: &str,
        email: &str,
        password: &str,
        request_id: &str,
        source: Source,
    ) -> latentdb_contracts::Result<LoginResult> {
        let tenant_slug = tenant_slug.trim();
        let email = normalize_email(email);
        let limiter_key = format!("{tenant_slug}|{email}");

        if self.login_limiter().is_locked(&limiter_key) {
            self.audit_login_failure(tenant_slug, &email, "rate_limited", request_id, source)
                .await;
            return Err(ApiError::new(
                latentdb_contracts::ErrorCode::RateLimited,
                "too many failed login attempts; try again later",
            ));
        }

        let tenant = sqlx::query("SELECT id FROM tenants WHERE slug = ? AND status = 'active'")
            .bind(tenant_slug)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?;
        let Some(tenant) = tenant else {
            crate::crypto::equalize_verify_timing(password);
            return Err(self
                .login_failure(
                    &limiter_key,
                    tenant_slug,
                    &email,
                    "unknown_tenant",
                    request_id,
                    source,
                )
                .await);
        };
        let tenant_id: String = tenant.try_get("id").map_err(map_db_err)?;

        let user = sqlx::query("SELECT * FROM users WHERE tenant_id = ? AND email = ?")
            .bind(&tenant_id)
            .bind(&email)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?;
        let Some(user) = user else {
            crate::crypto::equalize_verify_timing(password);
            return Err(self
                .login_failure(
                    &limiter_key,
                    tenant_slug,
                    &email,
                    "unknown_user",
                    request_id,
                    source,
                )
                .await);
        };

        let status: String = user.try_get("status").map_err(map_db_err)?;
        if status != "active" {
            crate::crypto::equalize_verify_timing(password);
            return Err(self
                .login_failure(
                    &limiter_key,
                    tenant_slug,
                    &email,
                    "user_inactive",
                    request_id,
                    source,
                )
                .await);
        }
        let pw_hash: String = user.try_get("password_hash").map_err(map_db_err)?;
        if !crate::crypto::verify_password(password, &pw_hash)? {
            return Err(self
                .login_failure(
                    &limiter_key,
                    tenant_slug,
                    &email,
                    "bad_password",
                    request_id,
                    source,
                )
                .await);
        }
        self.login_limiter().reset(&limiter_key);

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
        let expires = now + Duration::days(session_ttl_days());
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

        // A suspended tenant invalidates all of its credentials immediately.
        self.require_tenant_active(&tenant_id).await?;

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

        // A suspended tenant invalidates all of its credentials immediately.
        self.require_tenant_active(&tenant_id).await?;

        // The key is only as alive as the principal behind it: a disabled user
        // or service account must not keep authenticating through old keys.
        let (actor_type, principal_table) = if principal_type == "user" {
            (ActorType::User, "users")
        } else {
            (ActorType::ServiceAccount, "service_accounts")
        };
        let principal_status: Option<String> = sqlx::query(&format!(
            "SELECT status FROM {principal_table} WHERE tenant_id = ? AND id = ?"
        ))
        .bind(&tenant_id)
        .bind(&principal_id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_db_err)?
        .map(|r| r.try_get("status"))
        .transpose()
        .map_err(map_db_err)?;
        if principal_status.as_deref() != Some("active") {
            return Err(ApiError::unauthorized("api key principal is not active"));
        }

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

    /// Record a failed login in the limiter and the audit log, returning the
    /// generic credentials error. The audit row carries the failure reason so
    /// operators can monitor brute-force activity, while the caller only ever
    /// sees "invalid credentials".
    async fn login_failure(
        &self,
        limiter_key: &str,
        tenant_slug: &str,
        email: &str,
        reason: &'static str,
        request_id: &str,
        source: Source,
    ) -> ApiError {
        self.login_limiter().record_failure(limiter_key);
        self.audit_login_failure(tenant_slug, email, reason, request_id, source)
            .await;
        ApiError::unauthorized("invalid credentials")
    }

    /// Best-effort audit of a failed login attempt. Tenant id may be unknown at
    /// this point, so the slug is recorded instead.
    async fn audit_login_failure(
        &self,
        tenant_slug: &str,
        email: &str,
        reason: &'static str,
        request_id: &str,
        source: Source,
    ) {
        let ctx = AuthContext {
            actor_type: ActorType::User,
            actor_id: "anonymous".to_string(),
            tenant_id: format!("slug:{tenant_slug}"),
            org_id: String::new(),
            workspace_id: None,
            role_keys: vec![],
            is_platform_admin: false,
            request_id: request_id.to_string(),
            source,
            agent_safety_level: None,
        };
        let mut ev = event_from(
            &ctx,
            "auth.login.failed",
            Some("user"),
            None,
            None,
            Some(serde_json::json!({"email": email})),
        );
        ev.reason = Some(reason.to_string());
        let _ = self.audit(&ev).await;
    }

    /// Reject when the tenant is missing or not active. Used on every token
    /// verification so suspending a tenant cuts off existing sessions and API
    /// keys immediately, not just new logins.
    pub(crate) async fn require_tenant_active(
        &self,
        tenant_id: &str,
    ) -> latentdb_contracts::Result<()> {
        let row = sqlx::query("SELECT status FROM tenants WHERE id = ?")
            .bind(tenant_id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::unauthorized("tenant not found"))?;
        let status: String = row.try_get("status").map_err(map_db_err)?;
        if status != "active" {
            return Err(ApiError::unauthorized("tenant is not active"));
        }
        Ok(())
    }

    /// Revoke every session belonging to a user (e.g. when the user is
    /// disabled or their password is reset). Returns the number revoked.
    pub async fn revoke_sessions_for_user(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> latentdb_contracts::Result<u64> {
        let res = sqlx::query(
            "UPDATE sessions SET revoked = 1 WHERE tenant_id = ? AND user_id = ? AND revoked = 0",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(self.pool())
        .await
        .map_err(map_db_err)?;
        Ok(res.rows_affected())
    }

    /// Delete sessions that are expired or revoked so the table cannot grow
    /// without bound. Called from periodic housekeeping.
    pub async fn cleanup_expired_sessions(&self) -> latentdb_contracts::Result<u64> {
        let now = ids::now_rfc3339();
        let res = sqlx::query("DELETE FROM sessions WHERE revoked = 1 OR expires_at <= ?")
            .bind(&now)
            .execute(self.pool())
            .await
            .map_err(map_db_err)?;
        Ok(res.rows_affected())
    }
}
