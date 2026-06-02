//! The audit service.
//!
//! Mutating kernel methods build an [`AuditEvent`] and insert it *inside the same
//! transaction* as the change via [`insert_audit`], so a business row and its
//! audit row commit atomically — there is no window where a mutation exists
//! without its audit trail.

use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::{ActorType, AuditEvent, AuditQuery, AuthContext, Source};
use serde_json::Value;
use sqlx::{Row, SqliteConnection};

/// Build an audit event from the current context plus the specifics of a change.
/// Centralizing construction keeps every audit row uniformly populated.
pub(crate) fn event_from(
    ctx: &AuthContext,
    action: &str,
    target_object_type: Option<&str>,
    target_record_id: Option<&str>,
    before: Option<Value>,
    after: Option<Value>,
) -> AuditEvent {
    AuditEvent {
        id: latentdb_contracts::new_id(),
        tenant_id: ctx.tenant_id.clone(),
        org_id: Some(ctx.org_id.clone()),
        actor_type: ctx.actor_type,
        actor_id: ctx.actor_id.clone(),
        action: action.to_string(),
        target_object_type: target_object_type.map(|s| s.to_string()),
        target_record_id: target_record_id.map(|s| s.to_string()),
        before,
        after,
        request_id: ctx.request_id.clone(),
        reason: None,
        source: ctx.source,
        timestamp: latentdb_contracts::now_rfc3339(),
        client_meta: None,
        ai_meta: None,
        retrieved_source_ids: Vec::new(),
        risk_score: None,
        approval_id: None,
    }
}

/// Public builder used by the AI crate to construct AI-related audit events
/// (retrieval, recommendation, action). The resulting event is written via
/// [`Kernel::audit`]. Keeps audit construction uniform across crates.
pub fn event_from_public(
    ctx: &AuthContext,
    action: &str,
    target_object_type: Option<&str>,
    target_record_id: Option<&str>,
    before: Option<Value>,
    after: Option<Value>,
) -> AuditEvent {
    event_from(ctx, action, target_object_type, target_record_id, before, after)
}

fn actor_type_str(a: ActorType) -> &'static str {
    match a {
        ActorType::User => "user",
        ActorType::ServiceAccount => "service_account",
        ActorType::Agent => "agent",
        ActorType::System => "system",
    }
}

fn source_str(s: Source) -> &'static str {
    match s {
        Source::Api => "api",
        Source::AdminUi => "admin_ui",
        Source::Agent => "agent",
        Source::System => "system",
        Source::Seed => "seed",
    }
}

/// Insert an audit event using the given connection (a transaction or a pooled
/// connection). The single insertion point for the audit table.
pub(crate) async fn insert_audit(
    conn: &mut SqliteConnection,
    ev: &AuditEvent,
) -> latentdb_contracts::Result<()> {
    let before = ev.before.as_ref().map(|v| v.to_string());
    let after = ev.after.as_ref().map(|v| v.to_string());
    let client_meta = ev.client_meta.as_ref().map(|v| v.to_string());
    let ai_meta = ev.ai_meta.as_ref().map(|v| v.to_string());
    let sources = if ev.retrieved_source_ids.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&ev.retrieved_source_ids).unwrap_or_else(|_| "[]".into()))
    };

    sqlx::query(
        r#"INSERT INTO audit_logs
            (id, tenant_id, org_id, actor_type, actor_id, action,
             target_object_type, target_record_id, before_json, after_json,
             request_id, reason, source, timestamp, client_meta_json, ai_meta_json,
             retrieved_source_ids_json, risk_score, approval_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#,
    )
    .bind(&ev.id)
    .bind(&ev.tenant_id)
    .bind(&ev.org_id)
    .bind(actor_type_str(ev.actor_type))
    .bind(&ev.actor_id)
    .bind(&ev.action)
    .bind(&ev.target_object_type)
    .bind(&ev.target_record_id)
    .bind(before)
    .bind(after)
    .bind(&ev.request_id)
    .bind(&ev.reason)
    .bind(source_str(ev.source))
    .bind(&ev.timestamp)
    .bind(client_meta)
    .bind(ai_meta)
    .bind(sources)
    .bind(ev.risk_score)
    .bind(&ev.approval_id)
    .execute(conn)
    .await
    .map_err(map_db_err)?;
    Ok(())
}

impl Kernel {
    /// Record a standalone audit event (not tied to a single transaction) — used
    /// for reads, permission denials, exports, and AI operations.
    pub async fn audit(&self, ev: &AuditEvent) -> latentdb_contracts::Result<()> {
        let mut conn = self.pool().acquire().await.map_err(map_db_err)?;
        insert_audit(&mut conn, ev).await
    }

    /// Record a security-relevant permission denial.
    pub(crate) async fn audit_denial(
        &self,
        ctx: &AuthContext,
        action: &str,
        resource: &str,
        target_record_id: Option<&str>,
    ) {
        let mut ev = event_from(ctx, "permission.denied", Some(resource), target_record_id, None, None);
        ev.reason = Some(format!("denied {action} on {resource}"));
        // Best-effort: a failure to write the denial must not mask the denial.
        let _ = self.audit(&ev).await;
    }

    /// Query the audit log within the caller's tenant. Requires the caller to be
    /// able to `read` the `audit` resource.
    pub async fn audit_query(
        &self,
        ctx: &AuthContext,
        query: &AuditQuery,
    ) -> latentdb_contracts::Result<Vec<AuditEvent>> {
        self.authorize(ctx, latentdb_contracts::Action::Read, "audit", None)
            .await?;

        let mut sql = String::from("SELECT * FROM audit_logs WHERE tenant_id = ?");
        if query.actor_id.is_some() {
            sql.push_str(" AND actor_id = ?");
        }
        if query.action.is_some() {
            sql.push_str(" AND action = ?");
        }
        if query.target_object_type.is_some() {
            sql.push_str(" AND target_object_type = ?");
        }
        if query.target_record_id.is_some() {
            sql.push_str(" AND target_record_id = ?");
        }
        if query.since.is_some() {
            sql.push_str(" AND timestamp >= ?");
        }
        if query.until.is_some() {
            sql.push_str(" AND timestamp < ?");
        }
        sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");

        let mut q = sqlx::query(&sql).bind(&ctx.tenant_id);
        if let Some(v) = &query.actor_id {
            q = q.bind(v);
        }
        if let Some(v) = &query.action {
            q = q.bind(v);
        }
        if let Some(v) = &query.target_object_type {
            q = q.bind(v);
        }
        if let Some(v) = &query.target_record_id {
            q = q.bind(v);
        }
        if let Some(v) = &query.since {
            q = q.bind(v);
        }
        if let Some(v) = &query.until {
            q = q.bind(v);
        }
        let limit = query.limit.unwrap_or(100).clamp(1, 1000);
        let offset = query.offset.unwrap_or(0).max(0);
        q = q.bind(limit).bind(offset);

        let rows = q.fetch_all(self.pool()).await.map_err(map_db_err)?;
        rows.iter().map(row_to_event).collect()
    }
}

fn row_to_event(row: &sqlx::sqlite::SqliteRow) -> latentdb_contracts::Result<AuditEvent> {
    let parse_json = |s: Option<String>| -> Option<Value> {
        s.and_then(|s| serde_json::from_str(&s).ok())
    };
    let actor_type = match row.try_get::<String, _>("actor_type").map_err(map_db_err)?.as_str() {
        "user" => ActorType::User,
        "service_account" => ActorType::ServiceAccount,
        "agent" => ActorType::Agent,
        _ => ActorType::System,
    };
    let source = match row.try_get::<String, _>("source").map_err(map_db_err)?.as_str() {
        "admin_ui" => Source::AdminUi,
        "agent" => Source::Agent,
        "seed" => Source::Seed,
        "system" => Source::System,
        _ => Source::Api,
    };
    let sources: Vec<String> = row
        .try_get::<Option<String>, _>("retrieved_source_ids_json")
        .map_err(map_db_err)?
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    Ok(AuditEvent {
        id: row.try_get("id").map_err(map_db_err)?,
        tenant_id: row.try_get("tenant_id").map_err(map_db_err)?,
        org_id: row.try_get("org_id").map_err(map_db_err)?,
        actor_type,
        actor_id: row.try_get("actor_id").map_err(map_db_err)?,
        action: row.try_get("action").map_err(map_db_err)?,
        target_object_type: row.try_get("target_object_type").map_err(map_db_err)?,
        target_record_id: row.try_get("target_record_id").map_err(map_db_err)?,
        before: parse_json(row.try_get("before_json").map_err(map_db_err)?),
        after: parse_json(row.try_get("after_json").map_err(map_db_err)?),
        request_id: row.try_get("request_id").map_err(map_db_err)?,
        reason: row.try_get("reason").map_err(map_db_err)?,
        source,
        timestamp: row.try_get("timestamp").map_err(map_db_err)?,
        client_meta: parse_json(row.try_get("client_meta_json").map_err(map_db_err)?),
        ai_meta: parse_json(row.try_get("ai_meta_json").map_err(map_db_err)?),
        retrieved_source_ids: sources,
        risk_score: row.try_get("risk_score").map_err(map_db_err)?,
        approval_id: row.try_get("approval_id").map_err(map_db_err)?,
    })
}
