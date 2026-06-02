//! The event bus.
//!
//! Domain events (record created, workflow transitioned, low stock detected, ...)
//! are persisted to an `events` table. Automation and scheduled workers consume
//! them. Persisting rather than using only in-process channels means events
//! survive restarts and are themselves inspectable/auditable.

use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::{AuthContext, ids};
use serde_json::Value;
use sqlx::{Row, SqliteConnection};

/// A domain event row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Event {
    pub id: String,
    pub tenant_id: String,
    pub org_id: Option<String>,
    pub kind: String,
    pub payload: Value,
    pub created_at: String,
    pub processed: bool,
}

/// Emit an event on the given connection (transaction-aware).
pub(crate) async fn emit_on(
    conn: &mut SqliteConnection,
    ctx: &AuthContext,
    kind: &str,
    payload: Value,
) -> latentdb_contracts::Result<()> {
    sqlx::query(
        r#"INSERT INTO events (id, tenant_id, org_id, kind, payload_json, created_at, processed)
           VALUES (?,?,?,?,?,?,0)"#,
    )
    .bind(ids::new_id())
    .bind(&ctx.tenant_id)
    .bind(&ctx.org_id)
    .bind(kind)
    .bind(payload.to_string())
    .bind(ids::now_rfc3339())
    .execute(conn)
    .await
    .map_err(map_db_err)?;
    Ok(())
}

impl Kernel {
    /// Emit a standalone domain event.
    pub async fn emit_event(
        &self,
        ctx: &AuthContext,
        kind: &str,
        payload: Value,
    ) -> latentdb_contracts::Result<()> {
        let mut conn = self.pool().acquire().await.map_err(map_db_err)?;
        emit_on(&mut conn, ctx, kind, payload).await
    }

    /// Fetch unprocessed events for a tenant (for the background worker).
    pub async fn pending_events(
        &self,
        ctx: &AuthContext,
        limit: i64,
    ) -> latentdb_contracts::Result<Vec<Event>> {
        let rows = sqlx::query(
            "SELECT * FROM events WHERE tenant_id = ? AND processed = 0 ORDER BY created_at ASC LIMIT ?",
        )
        .bind(&ctx.tenant_id)
        .bind(limit.clamp(1, 500))
        .fetch_all(self.pool())
        .await
        .map_err(map_db_err)?;

        rows.iter()
            .map(|row| {
                Ok(Event {
                    id: row.try_get("id").map_err(map_db_err)?,
                    tenant_id: row.try_get("tenant_id").map_err(map_db_err)?,
                    org_id: row.try_get("org_id").map_err(map_db_err)?,
                    kind: row.try_get("kind").map_err(map_db_err)?,
                    payload: row
                        .try_get::<String, _>("payload_json")
                        .map_err(map_db_err)
                        .and_then(|s| {
                            serde_json::from_str(&s).map_err(|e| {
                                latentdb_contracts::ApiError::internal(format!("event payload: {e}"))
                            })
                        })?,
                    created_at: row.try_get("created_at").map_err(map_db_err)?,
                    processed: row.try_get::<i64, _>("processed").map_err(map_db_err)? != 0,
                })
            })
            .collect()
    }

    /// Mark an event processed.
    pub async fn mark_event_processed(&self, id: &str) -> latentdb_contracts::Result<()> {
        sqlx::query("UPDATE events SET processed = 1 WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_db_err)?;
        Ok(())
    }
}
