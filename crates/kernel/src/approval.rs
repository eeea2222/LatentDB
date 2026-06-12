//! Approvals: the human (or policy) gate on sensitive workflow transitions and
//! AI actions.
//!
//! When a transition `requires_approval`, the workflow engine records a pending
//! approval (plus a task) instead of moving the record. Deciding the approval is
//! what actually applies the gated transition — and it re-checks permission,
//! scopes to the tenant, and audits with the approval id linked.

use crate::audit::{event_from, insert_audit};
use crate::event::emit_on;
use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::{ids, Action, ApiError, AuthContext};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Row, SqliteConnection};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub tenant_id: String,
    pub org_id: String,
    pub status: String,
    pub policy: Option<String>,
    pub requested_by: String,
    pub decided_by: Option<String>,
    pub decision_reason: Option<String>,
    pub related_object_type: Option<String>,
    pub related_record_id: Option<String>,
    pub transition_key: Option<String>,
    pub target_state: Option<String>,
    pub risk_score: Option<f64>,
    pub data: Value,
    pub created_at: String,
    pub decided_at: Option<String>,
}

/// Internal: record a pending approval inside an existing transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_approval(
    conn: &mut SqliteConnection,
    ctx: &AuthContext,
    id: &str,
    policy: Option<&str>,
    related_object_type: Option<&str>,
    related_record_id: Option<&str>,
    transition_key: Option<&str>,
    target_state: Option<&str>,
    risk_score: Option<f64>,
    data: &Value,
) -> latentdb_contracts::Result<()> {
    sqlx::query("INSERT INTO approvals (id, tenant_id, org_id, status, policy, requested_by, related_object_type, related_record_id, transition_key, target_state, risk_score, data_json, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(id).bind(&ctx.tenant_id).bind(&ctx.org_id).bind("pending").bind(policy)
        .bind(&ctx.actor_id).bind(related_object_type).bind(related_record_id)
        .bind(transition_key).bind(target_state).bind(risk_score)
        .bind(data.to_string()).bind(ids::now_rfc3339())
        .execute(conn).await.map_err(map_db_err)?;
    Ok(())
}

impl Kernel {
    pub async fn get_approval(
        &self,
        ctx: &AuthContext,
        id: &str,
    ) -> latentdb_contracts::Result<Approval> {
        self.authorize(ctx, Action::Read, "approval", None).await?;
        let row = sqlx::query("SELECT * FROM approvals WHERE tenant_id = ? AND id = ?")
            .bind(&ctx.tenant_id)
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::not_found("approval not found"))?;
        row_to_approval(&row)
    }

    pub async fn list_pending_approvals(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<Vec<Approval>> {
        self.authorize(ctx, Action::Read, "approval", None).await?;
        let rows = sqlx::query("SELECT * FROM approvals WHERE tenant_id = ? AND status = 'pending' ORDER BY created_at DESC")
            .bind(&ctx.tenant_id)
            .fetch_all(self.pool())
            .await
            .map_err(map_db_err)?;
        rows.iter().map(row_to_approval).collect()
    }

    /// Decide a pending approval. On approval, the gated workflow transition is
    /// applied here (re-checking `approve` permission first). All branches audit
    /// with the approval id linked and emit a domain event.
    pub async fn decide_approval(
        &self,
        ctx: &AuthContext,
        approval_id: &str,
        approved: bool,
        reason: Option<&str>,
    ) -> latentdb_contracts::Result<Approval> {
        let mut approval = self
            .load_approval(&ctx.tenant_id, approval_id)
            .await?
            .ok_or_else(|| ApiError::not_found("approval not found"))?;
        if approval.status != "pending" {
            return Err(ApiError::failed_precondition("approval already decided"));
        }
        // Separation of duties (flag-gated): the requester may not decide
        // their own approval. System/platform actors are exempt.
        if self.flags().enable_approval_separation_of_duties
            && approval.requested_by == ctx.actor_id
            && !ctx.is_system()
            && !ctx.is_platform_admin
        {
            self.audit_denial(ctx, "approve", "approval", Some(approval_id))
                .await;
            return Err(ApiError::forbidden(
                "the requester cannot decide their own approval",
            ));
        }

        let object_type = approval.related_object_type.clone().unwrap_or_default();
        let resource = format!("object:{object_type}");
        // Authorize against the target record's scope where we have one.
        let target = match &approval.related_record_id {
            Some(rid) => self.load_record(&ctx.tenant_id, rid).await?,
            None => None,
        };
        self.authorize(ctx, Action::Approve, &resource, target.as_ref())
            .await?;

        let now = ids::now_rfc3339();
        let new_status = if approved { "approved" } else { "rejected" };
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;

        if approved {
            if let (Some(rid), Some(target_state)) =
                (&approval.related_record_id, &approval.target_state)
            {
                let before_state = target.as_ref().and_then(|r| r.workflow_state.clone());
                sqlx::query("UPDATE records SET workflow_state = ?, updated_at = ? WHERE tenant_id = ? AND id = ?")
                    .bind(target_state).bind(&now).bind(&ctx.tenant_id).bind(rid)
                    .execute(&mut *tx).await.map_err(map_db_err)?;
                let mut ev = event_from(
                    ctx,
                    "workflow.transition",
                    Some(&object_type),
                    Some(rid),
                    Some(serde_json::json!({"workflow_state": before_state})),
                    Some(serde_json::json!({"workflow_state": target_state})),
                );
                ev.approval_id = Some(approval_id.to_string());
                ev.reason = reason.map(|s| s.to_string());
                insert_audit(&mut tx, &ev).await?;
                emit_on(&mut tx, ctx, "workflow.transitioned",
                    serde_json::json!({"object_type": object_type, "id": rid, "to": target_state, "via_approval": approval_id})).await?;
            }
        } else {
            let mut ev = event_from(
                ctx,
                "approval.reject",
                Some(&object_type),
                approval.related_record_id.as_deref(),
                None,
                None,
            );
            ev.approval_id = Some(approval_id.to_string());
            ev.reason = reason.map(|s| s.to_string());
            insert_audit(&mut tx, &ev).await?;
        }

        sqlx::query("UPDATE approvals SET status = ?, decided_by = ?, decision_reason = ?, decided_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(new_status).bind(&ctx.actor_id).bind(reason).bind(&now)
            .bind(&ctx.tenant_id).bind(approval_id)
            .execute(&mut *tx).await.map_err(map_db_err)?;
        let task_status = if approved { "done" } else { "cancelled" };
        self.close_tasks_for_approval(&mut tx, &ctx.tenant_id, approval_id, task_status)
            .await?;
        tx.commit().await.map_err(map_db_err)?;

        approval.status = new_status.to_string();
        approval.decided_by = Some(ctx.actor_id.clone());
        approval.decision_reason = reason.map(|s| s.to_string());
        approval.decided_at = Some(now);
        Ok(approval)
    }

    pub(crate) async fn load_approval(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> latentdb_contracts::Result<Option<Approval>> {
        let row = sqlx::query("SELECT * FROM approvals WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?;
        match row {
            None => Ok(None),
            Some(row) => Ok(Some(row_to_approval(&row)?)),
        }
    }
}

fn row_to_approval(row: &sqlx::sqlite::SqliteRow) -> latentdb_contracts::Result<Approval> {
    Ok(Approval {
        id: row.try_get("id").map_err(map_db_err)?,
        tenant_id: row.try_get("tenant_id").map_err(map_db_err)?,
        org_id: row.try_get("org_id").map_err(map_db_err)?,
        status: row.try_get("status").map_err(map_db_err)?,
        policy: row.try_get("policy").map_err(map_db_err)?,
        requested_by: row.try_get("requested_by").map_err(map_db_err)?,
        decided_by: row.try_get("decided_by").map_err(map_db_err)?,
        decision_reason: row.try_get("decision_reason").map_err(map_db_err)?,
        related_object_type: row.try_get("related_object_type").map_err(map_db_err)?,
        related_record_id: row.try_get("related_record_id").map_err(map_db_err)?,
        transition_key: row.try_get("transition_key").map_err(map_db_err)?,
        target_state: row.try_get("target_state").map_err(map_db_err)?,
        risk_score: row.try_get("risk_score").map_err(map_db_err)?,
        data: row
            .try_get::<String, _>("data_json")
            .map_err(map_db_err)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Value::Null),
        created_at: row.try_get("created_at").map_err(map_db_err)?,
        decided_at: row.try_get("decided_at").map_err(map_db_err)?,
    })
}
