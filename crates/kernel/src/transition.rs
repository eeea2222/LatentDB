//! The workflow transition engine.
//!
//! `transition_record` is the only way a record's workflow state changes. It
//! enforces that the move is a declared transition from the current state, checks
//! the transition's guard permission, and — when the transition requires approval
//! — records a pending approval + task instead of moving the record. Everything
//! is tenant-scoped and audited.

use crate::audit::{event_from, insert_audit};
use crate::event::emit_on;
use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::{ids, Action, ApiError, AuthContext, Transition};
use serde::{Deserialize, Serialize};

/// Outcome of attempting a transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionResult {
    /// `"transitioned"` or `"pending_approval"`.
    pub status: String,
    pub record_id: String,
    pub from: String,
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
}

impl Kernel {
    /// The transitions available from a record's current state (for rendering
    /// action buttons). Caller must be able to read the record.
    pub async fn available_transitions(
        &self,
        ctx: &AuthContext,
        record_id: &str,
    ) -> latentdb_contracts::Result<Vec<Transition>> {
        let record = self
            .load_record(&ctx.tenant_id, record_id)
            .await?
            .ok_or_else(|| ApiError::not_found("record not found"))?;
        let resource = format!("object:{}", record.object_type);
        self.authorize(ctx, Action::Read, &resource, Some(&record))
            .await?;
        let otype = self
            .load_object_type(&ctx.tenant_id, &record.object_type)
            .await?;
        let Some(wf_key) = otype.workflow_key else {
            return Ok(vec![]);
        };
        let Some(wf) = self.load_workflow(&ctx.tenant_id, &wf_key).await? else {
            return Ok(vec![]);
        };
        let current = record.workflow_state.unwrap_or(wf.initial_state.clone());
        Ok(wf.available_from(&current).into_iter().cloned().collect())
    }

    /// Attempt a workflow transition by key.
    pub async fn transition_record(
        &self,
        ctx: &AuthContext,
        record_id: &str,
        transition_key: &str,
        reason: Option<&str>,
    ) -> latentdb_contracts::Result<TransitionResult> {
        let record = self
            .load_record(&ctx.tenant_id, record_id)
            .await?
            .ok_or_else(|| ApiError::not_found("record not found"))?;
        let object_type = record.object_type.clone();
        let resource = format!("object:{object_type}");
        let otype = self.load_object_type(&ctx.tenant_id, &object_type).await?;
        let wf_key = otype
            .workflow_key
            .ok_or_else(|| ApiError::failed_precondition("object type has no workflow"))?;
        let wf = self
            .load_workflow(&ctx.tenant_id, &wf_key)
            .await?
            .ok_or_else(|| ApiError::failed_precondition("workflow not found"))?;

        let current = record
            .workflow_state
            .clone()
            .unwrap_or_else(|| wf.initial_state.clone());
        let transition = wf
            .transition_from(&current, transition_key)
            .ok_or_else(|| {
                ApiError::failed_precondition(format!(
                    "transition '{transition_key}' is not valid from state '{current}'"
                ))
            })?
            .clone();

        // Guard: the actor must hold `transition` on the guard resource.
        let guard_resource = transition
            .guard_permission
            .clone()
            .unwrap_or_else(|| resource.clone());
        self.authorize(ctx, Action::Transition, &guard_resource, Some(&record))
            .await?;

        let now = ids::now_rfc3339();
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;

        if transition.requires_approval {
            let approval_id = ids::new_id();
            let task_id = ids::new_id();
            crate::approval::insert_approval(
                &mut tx,
                ctx,
                &approval_id,
                transition.approval_policy.as_deref(),
                Some(&object_type),
                Some(record_id),
                Some(transition_key),
                Some(&transition.to),
                None,
                &serde_json::json!({"from": current, "to": transition.to}),
            )
            .await?;
            crate::task::insert_task(
                &mut tx,
                ctx,
                &task_id,
                "approval",
                &format!("Approve: {}", transition.label),
                None,
                Some(&object_type),
                Some(record_id),
                &serde_json::json!({"approval_id": approval_id, "transition": transition_key}),
            )
            .await?;
            let mut ev = event_from(
                ctx,
                "workflow.transition.requested",
                Some(&object_type),
                Some(record_id),
                Some(serde_json::json!({"state": current})),
                Some(serde_json::json!({"requested_state": transition.to})),
            );
            ev.approval_id = Some(approval_id.clone());
            ev.reason = reason.map(|s| s.to_string());
            insert_audit(&mut tx, &ev).await?;
            emit_on(&mut tx, ctx, "approval.requested",
                serde_json::json!({"object_type": object_type, "id": record_id, "approval_id": approval_id})).await?;
            tx.commit().await.map_err(map_db_err)?;

            Ok(TransitionResult {
                status: "pending_approval".into(),
                record_id: record_id.into(),
                from: current,
                to: transition.to,
                approval_id: Some(approval_id),
            })
        } else {
            sqlx::query("UPDATE records SET workflow_state = ?, updated_at = ? WHERE tenant_id = ? AND id = ?")
                .bind(&transition.to).bind(&now).bind(&ctx.tenant_id).bind(record_id)
                .execute(&mut *tx).await.map_err(map_db_err)?;
            let mut ev = event_from(
                ctx,
                "workflow.transition",
                Some(&object_type),
                Some(record_id),
                Some(serde_json::json!({"workflow_state": current})),
                Some(serde_json::json!({"workflow_state": transition.to})),
            );
            ev.reason = reason.map(|s| s.to_string());
            insert_audit(&mut tx, &ev).await?;
            emit_on(&mut tx, ctx, "workflow.transitioned",
                serde_json::json!({"object_type": object_type, "id": record_id, "to": transition.to})).await?;
            tx.commit().await.map_err(map_db_err)?;

            Ok(TransitionResult {
                status: "transitioned".into(),
                record_id: record_id.into(),
                from: current,
                to: transition.to,
                approval_id: None,
            })
        }
    }
}
