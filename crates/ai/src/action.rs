//! Agent action safety: planning, dry-run, and approval-gated execution.
//!
//! Agents never mutate data directly. They propose an [`AgentAction`]; the
//! planner returns a dry-run [`ActionPlan`] (the exact before/after, no changes);
//! and execution only proceeds through kernel services (which re-check
//! permission and audit) — and only when policy/approval permits.
//!
//! Safety levels (per the platform spec):
//! - 0 read/summarize/explain      - 1 draft suggestions
//! - 2 internal notes/tasks (policy) - 3 mutate records (perm+dry-run+approval+audit)
//! - 4 external side effects (explicit human approval + rollback plan)

use latentdb_contracts::{ApiError, AuthContext, RecordPatch};
use latentdb_kernel::Kernel;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionOp {
    CreateRecord,
    UpdateRecord,
    Transition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAction {
    pub kind: String,
    pub description: String,
    pub op: ActionOp,
    #[serde(default)]
    pub object_type: Option<String>,
    #[serde(default)]
    pub record_id: Option<String>,
    /// For create/update: the field values. For transition: `{ "key": "submit" }`.
    #[serde(default)]
    pub payload: Value,
    /// 0..=4, see module docs.
    pub safety_level: u8,
    #[serde(default)]
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPlan {
    pub action: AgentAction,
    pub summary: String,
    /// State before (for updates/transitions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    /// Proposed state after.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
    /// Whether executing this requires human approval (level >= 3 with side
    /// effects, or level 4 always).
    pub requires_approval: bool,
}

impl AgentAction {
    pub fn requires_approval(&self) -> bool {
        self.safety_level >= 3
    }
}

/// Dry-run an action: compute the exact change without applying it. Audited as an
/// AI dry-run event. Read access to any target record is enforced by the kernel.
pub async fn dry_run(
    kernel: &Kernel,
    ctx: &AuthContext,
    action: &AgentAction,
) -> latentdb_contracts::Result<ActionPlan> {
    if !kernel.flags().enable_ai_agents {
        return Err(ApiError::feature_disabled("AI agents are disabled"));
    }

    let (before, after) = match action.op {
        ActionOp::CreateRecord => (None, Some(action.payload.clone())),
        ActionOp::UpdateRecord => {
            let id = action
                .record_id
                .as_deref()
                .ok_or_else(|| ApiError::validation("update action requires record_id"))?;
            let current = kernel.get_record(ctx, id).await?;
            let before = Value::Object(current.data.clone());
            let mut merged = current.data.clone();
            if let Some(patch) = action.payload.as_object() {
                for (k, v) in patch {
                    merged.insert(k.clone(), v.clone());
                }
            }
            (Some(before), Some(Value::Object(merged)))
        }
        ActionOp::Transition => {
            let id = action
                .record_id
                .as_deref()
                .ok_or_else(|| ApiError::validation("transition action requires record_id"))?;
            let current = kernel.get_record(ctx, id).await?;
            let to = action
                .payload
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            (
                Some(serde_json::json!({"workflow_state": current.workflow_state})),
                Some(serde_json::json!({"transition": to})),
            )
        }
    };

    let plan = ActionPlan {
        summary: action.description.clone(),
        before,
        after,
        requires_approval: action.requires_approval(),
        action: action.clone(),
    };

    // Audit the dry-run (no mutation).
    let mut ev = latentdb_kernel::audit::event_from_public(
        ctx,
        "ai.action.dry_run",
        action.object_type.as_deref(),
        action.record_id.as_deref(),
        None,
        Some(serde_json::json!({"kind": action.kind, "op": action.op})),
    );
    ev.risk_score = Some(action.risk_score);
    ev.ai_meta = Some(serde_json::json!({"safety_level": action.safety_level}));
    let _ = kernel.audit(&ev).await;

    Ok(plan)
}

/// Execute an action. Level >= 3 requires `enable_agent_action_execution`; if the
/// action requires approval it must be `approved`. Mutations go through kernel
/// services, which enforce permission and write their own audit; this adds an
/// `ai.action.execute` event on top.
pub async fn execute(
    kernel: &Kernel,
    ctx: &AuthContext,
    action: &AgentAction,
    approved: bool,
) -> latentdb_contracts::Result<Value> {
    if !kernel.flags().enable_ai_agents {
        return Err(ApiError::feature_disabled("AI agents are disabled"));
    }
    if action.safety_level >= 3 && !kernel.flags().enable_agent_action_execution {
        return Err(ApiError::feature_disabled(
            "agent action execution is disabled (enable_agent_action_execution)",
        ));
    }
    if action.requires_approval() && !approved {
        return Err(ApiError::failed_precondition(
            "this action requires human approval before execution",
        ));
    }

    let result = match action.op {
        ActionOp::CreateRecord => {
            let object_type = action
                .object_type
                .clone()
                .ok_or_else(|| ApiError::validation("create action requires object_type"))?;
            let data: Map<String, Value> = action.payload.as_object().cloned().unwrap_or_default();
            let rec = kernel
                .create_record(
                    ctx,
                    &latentdb_contracts::NewRecord {
                        object_type,
                        data,
                        workspace_id: None,
                    },
                )
                .await?;
            serde_json::to_value(rec).unwrap_or(Value::Null)
        }
        ActionOp::UpdateRecord => {
            let id = action
                .record_id
                .clone()
                .ok_or_else(|| ApiError::validation("update action requires record_id"))?;
            let data: Map<String, Value> = action.payload.as_object().cloned().unwrap_or_default();
            let rec = kernel
                .update_record(ctx, &id, &RecordPatch { data })
                .await?;
            serde_json::to_value(rec).unwrap_or(Value::Null)
        }
        ActionOp::Transition => {
            let id = action
                .record_id
                .clone()
                .ok_or_else(|| ApiError::validation("transition action requires record_id"))?;
            let key = action
                .payload
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ApiError::validation("transition action requires payload.key"))?;
            let res = kernel
                .transition_record(ctx, &id, key, Some("ai-action"))
                .await?;
            serde_json::to_value(res).unwrap_or(Value::Null)
        }
    };

    let mut ev = latentdb_kernel::audit::event_from_public(
        ctx,
        "ai.action.execute",
        action.object_type.as_deref(),
        action.record_id.as_deref(),
        None,
        Some(serde_json::json!({"kind": action.kind, "op": action.op, "approved": approved})),
    );
    ev.risk_score = Some(action.risk_score);
    ev.ai_meta = Some(serde_json::json!({"safety_level": action.safety_level}));
    let _ = kernel.audit(&ev).await;

    Ok(result)
}
