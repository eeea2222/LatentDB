//! The audit event contract.
//!
//! Every mutation in LatentDB emits one of these, written in the same transaction
//! as the change itself. The shape is intentionally wide so that business
//! mutations, admin changes, workflow transitions, approvals, exports, and AI
//! actions are all traceable through a single uniform record.

use crate::auth::{ActorType, Source};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    pub actor_type: ActorType,
    pub actor_id: String,
    /// Action verb, e.g. `"record.create"`, `"invoice.transition"`,
    /// `"ai.action.execute"`, `"permission.denied"`.
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_object_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_record_id: Option<String>,
    /// State before the change (for updates/transitions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    /// State after the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub source: Source,
    pub timestamp: String,
    /// Client metadata (ip, user agent, admin-ui marker, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_meta: Option<Value>,
    /// AI provider/model metadata, when an AI operation produced this event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_meta: Option<Value>,
    /// Source record/document ids retrieved by an AI operation (grounding trail).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retrieved_source_ids: Vec<String>,
    /// Risk score assigned to an AI action, 0.0–1.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<f64>,
    /// Approval id, when this event is gated by or records an approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
}

/// Filters for querying the audit log. All are optional and combine with AND.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub target_object_type: Option<String>,
    #[serde(default)]
    pub target_record_id: Option<String>,
    /// RFC3339 inclusive lower bound.
    #[serde(default)]
    pub since: Option<String>,
    /// RFC3339 exclusive upper bound.
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}
