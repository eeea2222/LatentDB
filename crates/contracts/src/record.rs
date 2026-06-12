//! The generic record — one row of a metadata-defined object type.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Lifecycle state independent of any business workflow. Workflow state (e.g.
/// invoice `submitted`) lives in `workflow_state`; this tracks soft-delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Active,
    Archived,
}

impl Lifecycle {
    pub fn as_str(self) -> &'static str {
        match self {
            Lifecycle::Active => "active",
            Lifecycle::Archived => "archived",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "archived" => Lifecycle::Archived,
            _ => Lifecycle::Active,
        }
    }
}

/// A stored record. `data` holds the dynamic, type-defined fields; the rest are
/// system columns the kernel manages and audits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub object_type: String,
    pub tenant_id: String,
    pub org_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    pub data: Map<String, Value>,
    pub lifecycle: Lifecycle,
    /// Current workflow state key, if the object type has a workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_state: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<String>,
}

impl Record {
    /// The owner field convention used by `Scope::Own` checks. A record is
    /// "owned" by its creator or by whoever an `owner_id`/`assignee_id` field
    /// points at.
    pub fn owner_candidates(&self) -> Vec<String> {
        let mut owners = vec![self.created_by.clone()];
        for key in ["owner_id", "assignee_id", "user_id"] {
            if let Some(Value::String(s)) = self.data.get(key) {
                owners.push(s.clone());
            }
        }
        owners
    }

    /// Project `data` down to only the fields visible under a field rule, used to
    /// enforce field-level read permissions before returning a record.
    pub fn project_fields<F: Fn(&str) -> bool>(&self, visible: F) -> Record {
        let mut clone = self.clone();
        clone.data = self
            .data
            .iter()
            .filter(|(k, _)| visible(k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        clone
    }
}

/// Payload to create a record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewRecord {
    pub object_type: String,
    #[serde(default)]
    pub data: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
}

/// Partial update payload. Only present keys are changed; explicit JSON `null`
/// clears a field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordPatch {
    #[serde(default)]
    pub data: Map<String, Value>,
}
