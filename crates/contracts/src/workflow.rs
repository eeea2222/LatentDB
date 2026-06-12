//! Workflow definitions: states, transitions, guards, and approval policy refs.
//!
//! A workflow is declarative data attached to an object type. The kernel's
//! workflow service interprets it: it only permits declared transitions, checks
//! the guard permission, and creates an approval task when a transition requires
//! one.

use serde::{Deserialize, Serialize};

/// A single state in a workflow (e.g. invoice `submitted`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowState {
    pub key: String,
    pub label: String,
    /// Terminal states have no outgoing transitions (e.g. `paid`, `cancelled`).
    #[serde(default)]
    pub terminal: bool,
}

/// A permitted move from one state to another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transition {
    /// Stable key for the transition, e.g. `"submit"`, `"approve"`.
    pub key: String,
    pub from: String,
    pub to: String,
    /// Human label for the action button, e.g. `"Submit for approval"`.
    pub label: String,
    /// Permission resource the actor must hold `transition` on to perform this
    /// move (e.g. `"object:invoice"`). When `None`, any actor who can update the
    /// record may transition it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_permission: Option<String>,
    /// When true, performing this transition creates an approval task and the
    /// record does not actually move until the approval is granted.
    #[serde(default)]
    pub requires_approval: bool,
    /// Named approval policy controlling who may approve and any thresholds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_policy: Option<String>,
}

/// A complete workflow definition bound to an object type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowDef {
    pub key: String,
    pub object_type: String,
    pub name: String,
    pub initial_state: String,
    pub states: Vec<WorkflowState>,
    pub transitions: Vec<Transition>,
}

impl WorkflowDef {
    pub fn state(&self, key: &str) -> Option<&WorkflowState> {
        self.states.iter().find(|s| s.key == key)
    }

    /// Find a transition by key that is valid from the given current state.
    pub fn transition_from(&self, current: &str, key: &str) -> Option<&Transition> {
        self.transitions
            .iter()
            .find(|t| t.key == key && t.from == current)
    }

    /// All transitions available from the given state.
    pub fn available_from(&self, current: &str) -> Vec<&Transition> {
        self.transitions
            .iter()
            .filter(|t| t.from == current)
            .collect()
    }
}
