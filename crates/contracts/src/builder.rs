//! Governed dynamic object builder contracts.

use crate::{
    FieldDefinition, ObjectTypeDef, PermissionGrant, Transition, WorkflowDef, WorkflowState,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuilderStatus {
    Draft,
    Validated,
    Published,
}

impl Default for BuilderStatus {
    fn default() -> Self {
        Self::Draft
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    OneToOne,
    OneToMany,
    ManyToOne,
    ManyToMany,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuilderRelation {
    pub key: String,
    pub label: String,
    pub from_object: String,
    pub to_object: String,
    pub kind: RelationKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRuleKind {
    Mutation,
    WorkflowTransition,
    AiActionExecution,
    MoneyThreshold,
    RestrictedFieldUpdate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRule {
    pub kind: ApprovalRuleKind,
    #[serde(default)]
    pub transition_key: Option<String>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub threshold: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuilderDefinition {
    pub key: String,
    pub label: String,
    #[serde(default)]
    pub label_plural: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub display_field: Option<String>,
    #[serde(default)]
    pub fields: Vec<FieldDefinition>,
    #[serde(default)]
    pub relations: Vec<BuilderRelation>,
    #[serde(default)]
    pub workflow: Option<WorkflowDef>,
    #[serde(default)]
    pub permissions: Vec<PermissionGrant>,
    #[serde(default)]
    pub approval_rules: Vec<ApprovalRule>,
    #[serde(default)]
    pub sensitive_ai_visibility_confirmed: bool,
}

impl BuilderDefinition {
    pub fn to_object_type(&self) -> ObjectTypeDef {
        ObjectTypeDef {
            id: String::new(),
            key: self.key.clone(),
            label: self.label.clone(),
            label_plural: self.label_plural.clone(),
            description: self.description.clone(),
            system: false,
            workflow_key: self.workflow.as_ref().map(|w| w.key.clone()),
            display_field: self.display_field.clone(),
            module: self.module.clone(),
            fields: self.fields.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuilderDraft {
    pub id: String,
    pub tenant_id: String,
    pub status: BuilderStatus,
    pub definition: BuilderDefinition,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub published_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SaveBuilderDraftRequest {
    #[serde(default)]
    pub id: Option<String>,
    pub definition: BuilderDefinition,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuilderValidationResult {
    pub valid: bool,
    pub status: BuilderStatus,
    pub issues: Vec<ValidationIssue>,
    #[serde(default)]
    pub preview: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublishBuilderDraftRequest {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublishBuilderResult {
    pub draft: BuilderDraft,
    pub object_type: ObjectTypeDef,
    #[serde(default)]
    pub workflow: Option<WorkflowDef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuilderTemplate {
    pub key: String,
    pub name: String,
    pub description: String,
    pub objects: Vec<BuilderDefinition>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstallTemplateRequest {
    pub key: String,
    #[serde(default)]
    pub include_sample_records: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstallTemplateResult {
    pub template_key: String,
    pub object_types: Vec<ObjectTypeDef>,
    pub record_count: usize,
    pub report_count: usize,
    pub dashboard_count: usize,
}

pub fn workflow_state(key: &str, terminal: bool) -> WorkflowState {
    WorkflowState {
        key: key.into(),
        label: key.replace('_', " "),
        terminal,
    }
}

pub fn workflow_transition(
    key: &str,
    from: &str,
    to: &str,
    label: &str,
    approval: bool,
) -> Transition {
    Transition {
        key: key.into(),
        from: from.into(),
        to: to.into(),
        label: label.into(),
        guard_permission: None,
        requires_approval: approval,
        approval_policy: approval.then(|| "default".into()),
    }
}
