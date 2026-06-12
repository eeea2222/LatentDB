//! First-run migration contracts.
//!
//! When a brand-new tenant signs in for the first time, they usually already run
//! *some* business model — a set of installed object types and the records inside
//! them. This crate calls that their **old system**. Onboarding lets them keep
//! booting that old system while they evaluate a **selected system** (one of the
//! Builder templates) to migrate onto.
//!
//! Nothing here performs IO. These are the shapes the kernel migration service
//! produces and the API returns. The headline artifact is [`MigrationReport`] —
//! the non-destructive "output" emitted at logout, describing either the old
//! system as-is or how its data maps onto the selected system.

use crate::field::FieldType;
use serde::{Deserialize, Serialize};

/// Which of the two systems an artifact is *about*. A first-time user is always
/// running one of these at a time (`active_system`), and a report is rendered for
/// one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemKind {
    /// The model the tenant already has installed (their existing object types).
    Old,
    /// The Builder template the tenant is migrating onto.
    Selected,
}

impl SystemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SystemKind::Old => "old",
            SystemKind::Selected => "selected",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "old" => Some(SystemKind::Old),
            "selected" => Some(SystemKind::Selected),
            _ => None,
        }
    }
}

/// Where a first-time user is in the migration lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    /// Booted into the old system; no target chosen yet (or deliberately staying).
    BootedOld,
    /// A target template has been selected; the old system is still intact.
    TargetSelected,
    /// At least one migration report has been emitted (e.g. on logout).
    Reported,
}

impl MigrationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            MigrationStatus::BootedOld => "booted_old",
            MigrationStatus::TargetSelected => "target_selected",
            MigrationStatus::Reported => "reported",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "target_selected" => MigrationStatus::TargetSelected,
            "reported" => MigrationStatus::Reported,
            _ => MigrationStatus::BootedOld,
        }
    }
}

/// One object type inside a system, with the data inventory that matters for a
/// migration: its field keys and how many live records exist.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemObject {
    pub key: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    pub field_keys: Vec<String>,
    /// Count of active (non-archived) records of this type.
    pub record_count: i64,
}

/// A point-in-time inventory of a system: which objects exist and how much data
/// they hold. Built live so counts are accurate when an artifact is produced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub kind: SystemKind,
    /// Stable key: `"installed"` for the old system, or a template key
    /// (`"finance"`, `"crm"`, ...) for a selected system.
    pub key: String,
    pub label: String,
    pub objects: Vec<SystemObject>,
}

impl SystemSnapshot {
    pub fn total_records(&self) -> i64 {
        self.objects.iter().map(|o| o.record_count).sum()
    }
}

/// The disposition of a single field when mapping old -> selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingStatus {
    /// Same key, same type — moves cleanly.
    Mapped,
    /// Same key, different type — values need transformation.
    TypeMismatch,
    /// Present only in the target — records gain a new (empty) field.
    AddedInTarget,
    /// Present only in the source — values would not be carried over.
    DroppedFromSource,
    /// Required in the target but absent in the source — blocks clean import.
    MissingRequiredInTarget,
}

/// How one source field lines up against the target object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldMapping {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_type: Option<FieldType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_type: Option<FieldType>,
    pub status: MappingStatus,
}

/// How one object type lines up: which target it maps to and the field-by-field
/// plan plus the record volume involved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectMapping {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_object: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_object: Option<String>,
    pub label: String,
    /// Records that this mapping would carry over (source record count when a
    /// source object exists, else 0).
    pub record_count: i64,
    pub field_mappings: Vec<FieldMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A categorized problem that needs a human decision before a clean import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// A source object has no counterpart in the selected system.
    UnmappedSourceObject,
    /// A field exists in both but with different types.
    TypeMismatch,
    /// A required target field has no source to populate it.
    MissingRequiredTarget,
    /// A source field would be dropped (its data is not represented in target).
    DroppedField,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationConflict {
    pub kind: ConflictKind,
    /// The object this conflict concerns (source or target key).
    pub object: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub detail: String,
}

/// Roll-up numbers for a plan — the at-a-glance "data management" view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationSummary {
    pub source_objects: usize,
    pub target_objects: usize,
    pub mapped_objects: usize,
    pub source_records: i64,
    /// Records belonging to objects that have a target (would be carried over).
    pub records_mappable: i64,
    /// Records in source objects with no target (retained in the old system).
    pub records_unmapped: i64,
    pub conflicts: usize,
}

/// The full old -> selected mapping. Produced only when a target is selected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub source_system: SystemSnapshot,
    pub target_system: SystemSnapshot,
    pub object_mappings: Vec<ObjectMapping>,
    pub conflicts: Vec<MigrationConflict>,
    pub summary: MigrationSummary,
}

/// The output emitted on logout (and on demand): a self-contained, non-destructive
/// description of the system the user is on. For [`SystemKind::Old`] it is an
/// inventory of the current system; for [`SystemKind::Selected`] it embeds the
/// migration [`MigrationPlan`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationReport {
    pub id: String,
    pub tenant_id: String,
    pub generated_at: String,
    pub for_system: SystemKind,
    pub source_system: SystemSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_system: Option<SystemSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<MigrationPlan>,
    pub summary: MigrationSummary,
    pub notes: Vec<String>,
}

/// The persisted onboarding session for a first-time user. One per tenant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationSession {
    pub tenant_id: String,
    pub status: MigrationStatus,
    /// Which system the user is currently booted into.
    pub active_system: SystemKind,
    /// The template key of the selected target system, if one has been chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_system_key: Option<String>,
    /// The old-system inventory captured when the session started.
    pub old_system: SystemSnapshot,
    /// The most recent report emitted for this session, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_report: Option<MigrationReport>,
    pub created_at: String,
    pub updated_at: String,
}
