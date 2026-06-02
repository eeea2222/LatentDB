//! Object type definitions — the schema layer of the metadata-driven database.

use crate::field::FieldDefinition;
use serde::{Deserialize, Serialize};

/// A dynamically defined business object type (e.g. `invoice`, `account`,
/// `employee`). Business modules are expressed as object types rather than
/// hardcoded tables.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectTypeDef {
    pub id: String,
    /// Stable machine key, unique per tenant, e.g. `"invoice"`.
    pub key: String,
    pub label: String,
    /// Plural label for list views, e.g. `"Invoices"`.
    #[serde(default)]
    pub label_plural: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// System object types are seeded by modules and protected from deletion.
    #[serde(default)]
    pub system: bool,
    /// Optional workflow key attached to records of this type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_key: Option<String>,
    /// Field key used as the human-readable record label in lists/relations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_field: Option<String>,
    /// Which business module registered this type (for grouping in the UI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    pub fields: Vec<FieldDefinition>,
}

impl ObjectTypeDef {
    pub fn field(&self, key: &str) -> Option<&FieldDefinition> {
        self.fields.iter().find(|f| f.key == key)
    }

    /// Fields flagged `restricted` (subject to field-level permission checks).
    pub fn restricted_fields(&self) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|f| f.restricted)
            .map(|f| f.key.as_str())
            .collect()
    }
}
