//! Field definitions for the metadata-driven object system.
//!
//! A business "model" (invoice, account, employee, ...) is just an object type
//! with a list of [`FieldDefinition`]s. Validation of record values against these
//! definitions is implemented here so it is shared by the kernel, the API layer,
//! and seeding.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The supported field types. The metadata-driven object system stores record
/// values as JSON; these types drive validation, display, and reference handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Text,
    LongText,
    Number,
    /// Stored as an integer number of minor units (cents) to avoid float drift.
    Money,
    Boolean,
    /// Date only, `YYYY-MM-DD`.
    Date,
    /// RFC3339 timestamp.
    DateTime,
    /// Single choice from `enum_options`.
    Enum,
    /// Multiple choices from `enum_options`.
    MultiEnum,
    /// Arbitrary JSON blob.
    Json,
    /// Reference to another record (id string); `ref_object_type` names the target.
    RecordRef,
    /// Reference to a user id.
    UserRef,
    /// Reference to a document id.
    FileRef,
    /// Computed/derived value; not written directly by clients.
    Formula,
}

/// A field on an object type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldDefinition {
    /// Stable machine key, e.g. `"amount"`, `"status"`, `"customer_id"`.
    pub key: String,
    pub label: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    #[serde(default)]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    /// Allowed values for `Enum`/`MultiEnum`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enum_options: Vec<String>,
    /// For `RecordRef`, the object type key of the referenced record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_object_type: Option<String>,
    /// Field is sensitive; field-level permission rules gate access to it
    /// (e.g. HR compensation). Default-restricted fields are hidden unless a
    /// grant explicitly allows them.
    #[serde(default)]
    pub restricted: bool,
    /// System fields are managed by the platform, not edited by users.
    #[serde(default)]
    pub system: bool,
    /// Whether this field is shown in default list/display views.
    #[serde(default)]
    pub display: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
}

impl FieldDefinition {
    /// Convenience constructor for the common case.
    pub fn new(key: &str, label: &str, field_type: FieldType) -> Self {
        Self {
            key: key.to_string(),
            label: label.to_string(),
            field_type,
            required: false,
            default: None,
            enum_options: Vec::new(),
            ref_object_type: None,
            restricted: false,
            system: false,
            display: false,
            help: None,
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
    pub fn display(mut self) -> Self {
        self.display = true;
        self
    }
    pub fn restricted(mut self) -> Self {
        self.restricted = true;
        self
    }
    pub fn options(mut self, opts: &[&str]) -> Self {
        self.enum_options = opts.iter().map(|s| s.to_string()).collect();
        self
    }
    pub fn references(mut self, object_type: &str) -> Self {
        self.ref_object_type = Some(object_type.to_string());
        self
    }
    pub fn with_default(mut self, v: Value) -> Self {
        self.default = Some(v);
        self
    }

    /// Validate a single JSON value against this field's type and constraints.
    /// Returns `Err(reason)` describing the first problem found.
    pub fn validate_value(&self, value: &Value) -> std::result::Result<(), String> {
        // Null handling: only allowed when not required.
        if value.is_null() {
            if self.required {
                return Err(format!("field '{}' is required", self.key));
            }
            return Ok(());
        }

        match self.field_type {
            FieldType::Text | FieldType::LongText => {
                if !value.is_string() {
                    return Err(format!("field '{}' must be a string", self.key));
                }
            }
            FieldType::Number => {
                if !value.is_number() {
                    return Err(format!("field '{}' must be a number", self.key));
                }
            }
            FieldType::Money => {
                // Money is an integer number of minor units.
                if !value.is_i64() && !value.is_u64() {
                    return Err(format!(
                        "field '{}' (money) must be an integer of minor units (cents)",
                        self.key
                    ));
                }
            }
            FieldType::Boolean => {
                if !value.is_boolean() {
                    return Err(format!("field '{}' must be a boolean", self.key));
                }
            }
            FieldType::Date => {
                let s = value
                    .as_str()
                    .ok_or_else(|| format!("field '{}' must be a YYYY-MM-DD string", self.key))?;
                if s.len() != 10 || s.as_bytes()[4] != b'-' || s.as_bytes()[7] != b'-' {
                    return Err(format!("field '{}' must be YYYY-MM-DD", self.key));
                }
            }
            FieldType::DateTime => {
                let s = value
                    .as_str()
                    .ok_or_else(|| format!("field '{}' must be an RFC3339 string", self.key))?;
                if crate::ids::parse_rfc3339(s).is_none() {
                    return Err(format!("field '{}' must be an RFC3339 timestamp", self.key));
                }
            }
            FieldType::Enum => {
                let s = value
                    .as_str()
                    .ok_or_else(|| format!("field '{}' must be a string enum value", self.key))?;
                if !self.enum_options.iter().any(|o| o == s) {
                    return Err(format!(
                        "field '{}' must be one of [{}]",
                        self.key,
                        self.enum_options.join(", ")
                    ));
                }
            }
            FieldType::MultiEnum => {
                let arr = value
                    .as_array()
                    .ok_or_else(|| format!("field '{}' must be an array", self.key))?;
                for item in arr {
                    let s = item.as_str().ok_or_else(|| {
                        format!("field '{}' must be an array of strings", self.key)
                    })?;
                    if !self.enum_options.iter().any(|o| o == s) {
                        return Err(format!(
                            "field '{}' value '{}' is not an allowed option",
                            self.key, s
                        ));
                    }
                }
            }
            FieldType::Json => { /* any JSON shape is acceptable */ }
            FieldType::RecordRef | FieldType::UserRef | FieldType::FileRef => {
                if !value.is_string() {
                    return Err(format!("field '{}' must be a reference id string", self.key));
                }
            }
            FieldType::Formula => {
                // Computed fields are not validated as user input.
            }
        }
        Ok(())
    }
}
