//! Pagination, list envelopes, and record query filters shared by the API and
//! kernel query paths.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Standard pagination request. Defaults keep list endpoints bounded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

impl Default for Page {
    fn default() -> Self {
        Self {
            limit: default_limit(),
            offset: 0,
        }
    }
}

impl Page {
    /// Clamp to safe bounds so a client cannot request an unbounded scan.
    pub fn clamped(&self) -> Page {
        Page {
            limit: self.limit.clamp(1, 500),
            offset: self.offset.max(0),
        }
    }
}

/// Uniform list response envelope. `total` is the unpaged count (post-permission
/// filtering) so the UI can render pagination controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

impl<T> ListResponse<T> {
    pub fn new(items: Vec<T>, total: i64, page: &Page) -> Self {
        Self {
            items,
            total,
            limit: page.limit,
            offset: page.offset,
        }
    }
}

/// A single filter clause over record data, e.g. `status eq "overdue"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldFilter {
    pub field: String,
    pub op: crate::permission::ConditionOp,
    pub value: Value,
}

/// Query parameters for listing records of an object type. Filtering, sorting,
/// search, and lifecycle are all expressed here; permission scoping is applied
/// by the kernel on top of whatever the caller asks for.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecordFilter {
    /// Structured field filters (AND-combined).
    #[serde(default)]
    pub filters: Vec<FieldFilter>,
    /// Free-text keyword search across text fields.
    #[serde(default)]
    pub search: Option<String>,
    /// Field key to sort by; defaults to `created_at`.
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub desc: bool,
    /// Include archived records (default: only active).
    #[serde(default)]
    pub include_archived: bool,
    #[serde(default)]
    pub page: Page,
}
