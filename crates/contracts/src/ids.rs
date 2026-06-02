//! Identifier and timestamp helpers.
//!
//! Records reference each other dynamically (the object system is metadata-driven),
//! so ids are opaque time-ordered strings rather than per-type newtypes. Using
//! UUID v7 keeps them sortable by creation time, which is convenient for paging
//! and audit ordering.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// An opaque entity identifier (UUID v7, lowercase hyphenated string).
pub type Id = String;

/// Generate a new time-ordered identifier.
pub fn new_id() -> Id {
    Uuid::now_v7().to_string()
}

/// Current wall-clock time (UTC).
pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Current time as an RFC3339 string (the on-the-wire timestamp format).
pub fn now_rfc3339() -> String {
    to_rfc3339(now())
}

/// Format a timestamp as RFC3339. Falls back to a stable sentinel on the
/// (practically impossible) formatting error so callers never panic.
pub fn to_rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Parse an RFC3339 timestamp string.
pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}
