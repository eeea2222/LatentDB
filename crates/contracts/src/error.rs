//! The unified error type and on-the-wire error envelope.
//!
//! Every API response that fails serializes as `{"error": {...}}` with a stable
//! machine-readable `code`, a human `message`, optional structured `details`, and
//! the `request_id` for tracing. Kernel/services return [`ApiError`]; the API layer
//! stamps the request id and maps to an HTTP status.

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, ApiError>;

/// Stable, machine-readable error codes. These are part of the public contract:
/// clients and the admin UI branch on them, so do not repurpose existing values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Authentication is missing or invalid.
    Unauthorized,
    /// Authenticated, but the actor lacks permission for this action/resource.
    Forbidden,
    /// The requested entity does not exist (or is not visible to this tenant).
    NotFound,
    /// Input failed validation (field constraints, bad shape, bad enum, ...).
    Validation,
    /// A conflicting state prevented the operation (duplicate, version clash).
    Conflict,
    /// A precondition for the operation was not met (e.g. invalid transition).
    FailedPrecondition,
    /// The caller is being rate limited or has exceeded a plan limit.
    RateLimited,
    /// A requested capability is disabled by a feature flag.
    FeatureDisabled,
    /// The capability exists in contract but is not implemented in this build.
    NotImplemented,
    /// An unexpected internal error. Never leak internals in `message`.
    Internal,
}

impl ErrorCode {
    /// Map to an HTTP status code (returned as a plain u16 so this crate stays
    /// free of any web-framework dependency).
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::Unauthorized => 401,
            ErrorCode::Forbidden => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::Validation => 422,
            ErrorCode::Conflict => 409,
            ErrorCode::FailedPrecondition => 412,
            ErrorCode::RateLimited => 429,
            ErrorCode::FeatureDisabled => 403,
            ErrorCode::NotImplemented => 501,
            ErrorCode::Internal => 500,
        }
    }
}

/// The canonical service/API error.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Filled in by the API layer right before serialization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
            request_id: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn http_status(&self) -> u16 {
        self.code.http_status()
    }

    // Ergonomic constructors used throughout the kernel.
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthorized, msg)
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, msg)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, msg)
    }
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Validation, msg)
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, msg)
    }
    pub fn failed_precondition(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::FailedPrecondition, msg)
    }
    pub fn feature_disabled(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::FeatureDisabled, msg)
    }
    pub fn not_implemented(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotImplemented, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, msg)
    }
}

/// The serialization wrapper that produces `{"error": {...}}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ApiError,
}

impl From<ApiError> for ErrorBody {
    fn from(error: ApiError) -> Self {
        ErrorBody { error }
    }
}
