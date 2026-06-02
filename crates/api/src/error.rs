//! HTTP error mapping.
//!
//! Kernel/services return [`ApiError`]; this wraps it so Axum can render the
//! canonical `{"error": {...}}` envelope with the right HTTP status. Handlers use
//! `Result<Json<T>, AppError>` and `?` to surface kernel errors uniformly.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use latentdb_contracts::{ApiError, ErrorBody};

pub struct AppError(pub ApiError);

impl From<ApiError> for AppError {
    fn from(e: ApiError) -> Self {
        AppError(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(ErrorBody::from(self.0))).into_response()
    }
}

/// Convenience alias for JSON handlers.
pub type ApiJson<T> = Result<Json<T>, AppError>;
