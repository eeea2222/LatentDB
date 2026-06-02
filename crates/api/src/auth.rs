//! The `Auth` extractor.
//!
//! Any handler that takes `Auth` is automatically protected: the extractor reads
//! the bearer token (session `lds_…` or API key `ldb_…`), resolves it through the
//! kernel into a full [`AuthContext`], and rejects with 401 if it is missing or
//! invalid. Public endpoints (login, health) simply do not take `Auth`.

use crate::app::AppState;
use crate::error::AppError;
use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use latentdb_contracts::{ids, ApiError, AuthContext, Source};

pub struct Auth(pub AuthContext);

#[async_trait]
impl FromRequestParts<AppState> for Auth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts)
            .ok_or_else(|| AppError(ApiError::unauthorized("missing bearer token")))?;
        let request_id = parts
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(ids::new_id);
        let source = detect_source(parts);
        let ctx = state.kernel.authenticate(&token, &request_id, source).await?;
        Ok(Auth(ctx))
    }
}

fn bearer(parts: &Parts) -> Option<String> {
    let raw = parts.headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

/// The admin UI sends `x-latentdb-source: admin_ui` so audit events record where
/// the action came from. Everything else is treated as a generic API call.
fn detect_source(parts: &Parts) -> Source {
    match parts.headers.get("x-latentdb-source").and_then(|v| v.to_str().ok()) {
        Some("admin_ui") => Source::AdminUi,
        Some("agent") => Source::Agent,
        _ => Source::Api,
    }
}
