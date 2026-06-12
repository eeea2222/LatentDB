//! The LatentDB API crate: assembles kernel services into an Axum application.
//!
//! Exposed as a library (so integration tests can drive the router directly) and
//! consumed by the `latentdb` binary for `serve`.

pub mod app;
pub mod auth;
pub mod error;

use app::AppState;
use latentdb_contracts::FeatureFlags;
use latentdb_kernel::{Kernel, StoreConfig};

/// Build application state from environment configuration (database URL +
/// feature flags). Local/on-prem friendly: defaults to a SQLite file.
pub async fn build_state() -> anyhow::Result<AppState> {
    let flags = FeatureFlags::from_env();
    let kernel = Kernel::open(StoreConfig::from_env(), flags)
        .await
        .map_err(|e| anyhow::anyhow!("kernel open failed: {}", e.message))?;
    let ai = latentdb_ai::AiEngine::from_env();
    Ok(AppState { kernel, ai })
}

/// Boot the HTTP server.
pub async fn run() -> anyhow::Result<()> {
    init_tracing();
    let state = build_state().await?;
    let app = app::router(state);
    let addr = std::env::var("LATENTDB_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("LatentDB API listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_env("LATENTDB_LOG")
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    let _ = fmt().with_env_filter(filter).try_init();
}
