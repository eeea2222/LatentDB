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

/// Boot the HTTP server with background housekeeping and graceful shutdown.
pub async fn run() -> anyhow::Result<()> {
    init_tracing();
    let state = build_state().await?;

    // Housekeeping loop: purge expired/revoked sessions and stale login
    // rate-limit windows. Runs immediately, then hourly.
    let housekeeper = state.kernel.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            if let Err(e) = housekeeper.run_housekeeping().await {
                tracing::warn!(error = %e.message, "housekeeping run failed");
            }
        }
    });

    let app = app::router(state);
    let addr = std::env::var("LATENTDB_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("LatentDB API listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Resolve on SIGINT (Ctrl-C) or SIGTERM so in-flight requests drain instead of
/// being severed on redeploys.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received; draining connections");
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_env("LATENTDB_LOG")
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    let _ = fmt().with_env_filter(filter).try_init();
}
