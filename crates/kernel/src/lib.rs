//! The LatentDB enterprise kernel.
//!
//! Everything the platform does flows through here. The kernel owns the database
//! connection privately — no other crate can obtain it — so business modules, the
//! AI layer, the API, and the admin UI can only ever go through kernel *services*.
//! That is what structurally enforces the platform's non-negotiable rules:
//!
//! * tenant isolation — every service method takes an [`AuthContext`] and scopes
//!   queries to its tenant; there is no un-scoped query path.
//! * permission checks — all access routes through [`Kernel::authorize`].
//! * audit on mutation — mutating methods write the change and its audit event in
//!   the same transaction.
//!
//! Services are organized as `impl Kernel` blocks across the modules below.

mod crypto;
mod store;

pub mod analytics;
pub mod approval;
pub mod audit;
pub mod auth;
pub mod builder;
pub mod event;
pub mod identity;
pub mod migration;
pub mod object;
pub mod rbac;
pub mod record;
pub mod task;
pub mod tenant;
pub mod transition;
pub mod workflow;

pub use store::{Store, StoreConfig};

use latentdb_contracts::FeatureFlags;
use sqlx::SqlitePool;

/// The kernel handle. Cloneable and cheap to share (the pool is reference
/// counted). The `pool` field is deliberately private to this crate.
#[derive(Clone)]
pub struct Kernel {
    pool: SqlitePool,
    flags: FeatureFlags,
}

impl Kernel {
    /// Open (or create) a kernel backed by the configured store, running schema
    /// migrations. Use `StoreConfig::memory()` for tests, `StoreConfig::file(..)`
    /// for local/on-prem.
    pub async fn open(
        config: StoreConfig,
        flags: FeatureFlags,
    ) -> latentdb_contracts::Result<Self> {
        let pool = store::connect(&config).await?;
        store::migrate(&pool).await?;
        Ok(Self { pool, flags })
    }

    /// Convenience: an in-memory kernel with default flags (used widely in tests).
    pub async fn in_memory() -> latentdb_contracts::Result<Self> {
        Self::open(StoreConfig::memory(), FeatureFlags::default()).await
    }

    pub fn flags(&self) -> &FeatureFlags {
        &self.flags
    }

    /// Crate-internal access to the pool for service methods. Not public: callers
    /// outside the kernel must use services.
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Liveness/readiness probe: confirms the store is reachable.
    pub async fn ping(&self) -> latentdb_contracts::Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(store::map_db_err)?;
        Ok(())
    }
}
