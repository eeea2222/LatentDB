//! Per-tenant usage metering.
//!
//! Counters live in the `usage_meters` table keyed by `(tenant, metric,
//! period)` with a monthly period, giving multi-customer deployments a billing
//! and fair-use signal. Metering is gated by `enable_usage_metering` and is
//! always best-effort from the caller's perspective: a metering failure must
//! never fail the metered request.

use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::{ids, Action, AuthContext};
use serde::{Deserialize, Serialize};
use sqlx::Row;

/// One usage counter for a tenant within a period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageMeter {
    pub metric: String,
    /// Calendar month, `YYYY-MM`.
    pub period: String,
    pub value: i64,
    pub updated_at: String,
}

/// The current metering period (calendar month, UTC).
fn current_period() -> String {
    let now = ids::now();
    format!("{:04}-{:02}", now.year(), u8::from(now.month()))
}

impl Kernel {
    /// Increment a tenant's counter for `metric` in the current period by
    /// `amount`. No-op when metering is disabled.
    pub async fn record_usage(
        &self,
        tenant_id: &str,
        metric: &str,
        amount: i64,
    ) -> latentdb_contracts::Result<()> {
        if !self.flags().enable_usage_metering {
            return Ok(());
        }
        sqlx::query(
            r#"INSERT INTO usage_meters (id, tenant_id, metric, period, value, updated_at)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(tenant_id, metric, period)
               DO UPDATE SET value = value + excluded.value, updated_at = excluded.updated_at"#,
        )
        .bind(ids::new_id())
        .bind(tenant_id)
        .bind(metric)
        .bind(current_period())
        .bind(amount)
        .bind(ids::now_rfc3339())
        .execute(self.pool())
        .await
        .map_err(map_db_err)?;
        Ok(())
    }

    /// Convenience wrapper used by the API layer per authenticated request.
    /// Best-effort by design — errors are logged, never propagated.
    pub async fn meter_api_call(&self, ctx: &AuthContext) {
        if let Err(e) = self.record_usage(&ctx.tenant_id, "api_calls", 1).await {
            tracing::warn!(error = %e.message, "usage metering failed");
        }
    }

    /// Usage meters for the caller's tenant (current and past periods).
    /// Requires `read` on `usage` (tenant admins hold it via `manage *`).
    pub async fn list_usage(
        &self,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<Vec<UsageMeter>> {
        self.authorize(ctx, Action::Read, "usage", None).await?;
        let rows = sqlx::query(
            "SELECT metric, period, value, updated_at FROM usage_meters
             WHERE tenant_id = ? ORDER BY period DESC, metric",
        )
        .bind(&ctx.tenant_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_db_err)?;
        rows.iter()
            .map(|row| {
                Ok(UsageMeter {
                    metric: row.try_get("metric").map_err(map_db_err)?,
                    period: row.try_get("period").map_err(map_db_err)?,
                    value: row.try_get("value").map_err(map_db_err)?,
                    updated_at: row.try_get("updated_at").map_err(map_db_err)?,
                })
            })
            .collect()
    }
}
