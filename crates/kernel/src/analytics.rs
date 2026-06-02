//! BI layer: permission-aware metrics, saved reports, and dashboards.
//!
//! Every aggregation runs over [`Kernel::scan_records`], which applies tenant
//! scope, record-level permission, and field-level projection *before* numbers
//! are computed — so a report can never surface a value the caller could not see
//! row-by-row. Transactional SQLite is the source of truth; an optional
//! DataFusion adapter (Phase 6) can accelerate this path but the kernel scan is
//! always the correctness baseline and fallback.

use crate::audit::{event_from, insert_audit};
use crate::store::map_db_err;
use crate::Kernel;
use latentdb_contracts::page::FieldFilter;
use latentdb_contracts::{ids, Action, ApiError, AuthContext, Record, RecordFilter};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;

/// Aggregation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggOp {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

/// A saved report / metric definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportDef {
    pub key: String,
    pub name: String,
    pub object_type: String,
    pub op: AggOp,
    /// Field to aggregate (required for sum/avg/min/max; ignored for count).
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub filters: Vec<FieldFilter>,
    /// Optional field to group by, producing buckets instead of a scalar.
    #[serde(default)]
    pub group_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupBucket {
    pub key: String,
    pub value: f64,
    pub count: i64,
}

/// The result of running a report: a scalar `value`, or `groups` when grouped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportResult {
    pub key: String,
    pub op: AggOp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupBucket>,
    /// Number of source records considered (post-permission). Supports the
    /// "reports cite their basis" expectation.
    pub sample_size: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub key: String,
    pub name: String,
    /// Free-form card definitions (each references a report key or metric spec).
    pub cards: Vec<Value>,
}

impl Kernel {
    /// Compute a single aggregate value, permission-aware.
    pub async fn aggregate(
        &self,
        ctx: &AuthContext,
        object_type: &str,
        op: AggOp,
        field: Option<&str>,
        filters: Vec<FieldFilter>,
    ) -> latentdb_contracts::Result<f64> {
        let filter = RecordFilter { filters, ..Default::default() };
        let records = self.scan_records(ctx, object_type, &filter).await?;
        Ok(compute(&records, op, field))
    }

    /// Save (or overwrite) a report definition. Requires `configure` on `report`.
    pub async fn save_report(
        &self,
        ctx: &AuthContext,
        def: &ReportDef,
    ) -> latentdb_contracts::Result<ReportDef> {
        self.authorize(ctx, Action::Configure, "report", None).await?;
        let json = serde_json::to_string(def)
            .map_err(|e| ApiError::internal(format!("serialize report: {e}")))?;
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query(
            r#"INSERT INTO reports (id, tenant_id, key, name, definition_json, created_at)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(tenant_id, key) DO UPDATE SET name = excluded.name, definition_json = excluded.definition_json"#,
        )
        .bind(ids::new_id())
        .bind(&ctx.tenant_id)
        .bind(&def.key)
        .bind(&def.name)
        .bind(&json)
        .bind(ids::now_rfc3339())
        .execute(&mut *tx)
        .await
        .map_err(map_db_err)?;
        let ev = event_from(ctx, "report.save", Some("report"), Some(&def.key), None,
            Some(serde_json::json!({"object_type": def.object_type, "op": def.op})));
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(def.clone())
    }

    pub async fn list_reports(&self, ctx: &AuthContext) -> latentdb_contracts::Result<Vec<ReportDef>> {
        self.authorize(ctx, Action::Read, "report", None).await?;
        let rows = sqlx::query("SELECT definition_json FROM reports WHERE tenant_id = ? ORDER BY key")
            .bind(&ctx.tenant_id)
            .fetch_all(self.pool())
            .await
            .map_err(map_db_err)?;
        Ok(rows
            .iter()
            .filter_map(|r| r.try_get::<String, _>("definition_json").ok())
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect())
    }

    async fn load_report(&self, ctx: &AuthContext, key: &str) -> latentdb_contracts::Result<ReportDef> {
        let row = sqlx::query("SELECT definition_json FROM reports WHERE tenant_id = ? AND key = ?")
            .bind(&ctx.tenant_id)
            .bind(key)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::not_found("report not found"))?;
        let json: String = row.try_get("definition_json").map_err(map_db_err)?;
        serde_json::from_str(&json).map_err(|e| ApiError::internal(format!("report def: {e}")))
    }

    /// Run a saved report by key (permission-aware).
    pub async fn run_report(
        &self,
        ctx: &AuthContext,
        key: &str,
    ) -> latentdb_contracts::Result<ReportResult> {
        self.authorize(ctx, Action::Read, "report", None).await?;
        let def = self.load_report(ctx, key).await?;
        self.run_report_def(ctx, &def).await
    }

    /// Run an ad-hoc report definition (permission-aware). Shared by `run_report`
    /// and module/BI-agent callers.
    pub async fn run_report_def(
        &self,
        ctx: &AuthContext,
        def: &ReportDef,
    ) -> latentdb_contracts::Result<ReportResult> {
        let filter = RecordFilter { filters: def.filters.clone(), ..Default::default() };
        let records = self.scan_records(ctx, &def.object_type, &filter).await?;
        let sample_size = records.len() as i64;

        if let Some(group_field) = &def.group_by {
            use std::collections::BTreeMap;
            let mut buckets: BTreeMap<String, Vec<Record>> = BTreeMap::new();
            for r in records {
                let key = r
                    .data
                    .get(group_field)
                    .map(value_to_key)
                    .unwrap_or_else(|| "(none)".to_string());
                buckets.entry(key).or_default().push(r);
            }
            let groups = buckets
                .into_iter()
                .map(|(key, recs)| GroupBucket {
                    value: compute(&recs, def.op, def.field.as_deref()),
                    count: recs.len() as i64,
                    key,
                })
                .collect();
            Ok(ReportResult { key: def.key.clone(), op: def.op, value: None, groups, sample_size })
        } else {
            let value = compute(&records, def.op, def.field.as_deref());
            Ok(ReportResult { key: def.key.clone(), op: def.op, value: Some(value), groups: vec![], sample_size })
        }
    }

    /// Save (or overwrite) a dashboard. Requires `configure` on `report`.
    pub async fn save_dashboard(
        &self,
        ctx: &AuthContext,
        dash: &Dashboard,
    ) -> latentdb_contracts::Result<Dashboard> {
        self.authorize(ctx, Action::Configure, "report", None).await?;
        let cards = serde_json::to_string(&dash.cards).unwrap_or_else(|_| "[]".into());
        let mut tx = self.pool().begin().await.map_err(map_db_err)?;
        sqlx::query(
            r#"INSERT INTO dashboards (id, tenant_id, key, name, cards_json, created_at)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(tenant_id, key) DO UPDATE SET name = excluded.name, cards_json = excluded.cards_json"#,
        )
        .bind(ids::new_id())
        .bind(&ctx.tenant_id)
        .bind(&dash.key)
        .bind(&dash.name)
        .bind(&cards)
        .bind(ids::now_rfc3339())
        .execute(&mut *tx)
        .await
        .map_err(map_db_err)?;
        let ev = event_from(ctx, "dashboard.save", Some("dashboard"), Some(&dash.key), None, None);
        insert_audit(&mut tx, &ev).await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(dash.clone())
    }

    pub async fn list_dashboards(&self, ctx: &AuthContext) -> latentdb_contracts::Result<Vec<Dashboard>> {
        self.authorize(ctx, Action::Read, "dashboard", None).await?;
        let rows = sqlx::query("SELECT key, name, cards_json FROM dashboards WHERE tenant_id = ? ORDER BY key")
            .bind(&ctx.tenant_id)
            .fetch_all(self.pool())
            .await
            .map_err(map_db_err)?;
        rows.iter()
            .map(|r| {
                Ok(Dashboard {
                    key: r.try_get("key").map_err(map_db_err)?,
                    name: r.try_get("name").map_err(map_db_err)?,
                    cards: r
                        .try_get::<String, _>("cards_json")
                        .map_err(map_db_err)
                        .ok()
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default(),
                })
            })
            .collect()
    }

    pub async fn get_dashboard(&self, ctx: &AuthContext, key: &str) -> latentdb_contracts::Result<Dashboard> {
        self.authorize(ctx, Action::Read, "dashboard", None).await?;
        let row = sqlx::query("SELECT key, name, cards_json FROM dashboards WHERE tenant_id = ? AND key = ?")
            .bind(&ctx.tenant_id)
            .bind(key)
            .fetch_optional(self.pool())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| ApiError::not_found("dashboard not found"))?;
        Ok(Dashboard {
            key: row.try_get("key").map_err(map_db_err)?,
            name: row.try_get("name").map_err(map_db_err)?,
            cards: row
                .try_get::<String, _>("cards_json")
                .map_err(map_db_err)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default(),
        })
    }
}

fn compute(records: &[Record], op: AggOp, field: Option<&str>) -> f64 {
    match op {
        AggOp::Count => records.len() as f64,
        _ => {
            let vals: Vec<f64> = records
                .iter()
                .filter_map(|r| field.and_then(|f| r.data.get(f)).and_then(num_val))
                .collect();
            match op {
                AggOp::Sum => vals.iter().sum(),
                AggOp::Avg => {
                    if vals.is_empty() {
                        0.0
                    } else {
                        vals.iter().sum::<f64>() / vals.len() as f64
                    }
                }
                AggOp::Min => vals.iter().cloned().fold(f64::INFINITY, f64::min),
                AggOp::Max => vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
                AggOp::Count => unreachable!(),
            }
        }
    }
}

fn num_val(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

fn value_to_key(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "(none)".to_string(),
        other => other.to_string(),
    }
}
